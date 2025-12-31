use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray};
use jni::sys::{jboolean, jstring, jbyteArray};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};

// Importera din huvudstruktur från lib.rs
use crate::SecureMessenger;
use crate::crypto::enhanced_ratchet::RatchetState;

// Globalt tillstånd för att hålla reda på aktiva sessioner
lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, SecureMessenger>> = Mutex::new(HashMap::new());
    static ref INITIALIZED: Mutex<bool> = Mutex::new(false);
}

// En enkel struktur för att returnera sessionsdata till Kotlin
#[derive(Serialize)]
struct RatchetSessionInfo {
    session_id: String,
    state: String,
    created_at: u64,
}

// Hjälpfunktion för att hantera fel och returnera null/false till Java vid panic
fn catch_unwind_result<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
    R: Default,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_default()
}

/// Initialize the Qubee cryptographic system
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInitialize(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut init = INITIALIZED.lock().unwrap();
    if *init {
        return 1;
    }

    // HACK: Androids `dirs::data_dir()` kan misslyckas om inte HOME är satt.
    // Vi sätter en rimlig path för appens data om det behövs.
    // I en produktionsmiljö bör sökvägen skickas in från Kotlin.
    unsafe {
        std::env::set_var("HOME", "/data/user/0/com.qubee.messenger/files");
    }

    // Initiera loggning om möjligt (kräver android_logger crate, annars print)
    // android_logger::init_once(...)

    *init = true;
    1
}

/// Generate a new identity key pair
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityKeyPair(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_unwind_result(|| {
        // Eftersom SecureMessenger hanterar nycklar internt i sin keystore,
        // kan vi här antingen returnera en public key eller en blob.
        // För detta exempel genererar vi en nyckel och returnerar den serialiserad.
        
        // OBS: Detta är en förenkling. I verkligheten bör du använda din KeyStore.
        let key_data = crate::utils::generate_random_key(32).unwrap_or(vec![]);
        
        let output = env.byte_array_from_slice(&key_data).unwrap();
        output
    })
}

/// Create a new hybrid ratchet session with a contact
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateRatchetSession(
    env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    their_public_key: JByteArray,
    is_initiator: jboolean,
) -> jbyteArray {
    catch_unwind_result(|| {
        let contact_id: String = env.get_string(contact_id).expect("Invalid contact_id").into();
        let their_pub_key_vec = env.convert_byte_array(their_public_key).expect("Invalid pubkey");
        
        // Skapa en ny messenger-instans
        let mut messenger = match SecureMessenger::new() {
            Ok(m) => m,
            Err(_) => return std::ptr::null_mut(),
        };

        // Här skulle vi egentligen behöva dela upp their_public_key i DH och PQ delar
        // Vi antar för enkelhetens skull att arrayen innehåller båda.
        let shared_secret = b"shared_secret_placeholder"; // Detta bör komma från en X3DH-handshake

        // Initiera beroende på roll
        let init_result = if is_initiator != 0 {
            // Placeholder-nycklar (I verkligheten måste dessa parsas korrekt från input)
            let dh_key = [0u8; 32]; 
            let pq_key = vec![0u8; 1184]; // Kyber768 public key size
            messenger.initialize_sender(shared_secret, &dh_key, &pq_key)
        } else {
            let dh_key = [0u8; 32];
            let pq_key = vec![0u8; 2400]; // Kyber768 private key size
            messenger.initialize_receiver(shared_secret, &dh_key, &pq_key)
        };

        if init_result.is_err() {
            return std::ptr::null_mut();
        }

        // Generera ett unikt sessions-ID (i detta fall återanvänder vi contact_id för enkelhet)
        let session_id = contact_id.clone();

        // Spara i global state
        let mut sessions = SESSIONS.lock().unwrap();
        sessions.insert(session_id.clone(), messenger);

        // Returnera sessionsinfo serialiserad
        let info = RatchetSessionInfo {
            session_id,
            state: "Active".to_string(),
            created_at: 1234567890,
        };
        
        let info_bytes = bincode::serialize(&info).unwrap();
        env.byte_array_from_slice(&info_bytes).unwrap()
    })
}

/// Encrypt a message using the hybrid ratchet
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessage(
    env: JNIEnv,
    _class: JClass,
    session_id: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    catch_unwind_result(|| {
        let session_id: String = env.get_string(session_id).expect("Invalid session_id").into();
        let plaintext_vec = env.convert_byte_array(plaintext).expect("Invalid plaintext");

        let mut sessions = SESSIONS.lock().unwrap();
        if let Some(messenger) = sessions.get_mut(&session_id) {
            match messenger.encrypt_message(&plaintext_vec) {
                Ok(encrypted_bytes) => {
                    env.byte_array_from_slice(&encrypted_bytes).unwrap()
                },
                Err(_) => std::ptr::null_mut()
            }
        } else {
            std::ptr::null_mut()
        }
    })
}

/// Decrypt a message using the hybrid ratchet
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessage(
    env: JNIEnv,
    _class: JClass,
    session_id: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    catch_unwind_result(|| {
        let session_id: String = env.get_string(session_id).expect("Invalid session_id").into();
        let cipher_vec = env.convert_byte_array(ciphertext).expect("Invalid ciphertext");

        let mut sessions = SESSIONS.lock().unwrap();
        if let Some(messenger) = sessions.get_mut(&session_id) {
            match messenger.decrypt_message(&cipher_vec) {
                Ok(decrypted_bytes) => {
                    env.byte_array_from_slice(&decrypted_bytes).unwrap()
                },
                Err(_) => std::ptr::null_mut()
            }
        } else {
            std::ptr::null_mut()
        }
    })
}

/// Generate ephemeral keys for key exchange
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateEphemeralKeys(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_unwind_result(|| {
        // Generera ett par (Detta bör egentligen anropa en funktion i SecureMessenger)
        let keys = crate::utils::generate_random_key(64).unwrap_or(vec![]);
        env.byte_array_from_slice(&keys).unwrap()
    })
}

/// Verify a contact's identity key
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyIdentityKey(
    env: JNIEnv,
    _class: JClass,
    _contact_id: JString,
    identity_key: JByteArray,
    signature: JByteArray,
) -> jboolean {
    catch_unwind_result(|| {
        // Exempel-implementering. Här bör du använda pqcrypto-dilithium för att verifiera.
        let _key_vec = env.convert_byte_array(identity_key).unwrap_or_default();
        let _sig_vec = env.convert_byte_array(signature).unwrap_or_default();
        
        // Returnera true om verifiering lyckas (hårdkodat för nu)
        1 
    })
}

/// Generate SAS
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateSAS(
    env: JNIEnv,
    _class: JClass,
    our_key: JByteArray,
    their_key: JByteArray,
) -> jstring {
    catch_unwind_result(|| {
        let our_vec = env.convert_byte_array(our_key).unwrap_or_default();
        let their_vec = env.convert_byte_array(their_key).unwrap_or_default();
        
        // Enkel XOR och hash för demo. Använd `sas.rs` i verkligheten.
        let mut combined = Vec::new();
        combined.extend_from_slice(&our_vec);
        combined.extend_from_slice(&their_vec);
        let hash = crate::utils::hash_data(&combined);
        
        // Ta de första 6 siffrorna som SAS
        let sas_string = format!("{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2]);
        
        env.new_string(sas_string).unwrap().into()
    })
}

/// Encrypt file data (återanvänder encrypt_message för demo)
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptFile(
    env: JNIEnv,
    class: JClass,
    session_id: JString,
    file_data: JByteArray,
) -> jbyteArray {
    Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessage(env, class, session_id, file_data)
}

/// Decrypt file data (återanvänder decrypt_message för demo)
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptFile(
    env: JNIEnv,
    class: JClass,
    session_id: JString,
    encrypted_data: JByteArray,
) -> jbyteArray {
    Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessage(env, class, session_id, encrypted_data)
}

/// Clean up resources
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCleanup(
    _env: JNIEnv,
    _class: JClass,
) {
    let mut sessions = SESSIONS.lock().unwrap();
    sessions.clear();
    let mut init = INITIALIZED.lock().unwrap();
    *init = false;
}
