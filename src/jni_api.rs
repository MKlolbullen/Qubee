use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray};
use jni::sys::{jboolean, jstring, jbyteArray};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};

// Import core structures
// Note: Adjust these paths if your SecureMessenger is in a different module
use crate::SecureMessenger; 
use crate::calling::signaling::CallSignal;

// Global state to keep sessions alive across JNI calls
lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, SecureMessenger>> = Mutex::new(HashMap::new());
    static ref INITIALIZED: Mutex<bool> = Mutex::new(false);
}

// Helper struct for returning session info to Kotlin
#[derive(Serialize)]
struct RatchetSessionInfo {
    session_id: String,
    state: String,
    created_at: u64,
}

// Helper to catch panics and prevent crashing the JVM
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

    // Android-specific: Set HOME for `dirs` crate to work
    unsafe {
        std::env::set_var("HOME", "/data/user/0/com.qubee.messenger/files");
    }

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
        // In a real scenario, this delegates to SecureMessenger::generate_identity()
        // For now, we generate random bytes as a placeholder
        let key_data = crate::utils::generate_random_key(32).unwrap_or(vec![]);
        env.byte_array_from_slice(&key_data).unwrap()
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
        let _their_pub_key_vec = env.convert_byte_array(their_public_key).expect("Invalid pubkey");
        
        // Instantiate the SecureMessenger
        let mut messenger = match SecureMessenger::new() {
            Ok(m) => m,
            Err(_) => return std::ptr::null_mut(),
        };

        // Placeholder for X3DH handshake logic
        let shared_secret = b"shared_secret_placeholder"; 
        let dh_key = [0u8; 32];
        let pq_key_len = if is_initiator != 0 { 1184 } else { 2400 }; 
        let pq_key = vec![0u8; pq_key_len];

        let init_result = if is_initiator != 0 {
            messenger.initialize_sender(shared_secret, &dh_key, &pq_key)
        } else {
            messenger.initialize_receiver(shared_secret, &dh_key, &pq_key)
        };

        if init_result.is_err() {
            return std::ptr::null_mut();
        }

        // Store session globally
        let session_id = contact_id.clone();
        let mut sessions = SESSIONS.lock().unwrap();
        sessions.insert(session_id.clone(), messenger);

        // Return session info
        let info = RatchetSessionInfo {
            session_id,
            state: "Active".to_string(),
            created_at: 1234567890,
        };
        
        let info_bytes = bincode::serialize(&info).unwrap();
        env.byte_array_from_slice(&info_bytes).unwrap()
    })
}

/// Encrypt a standard chat message
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

/// Encrypt a WebRTC Signaling message (Tunneling)
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptSignaling(
    env: JNIEnv,
    _class: JClass,
    session_id: JString,
    call_id: JString,
    sdp_json: JString,
) -> jbyteArray {
    catch_unwind_result(|| {
        let session_id: String = env.get_string(session_id).expect("Invalid session_id").into();
        let call_id: String = env.get_string(call_id).expect("Invalid call_id").into();
        let sdp: String = env.get_string(sdp_json).expect("Invalid sdp").into();

        // Wrap the SDP in a CallSignal structure
        let signal = CallSignal::Offer { sdp, call_id };
        let signal_bytes = signal.to_bytes().unwrap_or(vec![]);

        let mut sessions = SESSIONS.lock().unwrap();
        if let Some(messenger) = sessions.get_mut(&session_id) {
            // Encrypt the signal just like a normal message
            match messenger.encrypt_message(&signal_bytes) {
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

/// Decrypt a message and check if it is a WebRTC signal
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
            // Decrypt the blob
            match messenger.decrypt_message(&cipher_vec) {
                Ok(plaintext) => {
                    // Check if this is a hidden WebRTC signal
                    if let Ok(signal) = CallSignal::from_bytes(&plaintext) {
                        println!("Rust: Intercepted WebRTC Signal: {:?}", signal);
                        
                        // TODO: Forward this signal to the Rust WebRTCManager here
                        // webrtc_manager.handle_signal(signal);
                        
                        // Return null to indicate "This was consumed internally, do not show in chat"
                        return std::ptr::null_mut(); 
                    }

                    // Not a signal? Return plain text to Kotlin
                    env.byte_array_from_slice(&plaintext).unwrap()
                },
                Err(_) => std::ptr::null_mut()
            }
        } else {
            std::ptr::null_mut()
        }
    })
}

/// Cleanup resources
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

// Reuse existing functions for these implementations for now
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateEphemeralKeys(
    env: JNIEnv, _c: JClass) -> jbyteArray {
    Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityKeyPair(env, _c)
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyIdentityKey(
    _e: JNIEnv, _c: JClass, _contact: JString, _key: JByteArray, _sig: JByteArray) -> jboolean {
    1 
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateSAS(
    env: JNIEnv, _c: JClass, _k1: JByteArray, _k2: JByteArray) -> jstring {
    env.new_string("123-456").unwrap().into()
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptFile(
    env: JNIEnv, c: JClass, sid: JString, data: JByteArray) -> jbyteArray {
    Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessage(env, c, sid, data)
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptFile(
    env: JNIEnv, c: JClass, sid: JString, data: JByteArray) -> jbyteArray {
    Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessage(env, c, sid, data)
}
