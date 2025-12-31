use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray};
use jni::sys::{jboolean, jstring, jbyteArray};
use std::sync::Mutex;
use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use crate::{SecureMessenger, QubeeError};

lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, SecureMessenger>> = Mutex::new(HashMap::new());
}

#[derive(Serialize)]
struct RatchetSessionInfo {
    session_id: String,
    state: String, // Simplified state representation
}

fn jni_throw(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", message);
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInitialize(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if std::env::var("HOME").is_err() {
        let path = "/data/user/0/com.qubee.messenger/files";
        std::env::set_var("HOME", path);
    }
    true as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityKeyPair(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    match crate::utils::generate_random_key(32) {
        Ok(key_data) => match env.byte_array_from_slice(&key_data) {
            Ok(output) => output,
            Err(e) => {
                jni_throw(&mut env, &format!("Failed to create byte array: {:?}", e));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            jni_throw(&mut env, &format!("Failed to generate key pair: {:?}", e));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateRatchetSession(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    their_public_key: JByteArray,
    is_initiator: jboolean,
) -> jbyteArray {
    let contact_id_str: String = env.get_string(&contact_id).expect("Couldn't get string").into();
    let their_pub_key_vec = env.convert_byte_array(their_public_key).expect("Couldn't convert byte array");

    let mut messenger = match SecureMessenger::new() {
        Ok(m) => m,
        Err(e) => {
            jni_throw(&mut env, &format!("Failed to create messenger: {:?}", e));
            return std::ptr::null_mut();
        }
    };

    let shared_secret = b"shared_secret_placeholder"; // Replace with actual X3DH handshake

    let init_result = if is_initiator != 0 {
        let dh_key: [u8; 32] = their_pub_key_vec[..32].try_into().unwrap();
        let pq_key = &their_pub_key_vec[32..];
        messenger.initialize_sender(shared_secret, &dh_key, pq_key)
    } else {
        let dh_key: [u8; 32] = their_pub_key_vec[..32].try_into().unwrap();
        let pq_key = &their_pub_key_vec[32..];
        messenger.initialize_receiver(shared_secret, &dh_key, pq_key)
    };

    if let Err(e) = init_result {
        jni_throw(&mut env, &format!("Failed to initialize ratchet: {:?}", e));
        return std::ptr::null_mut();
    }

    let session_id = contact_id_str.clone();
    SESSIONS.lock().unwrap().insert(session_id.clone(), messenger);

    let info = RatchetSessionInfo {
        session_id,
        state: "Active".to_string(),
    };

    let info_bytes = bincode::serialize(&info).unwrap();
    env.byte_array_from_slice(&info_bytes).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    let session_id_str: String = env.get_string(&session_id).expect("Couldn't get string").into();
    let plaintext_vec = env.convert_byte_array(plaintext).expect("Couldn't convert byte array");

    let mut sessions = SESSIONS.lock().unwrap();
    if let Some(messenger) = sessions.get_mut(&session_id_str) {
        match messenger.encrypt_message(&plaintext_vec) {
            Ok(encrypted_bytes) => env.byte_array_from_slice(&encrypted_bytes).unwrap(),
            Err(e) => {
                jni_throw(&mut env, &format!("Encryption failed: {:?}", e));
                std::ptr::null_mut()
            }
        }
    } else {
        jni_throw(&mut env, "Session not found");
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    let session_id_str: String = env.get_string(&session_id).expect("Couldn't get string").into();
    let cipher_vec = env.convert_byte_array(ciphertext).expect("Couldn't convert byte array");

    let mut sessions = SESSIONS.lock().unwrap();
    if let Some(messenger) = sessions.get_mut(&session_id_str) {
        match messenger.decrypt_message(&cipher_vec) {
            Ok(decrypted_bytes) => env.byte_array_from_slice(&decrypted_bytes).unwrap(),
            Err(e) => {
                jni_throw(&mut env, &format!("Decryption failed: {:?}", e));
                std::ptr::null_mut()
            }
        }
    } else {
        jni_throw(&mut env, "Session not found");
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCleanup(
    _env: JNIEnv,
    _class: JClass,
) {
    SESSIONS.lock().unwrap().clear();
}
