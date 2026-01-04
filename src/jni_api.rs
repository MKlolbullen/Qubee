// src/jni_api.rs

use jni::{JNIEnv, JavaVM};
use jni::objects::{JClass, JString, JByteArray, JObject, GlobalRef, JValue};
use jni::sys::{jboolean, jstring, jbyteArray};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::Serialize;
use tokio::runtime::Runtime;

// Core modules from your library
// Adjust crate::SecureMessenger to match your actual struct name in lib.rs
use crate::SecureMessenger; 
use crate::calling::signaling::CallSignal;
use crate::network::p2p_node::{P2PNode, P2PCommand, NodeEvent};

// --- Global State ---
lazy_static! {
    // Stores active chat sessions in memory
    static ref SESSIONS: Mutex<HashMap<String, SecureMessenger>> = Mutex::new(HashMap::new());
    
    // Tracks initialization state
    static ref INITIALIZED: Mutex<bool> = Mutex::new(false);
    
    // Channel to send commands to the background P2P node (e.g., "Send Message")
    static ref P2P_COMMANDER: Mutex<Option<tokio::sync::mpsc::Sender<P2PCommand>>> = Mutex::new(None);
    
    // Reference to the Java Virtual Machine (needed to attach threads for callbacks)
    static ref JVM: Mutex<Option<JavaVM>> = Mutex::new(None);
    
    // Global reference to the Kotlin/Java 'NetworkCallback' object
    static ref CALLBACK_HANDLER: Mutex<Option<GlobalRef>> = Mutex::new(None);
}

// Helper struct for serializing session data
#[derive(Serialize)]
struct RatchetSessionInfo {
    session_id: String,
    state: String,
    created_at: u64,
}

// Helper to safely execute Rust code and catch panics (prevents crashing the Android App)
fn catch_unwind_result<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
    R: Default,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_default()
}

// --- Initialization & Callbacks ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInitialize(
    env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut init = INITIALIZED.lock().unwrap();
    if *init { return 1; }

    // Store the JVM instance so we can attach background threads later
    if let Ok(vm) = env.get_java_vm() {
        *JVM.lock().unwrap() = Some(vm);
    }

    // Android-specific: Set HOME for the 'dirs' crate to work correctly
    unsafe {
        std::env::set_var("HOME", "/data/user/0/com.qubee.messenger/files");
    }

    *init = true;
    1
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRegisterCallback(
    env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    // Create a global reference to the callback object so the GC doesn't collect it
    if let Ok(global_ref) = env.new_global_ref(callback) {
        *CALLBACK_HANDLER.lock().unwrap() = Some(global_ref);
    }
}

// --- Network Start (P2P Swarm) ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeStartNetwork(
    env: JNIEnv,
    _class: JClass,
    bootstrap_nodes: JString,
) -> jboolean {
    catch_unwind_result(|| {
        let _bootstrap_str: String = env.get_string(bootstrap_nodes).expect("Invalid string").into();

        // Spawn a new thread for the Tokio Runtime and P2P Node
        std::thread::spawn(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                // 1. Generate Identity (Ed25519 for libp2p)
                // In production, load this from secure storage!
                let id_keys = libp2p::identity::Keypair::generate_ed25519();
                println!("Rust: Starting P2P Node: {}", libp2p::PeerId::from(id_keys.public()));

                // 2. Create channels
                // Commands: Kotlin -> Rust
                let (tx_cmd, rx_cmd) = tokio::sync::mpsc::channel(32); 
                // Events: Rust -> Kotlin
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(32); 

                // 3. Initialize Node
                match P2PNode::new(id_keys, rx_cmd).await {
                    Ok(node) => {
                        // Save command sender for future use
                        *P2P_COMMANDER.lock().unwrap() = Some(tx_cmd);

                        // Spawn Event Dispatcher (Listens for Rust events and calls Kotlin)
                        tokio::spawn(async move {
                            while let Some(event) = rx_event.recv().await {
                                dispatch_event_to_kotlin(event);
                            }
                        });

                        // Run the Node (Blocks this async task)
                        node.run(tx_event).await;
                    },
                    Err(e) => {
                        eprintln!("Rust: Failed to start P2P node: {}", e);
                    }
                }
            });
        });

        1 // Return true
    })
}

// --- Helper: Dispatch Events to Kotlin ---
fn dispatch_event_to_kotlin(event: NodeEvent) {
    let jvm_lock = JVM.lock().unwrap();
    let jvm = match jvm_lock.as_ref() {
        Some(v) => v,
        None => return,
    };

    // Attach the current background thread to the JVM
    let mut env = match jvm.attach_current_thread() {
        Ok(e) => e,
        Err(_) => return,
    };
    
    let callback_lock = CALLBACK_HANDLER.lock().unwrap();
    let callback_obj = match callback_lock.as_ref() {
        Some(o) => o,
        None => return,
    };

    match event {
        NodeEvent::MessageReceived { sender, data, .. } => {
            let j_sender = env.new_string(sender).unwrap();
            let j_data = env.byte_array_from_slice(&data).unwrap();

            // Call Kotlin: onMessageReceived(String, byte[])
            let _ = env.call_method(
                callback_obj,
                "onMessageReceived",
                "(Ljava/lang/String;[B)V",
                &[JValue::Object(j_sender.into()), JValue::Object(j_data.into())]
            );
        },
        NodeEvent::PeerDiscovered { peer_id } => {
            let j_peer = env.new_string(peer_id).unwrap();
            
            // Call Kotlin: onPeerDiscovered(String)
            let _ = env.call_method(
                callback_obj,
                "onPeerDiscovered",
                "(Ljava/lang/String;)V",
                &[JValue::Object(j_peer.into())]
            );
        }
    }
}

// --- Identity & Session Management ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityKeyPair(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_unwind_result(|| {
        // Placeholder: Use SecureMessenger or KeyStore to generate/retrieve keys
        let key_data = crate::utils::generate_random_key(32).unwrap_or(vec![]);
        env.byte_array_from_slice(&key_data).unwrap()
    })
}

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
        let _key_bytes = env.convert_byte_array(their_public_key).expect("Invalid key bytes");

        let mut messenger = match SecureMessenger::new() {
            Ok(m) => m,
            Err(_) => return std::ptr::null_mut(),
        };

        // Placeholder Handshake Data
        let shared_secret = b"shared_secret_placeholder";
        let dh_key = [0u8; 32];
        let pq_len = if is_initiator != 0 { 1184 } else { 2400 };
        let pq_key = vec![0u8; pq_len];

        let init_result = if is_initiator != 0 {
            messenger.initialize_sender(shared_secret, &dh_key, &pq_key)
        } else {
            messenger.initialize_receiver(shared_secret, &dh_key, &pq_key)
        };

        if init_result.is_err() {
            return std::ptr::null_mut();
        }

        let session_id = contact_id.clone();
        let mut sessions = SESSIONS.lock().unwrap();
        sessions.insert(session_id.clone(), messenger);

        let info = RatchetSessionInfo {
            session_id,
            state: "Active".to_string(),
            created_at: 1234567890,
        };
        
        let info_bytes = bincode::serialize(&info).unwrap();
        env.byte_array_from_slice(&info_bytes).unwrap()
    })
}

// --- Messaging & WebRTC Interception ---

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
                Ok(plaintext) => {
                    // Check for WebRTC Signaling Interception
                    if let Ok(signal) = CallSignal::from_bytes(&plaintext) {
                        println!("Rust: Intercepted hidden WebRTC Signal: {:?}", signal);
                        // TODO: Forward 'signal' to internal WebRTCManager using a channel
                        return std::ptr::null_mut();
                    }
                    // Return normal decrypted text
                    env.byte_array_from_slice(&plaintext).unwrap()
                },
                Err(_) => std::ptr::null_mut()
            }
        } else {
            std::ptr::null_mut()
        }
    })
}

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

        // Wrap in hidden CallSignal struct
        let signal = CallSignal::Offer { sdp, call_id };
        let signal_bytes = signal.to_bytes().unwrap_or(vec![]);

        let mut sessions = SESSIONS.lock().unwrap();
        if let Some(messenger) = sessions.get_mut(&session_id) {
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

/// Send a P2P message (Publish/Direct)
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeSendP2PMessage(
    env: JNIEnv,
    _class: JClass,
    peer_id: JString,
    data: JByteArray,
) -> jboolean {
    catch_unwind_result(|| {
        let peer_id_str: String = env.get_string(peer_id).expect("Invalid peer_id").into();
        let data_vec = env.convert_byte_array(data).expect("Invalid data");

        // Hämta låset till vår command-channel
        let commander_lock = P2P_COMMANDER.lock().unwrap();
        
        if let Some(commander) = commander_lock.as_ref() {
            // Skapa kommandot
            let cmd = P2PCommand::SendMessage {
                peer_id: peer_id_str,
                data: data_vec
            };

            // Skicka kommandot till P2P-loopen.
            // Vi använder try_send för att inte blockera JNI-tråden om kanalen är full.
            match commander.try_send(cmd) {
                Ok(_) => {
                    // println!("Rust: Command sent to P2P node");
                    1 // True
                },
                Err(e) => {
                    eprintln!("Rust: Failed to send P2P command (Channel closed/full): {}", e);
                    0 // False
                }
            }
        } else {
            eprintln!("Rust: P2P Commander not initialized (Node not started?)");
            0 // False
        }
    })
}
// --- Cleanup ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCleanup(
    _env: JNIEnv,
    _class: JClass,
) {
    let mut sessions = SESSIONS.lock().unwrap();
    sessions.clear();
    let mut init = INITIALIZED.lock().unwrap();
    *init = false;
    // Note: We deliberately do not stop the P2P node here as it runs on a separate runtime.
    // In a production app, you would send a shutdown command to the P2P commander.
}

// --- Legacy/Placeholder Implementations ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateEphemeralKeys(
    env: JNIEnv, c: JClass) -> jbyteArray {
    Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityKeyPair(env, c)
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
