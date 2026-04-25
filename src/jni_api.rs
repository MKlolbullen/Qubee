// src/jni_api.rs

use jni::{JNIEnv, JavaVM};
use jni::objects::{JClass, JString, JByteArray, JObject, GlobalRef, JValue};
use jni::sys::{jboolean, jstring, jbyteArray};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;

// Core modules
use crate::network::p2p_node::{P2PNode, P2PCommand, NodeEvent};
use crate::identity::identity_key::{IdentityKeyPair, IdentityId};
use crate::onboarding::OnboardingBundle;
use crate::groups::group_invite::InvitePayload;
use crate::groups::group_manager::{GroupId, GroupInvitation, QUBEE_MAX_GROUP_MEMBERS};
use crate::storage::secure_keystore::{
    KeyMetadata, KeyType, KeyUsage, SecureKeyStore,
};

const ACTIVE_IDENTITY_KEY: &str = "active_identity";

#[derive(Serialize, Deserialize)]
struct PersistedActiveIdentity {
    user_id: String,
    display_name: String,
    /// Output of `IdentityKeyPair::serialize_for_keystore`.
    secret_bytes: Vec<u8>,
}

// --- Global State ---
lazy_static! {
    static ref INITIALIZED: Mutex<bool> = Mutex::new(false);

    // Command channel to talk to the background P2P node
    static ref P2P_COMMANDER: Mutex<Option<tokio::sync::mpsc::Sender<P2PCommand>>> = Mutex::new(None);

    // JVM Reference for callbacks
    static ref JVM: Mutex<Option<JavaVM>> = Mutex::new(None);

    // Callback Object Reference
    static ref CALLBACK_HANDLER: Mutex<Option<GlobalRef>> = Mutex::new(None);

    // Encrypted at-rest keystore opened during nativeInitialize.
    static ref KEYSTORE: Mutex<Option<SecureKeyStore>> = Mutex::new(None);

    // Cached active identity so we can sign without paying for a keystore
    // round-trip on every JNI call.
    static ref ACTIVE_IDENTITY: Mutex<Option<Arc<IdentityKeyPair>>> = Mutex::new(None);
}

fn catch_unwind_result<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
    R: Default,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_default()
}

// --- Initialization & Callbacks ---

/// Bootstrap the Rust core. Kotlin must pass `context.filesDir.absolutePath`
/// as `data_dir` so the encrypted keystore lands inside the app's
/// private storage. Idempotent.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInitialize(
    env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jboolean {
    let result = catch_unwind_result(|| -> anyhow::Result<()> {
        let mut init = INITIALIZED.lock().unwrap();
        if *init {
            return Ok(());
        }

        let dir: String = env
            .get_string(data_dir)
            .map_err(|e| anyhow::anyhow!("invalid data_dir: {e}"))?
            .into();

        if let Ok(vm) = env.get_java_vm() {
            *JVM.lock().unwrap() = Some(vm);
        }

        let mut path = PathBuf::from(&dir);
        path.push("qubee_keys.db");
        let keystore = SecureKeyStore::new(&path)
            .map_err(|e| anyhow::anyhow!("keystore open failed: {e}"))?;
        *KEYSTORE.lock().unwrap() = Some(keystore);

        // Best-effort eager identity load: lets nativeLoadOnboardingBundle
        // succeed without the caller having to do anything special, and
        // primes the in-memory cache for subsequent signing.
        let _ = load_identity_from_keystore();

        *init = true;
        Ok(())
    });
    if result.is_err() {
        eprintln!("Rust: nativeInitialize failed");
        return 0;
    }
    1
}

/// Load the persisted active identity (if any) from the keystore into
/// the in-memory cache. Returns the persisted (user_id, display_name)
/// metadata so the caller can rebuild the bundle.
fn load_identity_from_keystore() -> anyhow::Result<Option<(String, String)>> {
    let mut ks_guard = KEYSTORE.lock().unwrap();
    let ks = match ks_guard.as_mut() {
        Some(k) => k,
        None => return Ok(None),
    };
    let secret = match ks.retrieve_key(ACTIVE_IDENTITY_KEY)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let blob: PersistedActiveIdentity = bincode::deserialize(secret.expose_secret())
        .map_err(|e| anyhow::anyhow!("active identity decode: {e}"))?;
    let kp = IdentityKeyPair::deserialize_from_keystore(&blob.secret_bytes)?;
    *ACTIVE_IDENTITY.lock().unwrap() = Some(Arc::new(kp));
    Ok(Some((blob.user_id, blob.display_name)))
}

/// Persist the active identity to the keystore. Replaces any prior value.
fn store_identity_to_keystore(
    keypair: &IdentityKeyPair,
    user_id: &str,
    display_name: &str,
) -> anyhow::Result<()> {
    let mut ks_guard = KEYSTORE.lock().unwrap();
    let ks = ks_guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;
    let blob = PersistedActiveIdentity {
        user_id: user_id.to_string(),
        display_name: display_name.to_string(),
        secret_bytes: keypair.serialize_for_keystore()?,
    };
    let bytes = bincode::serialize(&blob)?;
    let metadata = KeyMetadata {
        algorithm: "hybrid_ed25519+dilithium2".to_string(),
        key_size: bytes.len(),
        usage: vec![KeyUsage::Signing, KeyUsage::Authentication],
        expiry: None,
        tags: std::collections::HashMap::new(),
    };
    ks.store_key(ACTIVE_IDENTITY_KEY, &bytes, KeyType::IdentityKey, metadata)?;
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRegisterCallback(
    env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    if let Ok(global_ref) = env.new_global_ref(callback) {
        *CALLBACK_HANDLER.lock().unwrap() = Some(global_ref);
    }
}

// --- Network Management ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeStartNetwork(
    env: JNIEnv,
    _class: JClass,
    bootstrap_nodes: JString,
) -> jboolean {
    catch_unwind_result(|| {
        let _bootstrap_str: String = env.get_string(bootstrap_nodes).expect("Invalid string").into();

        std::thread::spawn(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let id_keys = libp2p::identity::Keypair::generate_ed25519();
                println!("Rust: Starting P2P Node: {}", libp2p::PeerId::from(id_keys.public()));

                let (tx_cmd, rx_cmd) = tokio::sync::mpsc::channel(32); 
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(32); 

                match P2PNode::new(id_keys, rx_cmd).await {
                    Ok(node) => {
                        *P2P_COMMANDER.lock().unwrap() = Some(tx_cmd);

                        tokio::spawn(async move {
                            while let Some(event) = rx_event.recv().await {
                                dispatch_event_to_kotlin(event);
                            }
                        });

                        node.run(tx_event).await;
                    },
                    Err(e) => {
                        eprintln!("Rust: Failed to start P2P node: {}", e);
                    }
                }
            });
        });

        1
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

        let commander_lock = P2P_COMMANDER.lock().unwrap();
        
        if let Some(commander) = commander_lock.as_ref() {
            let cmd = P2PCommand::SendMessage {
                peer_id: peer_id_str,
                data: data_vec
            };

            match commander.try_send(cmd) {
                Ok(_) => 1,
                Err(e) => {
                    eprintln!("Rust: Failed to send P2P command: {}", e);
                    0
                }
            }
        } else {
            eprintln!("Rust: P2P Commander not initialized");
            0
        }
    })
}

// --- Helper: Dispatch to Kotlin ---
fn dispatch_event_to_kotlin(event: NodeEvent) {
    let jvm_lock = JVM.lock().unwrap();
    let jvm = match jvm_lock.as_ref() {
        Some(v) => v,
        None => return,
    };

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

            let _ = env.call_method(
                callback_obj,
                "onMessageReceived",
                "(Ljava/lang/String;[B)V",
                &[JValue::Object(j_sender.into()), JValue::Object(j_data.into())]
            );
        },
        NodeEvent::PeerDiscovered { peer_id } => {
            let j_peer = env.new_string(peer_id).unwrap();
            let _ = env.call_method(
                callback_obj,
                "onPeerDiscovered",
                "(Ljava/lang/String;)V",
                &[JValue::Object(j_peer.into())]
            );
        }
    }
}

// --- Encryption & Messaging ---

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
                    if let Ok(signal) = CallSignal::from_bytes(&plaintext) {
                        println!("Rust: Intercepted WebRTC Signal: {:?}", signal);
                        return std::ptr::null_mut();
                    }
                    env.byte_array_from_slice(&plaintext).unwrap()
                },
                Err(_) => std::ptr::null_mut()
            }
        } else {
            std::ptr::null_mut()
        }
    })
}

// --- Identity & Sessions (Standard) ---

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityKeyPair(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    catch_unwind_result(|| {
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

// --- WebRTC Tunneling ---

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

// --- Utils & Cleanup ---

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

// ---------------------------------------------------------------------------
// ZK Onboarding & invite-link surface (added for the identity/groups feature)
// ---------------------------------------------------------------------------

fn json_to_jstring(env: JNIEnv, value: serde_json::Value) -> jstring {
    match env.new_string(value.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn ok_or_null(env: JNIEnv, result: anyhow::Result<serde_json::Value>) -> jstring {
    match result {
        Ok(v) => json_to_jstring(env, v),
        Err(e) => {
            eprintln!("Rust: JNI op failed: {:#}", e);
            std::ptr::null_mut()
        }
    }
}

/// Generate a fresh hybrid identity, sign the onboarding bundle, and
/// **persist** the keypair to the encrypted keystore so it survives
/// process restarts. The cached keypair is also stashed in
/// [`ACTIVE_IDENTITY`] for subsequent signing without touching disk.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateOnboardingBundle(
    env: JNIEnv,
    _class: JClass,
    display_name: JString,
    user_id: JString,
) -> jstring {
    catch_unwind_result(|| {
        let display_name: String = match env.get_string(display_name) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let user_id: String = match env.get_string(user_id) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let keypair = IdentityKeyPair::generate()?;
            let bundle = OnboardingBundle::create(&keypair, &display_name, &user_id)?;
            store_identity_to_keystore(&keypair, &user_id, &display_name)?;
            *ACTIVE_IDENTITY.lock().unwrap() = Some(Arc::new(keypair));
            bundle_to_json(&bundle)
        })();

        ok_or_null(env, result)
    })
}

/// Re-export the previously persisted onboarding bundle. Re-signs the
/// canonical bytes with the loaded keypair so the embedded signature
/// timestamp is fresh — important because the bundle's verifier rejects
/// anything older than [`crate::onboarding::ONBOARDING_BUNDLE_TTL_SECS`].
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeLoadOnboardingBundle(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind_result(|| {
        let result: anyhow::Result<serde_json::Value> = (|| {
            // Lazily load if the eager init didn't happen (e.g. keystore
            // was empty at boot but Kotlin called create afterwards).
            if ACTIVE_IDENTITY.lock().unwrap().is_none() {
                load_identity_from_keystore()?;
            }
            let identity = ACTIVE_IDENTITY
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no active identity persisted"))?;

            // Read display_name + user_id from the keystore record.
            let mut ks_guard = KEYSTORE.lock().unwrap();
            let ks = ks_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;
            let secret = ks
                .retrieve_key(ACTIVE_IDENTITY_KEY)?
                .ok_or_else(|| anyhow::anyhow!("active identity record missing"))?;
            let blob: PersistedActiveIdentity = bincode::deserialize(secret.expose_secret())?;

            let bundle = OnboardingBundle::create(
                identity.as_ref(),
                blob.display_name.clone(),
                blob.user_id.clone(),
            )?;
            bundle_to_json(&bundle)
        })();

        match result {
            Ok(v) => json_to_jstring(env, v),
            Err(e) => {
                // No-identity is the *expected* state on first launch —
                // treat it as null rather than a hard error so the
                // Kotlin caller can branch cleanly.
                eprintln!("Rust: nativeLoadOnboardingBundle: {e:#}");
                std::ptr::null_mut()
            }
        }
    })
}

fn bundle_to_json(bundle: &OnboardingBundle) -> anyhow::Result<serde_json::Value> {
    let share_link = bundle.to_share_link()?;
    Ok(json!({
        "user_id": bundle.user_id,
        "display_name": bundle.display_name,
        "identity_id_hex": hex::encode(bundle.identity_id().as_ref()),
        "fingerprint": bundle.public_key.fingerprint(),
        "share_link": share_link,
        "max_group_members": QUBEE_MAX_GROUP_MEMBERS,
    }))
}

/// Verify and decode a `qubee://identity/<token>` deep link. On success,
/// returns a JSON object describing the remote identity. Returns NULL if
/// the link is malformed or the embedded ZK proof fails verification.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyOnboardingLink(
    env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    catch_unwind_result(|| {
        let link: String = match env.get_string(link) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let bundle = OnboardingBundle::from_share_link(&link)?;
            Ok(json!({
                "user_id": bundle.user_id,
                "display_name": bundle.display_name,
                "identity_id_hex": hex::encode(bundle.identity_id().as_ref()),
                "fingerprint": bundle.public_key.fingerprint(),
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Build a `qubee://invite/<token>` link from a JSON invitation document
/// `{group_id_hex, group_name, inviter_id_hex, inviter_name,
///   invitation_code, expires_at?}`. The Qubee-wide member cap is baked
/// into the encoded payload; senders cannot raise it.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeBuildInviteLink(
    env: JNIEnv,
    _class: JClass,
    invitation_json: JString,
) -> jstring {
    catch_unwind_result(|| {
        let raw: String = match env.get_string(invitation_json) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let v: serde_json::Value = serde_json::from_str(&raw)?;
            let group_id = parse_hex32(v.get("group_id_hex").and_then(|s| s.as_str()))?;
            let inviter_id = parse_hex32(v.get("inviter_id_hex").and_then(|s| s.as_str()))?;
            let group_name = v.get("group_name").and_then(|s| s.as_str()).unwrap_or("").to_string();
            let inviter_name = v.get("inviter_name").and_then(|s| s.as_str()).unwrap_or("").to_string();
            let invitation_code = v.get("invitation_code").and_then(|s| s.as_str()).unwrap_or("").to_string();
            let expires_at = v.get("expires_at").and_then(|s| s.as_u64());

            let invitation = GroupInvitation {
                group_id: GroupId::from_bytes(group_id),
                group_name,
                inviter_id: IdentityId::from(inviter_id),
                inviter_name,
                invitation_code,
                expires_at,
                max_uses: None,
                current_uses: 0,
                created_at: now_secs(),
            };
            let payload = InvitePayload::from_invitation(&invitation);
            let link = payload.to_invite_link()?;
            Ok(json!({ "link": link, "max_members": payload.max_members }))
        })();

        ok_or_null(env, result)
    })
}

/// Parse a `qubee://invite/<token>` deep link and return its contents
/// as JSON. Returns NULL if the link is malformed or its fingerprint
/// fails verification.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeParseInviteLink(
    env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    catch_unwind_result(|| {
        let link: String = match env.get_string(link) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let payload = InvitePayload::from_invite_link(&link)?;
            Ok(json!({
                "group_id_hex": hex::encode(payload.group_id.as_ref()),
                "group_name": payload.group_name,
                "inviter_id_hex": hex::encode(payload.inviter_id.as_ref()),
                "inviter_name": payload.inviter_name,
                "invitation_code": payload.invitation_code,
                "expires_at": payload.expires_at,
                "max_members": payload.max_members,
            }))
        })();

        ok_or_null(env, result)
    })
}

fn parse_hex32(s: Option<&str>) -> anyhow::Result<[u8; 32]> {
    let s = s.ok_or_else(|| anyhow::anyhow!("missing hex field"))?;
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte hex, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
