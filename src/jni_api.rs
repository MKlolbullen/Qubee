// src/jni_api.rs

use jni::{JNIEnv, JavaVM};
use jni::objects::{JByteArray, JClass, JObject, JString, JValue, GlobalRef};
use jni::sys::{jboolean, jbyteArray, jstring};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;

// Core modules
use crate::network::p2p_node::{group_topic, NodeEvent, P2PCommand, P2PNode};
use crate::identity::identity_key::{IdentityKey, IdentityKeyPair, IdentityId};
use crate::onboarding::OnboardingBundle;
use crate::groups::group_invite::InvitePayload;
use crate::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, sign_role_change, GroupHandshake,
    KeyRotationBody, RequestJoinBody,
};
use crate::groups::group_permissions::Role;
use crate::groups::group_message::{
    decrypt_group_message, encrypt_group_message, GroupMessageEnvelope,
};
use crate::groups::group_manager::{
    GroupId, GroupInvitation, GroupManager, GroupSettings, GroupType, QUBEE_MAX_GROUP_MEMBERS,
};
use crate::groups::handshake_handlers::{
    plan_key_rotation, process_join_accepted, process_key_rotation, process_request_join,
    HandshakeOutcome,
};
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};
use blake3::Hasher;
use std::collections::HashMap;
use zeroize::Zeroize;

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

    // Encrypted at-rest keystore opened during nativeInitialize, used for
    // the active identity record.
    static ref KEYSTORE: Mutex<Option<SecureKeyStore>> = Mutex::new(None);

    // Cached active identity so we can sign without paying for a keystore
    // round-trip on every JNI call.
    static ref ACTIVE_IDENTITY: Mutex<Option<Arc<IdentityKeyPair>>> = Mutex::new(None);

    // Persistent GroupManager backed by its own encrypted keystore. We
    // keep group state separate from the identity record so the two
    // can be reset independently (e.g. "wipe my groups but keep me").
    static ref GROUP_MANAGER: Mutex<Option<GroupManager>> = Mutex::new(None);

    // Ephemeral Kyber-768 secrets the joiner generated when sending a
    // RequestJoin, indexed by invitation_code. Lives only in process
    // memory and gets zeroised + dropped on JoinAccepted/JoinRejected.
    //
    // Each entry carries the time it was inserted; `prune_pending_kems`
    // evicts (and zeroises) entries older than `PENDING_JOIN_KEM_TTL`
    // so a lost JoinAccepted/JoinRejected reply doesn't keep the
    // joiner's ephemeral secret resident indefinitely.
    static ref PENDING_JOIN_KEMS: Mutex<HashMap<String, (Vec<u8>, std::time::SystemTime)>> =
        Mutex::new(HashMap::new());
}

/// Maximum lifetime of an entry in [`PENDING_JOIN_KEMS`]. Beyond this
/// the inviter's reply is presumed lost; the joiner re-attempts the
/// handshake from scratch and we drop the stale ephemeral. 10 minutes
/// is loose enough for a slow inviter on a flaky network and tight
/// enough that an undelivered reply doesn't pin secret material in
/// memory across a multi-hour app lifetime.
const PENDING_JOIN_KEM_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Evict + zeroise pending Kyber secrets older than [`PENDING_JOIN_KEM_TTL`].
/// Must be called while holding the `PENDING_JOIN_KEMS` mutex.
fn prune_pending_kems(
    pending: &mut HashMap<String, (Vec<u8>, std::time::SystemTime)>,
) {
    let now = std::time::SystemTime::now();
    pending.retain(|_code, (secret, inserted_at)| {
        match now.duration_since(*inserted_at) {
            Ok(age) if age >= PENDING_JOIN_KEM_TTL => {
                secret.zeroize();
                false
            }
            // duration_since returns Err iff `inserted_at` is in the
            // future (clock skew). Treat that as "still fresh" rather
            // than dropping the entry.
            _ => true,
        }
    });
}

/// Catch panics from a JNI body that returns a `Default`-able value
/// (jboolean, jint, integer types, `()`). Panics fold into the
/// type's default (`0` / `false` / `()`), which matches what JNI
/// code conventionally returns on error.
fn catch_unwind_result<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
    R: Default,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_default()
}

/// Like [`catch_unwind_result`] but for JNI bodies that return
/// `anyhow::Result<T>` for a `T` that doesn't impl `Default` —
/// raw pointers (`jstring`, `jobject`) and any caller that wants
/// errors-and-panics to fold into a caller-provided fallback.
/// Panics fold into `Err(...)` so the caller can decide the
/// fallback by chaining `.unwrap_or(...)`.
fn jni_catch_or<T>(
    f: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!("panic during JNI call")),
    }
}

/// Catch panics from a JNI body that returns `jstring` directly —
/// raw `*mut _jobject` pointers don't impl `Default`, so the
/// generic [`catch_unwind_result`] doesn't work. Folds panics into
/// a JNI null-pointer return, which is what every existing call
/// site already does on a non-panic error path.
fn jni_catch_jstring(f: impl FnOnce() -> jstring) -> jstring {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or(std::ptr::null_mut())
}

/// `jbyteArray` variant of [`jni_catch_jstring`]. Same shape — a
/// raw `*mut _jobject` that can't impl `Default`, so we hand-roll
/// the null fallback.
fn jni_catch_jbytearray(f: impl FnOnce() -> jbyteArray) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or(std::ptr::null_mut())
}

// --- Initialization & Callbacks ---

/// Bootstrap the Rust core. Kotlin must pass `context.filesDir.absolutePath`
/// as `data_dir` so the encrypted keystore lands inside the app's
/// private storage. Idempotent.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInitialize(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jboolean {
    let result = jni_catch_or(|| -> anyhow::Result<()> {
        let mut init = INITIALIZED.lock().unwrap();
        if *init {
            return Ok(());
        }

        let dir: String = env
            .get_string(&data_dir)
            .map_err(|e| anyhow::anyhow!("invalid data_dir: {e}"))?
            .into();

        if let Ok(vm) = env.get_java_vm() {
            *JVM.lock().unwrap() = Some(vm);
        }

        let mut id_path = PathBuf::from(&dir);
        id_path.push("qubee_keys.db");
        let id_keystore = SecureKeyStore::new(&id_path)
            .map_err(|e| anyhow::anyhow!("identity keystore open failed: {e}"))?;
        *KEYSTORE.lock().unwrap() = Some(id_keystore);

        let mut groups_path = PathBuf::from(&dir);
        groups_path.push("qubee_groups.db");
        let groups_keystore = SecureKeyStore::new(&groups_path)
            .map_err(|e| anyhow::anyhow!("groups keystore open failed: {e}"))?;
        let mut group_mgr = GroupManager::new(groups_keystore)
            .map_err(|e| anyhow::anyhow!("group manager init failed: {e}"))?;
        let _ = group_mgr.load_groups_from_storage();
        *GROUP_MANAGER.lock().unwrap() = Some(group_mgr);

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
    mut env: JNIEnv,
    _class: JClass,
    bootstrap_nodes: JString,
) -> jboolean {
    catch_unwind_result(|| {
        let _bootstrap_str: String = env.get_string(&bootstrap_nodes).expect("Invalid string").into();

        std::thread::spawn(|| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let id_keys = libp2p::identity::Keypair::generate_ed25519();
                tracing::info!(
                    peer_id = %libp2p::PeerId::from(id_keys.public()),
                    "Starting P2P Node",
                );

                let (tx_cmd, rx_cmd) = tokio::sync::mpsc::channel(32); 
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(32); 

                match P2PNode::new(id_keys, rx_cmd).await {
                    Ok(node) => {
                        *P2P_COMMANDER.lock().unwrap() = Some(tx_cmd);

                        // Re-subscribe to every group the local
                        // identity already belongs to so a process
                        // restart doesn't drop us off the topic mesh.
                        resubscribe_known_groups();

                        tokio::spawn(async move {
                            while let Some(event) = rx_event.recv().await {
                                // Intercept group-handshake traffic before
                                // the regular Kotlin callback so the
                                // Rust core can run protocol logic
                                // without needing a JNI round-trip.
                                if let NodeEvent::MessageReceived { sender, data, .. } = &event {
                                    if let Some(handshake) = GroupHandshake::from_wire(data) {
                                        handle_inbound_handshake(handshake, sender.clone());
                                        continue;
                                    }
                                    if let Some(envelope) = GroupMessageEnvelope::from_wire(data) {
                                        handle_inbound_group_message(envelope);
                                        continue;
                                    }
                                }
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
    mut env: JNIEnv,
    _class: JClass,
    peer_id: JString,
    data: JByteArray,
) -> jboolean {
    catch_unwind_result(|| {
        let peer_id_str: String = env.get_string(&peer_id).expect("Invalid peer_id").into();
        let data_vec = env.convert_byte_array(&data).expect("Invalid data");

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
fn handle_inbound_group_message(envelope: GroupMessageEnvelope) {
    let result: anyhow::Result<()> = (|| {
        let mut gm_guard = GROUP_MANAGER.lock().unwrap();
        let gm = gm_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;

        // Re-frame the envelope so the canonical decrypt helper can
        // verify + AEAD-decrypt it. We have the envelope already, so
        // we just need to feed wire bytes back in.
        let wire = envelope.to_wire()?;
        let decrypted = decrypt_group_message(gm, &wire)?;
        drop(gm_guard);

        dispatch_group_message_to_kotlin(&decrypted);
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("Rust: group message dropped: {e:#}");
    }
}

fn dispatch_group_message_to_kotlin(msg: &crate::groups::group_message::DecryptedGroupMessage) {
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

    let group_hex = match env.new_string(hex::encode(msg.group_id.as_ref())) {
        Ok(s) => s,
        Err(_) => return,
    };
    let sender_hex = match env.new_string(hex::encode(msg.sender_id.as_ref())) {
        Ok(s) => s,
        Err(_) => return,
    };
    let payload = match env.byte_array_from_slice(&msg.plaintext) {
        Ok(b) => b,
        Err(_) => return,
    };

    let _ = env.call_method(
        callback_obj,
        "onGroupMessageReceived",
        "(Ljava/lang/String;Ljava/lang/String;[BJ)V",
        &[
            JValue::Object(&group_hex),
            JValue::Object(&sender_hex),
            JValue::Object(&payload),
            JValue::Long(msg.timestamp as i64),
        ],
    );
}

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
                &[JValue::Object(&j_sender), JValue::Object(&j_data)],
            );
        },
        NodeEvent::PeerDiscovered { peer_id } => {
            let j_peer = env.new_string(peer_id).unwrap();
            let _ = env.call_method(
                callback_obj,
                "onPeerDiscovered",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&j_peer)],
            );
        }
        NodeEvent::Listening { .. } => {
            // Bound-address event used by integration tests; no
            // Kotlin callback exists for it today, so silently
            // ignore — the swarm is up by the time the JNI thread
            // sees this and we don't need to forward.
        }
    }
}

/// Create a brand new group owned by the active local identity.
/// Returns JSON `{group_id_hex, name, owner_id_hex}`. The group's
/// symmetric encryption key is generated and stored alongside the
/// group record so subsequent invitations can KEM-wrap it for joiners.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateGroup(
    mut env: JNIEnv,
    _class: JClass,
    name: JString,
    description: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let name: String = match env.get_string(&name) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let description: String = match env.get_string(&description) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("onboarding required before creating a group"))?;
            let owner_key = identity.public_key();
            let owner_id = identity.identity_id();

            let mut gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let group_id = gm.create_group(
                owner_id,
                owner_key,
                name.clone(),
                description,
                GroupType::Private,
                GroupSettings::default(),
            )?;
            // create_group already mints a key inside group_crypto, but
            // be explicit so future refactors can't accidentally regress.
            gm.ensure_group_key(group_id)?;
            // Drop the GM lock before talking to the network commander
            // so we don't hold two mutexes across an await-equivalent.
            drop(gm_guard);

            // Subscribe to this group's gossipsub topic so we receive
            // RequestJoin frames from peers who scan an invite.
            // Best-effort: if the network thread isn't up yet,
            // `resubscribe_known_groups()` picks it up on the next
            // bootstrap because `gm.create_group` already persisted
            // the group through `store_group_securely`.
            let _ = subscribe_topic(group_topic(&hex::encode(group_id.as_ref())));

            Ok(json!({
                "group_id_hex": hex::encode(group_id.as_ref()),
                "name": name,
                "owner_id_hex": hex::encode(owner_id.as_ref()),
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Mint a fresh invitation for the named group and return both the
/// `qubee://invite/<token>` deep link and the underlying invitation
/// metadata. The invitation record lands in the encrypted group
/// keystore so the inviter can match incoming RequestJoin frames
/// against it later.
///
/// `expires_at_seconds < 0` means "no expiry"; same convention for
/// `max_uses`.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateGroupInvite(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    expires_at_seconds: jni::sys::jlong,
    max_uses: jni::sys::jint,
) -> jstring {
    jni_catch_jstring(|| {
        let group_id_hex: String = match env.get_string(&group_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("onboarding required before issuing an invite"))?;
            let inviter_id = identity.identity_id();

            let group_id_bytes = parse_hex32(Some(group_id_hex.as_str()))?;
            let group_id = GroupId::from_bytes(group_id_bytes);

            let expires_at = if expires_at_seconds < 0 {
                None
            } else {
                Some(expires_at_seconds as u64)
            };
            let max_uses = if max_uses < 0 { None } else { Some(max_uses as u32) };

            let mut gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let invitation = gm.create_invitation(group_id, inviter_id, expires_at, max_uses)?;
            let payload = InvitePayload::from_invitation(&invitation);
            let link = payload.to_invite_link()?;

            Ok(json!({
                "link": link,
                "group_id_hex": hex::encode(invitation.group_id.as_ref()),
                "group_name": invitation.group_name,
                "inviter_id_hex": hex::encode(invitation.inviter_id.as_ref()),
                "inviter_name": invitation.inviter_name,
                "invitation_code": invitation.invitation_code,
                "expires_at": invitation.expires_at,
                "max_members": payload.max_members,
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Encrypt a plaintext group message under the current group key,
/// sign the envelope with the active identity, and publish it on the
/// per-group gossipsub topic. Returns JSON
/// `{group_id_hex, generation, network_published}`.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeSendGroupMessage(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    plaintext: JByteArray,
) -> jstring {
    jni_catch_jstring(|| {
        let group_id_hex: String = match env.get_string(&group_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let plaintext = match env.convert_byte_array(&plaintext) {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("onboarding required"))?;
            let group_id = GroupId::from_bytes(parse_hex32(Some(group_id_hex.as_str()))?);

            let (wire, generation) = {
                let gm_guard = GROUP_MANAGER.lock().unwrap();
                let gm = gm_guard
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
                let wire = encrypt_group_message(gm, identity.as_ref(), group_id, &plaintext)?;
                let generation = gm.get_group(&group_id).map(|g| g.version).unwrap_or(0);
                (wire, generation)
            };

            let topic = group_topic(&hex::encode(group_id.as_ref()));
            let published = publish_to_topic(topic, wire);

            Ok(json!({
                "group_id_hex": hex::encode(group_id.as_ref()),
                "generation": generation,
                "network_published": published,
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Remove a member from a group we own, rotate the group key, and
/// broadcast a signed `KeyRotation` so remaining members converge on
/// the fresh key. Returns JSON `{group_id_hex, removed_member_hex,
/// generation, network_published}`.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRemoveMember(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    member_id_hex: JString,
    reason: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let group_id_hex: String = match env.get_string(&group_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let member_id_hex: String = match env.get_string(&member_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let reason: String = match env.get_string(&reason) {
            Ok(s) => s.into(),
            Err(_) => String::new(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("onboarding required"))?;
            let group_id = GroupId::from_bytes(parse_hex32(Some(group_id_hex.as_str()))?);
            let member_id = IdentityId::from(parse_hex32(Some(member_id_hex.as_str()))?);

            let signed = {
                let mut gm_guard = GROUP_MANAGER.lock().unwrap();
                let gm = gm_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
                plan_key_rotation(
                    gm,
                    identity.as_ref(),
                    group_id,
                    Some(member_id),
                    &reason,
                )?
            };

            let generation = match &signed {
                GroupHandshake::KeyRotation { body, .. } => body.generation,
                _ => 0,
            };

            let topic = group_topic(&hex::encode(group_id.as_ref()));
            let wire = signed.to_wire()?;
            let published = publish_to_topic(topic, wire);

            Ok(json!({
                "group_id_hex": hex::encode(group_id.as_ref()),
                "removed_member_hex": hex::encode(member_id.as_ref()),
                "generation": generation,
                "network_published": published,
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Promote (or demote) a member of a group we own to a new role
/// and broadcast a signed `RoleChange` so other members converge on
/// the same membership view. Owner-only Rust-side; non-owner callers
/// get an `Err` from `GroupManager::promote_member` which surfaces
/// here as a null return.
///
/// `new_role` accepts a small fixed vocabulary — `"Owner"`, `"Admin"`,
/// `"Moderator"`, `"Member"`, `"Observer"` — case-insensitive, with
/// any other value rejected. We deliberately don't expose `Custom(_)`
/// over the JNI: the wire frame supports it, but there's no UI for
/// minting one yet, and silently round-tripping arbitrary strings
/// would let bugs in the client side leak through.
///
/// Returns JSON `{group_id_hex, member_id_hex, new_role,
/// new_version, network_published}` on success.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativePromoteMember(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    member_id_hex: JString,
    new_role: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let group_id_hex: String = match env.get_string(&group_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let member_id_hex: String = match env.get_string(&member_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let new_role: String = match env.get_string(&new_role) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("onboarding required"))?;
            let group_id = GroupId::from_bytes(parse_hex32(Some(group_id_hex.as_str()))?);
            let member_id = IdentityId::from(parse_hex32(Some(member_id_hex.as_str()))?);
            let role = match new_role.to_ascii_lowercase().as_str() {
                "owner" => Role::Owner,
                "admin" => Role::Admin,
                "moderator" => Role::Moderator,
                "member" => Role::Member,
                "observer" => Role::Observer,
                other => return Err(anyhow::anyhow!("unknown role: {other}")),
            };

            let signed = {
                let mut gm_guard = GROUP_MANAGER.lock().unwrap();
                let gm = gm_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
                let body = gm.promote_member(group_id, identity.identity_id(), member_id, role.clone())?;
                sign_role_change(identity.as_ref(), body)?
            };

            let (new_version, role_str) = match &signed {
                GroupHandshake::RoleChange { body, .. } => (
                    body.new_version,
                    role_to_str(&body.new_role).to_string(),
                ),
                _ => (0u64, new_role.clone()),
            };

            let topic = group_topic(&hex::encode(group_id.as_ref()));
            let wire = signed.to_wire()?;
            let published = publish_to_topic(topic, wire);

            Ok(json!({
                "group_id_hex": hex::encode(group_id.as_ref()),
                "member_id_hex": hex::encode(member_id.as_ref()),
                "new_role": role_str,
                "new_version": new_version,
                "network_published": published,
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Render a `Role` back to the canonical wire string used by
/// `nativePromoteMember` and `nativeListGroupMembers`. The roundtrip
/// stays in lock-step with the small vocabulary the JNI accepts so
/// the UI always sees the same set of strings.
fn role_to_str(role: &Role) -> &'static str {
    match role {
        Role::Owner => "Owner",
        Role::Admin => "Admin",
        Role::Moderator => "Moderator",
        Role::Member => "Member",
        Role::Observer => "Observer",
        Role::Custom(_) => "Custom",
    }
}

/// Record that the local user accepted a `qubee://invite/...` link
/// and (best-effort) publish a signed `RequestJoin` over the
/// gossipsub global topic so the inviter's device can enrol us.
///
/// The local receipt is always written so the UI can show "accepted,
/// awaiting handshake". Network publication may fail (network not up,
/// channel full) — that's reported via the `network_published` flag in
/// the returned JSON; the caller can retry by re-invoking accept.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeAcceptInvite(
    mut env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let link: String = match env.get_string(&link) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };

        let result: anyhow::Result<serde_json::Value> = (|| {
            let payload = InvitePayload::from_invite_link(&link)?;
            {
                let mut gm_guard = GROUP_MANAGER.lock().unwrap();
                let gm = gm_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
                gm.record_external_invite_acceptance(
                    payload.group_id,
                    &payload.group_name,
                    payload.inviter_id,
                    &payload.inviter_name,
                    &payload.invitation_code,
                )?;
            }

            // Best-effort network publication.
            let network_published = publish_request_join(&payload).unwrap_or_else(|e| {
                eprintln!("Rust: publish_request_join failed: {e:#}");
                false
            });

            Ok(json!({
                "group_id_hex": hex::encode(payload.group_id.as_ref()),
                "group_name": payload.group_name,
                "inviter_id_hex": hex::encode(payload.inviter_id.as_ref()),
                "inviter_name": payload.inviter_name,
                "max_members": payload.max_members,
                "status": if network_published {
                    "accepted_handshake_sent"
                } else {
                    "accepted_pending_network"
                },
                "network_published": network_published,
            }))
        })();

        ok_or_null(env, result)
    })
}

/// Build, sign, and publish a `RequestJoin` for the given invite payload.
/// Returns `Ok(true)` on a successful enqueue, `Ok(false)` if the P2P
/// commander isn't up yet (caller can retry later).
///
/// Generates a fresh ephemeral Kyber-768 keypair for this handshake and
/// stashes the secret in [`PENDING_JOIN_KEMS`] keyed by `invitation_code`
/// so we can decapsulate the inviter's wrapped group key on reply.
fn publish_request_join(payload: &InvitePayload) -> anyhow::Result<bool> {
    let identity = match active_identity()? {
        Some(id) => id,
        None => return Err(anyhow::anyhow!("no active identity to sign RequestJoin")),
    };

    let (kyber_pub, kyber_secret) = generate_ephemeral_kyber();
    {
        let mut pending = PENDING_JOIN_KEMS.lock().unwrap();
        prune_pending_kems(&mut pending);
        // If a previous attempt for this invitation_code is still
        // pending its reply, drop it — the new attempt invalidates the
        // old ephemeral.
        let now = std::time::SystemTime::now();
        if let Some((mut prev_secret, _)) =
            pending.insert(payload.invitation_code.clone(), (kyber_secret, now))
        {
            prev_secret.zeroize();
        }
    }

    let body = RequestJoinBody {
        group_id: payload.group_id,
        invitation_code: payload.invitation_code.clone(),
        joiner_public_key: identity.public_key(),
        joiner_display_name: active_display_name().unwrap_or_default(),
        joiner_kyber_pub: kyber_pub,
    };
    let signed = sign_request_join(identity.as_ref(), body)?;
    let wire = signed.to_wire()?;

    // Subscribe to the per-group topic so we receive the inviter's
    // JoinAccepted reply. Then publish the RequestJoin on the same
    // topic — every other peer not in the group is unsubscribed and
    // never sees the handshake.
    let topic = group_topic(&hex::encode(payload.group_id.as_ref()));
    let _ = subscribe_topic(topic.clone());
    Ok(publish_to_topic(topic, wire))
}

/// Pop the cached Kyber secret for an invitation, returning ownership
/// to the caller. The caller is responsible for zeroising once done.
///
/// Also prunes any other entries that have outlived
/// [`PENDING_JOIN_KEM_TTL`] — TTL eviction piggybacks on every
/// take/insert so we never need a background thread.
fn take_pending_kyber_secret(invitation_code: &str) -> Option<Vec<u8>> {
    let mut pending = PENDING_JOIN_KEMS.lock().unwrap();
    prune_pending_kems(&mut pending);
    pending.remove(invitation_code).map(|(secret, _)| secret)
}

/// Re-subscribe the network layer to every group topic the local user
/// is in. Called once after the network thread comes up, plus any time
/// we need to re-establish (e.g. a network reset). Best-effort: a
/// failure to subscribe is logged but doesn't take the node down.
fn resubscribe_known_groups() {
    let mut gm_guard = GROUP_MANAGER.lock().unwrap();
    let gm = match gm_guard.as_mut() {
        Some(g) => g,
        None => return,
    };
    let active = match active_identity() {
        Ok(Some(id)) => id,
        _ => return,
    };
    let groups: Vec<_> = gm
        .get_member_groups(&active.identity_id())
        .iter()
        .map(|g| hex::encode(g.id.as_ref()))
        .collect();
    drop(gm_guard);
    for hex_id in groups {
        let _ = subscribe_topic(group_topic(&hex_id));
    }
}

/// Subscribe to a named gossipsub topic. No-op (returns false) if the
/// network thread hasn't started yet.
fn subscribe_topic(topic: String) -> bool {
    let commander_lock = P2P_COMMANDER.lock().unwrap();
    let commander = match commander_lock.as_ref() {
        Some(c) => c,
        None => return false,
    };
    matches!(commander.try_send(P2PCommand::Subscribe { topic }), Ok(()))
}

/// Publish bytes on a named gossipsub topic. The local node must be
/// subscribed to the topic for the publish to actually go out — see
/// `p2p_node.rs::P2PCommand::PublishToTopic`.
fn publish_to_topic(topic: String, data: Vec<u8>) -> bool {
    let commander_lock = P2P_COMMANDER.lock().unwrap();
    let commander = match commander_lock.as_ref() {
        Some(c) => c,
        None => return false,
    };
    matches!(
        commander.try_send(P2PCommand::PublishToTopic { topic, data }),
        Ok(())
    )
}

/// Snapshot the active identity Arc without holding the mutex across
/// awaits. Returns `Ok(None)` if onboarding hasn't happened yet.
fn active_identity() -> anyhow::Result<Option<Arc<IdentityKeyPair>>> {
    Ok(ACTIVE_IDENTITY.lock().unwrap().clone())
}

/// Read the persisted display name from the keystore. Used to label
/// outbound `RequestJoin` payloads so the inviter sees a name.
fn active_display_name() -> anyhow::Result<String> {
    let mut ks_guard = KEYSTORE.lock().unwrap();
    let ks = ks_guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;
    let secret = ks
        .retrieve_key(ACTIVE_IDENTITY_KEY)?
        .ok_or_else(|| anyhow::anyhow!("no persisted identity"))?;
    let blob: PersistedActiveIdentity = bincode::deserialize(secret.expose_secret())?;
    Ok(blob.display_name)
}

/// Dispatch a handshake frame received from another peer.
///
/// Errors are logged but never bubbled — handshake processing is
/// best-effort: we don't want a malformed frame from a hostile peer to
/// take down the dispatch task.
///
/// `sender_peer_id` is the libp2p PeerId of the peer who delivered
/// this frame. After a successful handshake, we fire a
/// `onPeerLinked(peer_id, identity_id_hex)` callback so the Android
/// side can stamp the corresponding `Contact.peerId` — closes the
/// chicken-and-egg gap where a contact's `peerId` only got
/// populated on first inbound encrypted message, with nothing to
/// route the *first* outbound from before any inbound had landed.
fn handle_inbound_handshake(frame: GroupHandshake, sender_peer_id: String) {
    let extracted_identity = extract_peer_identity_hex(&frame);
    if let Err(e) = process_handshake(frame) {
        eprintln!("Rust: handshake rejected: {e:#}");
        return;
    }
    if let Some(identity_hex) = extracted_identity {
        dispatch_peer_linked(sender_peer_id, identity_hex);
    }
}

/// Pull the sender's `IdentityId` out of a handshake frame, hex-
/// encoded. `None` for variants where the sender's identity isn't
/// directly in the body (`JoinAccepted` / `JoinRejected` — both
/// signed by the inviter, but the inviter id lives in the joiner's
/// local invite-receipt, not in the body itself; the receiver
/// already knows the inviter's identity from `expected_inviter_id`
/// so a separate linkage from this side isn't needed).
fn extract_peer_identity_hex(frame: &GroupHandshake) -> Option<String> {
    let id: IdentityId = match frame {
        GroupHandshake::RequestJoin { body, .. } => body.joiner_public_key.identity_id,
        GroupHandshake::KeyRotation { body, .. } => body.rotator_id,
        GroupHandshake::MemberAdded { body, .. } => body.adder_id,
        GroupHandshake::RoleChange { body, .. } => body.promoter_id,
        GroupHandshake::RequestStateSync { body, .. } => body.requester_id,
        GroupHandshake::StateSyncResponse { body, .. } => body.responder_id,
        GroupHandshake::JoinAccepted { .. } | GroupHandshake::JoinRejected { .. } => return None,
    };
    Some(hex::encode(id.as_ref() as &[u8]))
}

/// Fire the Kotlin-side `onPeerLinked(peer_id, identity_id_hex)`
/// callback. Best-effort — if the JVM / callback isn't attached
/// (e.g., during early initialization), the linkage just isn't
/// fired and the receive-path TOFU population still applies on
/// the next inbound packet.
fn dispatch_peer_linked(peer_id: String, identity_id_hex: String) {
    let jvm_lock = JVM.lock().unwrap();
    let jvm = match jvm_lock.as_ref() {
        Some(v) => v,
        None => return,
    };
    let mut env = match jvm.attach_current_thread_permanently() {
        Ok(e) => e,
        Err(_) => return,
    };
    let cb_lock = CALLBACK_HANDLER.lock().unwrap();
    let callback_obj = match cb_lock.as_ref() {
        Some(o) => o,
        None => return,
    };
    let j_peer = match env.new_string(peer_id) {
        Ok(s) => s,
        Err(_) => return,
    };
    let j_identity = match env.new_string(identity_id_hex) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = env.call_method(
        callback_obj,
        "onPeerLinked",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[JValue::Object(&j_peer), JValue::Object(&j_identity)],
    );
}

fn process_handshake(frame: GroupHandshake) -> anyhow::Result<()> {
    match frame {
        GroupHandshake::RequestJoin { body, signature } => {
            on_request_join(body, signature)?;
        }
        GroupHandshake::JoinAccepted { body, signature } => {
            on_join_accepted(body, signature)?;
        }
        GroupHandshake::JoinRejected { body, signature: _ } => {
            // Drop the pending receipt; we'll rely on the inviter
            // signature check before propagating UX, but for now just
            // log so the joiner knows their join didn't land.
            // Also wipe the cached Kyber secret — without a matching
            // acceptance there's nothing to unwrap, and leaving it
            // around just gives attackers more time to grab it.
            if let Some(mut secret) = take_pending_kyber_secret(&body.invitation_code) {
                secret.zeroize();
            }
            eprintln!(
                "Rust: invite to group {} rejected: {}",
                body.group_id, body.reason
            );
        }
        GroupHandshake::KeyRotation { body, signature } => {
            on_key_rotation(body, signature)?;
        }
        GroupHandshake::MemberAdded { body, signature } => {
            // Existing-member side handler for inviter-broadcast
            // MemberAdded — keeps our local view convergent with
            // the inviter's roster (and picks up the new member's
            // per-group Kyber pubkey, without which any later
            // rotation we plan would silently skip them).
            let mut gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            crate::groups::handshake_handlers::process_member_added(gm, &body, &signature)?;
        }
        GroupHandshake::RoleChange { body, signature } => {
            let mut gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            crate::groups::handshake_handlers::process_role_change(gm, &body, &signature)?;
        }
        GroupHandshake::RequestStateSync { body, signature } => {
            // Responder side. Build + sign a snapshot reply and
            // publish it back on the group's gossipsub topic.
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let topic = group_topic(&hex::encode(body.group_id.as_ref()));
            let response = {
                let gm_guard = GROUP_MANAGER.lock().unwrap();
                let gm = gm_guard
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
                crate::groups::handshake_handlers::process_request_state_sync(
                    gm,
                    identity.as_ref(),
                    &body,
                    &signature,
                )?
            };
            if let Some((resp_body, resp_sig)) = response {
                let signed = GroupHandshake::StateSyncResponse {
                    body: resp_body,
                    signature: resp_sig,
                };
                let _ = publish_to_topic(topic, signed.to_wire()?);
            }
        }
        GroupHandshake::StateSyncResponse { body, signature } => {
            // Requester side — gossipsub fan-out delivers the
            // reply to everyone on the topic, so process_state_sync_response
            // self-filters by self_id == body.requester_id.
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let mut gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let _ = crate::groups::handshake_handlers::process_state_sync_response(
                gm,
                identity.identity_id(),
                &body,
                &signature,
            )?;
        }
    }
    Ok(())
}

fn on_key_rotation(
    body: KeyRotationBody,
    signature: crate::identity::identity_key::HybridSignature,
) -> anyhow::Result<()> {
    let identity = active_identity()?
        .ok_or_else(|| anyhow::anyhow!("no active identity available"))?;
    // Don't process our own rotations as if we received them — we
    // already installed the new key in plan_key_rotation.
    if body.rotator_id == identity.identity_id() {
        return Ok(());
    }
    let mut gm_guard = GROUP_MANAGER.lock().unwrap();
    let gm = gm_guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
    process_key_rotation(gm, identity.identity_id(), &body, &signature)
}

fn on_request_join(
    body: RequestJoinBody,
    signature: crate::identity::identity_key::HybridSignature,
) -> anyhow::Result<()> {
    // We only act on RequestJoins for invitations *we* minted.
    let identity = active_identity()?
        .ok_or_else(|| anyhow::anyhow!("no active identity available"))?;

    let outcome = {
        let mut gm_guard = GROUP_MANAGER.lock().unwrap();
        let gm = gm_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
        process_request_join(gm, identity.as_ref(), &body, &signature)?
    };

    let topic = group_topic(&hex::encode(body.group_id.as_ref()));
    match outcome {
        HandshakeOutcome::Accept {
            body: accepted,
            signature: accepted_sig,
            member_added_body,
            member_added_signature,
        } => {
            let signed = GroupHandshake::JoinAccepted {
                body: accepted,
                signature: accepted_sig,
            };
            let _ = publish_to_topic(topic.clone(), signed.to_wire()?);
            // Broadcast MemberAdded so existing members learn about
            // the new joiner (and their Kyber pubkey).
            let added = GroupHandshake::MemberAdded {
                body: member_added_body,
                signature: member_added_signature,
            };
            let _ = publish_to_topic(topic, added.to_wire()?);
        }
        HandshakeOutcome::Reject { body: rejected, signature: rejected_sig } => {
            let signed = GroupHandshake::JoinRejected {
                body: rejected,
                signature: rejected_sig,
            };
            let _ = publish_to_topic(topic, signed.to_wire()?);
        }
        HandshakeOutcome::UnknownInvitation => {
            // The RequestJoin doesn't match any invitation we minted.
            // Could be a different inviter's flow on the same topic —
            // silent no-op is the right behaviour.
        }
    }
    Ok(())
}

fn on_join_accepted(
    body: crate::groups::group_handshake::JoinAcceptedBody,
    signature: crate::identity::identity_key::HybridSignature,
) -> anyhow::Result<()> {
    let identity = active_identity()?
        .ok_or_else(|| anyhow::anyhow!("no active identity available"))?;
    if body.joiner_id != identity.identity_id() {
        return Ok(());
    }

    // Find the pending receipt to learn the expected inviter id.
    let expected_inviter_id = {
        let mut gm_guard = GROUP_MANAGER.lock().unwrap();
        let gm = gm_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
        let accepted = gm.list_accepted_external_invites().unwrap_or_default();
        accepted
            .into_iter()
            .find(|e| e.group_id == body.group_id)
            .ok_or_else(|| anyhow::anyhow!("no pending receipt for group"))?
            .inviter_id
    };

    // Pull the cached Kyber secret out of the global; the handler
    // function consumes it once, then we wipe.
    let mut kyber_secret = take_pending_kyber_secret(&body.invitation_code)
        .ok_or_else(|| anyhow::anyhow!("no pending Kyber secret for invitation"))?;

    let result = {
        let mut gm_guard = GROUP_MANAGER.lock().unwrap();
        let gm = gm_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
        process_join_accepted(gm, expected_inviter_id, &body, &signature, &kyber_secret)
    };
    kyber_secret.zeroize();
    result
}

/// List all invites the local user has accepted but not yet been
/// confirmed into. Returns a JSON array.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeListAcceptedInvites(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<serde_json::Value> = (|| {
            let mut gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let entries = gm.list_accepted_external_invites()?;
            let arr = entries
                .into_iter()
                .map(|e| {
                    json!({
                        "group_id_hex": hex::encode(e.group_id.as_ref()),
                        "group_name": e.group_name,
                        "inviter_id_hex": hex::encode(e.inviter_id.as_ref()),
                        "inviter_name": e.inviter_name,
                        "invitation_code": e.invitation_code,
                        "accepted_at": e.accepted_at,
                    })
                })
                .collect::<Vec<_>>();
            Ok(serde_json::Value::Array(arr))
        })();
        ok_or_null(env, result)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCleanup(
    _env: JNIEnv,
    _class: JClass,
) {
    *ACTIVE_IDENTITY.lock().unwrap() = None;
    *KEYSTORE.lock().unwrap() = None;
    *GROUP_MANAGER.lock().unwrap() = None;
    *INITIALIZED.lock().unwrap() = false;
}

/// Wipe the on-disk identity + group keystores plus all in-memory
/// caches, then mark the core as uninitialised. Used by Settings →
/// "Reset identity" to recover from a desynced state (e.g. the user
/// nuked the keystore files outside the app, or the persisted bundle
/// no longer matches the in-process keys).
///
/// After this returns, Kotlin must call `nativeInitialize(dataDir)`
/// again before any further JNI call. The next launch will see a
/// fresh keystore and route through onboarding again.
///
/// `data_dir` should be the same `context.filesDir.absolutePath` that
/// was passed to `nativeInitialize` so we delete the right files.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeResetIdentity(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jboolean {
    catch_unwind_result(|| {
        let dir: String = match env.get_string(&data_dir) {
            Ok(s) => s.into(),
            Err(_) => return 0,
        };

        // Drop in-memory state first so any pending operation can't
        // race the file deletes and write a stale record back.
        *ACTIVE_IDENTITY.lock().unwrap() = None;
        *KEYSTORE.lock().unwrap() = None;
        *GROUP_MANAGER.lock().unwrap() = None;
        {
            // Zeroise every cached ephemeral before dropping the map.
            // Vec::clear() runs Drop on the inner Vec<u8> but doesn't
            // overwrite its contents — explicit zeroize is what
            // actually erases the bytes.
            let mut pending = PENDING_JOIN_KEMS.lock().unwrap();
            for (_, (secret, _)) in pending.iter_mut() {
                secret.zeroize();
            }
            pending.clear();
        }
        *INITIALIZED.lock().unwrap() = false;

        // SecureKeyStore stores its data file at <path>.db and the
        // password-derived master key at <path>.master — wipe both
        // for both the identity and groups stores. Best-effort:
        // missing files are fine, anything else gets logged but
        // doesn't fail the reset.
        let path = std::path::Path::new(&dir);
        for name in &[
            "qubee_keys.db",
            "qubee_keys.master",
            "qubee_groups.db",
            "qubee_groups.master",
        ] {
            let p = path.join(name);
            if let Err(e) = std::fs::remove_file(&p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("Rust: reset failed to delete {p:?}: {e}");
                }
            }
        }
        1
    })
}

// ---------------------------------------------------------------------------
// Onboarding & invite-link surface (hybrid-signed, not ZK)
//
// The earlier prototype framed these calls as "ZK proofs" but every
// claim Qubee needs to make about an identity is "I hold the secret
// for this advertised public key" — which is a signature, not a
// zero-knowledge statement. We sign the canonical bytes of the
// onboarding bundle / invite token with the same hybrid Ed25519 +
// Dilithium-2 keypair the bundle advertises, and verifiers re-derive
// those bytes and check the signature. See README's Security model
// section for why we won't be reintroducing ZK.
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
    mut env: JNIEnv,
    _class: JClass,
    display_name: JString,
    user_id: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let display_name: String = match env.get_string(&display_name) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let user_id: String = match env.get_string(&user_id) {
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
    jni_catch_jstring(|| {
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
/// the link is malformed or the embedded hybrid signature fails verification.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyOnboardingLink(
    mut env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let link: String = match env.get_string(&link) {
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
    mut env: JNIEnv,
    _class: JClass,
    invitation_json: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let raw: String = match env.get_string(&invitation_json) {
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
    mut env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let link: String = match env.get_string(&link) {
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

// ---------------------------------------------------------------------------
// Identity verification & Short Authentication String (SAS)
// ---------------------------------------------------------------------------

/// Verify a peer's identity key by comparing its fingerprint to a
/// caller-provided value.
///
/// `identity_key_bytes` must be a serialized public `IdentityKey`
/// (`IdentityKey::to_bytes`). `verification_data` is the expected
/// fingerprint as ASCII bytes — case + space-insensitive comparison
/// against `IdentityKey::fingerprint()`.
///
/// Returns 1 if the fingerprints match, else 0. Returns 0 (not an
/// exception) on any decode error so the caller's UI surface stays
/// recoverable.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyIdentityKey(
    env: JNIEnv,
    _class: JClass,
    _contact_id: JString,
    identity_key_bytes: JByteArray,
    verification_data: JByteArray,
) -> jboolean {
    jni_catch_or(|| -> anyhow::Result<jboolean> {
        let id_bytes: Vec<u8> = env
            .convert_byte_array(identity_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid identity key bytes: {e}"))?;
        let identity = IdentityKey::from_bytes(&id_bytes)
            .map_err(|e| anyhow::anyhow!("IdentityKey decode failed: {e}"))?;
        let fp = identity.fingerprint().replace(' ', "").to_ascii_uppercase();
        let verif: Vec<u8> = env
            .convert_byte_array(verification_data)
            .map_err(|e| anyhow::anyhow!("invalid verification data: {e}"))?;
        let verif_str = String::from_utf8(verif).unwrap_or_default();
        let normalized = verif_str.replace(' ', "").to_ascii_uppercase();
        Ok(if fp == normalized { 1 } else { 0 })
    })
    .unwrap_or(0)
}

/// Generate a short authentication string (SAS) from our + a peer's
/// identity key. Both parties' devices compute the same SAS as long
/// as the byte inputs match (`IdentityKey::to_bytes` is canonical).
///
/// Algorithm:
///   1. Lexicographically order the two key byte buffers so each side
///      hashes the same `(first || second)` regardless of who's
///      calling.
///   2. BLAKE3 over the concatenation; take the first 4 bytes as a
///      big-endian u32.
///   3. Split into two 16-bit halves, reduce each `% 10000` so the
///      `{:04}` format produces a guaranteed 4-digit group (the
///      naïve `& 0xFFFF` lets values up to 65535 leak through, which
///      breaks the visual contract).
///   4. Format as `"NNNN NNNN"`.
///
/// Returns a JNI string on success, or NULL on failure.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateSAS(
    env: JNIEnv,
    _class: JClass,
    our_identity_key: JByteArray,
    peer_identity_key: JByteArray,
) -> jstring {
    jni_catch_or(|| -> anyhow::Result<jstring> {
        let our_bytes: Vec<u8> = env
            .convert_byte_array(our_identity_key)
            .map_err(|e| anyhow::anyhow!("invalid our_identity_key bytes: {e}"))?;
        let peer_bytes: Vec<u8> = env
            .convert_byte_array(peer_identity_key)
            .map_err(|e| anyhow::anyhow!("invalid peer_identity_key bytes: {e}"))?;
        let (first, second) = if our_bytes <= peer_bytes {
            (our_bytes.as_slice(), peer_bytes.as_slice())
        } else {
            (peer_bytes.as_slice(), our_bytes.as_slice())
        };
        let mut hasher = Hasher::new();
        hasher.update(first);
        hasher.update(second);
        let digest = hasher.finalize();
        let h = digest.as_bytes();
        let value: u32 = ((h[0] as u32) << 24)
            | ((h[1] as u32) << 16)
            | ((h[2] as u32) << 8)
            | (h[3] as u32);
        // Reduce each 16-bit half to 0..=9999 so the {:04} format
        // spec is a 4-digit ceiling, not just a minimum width.
        let high = ((value >> 16) & 0xFFFF) % 10_000;
        let low = (value & 0xFFFF) % 10_000;
        let sas = format!("{:04} {:04}", high, low);
        let java_str = env.new_string(sas)?;
        Ok(java_str.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

// ---------------------------------------------------------------------------
// Message + file crypto
// ---------------------------------------------------------------------------
//
// Kotlin's `QubeeManager.{encrypt,decrypt}{Message,File}` calls these
// four exports to encrypt / decrypt traffic in a "session". The
// session model in this codebase is "a 2-member group for 1:1, an
// N-member group for chats" — there's no separate 1:1 ratchet; the
// wire format and key handling go through `groups::group_message`
// for both shapes. The Kotlin-side `sessionId` is the hex-encoded
// `GroupId` (64 chars / 32 bytes); the caller is responsible for
// having created the matching group + completed its key exchange
// via the existing handshake flow before any of these exports get
// called. Failed lookup / un-keyed group / decrypt failure all
// surface as a JNI null return, which Kotlin maps to `null` —
// matching the nullable signatures in `QubeeManager.kt`.

fn parse_session_id(env: &mut JNIEnv, session_id: JString) -> anyhow::Result<GroupId> {
    let raw: String = env
        .get_string(&session_id)
        .map_err(|e| anyhow::anyhow!("invalid session_id: {e}"))?
        .into();
    Ok(GroupId::from_bytes(parse_hex32(Some(raw.as_str()))?))
}

/// Encrypt a UTF-8 plaintext string for a session. Returns the
/// signed wire envelope (`encrypt_group_message` output, a
/// `QUBEE_GMS\x01`-prefixed bincode-serialised
/// `GroupMessageEnvelope`) as a Java `byte[]`. Returns `null` on
/// any failure — onboarding not done, group not known, group key
/// not yet installed, etc.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    plaintext: JString,
) -> jbyteArray {
    jni_catch_jbytearray(|| {
        let result: anyhow::Result<jbyteArray> = (|| {
            let group_id = parse_session_id(&mut env, session_id)?;
            let plaintext_str: String = env
                .get_string(&plaintext)
                .map_err(|e| anyhow::anyhow!("invalid plaintext: {e}"))?
                .into();
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let wire =
                encrypt_group_message(gm, identity.as_ref(), group_id, plaintext_str.as_bytes())?;
            let arr = env
                .byte_array_from_slice(&wire)
                .map_err(|e| anyhow::anyhow!("byte_array_from_slice: {e}"))?;
            Ok(arr.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Decrypt a wire envelope produced by `nativeEncryptMessage` (or
/// any peer's `encrypt_group_message`) back into a UTF-8
/// plaintext string. Returns `null` if decryption fails OR if the
/// plaintext isn't valid UTF-8 — binary payloads should ride
/// `nativeDecryptFile` instead.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    encrypted_envelope: JByteArray,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let _group_id = parse_session_id(&mut env, session_id)?;
            // session_id is required by the Kotlin signature but
            // decrypt_group_message reads the group_id off the wire
            // envelope itself; we still parse it to surface a
            // malformed session_id as a null return rather than a
            // misleading "decrypt succeeded" against the wrong
            // session. Caller-side wiring expects the two to match.
            let wire = env
                .convert_byte_array(&encrypted_envelope)
                .map_err(|e| anyhow::anyhow!("invalid encrypted_envelope: {e}"))?;
            let gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let decrypted = decrypt_group_message(gm, &wire)?;
            let plaintext = String::from_utf8(decrypted.plaintext)
                .map_err(|e| anyhow::anyhow!("plaintext is not UTF-8: {e}"))?;
            let java_str = env
                .new_string(plaintext)
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Encrypt arbitrary file bytes for a session. Same wire shape as
/// `nativeEncryptMessage` — the difference is only that the input
/// is a `byte[]` rather than a `String`, so binary payloads survive
/// the round-trip without UTF-8 validation. Returns `null` on
/// failure.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptFile(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    file_data: JByteArray,
) -> jbyteArray {
    jni_catch_jbytearray(|| {
        let result: anyhow::Result<jbyteArray> = (|| {
            let group_id = parse_session_id(&mut env, session_id)?;
            let plaintext = env
                .convert_byte_array(&file_data)
                .map_err(|e| anyhow::anyhow!("invalid file_data: {e}"))?;
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let wire = encrypt_group_message(gm, identity.as_ref(), group_id, &plaintext)?;
            let arr = env
                .byte_array_from_slice(&wire)
                .map_err(|e| anyhow::anyhow!("byte_array_from_slice: {e}"))?;
            Ok(arr.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Decrypt a wire envelope back into the original file bytes.
/// Companion to `nativeEncryptFile` — same wire format, no UTF-8
/// constraint on the output. Returns `null` on failure.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptFile(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    encrypted_envelope: JByteArray,
) -> jbyteArray {
    jni_catch_jbytearray(|| {
        let result: anyhow::Result<jbyteArray> = (|| {
            let _group_id = parse_session_id(&mut env, session_id)?;
            let wire = env
                .convert_byte_array(&encrypted_envelope)
                .map_err(|e| anyhow::anyhow!("invalid encrypted_envelope: {e}"))?;
            let gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let decrypted = decrypt_group_message(gm, &wire)?;
            let arr = env
                .byte_array_from_slice(&decrypted.plaintext)
                .map_err(|e| anyhow::anyhow!("byte_array_from_slice: {e}"))?;
            Ok(arr.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Compute the canonical 8-byte BLAKE3 fingerprint of an
/// `IdentityKey` and return it as a string in the form
/// `"AABB CCDD EEFF GGHH"` (4 groups of 2 bytes / 4 hex chars,
/// space-separated). Same value as `IdentityKey::fingerprint()`,
/// exposed through JNI so the verify UI can display the same
/// fingerprint Rust uses internally — closes the format-disagreement
/// gap from the bridge-checkpoint commit (the Kotlin
/// `ByteArray.toFingerprint` extension formats the first 8 raw
/// bytes with dashes, which doesn't match Rust's hash).
///
/// Returns `null` on any decode error.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeComputeFingerprint(
    env: JNIEnv,
    _class: JClass,
    identity_key_bytes: JByteArray,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let id_bytes: Vec<u8> = env
                .convert_byte_array(&identity_key_bytes)
                .map_err(|e| anyhow::anyhow!("invalid identity key bytes: {e}"))?;
            let identity = IdentityKey::from_bytes(&id_bytes)
                .map_err(|e| anyhow::anyhow!("IdentityKey decode failed: {e}"))?;
            let java_str = env
                .new_string(identity.fingerprint())
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Read the `sender_id` field out of a `GroupMessageEnvelope` wire
/// envelope without decrypting. The signed body carries this in
/// the clear (it's authenticated, just not confidential), so the
/// receiver can identify which Qubee identity sent the packet
/// before going through the AEAD path.
///
/// Used by the Android `MessageService.onMessageReceived` flow to
/// link the libp2p PeerId of an inbound packet to the matching
/// `Contact.identityId` — the missing piece the
/// `getContactByPeerId` lookup needed to actually populate.
///
/// Returns the sender id as a 64-character hex string on success,
/// or `null` if the bytes don't parse as a wire envelope.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInspectEnvelopeSender(
    env: JNIEnv,
    _class: JClass,
    wire: JByteArray,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let wire_bytes: Vec<u8> = env
                .convert_byte_array(&wire)
                .map_err(|e| anyhow::anyhow!("invalid wire bytes: {e}"))?;
            let envelope = GroupMessageEnvelope::from_wire(&wire_bytes)
                .ok_or_else(|| anyhow::anyhow!("not a group message frame"))?;
            let hex_id = hex::encode(envelope.body.sender_id.as_ref() as &[u8]);
            let java_str = env
                .new_string(hex_id)
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Generate a Short Authentication String (SAS) between the locally
/// active identity and the supplied peer `IdentityKey` bytes,
/// without forcing the caller to first fetch their own identity
/// bytes. Convenience wrapper over `nativeGenerateSAS` for the
/// common 1:1 verification UI path.
///
/// Returns the SAS as `"NNNN NNNN"` (two zero-padded 4-digit decimal
/// groups) on success, or null on any failure (no active identity,
/// invalid peer key, etc.). Both peers compute the same SAS as long
/// as both supply each other's `IdentityKey::to_bytes()` output.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateSASForContact(
    env: JNIEnv,
    _class: JClass,
    peer_identity_key: JByteArray,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let peer_bytes: Vec<u8> = env
                .convert_byte_array(&peer_identity_key)
                .map_err(|e| anyhow::anyhow!("invalid peer_identity_key bytes: {e}"))?;
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let our_bytes = identity.public_key().to_bytes();

            let (first, second) = if our_bytes <= peer_bytes {
                (our_bytes.as_slice(), peer_bytes.as_slice())
            } else {
                (peer_bytes.as_slice(), our_bytes.as_slice())
            };
            let mut hasher = Hasher::new();
            hasher.update(first);
            hasher.update(second);
            let digest = hasher.finalize();
            let h = digest.as_bytes();
            let value: u32 = ((h[0] as u32) << 24)
                | ((h[1] as u32) << 16)
                | ((h[2] as u32) << 8)
                | (h[3] as u32);
            let high = ((value >> 16) & 0xFFFF) % 10_000;
            let low = (value & 0xFFFF) % 10_000;
            let sas = format!("{:04} {:04}", high, low);
            let java_str = env
                .new_string(sas)
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Return the locally-active identity's fingerprint as a string in
/// the canonical `"AABB CCDD EEFF GGHH"` shape — same value as
/// `IdentityKey::fingerprint()` over our own public key. Lets the
/// Android verify UI render the local user's self-fingerprint as
/// a QR code for the peer to scan; closes the missing direction
/// of the OOB compare ceremony (`nativeComputeFingerprint` covers
/// the peer's fingerprint side, this covers ours).
///
/// Returns `null` if onboarding hasn't completed yet.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGetMyFingerprint(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let java_str = env
                .new_string(identity.public_key().fingerprint())
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Return the locally-active identity's `IdentityId` as a 64-char
/// lowercase hex string. Used by the Android Group Details sheet
/// to flag "this row is you" on the member list, to wire the
/// "Leave group" action (which passes our own id into
/// `nativeRemoveMember`), and as the canonical sender id baked
/// into persisted `Message.senderId` rows so send + receive paths
/// stay interoperable. Distinct from `nativeGetMyFingerprint` —
/// fingerprint is the 8-byte BLAKE3 truncation used for OOB
/// compare; this is the full 32-byte address used on the wire.
///
/// Two exports with identical bodies on purpose:
///   * `nativeGetMyIdentityIdHex` — historical name used by the
///     Group UX surface; kept stable so old Kotlin call sites
///     keep linking.
///   * `nativeGetMyIdentityId` — newer alias used by `ChatViewModel`
///     when stamping outbound `Message.senderId`. Same return.
///
/// Returns `null` if onboarding hasn't completed yet.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGetMyIdentityIdHex(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    my_identity_id_hex_impl(env)
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGetMyIdentityId(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    my_identity_id_hex_impl(env)
}

fn my_identity_id_hex_impl(env: JNIEnv) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let id_hex = hex::encode(identity.identity_id().as_ref() as &[u8]);
            let java_str = env
                .new_string(id_hex)
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// Return the active members of a group as a JSON array. Each entry
/// is `{identity_id_hex, display_name, role, is_active, joined_at}`.
/// Used by the Android Group Details sheet to render the member
/// list — the Rust side is the source of truth (the Kotlin
/// `Conversation.participants` field is a hint, not authoritative).
///
/// Returns:
///   * the JSON array on success,
///   * `[]` if the group exists but has no active members (shouldn't
///     happen — the owner is always an active member — but matches
///     the empty-state UI gracefully),
///   * `null` if the group isn't in the local view (legacy enrolment,
///     bad input). The caller treats null as "couldn't load".
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeListGroupMembers(
    mut env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let raw: String = env
                .get_string(&group_id_hex)
                .map_err(|e| anyhow::anyhow!("invalid group_id_hex: {e}"))?
                .into();
            let group_id = GroupId::from_bytes(parse_hex32(Some(raw.as_str()))?);
            let gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;
            let group = gm
                .get_group(&group_id)
                .ok_or_else(|| anyhow::anyhow!("group not in local view"))?;
            let members: Vec<serde_json::Value> = group
                .members
                .values()
                .map(|m| {
                    let role_label = role_to_str(&m.role);
                    let is_active = matches!(
                        m.member_status,
                        crate::groups::group_manager::MemberStatus::Active,
                    );
                    serde_json::json!({
                        "identity_id_hex": hex::encode(m.identity_id.as_ref() as &[u8]),
                        "display_name": m.display_name,
                        "role": role_label,
                        "is_active": is_active,
                        "joined_at": m.joined_at,
                    })
                })
                .collect();
            let payload = serde_json::Value::Array(members).to_string();
            let java_str = env
                .new_string(payload)
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}

/// List every group the active identity is a member of, from the
/// Rust core's local view. Used on fresh-install / cold-launch to
/// hydrate the Conversation table when the Kotlin DB is empty but
/// the Rust state (recovered from `nativeInitialize`) isn't.
///
/// JSON shape: array of
/// `{group_id_hex, name, member_count, my_role, last_updated,
/// version}`. `my_role` mirrors the small fixed vocabulary used by
/// `nativeListGroupMembers` / `nativePromoteMember`.
///
/// Returns:
///  * a (possibly empty) JSON array on success — including when
///    the active identity is in no groups.
///  * `null` if no active identity has been loaded yet (caller
///    treats this as "wait until onboarding finishes").
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeListGroups(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    jni_catch_jstring(|| {
        let result: anyhow::Result<jstring> = (|| {
            let identity = active_identity()?
                .ok_or_else(|| anyhow::anyhow!("no active identity"))?;
            let my_id = identity.identity_id();

            let gm_guard = GROUP_MANAGER.lock().unwrap();
            let gm = gm_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("group manager not initialised"))?;

            let groups: Vec<serde_json::Value> = gm
                .get_member_groups(&my_id)
                .into_iter()
                .map(|group| {
                    let my_role = group
                        .members
                        .get(&my_id)
                        .map(|m| role_to_str(&m.role))
                        .unwrap_or("Member");
                    let active_count = group
                        .members
                        .values()
                        .filter(|m| matches!(
                            m.member_status,
                            crate::groups::group_manager::MemberStatus::Active,
                        ))
                        .count();
                    serde_json::json!({
                        "group_id_hex": hex::encode(group.id.as_ref() as &[u8]),
                        "name": group.name,
                        "member_count": active_count,
                        "my_role": my_role,
                        "last_updated": group.last_updated,
                        "version": group.version,
                    })
                })
                .collect();
            let payload = serde_json::Value::Array(groups).to_string();
            let java_str = env
                .new_string(payload)
                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;
            Ok(java_str.into_raw())
        })();
        result.unwrap_or(std::ptr::null_mut())
    })
}
