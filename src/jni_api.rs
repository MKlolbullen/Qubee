// src/jni_api.rs

use jni::{JNIEnv, JavaVM};
use jni::objects::{JByteArray, JClass, JObject, JString, JValue, GlobalRef};
use jni::sys::{jboolean, jstring};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;

// Core modules
use crate::network::p2p_node::{group_topic, NodeEvent, P2PCommand, P2PNode};
use crate::identity::identity_key::{IdentityKeyPair, IdentityId};
use crate::onboarding::OnboardingBundle;
use crate::groups::group_invite::InvitePayload;
use crate::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, KeyRotationBody, RequestJoinBody,
};
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
    static ref PENDING_JOIN_KEMS: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
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
                                if let NodeEvent::MessageReceived { data, .. } = &event {
                                    if let Some(handshake) = GroupHandshake::from_wire(data) {
                                        handle_inbound_handshake(handshake);
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
            JValue::Object(group_hex.into()),
            JValue::Object(sender_hex.into()),
            JValue::Object(payload.into()),
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

/// Create a brand new group owned by the active local identity.
/// Returns JSON `{group_id_hex, name, owner_id_hex}`. The group's
/// symmetric encryption key is generated and stored alongside the
/// group record so subsequent invitations can KEM-wrap it for joiners.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateGroup(
    env: JNIEnv,
    _class: JClass,
    name: JString,
    description: JString,
) -> jstring {
    catch_unwind_result(|| {
        let name: String = match env.get_string(name) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let description: String = match env.get_string(description) {
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
            // Best-effort: if the network thread isn't up yet, we'll
            // re-subscribe on next bootstrap (TODO once we persist a
            // group→subscribed mapping).
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
    env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    expires_at_seconds: jni::sys::jlong,
    max_uses: jni::sys::jint,
) -> jstring {
    catch_unwind_result(|| {
        let group_id_hex: String = match env.get_string(group_id_hex) {
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
    env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    plaintext: JByteArray,
) -> jstring {
    catch_unwind_result(|| {
        let group_id_hex: String = match env.get_string(group_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let plaintext = match env.convert_byte_array(plaintext) {
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
    env: JNIEnv,
    _class: JClass,
    group_id_hex: JString,
    member_id_hex: JString,
    reason: JString,
) -> jstring {
    catch_unwind_result(|| {
        let group_id_hex: String = match env.get_string(group_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let member_id_hex: String = match env.get_string(member_id_hex) {
            Ok(s) => s.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        let reason: String = match env.get_string(reason) {
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
        // If a previous attempt for this invitation_code is still
        // pending its reply, drop it — the new attempt invalidates the
        // old ephemeral.
        if let Some(mut prev) = pending.insert(payload.invitation_code.clone(), kyber_secret) {
            prev.zeroize();
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
fn take_pending_kyber_secret(invitation_code: &str) -> Option<Vec<u8>> {
    PENDING_JOIN_KEMS.lock().unwrap().remove(invitation_code)
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
fn handle_inbound_handshake(frame: GroupHandshake) {
    if let Err(e) = process_handshake(frame) {
        eprintln!("Rust: handshake rejected: {e:#}");
    }
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
    catch_unwind_result(|| {
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
    env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jboolean {
    catch_unwind_result(|| {
        let dir: String = match env.get_string(data_dir) {
            Ok(s) => s.into(),
            Err(_) => return 0,
        };

        // Drop in-memory state first so any pending operation can't
        // race the file deletes and write a stale record back.
        *ACTIVE_IDENTITY.lock().unwrap() = None;
        *KEYSTORE.lock().unwrap() = None;
        *GROUP_MANAGER.lock().unwrap() = None;
        PENDING_JOIN_KEMS.lock().unwrap().clear();
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
/// the link is malformed or the embedded hybrid signature fails verification.
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
