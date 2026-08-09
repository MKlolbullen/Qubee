from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


def replace_all(path: str, old: str, new: str, minimum: int = 1) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count < minimum:
        raise SystemExit(f"{path}: expected >= {minimum} matches, got {count}: {old!r}")
    p.write_text(text.replace(old, new))


# ---------------------------------------------------------------------------
# Direct wire v2: the durable wire itself carries the intended recipient.
# ---------------------------------------------------------------------------
path = "src/ratchet/direct_message.rs"
replace_all(path, r"QUBEE_DMS\x01", r"QUBEE_DMS\x02", minimum=3)
replace_once(
    path,
    "    pub sender_id: IdentityId,\n    /// Present only on the conversation's first message: the PQXDH\n",
    "    pub sender_id: IdentityId,\n"
    "    /// The intended recipient identity. This is routing metadata, not a\n"
    "    /// new authentication primitive: the same sender/recipient pair is\n"
    "    /// already committed into the ratchet's conversation associated data.\n"
    "    /// Receivers reject frames addressed to any other local identity.\n"
    "    pub recipient_id: IdentityId,\n"
    "    /// Present only on the conversation's first message: the PQXDH\n",
)
replace_once(
    path,
    "pub fn is_direct_message_frame(bytes: &[u8]) -> bool {\n"
    "    bytes.len() >= MAGIC_DIRECT_MESSAGE.len()\n"
    "        && &bytes[..MAGIC_DIRECT_MESSAGE.len()] == MAGIC_DIRECT_MESSAGE\n"
    "}\n",
    "pub fn is_direct_message_frame(bytes: &[u8]) -> bool {\n"
    "    bytes.len() >= MAGIC_DIRECT_MESSAGE.len()\n"
    "        && &bytes[..MAGIC_DIRECT_MESSAGE.len()] == MAGIC_DIRECT_MESSAGE\n"
    "}\n\n"
    "/// Read the intended recipient from a well-formed direct frame without\n"
    "/// touching ratchet state. Used only for transport routing; authenticity\n"
    "/// still comes from the pair-bound ratchet AEAD on receive.\n"
    "pub fn inspect_direct_recipient(bytes: &[u8]) -> Option<IdentityId> {\n"
    "    DirectMessage::from_wire(bytes).map(|dm| dm.recipient_id)\n"
    "}\n",
)
replace_once(
    path,
    "            sender_id: IdentityId::from([4u8; 32]),\n            initial: Some(sample_initial()),\n",
    "            sender_id: IdentityId::from([4u8; 32]),\n"
    "            recipient_id: IdentityId::from([6u8; 32]),\n"
    "            initial: Some(sample_initial()),\n",
)
replace_once(
    path,
    "            sender_id: IdentityId::from([5u8; 32]),\n            initial: None,\n",
    "            sender_id: IdentityId::from([5u8; 32]),\n"
    "            recipient_id: IdentityId::from([7u8; 32]),\n"
    "            initial: None,\n",
)
replace_once(
    path,
    "        assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);\n    }\n\n    #[test]\n    fn rejects_foreign_and_truncated_frames()",
    "        assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);\n"
    "        assert_eq!(inspect_direct_recipient(&wire), Some(IdentityId::from([7u8; 32])));\n"
    "    }\n\n"
    "    #[test]\n"
    "    fn rejects_foreign_and_truncated_frames()",
)

# ---------------------------------------------------------------------------
# Send/receive orchestration: stamp and enforce that recipient.
# ---------------------------------------------------------------------------
path = "src/ratchet/direct.rs"
replace_all(path, r"QUBEE_DMS\x01", r"QUBEE_DMS\x02", minimum=2)
replace_once(
    path,
    "    DirectMessage {\n        sender_id: local_id,\n        initial,\n",
    "    DirectMessage {\n"
    "        sender_id: local_id,\n"
    "        recipient_id: peer_id,\n"
    "        initial,\n",
)
replace_once(
    path,
    "    let peer_id = dm.sender_id;\n    if peer_id == local_id {\n",
    "    let peer_id = dm.sender_id;\n"
    "    if dm.recipient_id != local_id {\n"
    "        bail!(\"direct message addressed to a different recipient\");\n"
    "    }\n"
    "    if peer_id == local_id {\n",
)

# ---------------------------------------------------------------------------
# JNI transport boundary: QUBEE_DMS is always direct and fail-closed.
# The peer hint from Kotlin remains relevant only to legacy/non-DMS traffic.
# ---------------------------------------------------------------------------
path = "src/jni_api.rs"
replace_once(
    path,
    "    inspect_direct_sender, install_peer_bundle, reset_direct_session, DirectPayload,\n"
    "};\n"
    "use crate::ratchet::prekey_store::{build_body, get_or_create_local_bundle, store_peer_bundle};\n",
    "    inspect_direct_sender, install_peer_bundle, reset_direct_session, DirectPayload,\n"
    "};\n"
    "use crate::ratchet::direct_message::{inspect_direct_recipient, is_direct_message_frame};\n"
    "use crate::ratchet::prekey_store::{build_body, get_or_create_local_bundle, store_peer_bundle};\n",
)
old_fn = '''/// Send a P2P message (Publish/Direct)
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeSendP2PMessage(
    mut env: JNIEnv,
    _class: JClass,
    peer_id: JString,
    data: JByteArray,
) -> jboolean {
    catch_unwind_result(|| {
        // Untrusted JNI input: never `.expect()` here. A malformed
        // peer_id or byte array must fail closed (return 0), not panic.
        let peer_id_str: String = match env.get_string(&peer_id) {
            Ok(s) => s.into(),
            Err(_) => return 0,
        };
        let data_vec = match env.convert_byte_array(&data) {
            Ok(d) => d,
            Err(_) => return 0,
        };

        let commander_lock = P2P_COMMANDER.lock().unwrap();

        if let Some(commander) = commander_lock.as_ref() {
            let cmd = P2PCommand::SendMessage {
                peer_id: peer_id_str,
                data: data_vec,
            };

            match commander.try_send(cmd) {
                Ok(_) => 1,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to send P2P command");
                    0
                }
            }
        } else {
            tracing::warn!("P2P Commander not initialized");
            0
        }
    })
}
'''
new_fn = '''/// Send an outbound frame.
///
/// Forward-secret QUBEE_DMS frames are never gossip-published: their v2
/// envelope carries the intended Qubee IdentityId, which is resolved through
/// the authenticated IdentityId -> libp2p PeerId directory and delivered over
/// `/qubee/direct/1`. Missing/invalid routes fail closed. The caller-provided
/// `peer_id` remains a compatibility hint for non-DMS legacy traffic only.
#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeSendP2PMessage(
    mut env: JNIEnv,
    _class: JClass,
    peer_id: JString,
    data: JByteArray,
) -> jboolean {
    catch_unwind_result(|| {
        let data_vec = match env.convert_byte_array(&data) {
            Ok(d) => d,
            Err(_) => return 0,
        };

        // A direct-magic frame must *never* fall through to gossipsub. If it
        // does not parse cleanly, or its authenticated identity has no known
        // transport route, leave it queued for retry instead of broadcasting.
        if is_direct_message_frame(&data_vec) {
            let recipient = match inspect_direct_recipient(&data_vec) {
                Some(id) => id,
                None => {
                    tracing::warn!("malformed QUBEE_DMS frame; refusing gossip fallback");
                    return 0;
                }
            };
            let recipient_hex = hex::encode(recipient.as_ref());
            let route = match resolve_peer_id(&recipient_hex) {
                Some(peer) => peer,
                None => {
                    tracing::debug!(recipient = %recipient_hex, "direct recipient has no authenticated PeerId route yet");
                    return 0;
                }
            };
            if send_direct(route, data_vec) {
                return 1;
            }
            tracing::debug!(recipient = %recipient_hex, "direct frame could not be enqueued; caller will retry same wire");
            return 0;
        }

        // Legacy/non-direct compatibility path. This remains unchanged until
        // the v0.2.0 cutover removes legacy emission.
        let peer_id_str: String = match env.get_string(&peer_id) {
            Ok(s) => s.into(),
            Err(_) => return 0,
        };
        let commander_lock = P2P_COMMANDER.lock().unwrap();
        if let Some(commander) = commander_lock.as_ref() {
            let cmd = P2PCommand::SendMessage {
                peer_id: peer_id_str,
                data: data_vec,
            };
            match commander.try_send(cmd) {
                Ok(_) => 1,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to send P2P command");
                    0
                }
            }
        } else {
            tracing::warn!("P2P Commander not initialized");
            0
        }
    })
}
'''
replace_once(path, old_fn, new_fn)

# ---------------------------------------------------------------------------
# Wire-freeze contract: this is an intentional direct wire version bump.
# ---------------------------------------------------------------------------
path = "tests/wire_stability.rs"
replace_once(
    path,
    "    // `\\x01` is the first PQXDH + Double Ratchet 1:1 wire version. A bump\n"
    "    // here means old devices silently drop new-format direct messages, so\n"
    "    // it must be a deliberate version change with a migration path.\n"
    "    assert_eq!(MAGIC_DIRECT_MESSAGE, b\"QUBEE_DMS\\x01\");\n",
    "    // `\\x02` adds the intended recipient IdentityId to the durable frame,\n"
    "    // allowing Rust to route initial sends and exact-wire retries through\n"
    "    // `/qubee/direct/1` without trusting Kotlin sender/contact fields.\n"
    "    assert_eq!(MAGIC_DIRECT_MESSAGE, b\"QUBEE_DMS\\x02\");\n",
)
replace_once(
    path,
    "        sender_id: IdentityId::from([3u8; 32]),\n        initial: None,\n",
    "        sender_id: IdentityId::from([3u8; 32]),\n"
    "        recipient_id: IdentityId::from([4u8; 32]),\n"
    "        initial: None,\n",
)
replace_once(path, '    assert!(wire.starts_with(b"QUBEE_DMS\\x01"));\n', '    assert!(wire.starts_with(b"QUBEE_DMS\\x02"));\n')

# Keep docs honest about the wire version where it is explicitly named.
doc = Path("docs/double-ratchet-design.md")
if doc.exists():
    t = doc.read_text()
    if r"QUBEE_DMS\x01" in t:
        doc.write_text(t.replace(r"QUBEE_DMS\x01", r"QUBEE_DMS\x02"))

print("direct-routing patch applied")
