from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# Rust: stable direct wire id + deniable ACK payload
# ---------------------------------------------------------------------------
replace_once(
    "src/ratchet/direct_message.rs",
    'pub const DIRECT_ID_SELECTOR_LEN: usize = 16;\n',
    'pub const DIRECT_ID_SELECTOR_LEN: usize = 16;\n'
    'pub const DIRECT_MESSAGE_ID_LEN: usize = 16;\n'
    'const DIRECT_MESSAGE_ID_TAG: &[u8] = b"qubee_direct_message_id_v1";\n',
)

replace_once(
    "src/ratchet/direct_message.rs",
    '/// True if `bytes` carries the direct-message magic — a cheap prefix\n',
    '''/// Deterministic id for an exact direct wire frame. The id is derived only\n/// after the frame parses as the current QUBEE_DMS format, so arbitrary bytes\n/// cannot manufacture delivery-receipt ids. Retries reuse the exact durable\n/// wire bytes and therefore keep the same id without re-encrypting.\npub fn extract_direct_message_id(bytes: &[u8]) -> Option<[u8; DIRECT_MESSAGE_ID_LEN]> {\n    DirectMessage::from_wire(bytes)?;\n    let mut h = blake3::Hasher::new();\n    h.update(DIRECT_MESSAGE_ID_TAG);\n    h.update(bytes);\n    let mut out = [0u8; DIRECT_MESSAGE_ID_LEN];\n    out.copy_from_slice(&h.finalize().as_bytes()[..DIRECT_MESSAGE_ID_LEN]);\n    Some(out)\n}\n\n/// True if `bytes` carries the direct-message magic — a cheap prefix\n''',
)

replace_once(
    "src/ratchet/direct_message.rs",
    '    #[test]\n    fn rejects_foreign_and_truncated_frames() {\n',
    '''    #[test]\n    fn direct_message_id_is_stable_and_wire_bound() {\n        let sender = IdentityId::from([0x31u8; 32]);\n        let recipient = IdentityId::from([0x42u8; 32]);\n        let route_nonce = [0x53u8; DIRECT_ROUTE_NONCE_LEN];\n        let dm = DirectMessage {\n            route_nonce,\n            sender_selector: direct_identity_selector(&sender, &route_nonce),\n            recipient_selector: direct_identity_selector(&recipient, &route_nonce),\n            initial: None,\n            header: MessageHeader {\n                dh: [0x64u8; 32],\n                pn: 2,\n                n: 9,\n            },\n            ciphertext: vec![0x75; 48],\n        };\n        let wire = dm.to_wire().unwrap();\n        let id = extract_direct_message_id(&wire).unwrap();\n        assert_eq!(id, extract_direct_message_id(&wire).unwrap());\n\n        let mut changed = dm;\n        changed.ciphertext[0] ^= 0x80;\n        let changed_wire = changed.to_wire().unwrap();\n        assert_ne!(id, extract_direct_message_id(&changed_wire).unwrap());\n        assert!(extract_direct_message_id(b"not-a-direct-frame").is_none());\n    }\n\n    #[test]\n    fn rejects_foreign_and_truncated_frames() {\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    '    direct_identity_selector, DirectMessage, DIRECT_ID_SELECTOR_LEN, DIRECT_ROUTE_NONCE_LEN,\n',
    '    direct_identity_selector, DirectMessage, DIRECT_ID_SELECTOR_LEN, DIRECT_MESSAGE_ID_LEN,\n'
    '    DIRECT_ROUTE_NONCE_LEN,\n',
)

replace_once(
    "src/ratchet/direct.rs",
    '''    for candidate in list_peer_bundle_ids(ks)? {\n        if direct_identity_selector(&candidate, route_nonce) == *selector {\n            if matched.replace(candidate).is_some() {\n                bail!("ambiguous direct identity selector collision");\n            }\n        }\n    }\n''',
    '''    for candidate in list_peer_bundle_ids(ks)? {\n        if direct_identity_selector(&candidate, route_nonce) == *selector\n            && matched.replace(candidate).is_some()\n        {\n            bail!("ambiguous direct identity selector collision");\n        }\n    }\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    'pub const PAYLOAD_TAG_SENDER_KEY_DIST: u8 = 0x02;\n',
    'pub const PAYLOAD_TAG_SENDER_KEY_DIST: u8 = 0x02;\n'
    '/// Deniable delivery receipt for an exact QUBEE_DMS wire id.\n'
    'pub const PAYLOAD_TAG_ACK: u8 = 0x03;\n',
)

replace_once(
    "src/ratchet/direct.rs",
    '''    SenderKeyDistribution(SenderKeyDistribution),\n}\n''',
    '''    SenderKeyDistribution(SenderKeyDistribution),\n    /// Delivery receipt authenticated only by the 1:1 ratchet session. It is\n    /// deliberately not identity-signed, preserving transcript deniability.\n    Ack([u8; DIRECT_MESSAGE_ID_LEN]),\n}\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    '''        DirectPayload::SenderKeyDistribution(dist) => {\n            let body = dist.to_bytes()?;\n            let mut out = Vec::with_capacity(1 + body.len());\n            out.push(PAYLOAD_TAG_SENDER_KEY_DIST);\n            out.extend_from_slice(&body);\n            Ok(out)\n        }\n''',
    '''        DirectPayload::SenderKeyDistribution(dist) => {\n            let body = dist.to_bytes()?;\n            let mut out = Vec::with_capacity(1 + body.len());\n            out.push(PAYLOAD_TAG_SENDER_KEY_DIST);\n            out.extend_from_slice(&body);\n            Ok(out)\n        }\n        DirectPayload::Ack(message_id) => {\n            let mut out = Vec::with_capacity(1 + DIRECT_MESSAGE_ID_LEN);\n            out.push(PAYLOAD_TAG_ACK);\n            out.extend_from_slice(message_id);\n            Ok(out)\n        }\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    '''        PAYLOAD_TAG_SENDER_KEY_DIST => Ok(DirectPayload::SenderKeyDistribution(\n            SenderKeyDistribution::from_bytes(body)?,\n        )),\n        other => bail!("unknown direct payload tag {other:#04x}"),\n''',
    '''        PAYLOAD_TAG_SENDER_KEY_DIST => Ok(DirectPayload::SenderKeyDistribution(\n            SenderKeyDistribution::from_bytes(body)?,\n        )),\n        PAYLOAD_TAG_ACK => {\n            let message_id: [u8; DIRECT_MESSAGE_ID_LEN] = body\n                .try_into()\n                .map_err(|_| anyhow!("direct ack message id must be {DIRECT_MESSAGE_ID_LEN} bytes"))?;\n            Ok(DirectPayload::Ack(message_id))\n        }\n        other => bail!("unknown direct payload tag {other:#04x}"),\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    '''pub fn encrypt_direct_distribution_with_route(\n    ks: &mut SecureKeyStore,\n    local_id: IdentityId,\n    peer_id: IdentityId,\n    dist: &SenderKeyDistribution,\n    sender_peer_id: Option<&str>,\n    now: u64,\n) -> Result<Vec<u8>> {\n    let payload = encode_payload_with_route(\n        &DirectPayload::SenderKeyDistribution(dist.clone()),\n        sender_peer_id,\n    )?;\n    encrypt_direct(ks, local_id, peer_id, &payload, now)\n}\n\n/// Decrypt an inbound frame and decode its tagged payload. Returns the\n''',
    '''pub fn encrypt_direct_distribution_with_route(\n    ks: &mut SecureKeyStore,\n    local_id: IdentityId,\n    peer_id: IdentityId,\n    dist: &SenderKeyDistribution,\n    sender_peer_id: Option<&str>,\n    now: u64,\n) -> Result<Vec<u8>> {\n    let payload = encode_payload_with_route(\n        &DirectPayload::SenderKeyDistribution(dist.clone()),\n        sender_peer_id,\n    )?;\n    encrypt_direct(ks, local_id, peer_id, &payload, now)\n}\n\n/// Encrypt a deniable delivery receipt over the same ratchet session. The\n/// receipt authenticates possession of the session state but carries no\n/// long-term identity signature.\npub fn encrypt_direct_ack(\n    ks: &mut SecureKeyStore,\n    local_id: IdentityId,\n    peer_id: IdentityId,\n    message_id: [u8; DIRECT_MESSAGE_ID_LEN],\n    now: u64,\n) -> Result<Vec<u8>> {\n    encrypt_direct_ack_with_route(ks, local_id, peer_id, message_id, None, now)\n}\n\npub fn encrypt_direct_ack_with_route(\n    ks: &mut SecureKeyStore,\n    local_id: IdentityId,\n    peer_id: IdentityId,\n    message_id: [u8; DIRECT_MESSAGE_ID_LEN],\n    sender_peer_id: Option<&str>,\n    now: u64,\n) -> Result<Vec<u8>> {\n    let payload = encode_payload_with_route(&DirectPayload::Ack(message_id), sender_peer_id)?;\n    encrypt_direct(ks, local_id, peer_id, &payload, now)\n}\n\n/// Decrypt an inbound frame and decode its tagged payload. Returns the\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    '''    fn payload_tags_are_pinned() {\n        assert_eq!(PAYLOAD_TAG_TEXT, 0x01);\n        assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);\n    }\n''',
    '''    fn payload_tags_are_pinned() {\n        assert_eq!(PAYLOAD_TAG_TEXT, 0x01);\n        assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);\n        assert_eq!(PAYLOAD_TAG_ACK, 0x03);\n    }\n''',
)

replace_once(
    "src/ratchet/direct.rs",
    '''    #[test]\n    fn padding_collapses_distinct_message_lengths_to_one_wire_size() {\n''',
    '''    #[test]\n    fn deniable_delivery_ack_round_trips_over_ratchet() {\n        use crate::ratchet::direct_message::extract_direct_message_id;\n\n        let (mut a, mut b) = paired();\n        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());\n\n        let text_wire = encrypt_direct_text(&mut a.ks, aid, bid, "please ack", 1).unwrap();\n        let message_id = extract_direct_message_id(&text_wire).unwrap();\n        let (sender, payload) =\n            decrypt_direct_payload(&mut b.ks, bid, &text_wire, 1).unwrap();\n        assert_eq!(sender, aid);\n        assert_eq!(payload, DirectPayload::Text("please ack".to_string()));\n\n        let ack_wire = encrypt_direct_ack(&mut b.ks, bid, aid, message_id, 2).unwrap();\n        let (sender, payload) =\n            decrypt_direct_payload(&mut a.ks, aid, &ack_wire, 2).unwrap();\n        assert_eq!(sender, bid);\n        assert_eq!(payload, DirectPayload::Ack(message_id));\n        assert_ne!(\n            extract_direct_message_id(&ack_wire).unwrap(),\n            message_id,\n            "the receipt is its own ratchet frame, not an echo of the message",\n        );\n    }\n\n    #[test]\n    fn padding_collapses_distinct_message_lengths_to_one_wire_size() {\n''',
)

# ---------------------------------------------------------------------------
# JNI: direct id extractor + ACK constructor/decode kind
# ---------------------------------------------------------------------------
replace_once(
    "src/jni_api.rs",
    '''use crate::ratchet::direct::{\n    decrypt_direct_payload_with_route, encrypt_direct_distribution_with_route,\n    encrypt_direct_text_with_route, inspect_direct_recipient, inspect_direct_sender,\n    install_peer_bundle, reset_direct_session, DirectPayload,\n};\nuse crate::ratchet::direct_message::is_direct_message_frame;\n''',
    '''use crate::ratchet::direct::{\n    decrypt_direct_payload_with_route, encrypt_direct_ack_with_route,\n    encrypt_direct_distribution_with_route, encrypt_direct_text_with_route, inspect_direct_recipient,\n    inspect_direct_sender, install_peer_bundle, reset_direct_session, DirectPayload,\n};\nuse crate::ratchet::direct_message::{extract_direct_message_id, is_direct_message_frame};\n''',
)

replace_once(
    "src/jni_api.rs",
    '''/// Encrypt this device's sender key for `group_id_hex` to one peer over\n''',
    '''/// Extract the deterministic 16-byte id of an exact QUBEE_DMS frame as\n/// 32-char lowercase hex. Returns null for malformed/non-direct bytes.\n#[no_mangle]\npub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeExtractDirectMessageId(\n    env: JNIEnv,\n    _class: JClass,\n    wire: JByteArray,\n) -> jstring {\n    jni_catch_jstring(|| {\n        let result: anyhow::Result<jstring> = (|| {\n            let bytes = env\n                .convert_byte_array(&wire)\n                .map_err(|e| anyhow::anyhow!("invalid direct wire: {e}"))?;\n            let id = match extract_direct_message_id(&bytes) {\n                Some(id) => id,\n                None => return Ok(std::ptr::null_mut()),\n            };\n            let java_str = env\n                .new_string(hex::encode(id))\n                .map_err(|e| anyhow::anyhow!("new_string: {e}"))?;\n            Ok(java_str.into_raw())\n        })();\n        result.unwrap_or(std::ptr::null_mut())\n    })\n}\n\n/// Build a deniable direct delivery receipt. `message_id_hex` names the exact\n/// accepted QUBEE_DMS wire frame; authentication comes from the Double Ratchet\n/// rather than a long-term identity signature.\n#[no_mangle]\npub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateDirectMessageAck(\n    mut env: JNIEnv,\n    _class: JClass,\n    peer_id_hex: JString,\n    message_id_hex: JString,\n) -> jbyteArray {\n    jni_catch_jbytearray(|| {\n        let result: anyhow::Result<jbyteArray> = (|| {\n            let peer_hex: String = env\n                .get_string(&peer_id_hex)\n                .map_err(|e| anyhow::anyhow!("invalid peer_id_hex: {e}"))?\n                .into();\n            let peer_id = IdentityId::from(parse_hex32(Some(&peer_hex))?);\n            let message_hex: String = env\n                .get_string(&message_id_hex)\n                .map_err(|e| anyhow::anyhow!("invalid message_id_hex: {e}"))?\n                .into();\n            let decoded = hex::decode(message_hex.trim())\n                .map_err(|e| anyhow::anyhow!("bad direct message id hex: {e}"))?;\n            let message_id: [u8; 16] = decoded\n                .as_slice()\n                .try_into()\n                .map_err(|_| anyhow::anyhow!("direct message id must be 16 bytes"))?;\n            let identity =\n                active_identity()?.ok_or_else(|| anyhow::anyhow!("no active identity"))?;\n            let local_id = identity.identity_id();\n            let mut ks_guard = KEYSTORE.lock().unwrap();\n            let ks = ks_guard\n                .as_mut()\n                .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;\n            let local_peer_id = LOCAL_PEER_ID.lock().unwrap().clone();\n            let wire = encrypt_direct_ack_with_route(\n                ks,\n                local_id,\n                peer_id,\n                message_id,\n                local_peer_id.as_deref(),\n                now_secs(),\n            )?;\n            let arr = env\n                .byte_array_from_slice(&wire)\n                .map_err(|e| anyhow::anyhow!("byte_array_from_slice: {e}"))?;\n            Ok(arr.into_raw())\n        })();\n        result.unwrap_or(std::ptr::null_mut())\n    })\n}\n\n/// Encrypt this device's sender key for `group_id_hex` to one peer over\n''',
)

replace_once(
    "src/jni_api.rs",
    '''                DirectPayload::SenderKeyDistribution(dist) => {\n                    {\n''',
    '''                DirectPayload::Ack(message_id) => Ok(json!({\n                    "senderId": sender_hex,\n                    "kind": "ack",\n                    "messageId": hex::encode(message_id),\n                })),\n                DirectPayload::SenderKeyDistribution(dist) => {\n                    {\n''',
)

# ---------------------------------------------------------------------------
# Kotlin manager/repository/send+receive orchestration
# ---------------------------------------------------------------------------
replace_once(
    "app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt",
    '''    /**\n     * Decrypt an inbound QUBEE_DMS frame (Ratchet Stage 3d/5),\n''',
    '''    /** Deterministic 16-byte id of an exact QUBEE_DMS frame, as hex. */\n    suspend fun extractDirectMessageId(wire: ByteArray): String? = withContext(Dispatchers.IO) {\n        if (!isInitialized) return@withContext null\n        try {\n            nativeExtractDirectMessageId(wire)\n        } catch (e: UnsatisfiedLinkError) {\n            Timber.e(e, "Rust direct-message-id JNI is not linked")\n            null\n        } catch (e: Exception) {\n            Timber.e(e, "Direct message id extraction failed")\n            null\n        }\n    }\n\n    /**\n     * Build a ratchet-authenticated, deniable delivery receipt for one exact\n     * direct frame. No long-term identity signature is produced.\n     */\n    suspend fun createDirectMessageAck(peerIdHex: String, messageIdHex: String): ByteArray? =\n        withContext(Dispatchers.IO) {\n            if (!isInitialized) return@withContext null\n            try {\n                nativeCreateDirectMessageAck(peerIdHex, messageIdHex)\n            } catch (e: UnsatisfiedLinkError) {\n                Timber.e(e, "Rust direct-ack JNI is not linked")\n                null\n            } catch (e: Exception) {\n                Timber.e(e, "Direct ack creation failed")\n                null\n            }\n        }\n\n    /**\n     * Decrypt an inbound QUBEE_DMS frame (Ratchet Stage 3d/5),\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt",
    '''     * `{"senderId": hex, "kind": "text", "text": str}` for chat, or\n     * `{"senderId": hex, "kind": "senderKeyDistribution", "groupId":\n''',
    '''     * `{"senderId": hex, "kind": "text", "text": str}` for chat,\n     * `{"senderId": hex, "kind": "ack", "messageId": hex}` for a\n     * deniable delivery receipt, or\n     * `{"senderId": hex, "kind": "senderKeyDistribution", "groupId":\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt",
    '''    private external fun nativeEncryptDirectMessage(peerIdHex: String, plaintext: String): ByteArray?\n    private external fun nativeDecryptDirectMessage(wire: ByteArray): String?\n''',
    '''    private external fun nativeEncryptDirectMessage(peerIdHex: String, plaintext: String): ByteArray?\n    private external fun nativeExtractDirectMessageId(wire: ByteArray): String?\n    private external fun nativeCreateDirectMessageAck(peerIdHex: String, messageIdHex: String): ByteArray?\n    private external fun nativeDecryptDirectMessage(wire: ByteArray): String?\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/MessageRepository.kt",
    '''    suspend fun updateMessageStatus(messageId: String, status: MessageStatus) {\n        messageDao.updateMessageStatus(messageId, status)\n    }\n''',
    '''    suspend fun updateMessageStatus(messageId: String, status: MessageStatus) {\n        messageDao.updateMessageStatus(messageId, status)\n    }\n\n    suspend fun getMessageByWireId(wireId: String): Message? =\n        messageDao.getMessageByWireId(wireId)\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/ui/chat/ChatViewModel.kt",
    '''            // Best-effort id extraction, so a delivery ack flips the\n            // row to DELIVERED. Group v3 (QUBEE_GMS\\x03) frames now\n            // carry their own deterministic id; the v2 envelope path\n            // uses the legacy id. 1:1 QUBEE_DMS frames still have no\n            // ack channel and persist without a wireId (retry re-sends\n            // the same frame; replay-guarded receiver-side).\n            val wireId = if (ratchetSender.enabled() && isGroup) {\n                qubeeManager.extractV3MessageId(wire)\n            } else {\n                qubeeManager.extractMessageId(wire)\n            }\n''',
    '''            // Stable wire id lets a cryptographic receipt retire the durable\n            // retry row. Each ratchet format owns its own id derivation; legacy\n            // group envelopes keep the pre-ratchet extractor.\n            val wireId = when {\n                ratchetSender.enabled() && isGroup -> qubeeManager.extractV3MessageId(wire)\n                ratchetSender.enabled() -> qubeeManager.extractDirectMessageId(wire)\n                else -> qubeeManager.extractMessageId(wire)\n            }\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''        if (isDirectV2Frame(data)) {\n            val resultJson = qubeeManager.decryptDirectMessage(data)\n''',
    '''        if (isDirectV2Frame(data)) {\n            val directMessageId = qubeeManager.extractDirectMessageId(data)\n            if (directMessageId == null) {\n                Timber.w("Malformed QUBEE_DMS frame from %s", peerId)\n                return true\n            }\n\n            // Lost-receipt recovery: retries deliberately reuse the exact wire\n            // bytes, while the Double Ratchet correctly rejects decrypting the\n            // same frame twice. Persisting the inbound wireId lets us recognise\n            // an already-accepted frame and issue a fresh encrypted receipt\n            // without weakening ratchet replay protection. This survives a\n            // process death because the evidence is in Room, not a RAM cache.\n            val prior = messageRepository.getMessageByWireId(directMessageId)\n            if (prior != null && !prior.isFromMe) {\n                val senderIdentityHex = qubeeManager.inspectDirectMessageSender(data)\n                if (!senderIdentityHex.isNullOrBlank()) {\n                    sendDirectDeliveryAck(senderIdentityHex, directMessageId)\n                } else {\n                    Timber.w("Cannot re-ack direct replay: sender selector is unresolved")\n                }\n                return true\n            }\n\n            val resultJson = qubeeManager.decryptDirectMessage(data)\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''                            timestamp = System.currentTimeMillis(),\n                            status = MessageStatus.DELIVERED,\n                            isFromMe = false,\n                        ),\n                    )\n                    if (contact != null) {\n''',
    '''                            timestamp = System.currentTimeMillis(),\n                            status = MessageStatus.DELIVERED,\n                            isFromMe = false,\n                            wireId = directMessageId,\n                        ),\n                    )\n                    if (contact != null) {\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''                    if (contact != null) {\n                        contactRepository.updateOnlineStatus(\n                            contact.id,\n                            true,\n                            System.currentTimeMillis(),\n                        )\n                    }\n                }\n                "senderKeyDistribution" -> {\n''',
    '''                    if (contact != null) {\n                        contactRepository.updateOnlineStatus(\n                            contact.id,\n                            true,\n                            System.currentTimeMillis(),\n                        )\n                    }\n                    // Receipt only after the plaintext is durably persisted. If\n                    // this send is lost, the sender retries the same ciphertext\n                    // and the prior-wireId branch above emits a fresh receipt.\n                    sendDirectDeliveryAck(senderIdentityHex, directMessageId)\n                }\n                "ack" -> {\n                    val ackedWireId = result.optString("messageId")\n                    if (ackedWireId.isBlank()) {\n                        Timber.w("Ratchet direct ack from %s has no message id", senderIdentityHex)\n                    } else {\n                        val applied = messageRepository.applyAck(ackedWireId, senderIdentityHex)\n                        if (!applied) {\n                            Timber.d("Ignored direct ack for unknown wireId=%s", ackedWireId)\n                        }\n                    }\n                    // Never ack an ack: that would create an infinite receipt loop.\n                }\n                "senderKeyDistribution" -> {\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''    private fun isDirectV2Frame(data: ByteArray): Boolean {\n''',
    '''    private suspend fun sendDirectDeliveryAck(recipientIdentityHex: String, messageIdHex: String) {\n        val ackWire = qubeeManager.createDirectMessageAck(recipientIdentityHex, messageIdHex)\n        if (ackWire == null) {\n            Timber.w("Could not create direct delivery ack for %s", messageIdHex)\n            return\n        }\n        // Rust owns QUBEE_DMS routing from the frame's opaque recipient\n        // selector. Empty compatibility hint makes that authority explicit.\n        if (!qubeeManager.sendP2PMessage("", ackWire)) {\n            Timber.d("Direct delivery ack enqueue failed for %s; sender retry will solicit another", messageIdHex)\n        }\n    }\n\n    private fun isDirectV2Frame(data: ByteArray): Boolean {\n''',
)

# ---------------------------------------------------------------------------
# Wire pins
# ---------------------------------------------------------------------------
replace_once(
    "tests/wire_stability.rs",
    '''        DIRECT_PAYLOAD_ENVELOPE_VERSION, PAYLOAD_TAG_SENDER_KEY_DIST, PAYLOAD_TAG_TEXT,\n''',
    '''        DIRECT_PAYLOAD_ENVELOPE_VERSION, PAYLOAD_TAG_ACK, PAYLOAD_TAG_SENDER_KEY_DIST,\n        PAYLOAD_TAG_TEXT,\n''',
)
replace_once(
    "tests/wire_stability.rs",
    '''    assert_eq!(PAYLOAD_TAG_TEXT, 0x01);\n    assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);\n}\n''',
    '''    assert_eq!(PAYLOAD_TAG_TEXT, 0x01);\n    assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);\n    assert_eq!(PAYLOAD_TAG_ACK, 0x03);\n}\n''',
)

print("direct ACK patch applied")
