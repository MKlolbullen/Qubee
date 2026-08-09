from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, got {count}: {old[:140]!r}")
    p.write_text(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# Verified peer bundle index: direct selectors resolve only against peers whose
# hybrid-signed prekey bundle is already cached by Rust. Any QUBEE_DMS sender
# or recipient necessarily has such a bundle before a session can be created.
# ---------------------------------------------------------------------------
path = "src/ratchet/prekey_store.rs"
replace_once(
    path,
    '''fn peer_key_id(id: &IdentityId) -> String {
    format!("ratchet_peer_prekey_{}", hex::encode(id.as_ref() as &[u8]))
}
''',
    '''const PEER_BUNDLE_KEY_PREFIX: &str = "ratchet_peer_prekey_";

fn peer_key_id(id: &IdentityId) -> String {
    format!("{PEER_BUNDLE_KEY_PREFIX}{}", hex::encode(id.as_ref() as &[u8]))
}

/// Enumerate identities for which Rust has a signature-verified peer prekey
/// bundle. These ids form the candidate set for opaque direct-message route
/// selectors. Prefix-matching entries are keystore-owned state; malformed
/// entries fail closed rather than being silently ignored.
pub fn list_peer_bundle_ids(ks: &SecureKeyStore) -> Result<Vec<IdentityId>> {
    let mut out = Vec::new();
    for key in ks.list_keys() {
        let Some(hex_id) = key.strip_prefix(PEER_BUNDLE_KEY_PREFIX) else {
            continue;
        };
        let raw = hex::decode(hex_id)
            .map_err(|e| anyhow!("malformed peer prekey id in keystore: {e}"))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("malformed peer prekey id length in keystore"))?;
        out.push(IdentityId::from(bytes));
    }
    Ok(out)
}
''',
)
replace_once(
    path,
    '''        let loaded = get_peer_bundle(&ks, &peer.public_key().identity_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.publisher.identity_id, peer.public_key().identity_id);
''',
    '''        let loaded = get_peer_bundle(&ks, &peer.public_key().identity_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.publisher.identity_id, peer.public_key().identity_id);
        let ids = list_peer_bundle_ids(&ks).unwrap();
        assert!(ids.contains(&peer.public_key().identity_id));
''',
)

# ---------------------------------------------------------------------------
# Direct wire: no raw Qubee endpoint identities outside the ratchet ciphertext.
# A fresh nonce makes both selectors unlinkable across frames to observers that
# do not already know the endpoint identity.
# ---------------------------------------------------------------------------
path = "src/ratchet/direct_message.rs"
replace_once(
    path,
    '''/// Magic prefix for a direct-message frame. `\\x01` is the first
/// (PQXDH + Double Ratchet) direct-message wire version, matching the
/// `QUBEE_GHS`/`QUBEE_GMS` family used by the group frames.
pub const MAGIC_DIRECT_MESSAGE: &[u8] = b"QUBEE_DMS\\x02";
''',
    '''/// Magic prefix for the current direct-message frame. `\\x02` adds an
/// opaque per-message routing envelope so route-less bootstrap traffic does
/// not expose either Qubee IdentityId outside the ratchet ciphertext.
pub const MAGIC_DIRECT_MESSAGE: &[u8] = b"QUBEE_DMS\\x02";

const DIRECT_ID_SELECTOR_TAG: &[u8] = b"qubee_direct_identity_selector_v1";
pub const DIRECT_ROUTE_NONCE_LEN: usize = 16;
pub const DIRECT_ID_SELECTOR_LEN: usize = 16;

/// Domain-separated, per-message opaque handle for one Qubee identity.
/// IdentityIds are 256-bit public-key-derived values; the fresh route nonce
/// prevents a stable wire handle while making inversion infeasible to a party
/// that does not already know the identity. Parties that *do* know an identity
/// can test it — the same knowledge already lets them derive its blinded inbox.
pub fn direct_identity_selector(
    identity: &IdentityId,
    route_nonce: &[u8; DIRECT_ROUTE_NONCE_LEN],
) -> [u8; DIRECT_ID_SELECTOR_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(DIRECT_ID_SELECTOR_TAG);
    h.update(route_nonce);
    h.update(identity.as_ref());
    let mut out = [0u8; DIRECT_ID_SELECTOR_LEN];
    out.copy_from_slice(&h.finalize().as_bytes()[..DIRECT_ID_SELECTOR_LEN]);
    out
}
''',
)
replace_once(
    path,
    '''pub struct DirectMessage {
    /// The sender's identity id, so the receiver can find (or, on the
    /// first message, establish) the matching session.
    pub sender_id: IdentityId,
    /// The intended recipient identity. This is routing metadata, not a
    /// new authentication primitive: the same sender/recipient pair is
    /// already committed into the ratchet's conversation associated data.
    /// Receivers reject frames addressed to any other local identity.
    pub recipient_id: IdentityId,
''',
    '''pub struct DirectMessage {
    /// Fresh random nonce for this frame's endpoint selectors.
    pub route_nonce: [u8; DIRECT_ROUTE_NONCE_LEN],
    /// Opaque selector for the sender. The receiver resolves it only against
    /// identities with signature-verified prekey bundles in the Rust keystore.
    pub sender_selector: [u8; DIRECT_ID_SELECTOR_LEN],
    /// Opaque selector for the intended recipient. The local device verifies
    /// this against its own identity before touching ratchet state; the sender
    /// resolves the same selector on crash/retry to recover the destination.
    pub recipient_selector: [u8; DIRECT_ID_SELECTOR_LEN],
''',
)
replace_once(
    path,
    '''    /// Encode as a magic-prefixed byte string for gossip publication.
''',
    '''    /// Encode as a magic-prefixed byte string for transport/storage.
''',
)
replace_once(
    path,
    '''/// Read the intended recipient from a well-formed direct frame without
/// touching ratchet state. Used only for transport routing; authenticity
/// still comes from the pair-bound ratchet AEAD on receive.
pub fn inspect_direct_recipient(bytes: &[u8]) -> Option<IdentityId> {
    DirectMessage::from_wire(bytes).map(|dm| dm.recipient_id)
}
''',
    '''/// Read only the opaque routing tuple from a syntactically valid frame.
/// Identity resolution is intentionally stateful and lives in `direct.rs`,
/// where candidates come from the signature-verified prekey cache.
pub fn inspect_direct_selectors(
    bytes: &[u8],
) -> Option<(
    [u8; DIRECT_ROUTE_NONCE_LEN],
    [u8; DIRECT_ID_SELECTOR_LEN],
    [u8; DIRECT_ID_SELECTOR_LEN],
)> {
    DirectMessage::from_wire(bytes)
        .map(|dm| (dm.route_nonce, dm.sender_selector, dm.recipient_selector))
}
''',
)
replace_once(
    path,
    '''        let dm = DirectMessage {
            sender_id: IdentityId::from([4u8; 32]),
            recipient_id: IdentityId::from([6u8; 32]),
''',
    '''        let sender = IdentityId::from([4u8; 32]);
        let recipient = IdentityId::from([6u8; 32]);
        let route_nonce = [0x41u8; DIRECT_ROUTE_NONCE_LEN];
        let dm = DirectMessage {
            route_nonce,
            sender_selector: direct_identity_selector(&sender, &route_nonce),
            recipient_selector: direct_identity_selector(&recipient, &route_nonce),
''',
)
replace_once(
    path,
    '''        let dm = DirectMessage {
            sender_id: IdentityId::from([5u8; 32]),
            recipient_id: IdentityId::from([7u8; 32]),
''',
    '''        let sender = IdentityId::from([5u8; 32]);
        let recipient = IdentityId::from([7u8; 32]);
        let route_nonce = [0x52u8; DIRECT_ROUTE_NONCE_LEN];
        let dm = DirectMessage {
            route_nonce,
            sender_selector: direct_identity_selector(&sender, &route_nonce),
            recipient_selector: direct_identity_selector(&recipient, &route_nonce),
''',
)
replace_once(
    path,
    '''        assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
        assert_eq!(
            inspect_direct_recipient(&wire),
            Some(IdentityId::from([7u8; 32]))
        );
''',
    '''        assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
        assert_eq!(
            inspect_direct_selectors(&wire),
            Some((route_nonce, dm.sender_selector, dm.recipient_selector))
        );
        assert!(!wire.windows(32).any(|w| w == sender.as_ref()));
        assert!(!wire.windows(32).any(|w| w == recipient.as_ref()));
        let other_nonce = [0x53u8; DIRECT_ROUTE_NONCE_LEN];
        assert_ne!(
            direct_identity_selector(&recipient, &route_nonce),
            direct_identity_selector(&recipient, &other_nonce),
            "selector must rotate with the per-message nonce",
        );
''',
)

# ---------------------------------------------------------------------------
# Direct orchestration: resolve selectors against verified peers, validate the
# local recipient selector before ratchet state, and generate a fresh nonce on
# every encryption. Exact-wire retry preserves the selector+nonce.
# ---------------------------------------------------------------------------
path = "src/ratchet/direct.rs"
replace_once(
    path,
    '''use crate::ratchet::direct_message::DirectMessage;
''',
    '''use crate::ratchet::direct_message::{
    direct_identity_selector, DirectMessage, DIRECT_ID_SELECTOR_LEN, DIRECT_ROUTE_NONCE_LEN,
};
''',
)
replace_once(
    path,
    '''    body_to_public, consume_one_time_prekey, get_or_create_local_bundle, get_peer_bundle,
    store_peer_bundle,
''',
    '''    body_to_public, consume_one_time_prekey, get_or_create_local_bundle, get_peer_bundle,
    list_peer_bundle_ids, store_peer_bundle,
''',
)
replace_once(
    path,
    '''pub fn encrypt_direct(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    plaintext: &[u8],
    now: u64,
) -> Result<Vec<u8>> {
    let mut session = match load_session(ks, &peer_id)? {
''',
    '''pub fn encrypt_direct(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    plaintext: &[u8],
    now: u64,
) -> Result<Vec<u8>> {
    // Generate routing metadata before advancing the ratchet. If secure RNG
    // fails, the send fails without consuming a message-key position.
    let route_nonce = crate::security::secure_rng::random::array::<DIRECT_ROUTE_NONCE_LEN>()?;
    let sender_selector = direct_identity_selector(&local_id, &route_nonce);
    let recipient_selector = direct_identity_selector(&peer_id, &route_nonce);

    let mut session = match load_session(ks, &peer_id)? {
''',
)
replace_once(
    path,
    '''    DirectMessage {
        sender_id: local_id,
        recipient_id: peer_id,
        initial,
''',
    '''    DirectMessage {
        route_nonce,
        sender_selector,
        recipient_selector,
        initial,
''',
)
replace_once(
    path,
    '''pub fn decrypt_direct(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, Vec<u8>)> {
    let dm = DirectMessage::from_wire(wire).ok_or_else(|| anyhow!("not a direct message frame"))?;
    let peer_id = dm.sender_id;
    if dm.recipient_id != local_id {
        bail!("direct message addressed to a different recipient");
    }
    if peer_id == local_id {
''',
    '''pub fn decrypt_direct(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, Vec<u8>)> {
    let dm = DirectMessage::from_wire(wire).ok_or_else(|| anyhow!("not a direct message frame"))?;
    if direct_identity_selector(&local_id, &dm.route_nonce) != dm.recipient_selector {
        bail!("direct message addressed to a different recipient");
    }
    let peer_id = resolve_direct_selector(ks, &dm.route_nonce, &dm.sender_selector)?;
    if peer_id == local_id {
''',
)
replace_once(
    path,
    '''/// Cheap sender extraction for dispatcher routing — parses the frame
/// without touching any session state. `None` if `wire` is not a direct
/// message frame.
pub fn inspect_direct_sender(wire: &[u8]) -> Option<IdentityId> {
    DirectMessage::from_wire(wire).map(|dm| dm.sender_id)
}
''',
    '''fn resolve_direct_selector(
    ks: &SecureKeyStore,
    route_nonce: &[u8; DIRECT_ROUTE_NONCE_LEN],
    selector: &[u8; DIRECT_ID_SELECTOR_LEN],
) -> Result<IdentityId> {
    let mut matched: Option<IdentityId> = None;
    for candidate in list_peer_bundle_ids(ks)? {
        if direct_identity_selector(&candidate, route_nonce) == *selector {
            if matched.replace(candidate).is_some() {
                bail!("ambiguous direct identity selector collision");
            }
        }
    }
    matched.ok_or_else(|| anyhow!("direct identity selector does not match a verified peer"))
}

/// Resolve the opaque sender selector against Rust's signature-verified peer
/// bundle cache. Used by JNI only as a diagnostic/dispatcher helper; actual
/// authentication still requires the ratchet decrypt to succeed.
pub fn inspect_direct_sender(ks: &SecureKeyStore, wire: &[u8]) -> Option<IdentityId> {
    let dm = DirectMessage::from_wire(wire)?;
    resolve_direct_selector(ks, &dm.route_nonce, &dm.sender_selector).ok()
}

/// Resolve the durable destination for initial send / exact-wire retry. This
/// is the routing authority: Kotlin fields are never consulted for QUBEE_DMS.
pub fn inspect_direct_recipient(ks: &SecureKeyStore, wire: &[u8]) -> Option<IdentityId> {
    let dm = DirectMessage::from_wire(wire)?;
    resolve_direct_selector(ks, &dm.route_nonce, &dm.recipient_selector).ok()
}
''',
)
replace_once(
    path,
    '''    #[test]
    fn initial_rides_every_frame_until_first_reply() {''',
    '''    #[test]
    fn opaque_direct_selectors_resolve_only_verified_peers() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        let wire = encrypt_direct_text(&mut a.ks, aid, bid, "selector", 1).unwrap();
        assert_eq!(inspect_direct_recipient(&a.ks, &wire), Some(bid));
        assert_eq!(inspect_direct_sender(&b.ks, &wire), Some(aid));

        let mut dm = DirectMessage::from_wire(&wire).unwrap();
        dm.sender_selector[0] ^= 0x80;
        let tampered = dm.to_wire().unwrap();
        assert_eq!(inspect_direct_sender(&b.ks, &tampered), None);
        assert!(decrypt_direct_payload(&mut b.ks, bid, &tampered, 1).is_err());
    }

    #[test]
    fn initial_rides_every_frame_until_first_reply() {''',
)

# ---------------------------------------------------------------------------
# JNI: selector resolution now needs the encrypted keystore candidate set.
# ---------------------------------------------------------------------------
path = "src/jni_api.rs"
replace_once(
    path,
    '''    decrypt_direct_payload_with_route, encrypt_direct_distribution_with_route,
    encrypt_direct_text_with_route, inspect_direct_sender, install_peer_bundle,
    reset_direct_session, DirectPayload,
};
use crate::ratchet::direct_message::{inspect_direct_recipient, is_direct_message_frame};
''',
    '''    decrypt_direct_payload_with_route, encrypt_direct_distribution_with_route,
    encrypt_direct_text_with_route, inspect_direct_recipient, inspect_direct_sender,
    install_peer_bundle, reset_direct_session, DirectPayload,
};
use crate::ratchet::direct_message::is_direct_message_frame;
''',
)
replace_once(
    path,
    '''            let recipient = match inspect_direct_recipient(&data_vec) {
                Some(id) => id,
                None => {
                    tracing::warn!("malformed QUBEE_DMS frame; refusing gossip fallback");
                    return 0;
                }
            };
''',
    '''            let recipient = {
                let mut ks_guard = KEYSTORE.lock().unwrap();
                let ks = match ks_guard.as_mut() {
                    Some(ks) => ks,
                    None => {
                        tracing::warn!("QUBEE_DMS routing attempted before keystore init");
                        return 0;
                    }
                };
                match inspect_direct_recipient(ks, &data_vec) {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            "malformed/unresolvable QUBEE_DMS route; refusing global gossip fallback"
                        );
                        return 0;
                    }
                }
            };
''',
)
replace_once(
    path,
    '''/// Forward-secret QUBEE_DMS frames are never published on the global gossip
/// topic: their v2 envelope carries the intended Qubee IdentityId, resolved through
/// the authenticated IdentityId -> libp2p PeerId directory and delivered over
''',
    '''/// Forward-secret QUBEE_DMS frames are never published on the global gossip
/// topic: their v2 envelope carries only per-message opaque endpoint selectors.
/// Rust resolves the recipient selector against its signature-verified peer cache,
/// then uses the authenticated IdentityId -> libp2p PeerId directory and delivers over
''',
)
replace_once(
    path,
    '''/// Cheap dispatcher probe: if `wire` is a `QUBEE_DMS\\x01` frame, return
/// the claimed sender's identity id as a 64-char hex string without
/// touching session state; `null` otherwise. The claim is only
/// authenticated once `nativeDecryptDirectMessage` succeeds.
''',
    '''/// Diagnostic sender probe for a syntactically valid `QUBEE_DMS\\x02` frame.
/// The outer wire contains only an opaque selector, so resolution is limited
/// to identities with signature-verified prekey bundles in the Rust keystore.
/// The resolved identity is still only authenticated once decrypt succeeds.
''',
)
replace_once(
    path,
    '''            let sender = inspect_direct_sender(&wire_bytes)
                .ok_or_else(|| anyhow::anyhow!("not a direct message frame"))?;
''',
    '''            let sender = {
                let mut ks_guard = KEYSTORE.lock().unwrap();
                let ks = ks_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;
                inspect_direct_sender(ks, &wire_bytes)
                    .ok_or_else(|| anyhow::anyhow!("unresolvable direct sender selector"))?
            };
''',
)

# ---------------------------------------------------------------------------
# Android fail-closed dispatcher: identify direct frames by magic, not by a
# pre-decrypt sender-resolution result. Unknown selectors must never reach the
# legacy path.
# ---------------------------------------------------------------------------
path = "app/src/main/java/com/qubee/messenger/service/MessageService.kt"
replace_once(
    path,
    '''        /// "QUBEE_GMS\\x03" — the Stage 4 sender-keys group frame magic.
''',
    '''        /// "QUBEE_DMS\\x02" — current PQXDH + Double Ratchet frame magic.
        private val DIRECT_V2_MAGIC: ByteArray =
            "QUBEE_DMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x02)
        /// "QUBEE_GMS\\x03" — the Stage 4 sender-keys group frame magic.
''',
)
replace_once(
    path,
    '''        // 1:1 PQXDH + Double Ratchet frame (QUBEE_DMS).
        if (qubeeManager.inspectDirectMessageSender(data) != null) {
''',
    '''        // 1:1 PQXDH + Double Ratchet frame (QUBEE_DMS). Detect by magic,
        // not by sender resolution: an unknown/tampered selector is still a
        // direct frame and must fail closed here rather than reach legacy decrypt.
        if (isDirectV2Frame(data)) {
''',
)
replace_once(
    path,
    '''    private fun isGroupV3Frame(data: ByteArray): Boolean {
''',
    '''    private fun isDirectV2Frame(data: ByteArray): Boolean {
        if (data.size < DIRECT_V2_MAGIC.size) return false
        for (i in DIRECT_V2_MAGIC.indices) {
            if (data[i] != DIRECT_V2_MAGIC[i]) return false
        }
        return true
    }

    private fun isGroupV3Frame(data: ByteArray): Boolean {
''',
)

# ---------------------------------------------------------------------------
# Parser/fuzz targets now exercise the pure opaque-selector parser helper.
# ---------------------------------------------------------------------------
path = "tests/wire_parser_robustness.rs"
replace_once(
    path,
    '''use qubee_crypto::ratchet::direct::inspect_direct_sender;
use qubee_crypto::ratchet::direct_message::DirectMessage;
''',
    '''use qubee_crypto::ratchet::direct_message::{
    direct_identity_selector, inspect_direct_selectors, DirectMessage,
};
''',
)
replace_once(
    path,
    '''    DirectMessage {
        sender_id: IdentityId::from([3u8; 32]),
        recipient_id: IdentityId::from([4u8; 32]),
''',
    '''    let sender = IdentityId::from([3u8; 32]);
    let recipient = IdentityId::from([4u8; 32]);
    let route_nonce = [5u8; 16];
    DirectMessage {
        route_nonce,
        sender_selector: direct_identity_selector(&sender, &route_nonce),
        recipient_selector: direct_identity_selector(&recipient, &route_nonce),
''',
)
replace_once(path, '        let _ = inspect_direct_sender(&bytes);\n', '        let _ = inspect_direct_selectors(&bytes);\n')
replace_once(path, '        let _ = inspect_direct_sender(prefix);\n', '        let _ = inspect_direct_selectors(prefix);\n')
replace_once(path, '        let _ = inspect_direct_sender(&mutated);\n', '        let _ = inspect_direct_selectors(&mutated);\n')

path = "fuzz/fuzz_targets/parse_direct_message.rs"
replace_once(
    path,
    '''//! Fuzz the 1:1 `QUBEE_DMS` decoder and the sender-inspection helper.
use libfuzzer_sys::fuzz_target;
use qubee_crypto::ratchet::direct::inspect_direct_sender;
use qubee_crypto::ratchet::direct_message::DirectMessage;
''',
    '''//! Fuzz the 1:1 `QUBEE_DMS` decoder and opaque-routing parser.
use libfuzzer_sys::fuzz_target;
use qubee_crypto::ratchet::direct_message::{inspect_direct_selectors, DirectMessage};
''',
)
replace_once(path, '    let _ = inspect_direct_sender(data);\n', '    let _ = inspect_direct_selectors(data);\n')

# ---------------------------------------------------------------------------
# Wire pins: fixed nonce + deterministic selectors. The raw endpoint ids must
# not appear in the serialized frame.
# ---------------------------------------------------------------------------
path = "tests/wire_stability.rs"
replace_once(
    path,
    '''    // `\\x02` adds the intended recipient IdentityId to the durable frame,
    // allowing Rust to route initial sends and exact-wire retries through
    // `/qubee/direct/1` without trusting Kotlin sender/contact fields.
''',
    '''    // `\\x02` adds the opaque endpoint-selector routing envelope. Rust can
    // recover initial-send/retry destinations from verified peer state without
    // exposing either raw Qubee IdentityId on bootstrap gossip.
''',
)
replace_once(
    path,
    '''    use qubee_crypto::ratchet::direct_message::DirectMessage;
    use qubee_crypto::ratchet::double_ratchet::MessageHeader;
    let dm = DirectMessage {
        sender_id: IdentityId::from([3u8; 32]),
        recipient_id: IdentityId::from([4u8; 32]),
''',
    '''    use qubee_crypto::ratchet::direct_message::{direct_identity_selector, DirectMessage};
    use qubee_crypto::ratchet::double_ratchet::MessageHeader;
    let sender = IdentityId::from([3u8; 32]);
    let recipient = IdentityId::from([4u8; 32]);
    let route_nonce = [5u8; 16];
    let dm = DirectMessage {
        route_nonce,
        sender_selector: direct_identity_selector(&sender, &route_nonce),
        recipient_selector: direct_identity_selector(&recipient, &route_nonce),
''',
)
replace_once(
    path,
    '''    assert!(wire.starts_with(b"QUBEE_DMS\\x02"));
    assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
''',
    '''    assert!(wire.starts_with(b"QUBEE_DMS\\x02"));
    assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
    assert!(!wire.windows(32).any(|w| w == sender.as_ref()));
    assert!(!wire.windows(32).any(|w| w == recipient.as_ref()));
''',
)

# ---------------------------------------------------------------------------
# Transient inbox queue: when multiple exact-wire sends to one unknown route
# are pending, unsubscribe only after the LAST item for that topic is gone.
# ---------------------------------------------------------------------------
path = "src/network/p2p_node.rs"
replace_once(
    path,
    '''        let pending = std::mem::take(&mut self.pending_direct_inbox_publishes);
        let mut keep = Vec::with_capacity(pending.len());

        for mut item in pending {
''',
    '''        let pending = std::mem::take(&mut self.pending_direct_inbox_publishes);
        let mut keep = Vec::with_capacity(pending.len());
        let mut cleanup_topics: HashSet<String> = HashSet::new();

        for mut item in pending {
''',
)
replace_once(
    path,
    '''                Ok(_) => {
                    if !self.live_direct_inbox_topics.contains(&item.topic) {
                        self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                    }
                }
''',
    '''                Ok(_) => {
                    cleanup_topics.insert(item.topic);
                }
''',
)
replace_once(
    path,
    '''                        if !self.live_direct_inbox_topics.contains(&item.topic) {
                            self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                        }
''',
    '''                        cleanup_topics.insert(item.topic);
''',
)
replace_once(
    path,
    '''        self.pending_direct_inbox_publishes = keep;
    }
''',
    '''        let still_pending_topics: HashSet<&str> =
            keep.iter().map(|item| item.topic.as_str()).collect();
        for topic_name in cleanup_topics {
            if self.live_direct_inbox_topics.contains(&topic_name)
                || still_pending_topics.contains(topic_name.as_str())
            {
                continue;
            }
            let topic = gossipsub::IdentTopic::new(topic_name);
            self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
        }

        self.pending_direct_inbox_publishes = keep;
    }
''',
)

# Strengthen the network test: two rapid same-inbox sends from Alice must both
# arrive before Alice's temporary subscription is dropped.
path = "tests/p2p_direct_inbox_e2e.rs"
replace_once(
    path,
    '''    let first = b"opaque-qdm-bootstrap-from-alice".to_vec();
    send_cmd(
        &alice,
        P2PCommand::PublishDirectInbox {
            recipient_id_hex: bob_identity.clone(),
            data: first.clone(),
        },
        "alice",
    )
    .await;

    let event = next_matching(&mut bob, Duration::from_secs(5), |event| {
''',
    '''    let first = b"opaque-qdm-bootstrap-from-alice-1".to_vec();
    let first_b = b"opaque-qdm-bootstrap-from-alice-2".to_vec();
    for payload in [&first, &first_b] {
        send_cmd(
            &alice,
            P2PCommand::PublishDirectInbox {
                recipient_id_hex: bob_identity.clone(),
                data: payload.clone(),
            },
            "alice",
        )
        .await;
    }

    let event = next_matching(&mut bob, Duration::from_secs(5), |event| {
''',
)
replace_once(
    path,
    '''    assert_payload_not_received(&mut carol, &first, Duration::from_millis(700)).await;

    // Alice's temporary publish subscription should now be gone. Let Carol
''',
    '''    let second_alice = next_matching(&mut bob, Duration::from_secs(5), |event| {
        matches!(
            event,
            NodeEvent::MessageReceived { topic, data, .. }
                if topic == &expected_topic && data == &first_b
        )
    })
    .await;
    let NodeEvent::MessageReceived { sender, .. } = second_alice else {
        unreachable!("predicate guarantees MessageReceived")
    };
    assert!(sender.is_empty());

    assert_payload_not_received(&mut carol, &first, Duration::from_millis(700)).await;
    assert_payload_not_received(&mut carol, &first_b, Duration::from_millis(250)).await;

    // Alice's temporary publish subscription should now be gone. Let Carol
''',
)

# ---------------------------------------------------------------------------
# Architecture doc: bootstrap gossip has no clear Qubee endpoint ids.
# ---------------------------------------------------------------------------
path = "docs/double-ratchet-design.md"
p = Path(path)
text = p.read_text()
old = '''`QUBEE_DMS\\x02` is recipient-bound in the durable outer frame. When Rust already
knows the recipient's authenticated libp2p `PeerId`, delivery uses
`/qubee/direct/1`. If that route is not known yet, the exact same ratchet frame is
published only to the recipient's rotating blinded direct-inbox topic — never to
`qubee-global`. The recipient follows that inbox persistently; publishers subscribe
only transiently for mesh formation + send, then drop it so prior senders cannot
passively observe later inbox traffic. The sender's current `PeerId` is carried inside
the ratchet-encrypted payload; after a successful decrypt the receiver binds that
route to the channel-authenticated Qubee identity and subsequent replies can upgrade
to the direct request/response transport.
'''
new = '''`QUBEE_DMS\\x02` is endpoint-bound without placing either raw Qubee IdentityId in
the outer frame. A fresh 16-byte route nonce derives independent 16-byte sender and
recipient selectors; Rust resolves selectors only against its signature-verified peer
prekey cache, and the local recipient validates its own selector before ratchet state
is touched. When Rust already knows the recipient's authenticated libp2p `PeerId`,
delivery uses `/qubee/direct/1`. If that route is not known yet, the exact same ratchet
frame is published only to the recipient's rotating blinded direct-inbox topic — never
to `qubee-global`. The recipient follows that inbox persistently; publishers subscribe
only transiently for mesh formation + send, then drop it so prior senders cannot
passively observe later inbox traffic. The sender's current `PeerId` is carried inside
the ratchet-encrypted payload; after a successful decrypt the receiver binds that
route to the channel-authenticated Qubee identity and subsequent replies can upgrade
to the direct request/response transport.
'''
if old not in text:
    raise SystemExit("docs route-bootstrap paragraph did not match expected current text")
p.write_text(text.replace(old, new, 1))

print("opaque direct selector patch applied")
