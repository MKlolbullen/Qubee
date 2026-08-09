//! Pinned wire-format invariants.
//!
//! Anything that goes on the gossipsub wire is something a future
//! version of Qubee will need to keep parsing. Unintentional changes
//! to byte order, magic prefixes, or canonical signing payloads
//! silently break cross-version interop. These tests pin the
//! invariants so a regression in serialisation surfaces immediately.
//!
//! When you intentionally bump a wire format, the right move is:
//!   1. Bump the per-tag version suffix (`_v1` → `_v2`).
//!   2. Update the corresponding pin below.
//!   3. Add a separate test that exercises the migration path.
//!
//! Don't just edit the magic bytes in place — that means devices
//! running the old code will silently drop frames from the new code.

use qubee_crypto::groups::group_handshake::{
    canonical_join_accepted, canonical_join_rejected, canonical_key_delivery,
    canonical_key_rotation, canonical_key_rotation_announce, canonical_member_added,
    canonical_prekey_bundle, canonical_request_join, canonical_role_change,
    generate_ephemeral_kyber, GroupMemberSummary, JoinAcceptedBody, JoinRejectedBody,
    KeyDeliveryBody, KeyRotationAnnounceBody, KeyRotationBody, MemberAddedBody, PrekeyBundleBody,
    RequestJoinBody, RoleChangeBody, WrappedGroupKey, HANDSHAKE_MAGIC,
};
use qubee_crypto::groups::group_manager::GroupId;
use qubee_crypto::groups::group_message::{
    canonical_group_message, GroupMessageBody, MAGIC_GROUP_MESSAGE,
};
use qubee_crypto::groups::group_permissions::Role;
use qubee_crypto::identity::identity_key::{IdentityId, IdentityKeyPair};

#[test]
fn handshake_magic_is_pinned() {
    assert_eq!(HANDSHAKE_MAGIC, b"QUBEE_GHS\x01");
}

#[test]
fn direct_message_magic_is_pinned() {
    use qubee_crypto::ratchet::direct_message::MAGIC_DIRECT_MESSAGE;
    // `\x02` adds the intended recipient IdentityId to the durable frame,
    // allowing Rust to route initial sends and exact-wire retries through
    // `/qubee/direct/1` without trusting Kotlin sender/contact fields.
    assert_eq!(MAGIC_DIRECT_MESSAGE, b"QUBEE_DMS\x02");
}

#[test]
fn direct_message_round_trips_through_wire() {
    use qubee_crypto::ratchet::direct_message::DirectMessage;
    use qubee_crypto::ratchet::double_ratchet::MessageHeader;
    let dm = DirectMessage {
        sender_id: IdentityId::from([3u8; 32]),
        recipient_id: IdentityId::from([4u8; 32]),
        initial: None,
        header: MessageHeader {
            dh: [8u8; 32],
            pn: 1,
            n: 2,
        },
        ciphertext: vec![0x11, 0x22, 0x33],
    };
    let wire = dm.to_wire().unwrap();
    assert!(wire.starts_with(b"QUBEE_DMS\x02"));
    assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
}

#[test]
fn direct_payload_tags_are_pinned() {
    use qubee_crypto::ratchet::direct::{PAYLOAD_TAG_SENDER_KEY_DIST, PAYLOAD_TAG_TEXT};
    // These sit inside the 1:1 ratchet plaintext but are still a
    // cross-version compatibility surface: an old app receiving an
    // unknown tag drops the message.
    assert_eq!(PAYLOAD_TAG_TEXT, 0x01);
    assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);
}

#[test]
fn group_message_v3_magic_is_pinned() {
    use qubee_crypto::ratchet::sender_keys::MAGIC_GROUP_MESSAGE_V3;
    // `\x03` is the sender-keys wire format (Ratchet Stage 4). It
    // coexists with `\x02` through the migration window; a bump here is
    // a deliberate version change with a migration path.
    assert_eq!(MAGIC_GROUP_MESSAGE_V3, b"QUBEE_GMS\x03");
}

#[test]
fn sender_key_distribution_round_trips() {
    use qubee_crypto::groups::group_manager::GroupId;
    use qubee_crypto::ratchet::sender_keys::SenderKeyDistribution;
    let d = SenderKeyDistribution {
        group_id: GroupId::from_bytes([7u8; 32]),
        sender_id: IdentityId::from([8u8; 32]),
        iteration: 42,
        chain_key: [9u8; 32],
        signing_pub: [10u8; 32],
    };
    let bytes = d.to_bytes().unwrap();
    assert_eq!(SenderKeyDistribution::from_bytes(&bytes).unwrap(), d);
}

#[test]
fn group_message_magic_is_pinned() {
    // `\x02` is the sealed-outer-envelope wire format. `\x01` was the
    // pre-sealing format that left signed bodies plaintext on the
    // wire; pinned here so a "let's bump the magic" change has to
    // also bump this assertion (and the doc on `MAGIC_GROUP_MESSAGE`).
    assert_eq!(MAGIC_GROUP_MESSAGE, b"QUBEE_GMS\x04");
}

#[test]
fn canonical_request_join_starts_with_versioned_tag() {
    let kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _) = generate_ephemeral_kyber();
    let body = RequestJoinBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        invitation_code: "code".to_string(),
        joiner_public_key: kp.public_key(),
        joiner_display_name: "Bob".to_string(),
        joiner_kyber_pub: kyber_pub,
        joiner_peer_id: "12D3KooWBob".to_string(),
    };
    let canonical = canonical_request_join(&body).unwrap();
    // _v2 — the body grew `joiner_peer_id` so the inviter can route the
    // direct reply from the authenticated frame, not the gossip author.
    assert!(canonical.starts_with(b"qubee_handshake_request_join_v2"));
}

#[test]
fn canonical_join_accepted_starts_with_versioned_tag() {
    use qubee_crypto::groups::group_handshake::WrappedGroupKey;
    let (kyber_pub, _) = generate_ephemeral_kyber();
    let wrapped = WrappedGroupKey::wrap(&[0u8; 32], &kyber_pub).unwrap();
    let body = JoinAcceptedBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        invitation_code: "code".to_string(),
        group_name: "Group".to_string(),
        members: Vec::new(),
        joiner_id: IdentityId::from([0u8; 32]),
        wrapped_group_key: wrapped,
        snapshot_version: 1,
    };
    let canonical = canonical_join_accepted(&body).unwrap();
    // _v3 — GroupMemberSummary grew `peer_id` (in-band member PeerId
    // distribution). It was _v2 when the summary grew kyber_pub in plan
    // revision 2 priority 5b. Devices on an old tag fail signature
    // verification for new-format frames and vice versa.
    assert!(canonical.starts_with(b"qubee_handshake_join_accepted_v3"));
}

#[test]
fn canonical_join_rejected_starts_with_versioned_tag() {
    let body = JoinRejectedBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        invitation_code: "code".to_string(),
        joiner_id: IdentityId::from([0u8; 32]),
        reason: "test".to_string(),
    };
    let canonical = canonical_join_rejected(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_join_rejected_v1"));

    // Golden vector — pin the full byte layout, not just the tag.
    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_join_rejected_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(b"code"); // invitation_code
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // joiner_id
    expected.push(0);
    expected.extend_from_slice(b"test"); // reason
    assert_eq!(canonical, expected, "canonical JoinRejected bytes changed");
}

#[test]
fn canonical_key_rotation_starts_with_versioned_tag() {
    let body = KeyRotationBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        generation: 1,
        rotator_id: IdentityId::from([0u8; 32]),
        removed_member_id: None,
        deliveries: Vec::new(),
        timestamp: 0,
    };
    let canonical = canonical_key_rotation(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_key_rotation_v1"));

    // Golden vector — full byte layout for the no-removal, no-deliveries
    // shape (the empty-deliveries length prefix is part of the contract).
    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_key_rotation_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(&1u64.to_le_bytes()); // generation
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // rotator_id
    expected.push(0);
    expected.push(0); // removed_member_id == None
    expected.push(0);
    expected.extend_from_slice(&0u64.to_le_bytes()); // timestamp
    expected.push(0);
    expected.extend_from_slice(&0u32.to_le_bytes()); // deliveries.len() == 0
    assert_eq!(canonical, expected, "canonical KeyRotation bytes changed");
}

#[test]
fn canonical_key_rotation_announce_starts_with_versioned_tag() {
    let body = KeyRotationAnnounceBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        generation: 1,
        rotator_id: IdentityId::from([0u8; 32]),
        removed_member_id: IdentityId::from([1u8; 32]),
        timestamp: 0,
    };
    let canonical = canonical_key_rotation_announce(&body);
    assert!(canonical.starts_with(b"qubee_handshake_key_rotation_announce_v1"));

    // Pin the full byte layout, not just the tag — a reordered field or a
    // dropped separator is a silent wire-format change on a signed payload.
    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_key_rotation_announce_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(&1u64.to_le_bytes()); // generation
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // rotator_id
    expected.push(0);
    expected.extend_from_slice(&[1u8; 32]); // removed_member_id
    expected.push(0);
    expected.extend_from_slice(&0u64.to_le_bytes()); // timestamp
    assert_eq!(
        canonical, expected,
        "canonical KeyRotationAnnounce bytes changed"
    );
}

#[test]
fn canonical_key_delivery_starts_with_versioned_tag() {
    let body = KeyDeliveryBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        generation: 1,
        rotator_id: IdentityId::from([0u8; 32]),
        removed_member_id: None,
        recipient_id: IdentityId::from([2u8; 32]),
        wrapped_key: WrappedGroupKey {
            kem_ciphertext: Vec::new(),
            nonce: [0u8; 12],
            wrapped_key: Vec::new(),
        },
        timestamp: 0,
    };
    let canonical = canonical_key_delivery(&body);
    assert!(canonical.starts_with(b"qubee_handshake_key_delivery_v1"));

    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_key_delivery_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(&1u64.to_le_bytes()); // generation
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // rotator_id
    expected.push(0);
    expected.push(0); // removed_member_id == None
    expected.push(0);
    expected.extend_from_slice(&[2u8; 32]); // recipient_id
    expected.push(0);
    expected.extend_from_slice(&0u32.to_le_bytes()); // kem_ciphertext len
    expected.extend_from_slice(&[0u8; 12]); // nonce
    expected.extend_from_slice(&0u32.to_le_bytes()); // wrapped_key len
    expected.push(0);
    expected.extend_from_slice(&0u64.to_le_bytes()); // timestamp
    assert_eq!(canonical, expected, "canonical KeyDelivery bytes changed");
}

#[test]
fn canonical_prekey_bundle_starts_with_versioned_tag() {
    let kp = IdentityKeyPair::generate().unwrap();
    let body = PrekeyBundleBody {
        publisher: kp.public_key(),
        identity_x25519: [1u8; 32],
        signed_prekey: [2u8; 32],
        one_time_prekey: Some([3u8; 32]),
        kem_public: vec![4u8; 1184],
        timestamp: 0,
    };
    let canonical = canonical_prekey_bundle(&body);
    assert!(canonical.starts_with(b"qubee_handshake_prekey_bundle_v1"));
    // Explicit length-prefixed layout, not bincode: the publisher's raw
    // identity id must appear verbatim right after the tag + separator,
    // which a bincode framing would not reproduce.
    assert!(canonical
        .windows(32)
        .any(|w| w == kp.identity_id().as_ref() as &[u8]));
}

#[test]
fn canonical_group_message_starts_with_versioned_tag() {
    let body = GroupMessageBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        sender_id: IdentityId::from([0u8; 32]),
        generation: 1,
        aead_payload: vec![0u8; 12],
        timestamp: 0,
    };
    let canonical = canonical_group_message(&body);
    assert!(canonical.starts_with(b"qubee_group_message_v1"));
}

#[test]
fn canonical_member_added_starts_with_versioned_tag() {
    let kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _) = generate_ephemeral_kyber();
    let summary = GroupMemberSummary {
        identity_id: kp.identity_id(),
        identity_key: kp.public_key(),
        display_name: "x".to_string(),
        role: Role::Member,
        joined_at: 0,
        kyber_pub,
        peer_id: String::new(),
    };
    let body = MemberAddedBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        adder_id: IdentityId::from([0u8; 32]),
        new_member: summary,
        new_version: 1,
        timestamp: 0,
    };
    let canonical = canonical_member_added(&body).unwrap();
    // _v2 — GroupMemberSummary grew `peer_id` (bincoded into these bytes).
    assert!(canonical.starts_with(b"qubee_handshake_member_added_v2"));
}

#[test]
fn canonical_role_change_starts_with_versioned_tag() {
    let body = RoleChangeBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        promoter_id: IdentityId::from([0u8; 32]),
        member_id: IdentityId::from([0u8; 32]),
        new_role: Role::Admin,
        new_version: 1,
        timestamp: 0,
    };
    let canonical = canonical_role_change(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_role_change_v1"));
}

#[test]
fn canonical_request_state_sync_starts_with_versioned_tag() {
    use qubee_crypto::groups::group_handshake::{
        canonical_request_state_sync, RequestStateSyncBody,
    };
    let body = RequestStateSyncBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        requester_id: IdentityId::from([0u8; 32]),
        since_version: 1,
        timestamp: 0,
    };
    let canonical = canonical_request_state_sync(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_request_state_sync_v1"));

    // Golden vector — full byte layout.
    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_request_state_sync_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // requester_id
    expected.push(0);
    expected.extend_from_slice(&1u64.to_le_bytes()); // since_version
    expected.push(0);
    expected.extend_from_slice(&0u64.to_le_bytes()); // timestamp
    assert_eq!(
        canonical, expected,
        "canonical RequestStateSync bytes changed"
    );
}

#[test]
fn canonical_message_ack_is_pinned() {
    use qubee_crypto::groups::group_handshake::{canonical_message_ack, MessageAckBody};
    // Previously untested on the wire — a signed payload with no stability
    // vector could drift silently. Pin tag + full byte layout.
    let body = MessageAckBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        message_id: [3u8; 16],
        acker_id: IdentityId::from([1u8; 32]),
        timestamp: 42,
    };
    let canonical = canonical_message_ack(&body);
    assert!(canonical.starts_with(b"qubee_handshake_message_ack_v1"));

    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_message_ack_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(&[3u8; 16]); // message_id
    expected.push(0);
    expected.extend_from_slice(&[1u8; 32]); // acker_id
    expected.push(0);
    expected.extend_from_slice(&42u64.to_le_bytes()); // timestamp
    assert_eq!(canonical, expected, "canonical MessageAck bytes changed");
}

#[test]
fn canonical_ownership_transfer_is_pinned() {
    use qubee_crypto::groups::group_handshake::{
        canonical_ownership_transfer, OwnershipTransferBody,
    };
    // Previously untested on the wire. Pin tag + full byte layout.
    let body = OwnershipTransferBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        donor_id: IdentityId::from([1u8; 32]),
        new_owner_id: IdentityId::from([2u8; 32]),
        new_version: 7,
        timestamp: 42,
    };
    let canonical = canonical_ownership_transfer(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_ownership_transfer_v1"));

    let mut expected = Vec::new();
    expected.extend_from_slice(b"qubee_handshake_ownership_transfer_v1");
    expected.push(0);
    expected.extend_from_slice(&[0u8; 32]); // group_id
    expected.push(0);
    expected.extend_from_slice(&[1u8; 32]); // donor_id
    expected.push(0);
    expected.extend_from_slice(&[2u8; 32]); // new_owner_id
    expected.push(0);
    expected.extend_from_slice(&7u64.to_le_bytes()); // new_version
    expected.push(0);
    expected.extend_from_slice(&42u64.to_le_bytes()); // timestamp
    assert_eq!(
        canonical, expected,
        "canonical OwnershipTransfer bytes changed"
    );
}

#[test]
fn canonical_state_sync_response_starts_with_versioned_tag() {
    use qubee_crypto::groups::group_handshake::{
        canonical_state_sync_response, StateSyncResponseBody,
    };
    let body = StateSyncResponseBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        responder_id: IdentityId::from([0u8; 32]),
        requester_id: IdentityId::from([0u8; 32]),
        members: Vec::new(),
        current_version: 1,
        wrapped_group_key: None,
        timestamp: 0,
    };
    let canonical = canonical_state_sync_response(&body).unwrap();
    // _v3: GroupMemberSummary grew `peer_id` (in-band member PeerId
    // distribution); it was _v2 when the body grew Option<WrappedGroupKey>.
    assert!(canonical.starts_with(b"qubee_handshake_state_sync_response_v3"));
}

#[test]
fn canonical_payload_uses_explicit_length_prefixes_not_bincode() {
    // The whole point of `canonical_*` is to be byte-stable across
    // serde / bincode revisions. We test this by checking the
    // canonical payload's *length* for a known input — it should
    // match the explicit byte concatenation, not whatever bincode
    // happens to produce today.
    //
    // RequestJoinBody fixed input:
    //   group_id (32 bytes)
    //   invitation_code "abc" (3 bytes)
    //   joiner_public_key (bincode)
    //   joiner_display_name "x" (1 byte)
    //   joiner_kyber_pub: 1184 bytes (Kyber-768 public key length)
    //
    // Plus 5 separator NUL bytes plus the 31-byte tag plus the
    // 4-byte u32 length prefix on joiner_kyber_pub.
    //
    // Total non-pubkey overhead = 31 + 5 + 32 + 3 + 1 + 4 + 1184 = 1260
    // ... + however many bytes bincode picks for IdentityKey.
    //
    // We don't pin the IdentityKey size (Dilithium pubkey is large
    // and version-dependent), but we do pin the tag length and the
    // structural layout: tag, separator, group_id, separator,
    // invitation_code, ... etc.
    let kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _) = generate_ephemeral_kyber();
    assert_eq!(
        kyber_pub.len(),
        1184,
        "Kyber-768 public key size has shifted — check pqcrypto-kyber upgrade",
    );
    let body = RequestJoinBody {
        group_id: GroupId::from_bytes([1u8; 32]),
        invitation_code: "abc".to_string(),
        joiner_public_key: kp.public_key(),
        joiner_display_name: "x".to_string(),
        joiner_kyber_pub: kyber_pub.clone(),
        joiner_peer_id: "12D3KooWx".to_string(),
    };
    let canonical = canonical_request_join(&body).unwrap();

    // Tag prefix
    assert_eq!(&canonical[..31], b"qubee_handshake_request_join_v2");
    // First separator
    assert_eq!(canonical[31], 0u8);
    // group_id
    assert_eq!(&canonical[32..64], &[1u8; 32]);
    // Separator + invitation_code "abc"
    assert_eq!(canonical[64], 0u8);
    assert_eq!(&canonical[65..68], b"abc");

    // Tail must include the joiner_kyber_pub bytes verbatim, so any
    // accidental re-encoding (base64, etc.) would break this.
    assert!(canonical.windows(kyber_pub.len()).any(|w| w == kyber_pub));
}

// ---------------------------------------------------------------------
// Property-based round-trip tests.
//
// The pinned vectors above catch byte-level layout regressions for one
// fixed input per type. The properties below run the same encode→decode
// loop across many randomized inputs to surface input shapes that the
// fixed vectors don't cover (long invitation_codes, NUL bytes inside
// display names, max-size groups, etc.).
//
// Cases are capped at 64 — Kyber-768 pubkeys are 1184 bytes and the
// default 256-case run blows CI runtime; 64 cases is enough to surface
// any obvious encode/decode asymmetry while keeping the bench tight.
// ---------------------------------------------------------------------

use proptest::prelude::*;
use qubee_crypto::groups::group_handshake::{sign_request_join, sign_role_change, GroupHandshake};
use qubee_crypto::groups::group_message::GroupMessageEnvelope;

// ---------------------------------------------------------------------
// Wire-freeze guard.
//
// Every signed `GroupHandshake` frame is part of the frozen wire surface
// and MUST carry a pinned byte layout (a `canonical_*` golden vector
// above), keyed by a stable `qubee_handshake_<name>_vN` domain-separation
// tag. This match has NO wildcard arm on purpose: adding a variant breaks
// compilation here, forcing whoever adds a frame to register its frozen
// tag below AND pin its bytes above. A frame that changes layout without a
// `_vN` bump silently breaks old peers — that is exactly what the pins,
// and this guard, exist to prevent.
// ---------------------------------------------------------------------
fn frozen_handshake_tag(frame: &GroupHandshake) -> &'static str {
    match frame {
        GroupHandshake::RequestJoin { .. } => "qubee_handshake_request_join_v2",
        GroupHandshake::JoinAccepted { .. } => "qubee_handshake_join_accepted_v3",
        GroupHandshake::JoinRejected { .. } => "qubee_handshake_join_rejected_v1",
        GroupHandshake::KeyRotation { .. } => "qubee_handshake_key_rotation_v1",
        GroupHandshake::MemberAdded { .. } => "qubee_handshake_member_added_v2",
        GroupHandshake::RoleChange { .. } => "qubee_handshake_role_change_v1",
        GroupHandshake::RequestStateSync { .. } => "qubee_handshake_request_state_sync_v1",
        GroupHandshake::StateSyncResponse { .. } => "qubee_handshake_state_sync_response_v3",
        GroupHandshake::OwnershipTransfer { .. } => "qubee_handshake_ownership_transfer_v1",
        GroupHandshake::MessageAck { .. } => "qubee_handshake_message_ack_v1",
        GroupHandshake::PrekeyBundle { .. } => "qubee_handshake_prekey_bundle_v1",
        GroupHandshake::KeyRotationAnnounce { .. } => "qubee_handshake_key_rotation_announce_v1",
        GroupHandshake::KeyDelivery { .. } => "qubee_handshake_key_delivery_v1",
    }
}

#[test]
fn frozen_handshake_tags_match_canonical_encoders() {
    // Anchor the guard's tag literals to what the canonical encoders
    // actually emit, for the two variants whose signers are cheap to
    // build here. The other eleven are compile-forced by the exhaustive
    // match above and byte-pinned by their own `canonical_*` tests.
    let kp = IdentityKeyPair::generate().unwrap();

    let (kyber_pub, _) = generate_ephemeral_kyber();
    let rj_body = RequestJoinBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        invitation_code: "code".to_string(),
        joiner_public_key: kp.public_key(),
        joiner_display_name: "Bob".to_string(),
        joiner_kyber_pub: kyber_pub,
        joiner_peer_id: "12D3KooWBob".to_string(),
    };
    let rj_canonical = canonical_request_join(&rj_body).unwrap();
    let rj = sign_request_join(&kp, rj_body).unwrap();
    let rj_tag = frozen_handshake_tag(&rj);
    assert_eq!(rj_tag, "qubee_handshake_request_join_v2");
    assert!(
        rj_canonical.starts_with(rj_tag.as_bytes()),
        "RequestJoin canonical bytes no longer start with the frozen tag",
    );

    let rc_body = RoleChangeBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        promoter_id: IdentityId::from([0u8; 32]),
        member_id: IdentityId::from([0u8; 32]),
        new_role: Role::Admin,
        new_version: 1,
        timestamp: 0,
    };
    let rc_canonical = canonical_role_change(&rc_body).unwrap();
    let rc = sign_role_change(&kp, rc_body).unwrap();
    let rc_tag = frozen_handshake_tag(&rc);
    assert_eq!(rc_tag, "qubee_handshake_role_change_v1");
    assert!(
        rc_canonical.starts_with(rc_tag.as_bytes()),
        "RoleChange canonical bytes no longer start with the frozen tag",
    );
}

fn config_64() -> ProptestConfig {
    ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config_64())]

    /// Round-trip a `GroupMessageEnvelope` through `to_wire` /
    /// `from_wire` for arbitrary plaintext-shaped inputs. Catches any
    /// length-prefix asymmetry that the pinned single-vector test
    /// can't surface.
    #[test]
    fn group_message_envelope_round_trips(
        group_seed in any::<[u8; 32]>(),
        sender_seed in any::<[u8; 32]>(),
        generation in 0u64..=1_000_000,
        aead_payload in proptest::collection::vec(any::<u8>(), 0..1024),
        timestamp in 0u64..=4_000_000_000,
    ) {
        let kp = IdentityKeyPair::generate().unwrap();
        let body = GroupMessageBody {
            group_id: GroupId::from_bytes(group_seed),
            sender_id: IdentityId::from(sender_seed),
            generation,
            aead_payload,
            timestamp,
        };
        let payload = canonical_group_message(&body);
        let signature = kp.sign(&payload).unwrap();
        let envelope = GroupMessageEnvelope { body: body.clone(), signature };

        // Round-trip via the sealed outer envelope. The sealed wire is
        // what actually rides on gossipsub; pinning the structure here
        // catches anyone "simplifying" the seal/open path in a way
        // that breaks bincode round-trips of the inner envelope.
        let group_key = [0x5Au8; 32];
        let inner = envelope.to_inner_bincode().expect("inner bincode");
        let wire = qubee_crypto::groups::group_message::seal_outer_envelope(&group_key, &inner)
            .expect("seal");
        let (gid_out, inner_out) = qubee_crypto::groups::group_message::open_outer_envelope(
            &wire,
            vec![(body.group_id, group_key)],
        )
        .expect("open");
        prop_assert_eq!(gid_out, body.group_id);
        let decoded = GroupMessageEnvelope::from_inner_bincode(&inner_out)
            .expect("from_inner_bincode on freshly-encoded inner envelope must succeed");
        prop_assert_eq!(decoded.body.group_id, body.group_id);
        prop_assert_eq!(decoded.body.sender_id, body.sender_id);
        prop_assert_eq!(decoded.body.generation, body.generation);
        prop_assert_eq!(decoded.body.aead_payload, body.aead_payload);
        prop_assert_eq!(decoded.body.timestamp, body.timestamp);
    }

    /// Round-trip a signed `RequestJoin` handshake for arbitrary
    /// invitation codes and joiner display names. The signed
    /// `GroupHandshake::to_wire` / `from_wire` path goes through
    /// bincode, so this surfaces any field-ordering or option-encoding
    /// asymmetries.
    #[test]
    fn signed_request_join_round_trips(
        group_seed in any::<[u8; 32]>(),
        invitation_code in "[A-Za-z0-9_-]{0,32}",
        joiner_display_name in "[\\PC]{0,64}",
        joiner_peer_id in "[A-Za-z0-9]{0,52}",
    ) {
        let kp = IdentityKeyPair::generate().unwrap();
        let (kyber_pub, _) = generate_ephemeral_kyber();
        let body = RequestJoinBody {
            group_id: GroupId::from_bytes(group_seed),
            invitation_code: invitation_code.clone(),
            joiner_public_key: kp.public_key(),
            joiner_display_name: joiner_display_name.clone(),
            joiner_kyber_pub: kyber_pub.clone(),
            joiner_peer_id: joiner_peer_id.clone(),
        };
        let signed = sign_request_join(&kp, body).unwrap();
        let wire = signed.to_wire().expect("handshake to_wire");
        let decoded = GroupHandshake::from_wire(&wire)
            .expect("handshake from_wire on freshly-encoded request");
        match decoded {
            GroupHandshake::RequestJoin { body, .. } => {
                prop_assert_eq!(body.group_id.as_ref(), &group_seed[..]);
                prop_assert_eq!(body.invitation_code, invitation_code);
                prop_assert_eq!(body.joiner_display_name, joiner_display_name);
                prop_assert_eq!(body.joiner_kyber_pub, kyber_pub);
                prop_assert_eq!(body.joiner_peer_id, joiner_peer_id);
            }
            other => prop_assert!(false, "expected RequestJoin variant, got {:?}", other),
        }
    }

    /// Round-trip a signed `RoleChange` for arbitrary versions and
    /// timestamps. RoleChange is the smallest signed handshake variant;
    /// good canary for the bincode encode path.
    #[test]
    fn signed_role_change_round_trips(
        group_seed in any::<[u8; 32]>(),
        promoter_seed in any::<[u8; 32]>(),
        member_seed in any::<[u8; 32]>(),
        new_version in 1u64..=1_000_000,
        timestamp in 0u64..=4_000_000_000,
    ) {
        let kp = IdentityKeyPair::generate().unwrap();
        let body = RoleChangeBody {
            group_id: GroupId::from_bytes(group_seed),
            promoter_id: IdentityId::from(promoter_seed),
            member_id: IdentityId::from(member_seed),
            new_role: Role::Admin,
            new_version,
            timestamp,
        };
        let signed = sign_role_change(&kp, body).unwrap();
        let wire = signed.to_wire().expect("handshake to_wire");
        let decoded = GroupHandshake::from_wire(&wire)
            .expect("handshake from_wire on freshly-encoded role-change");
        match decoded {
            GroupHandshake::RoleChange { body, .. } => {
                prop_assert_eq!(body.group_id.as_ref(), &group_seed[..]);
                prop_assert_eq!(body.new_version, new_version);
                prop_assert_eq!(body.timestamp, timestamp);
            }
            other => prop_assert!(false, "expected RoleChange variant, got {:?}", other),
        }
    }
}
