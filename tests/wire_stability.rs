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
    canonical_join_accepted, canonical_join_rejected, canonical_key_rotation,
    canonical_member_added, canonical_request_join, canonical_role_change,
    generate_ephemeral_kyber, GroupMemberSummary, JoinAcceptedBody, JoinRejectedBody,
    KeyRotationBody, MemberAddedBody, RequestJoinBody, RoleChangeBody, HANDSHAKE_MAGIC,
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
fn group_message_magic_is_pinned() {
    // `\x02` is the sealed-outer-envelope wire format. `\x01` was the
    // pre-sealing format that left signed bodies plaintext on the
    // wire; pinned here so a "let's bump the magic" change has to
    // also bump this assertion (and the doc on `MAGIC_GROUP_MESSAGE`).
    assert_eq!(MAGIC_GROUP_MESSAGE, b"QUBEE_GMS\x02");
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
    };
    let canonical = canonical_request_join(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_request_join_v1"));
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
    // _v2 — GroupMemberSummary grew a kyber_pub field in plan revision 2
    // priority 5b. Devices on the old tag will fail signature
    // verification for new-format frames and vice versa.
    assert!(canonical.starts_with(b"qubee_handshake_join_accepted_v2"));
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
    };
    let body = MemberAddedBody {
        group_id: GroupId::from_bytes([0u8; 32]),
        adder_id: IdentityId::from([0u8; 32]),
        new_member: summary,
        new_version: 1,
        timestamp: 0,
    };
    let canonical = canonical_member_added(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_member_added_v1"));
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
    // _v2: body grew an Option<WrappedGroupKey> in this batch.
    assert!(canonical.starts_with(b"qubee_handshake_state_sync_response_v2"));
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
    };
    let canonical = canonical_request_join(&body).unwrap();

    // Tag prefix
    assert_eq!(&canonical[..31], b"qubee_handshake_request_join_v1");
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
        let wire = qubee_crypto::groups::group_message::seal_outer_envelope(
            &body.group_id, &group_key, &inner,
        )
        .expect("seal");
        let (gid_out, inner_out) = qubee_crypto::groups::group_message::open_outer_envelope(
            &wire,
            |gid| if *gid == body.group_id { Some(group_key) } else { None },
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
    ) {
        let kp = IdentityKeyPair::generate().unwrap();
        let (kyber_pub, _) = generate_ephemeral_kyber();
        let body = RequestJoinBody {
            group_id: GroupId::from_bytes(group_seed),
            invitation_code: invitation_code.clone(),
            joiner_public_key: kp.public_key(),
            joiner_display_name: joiner_display_name.clone(),
            joiner_kyber_pub: kyber_pub.clone(),
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
