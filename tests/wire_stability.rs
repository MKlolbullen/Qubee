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
use qubee_crypto::groups::group_message::{canonical_group_message, GroupMessageBody, MAGIC_GROUP_MESSAGE};
use qubee_crypto::groups::group_permissions::Role;
use qubee_crypto::identity::identity_key::{IdentityId, IdentityKeyPair};

#[test]
fn handshake_magic_is_pinned() {
    assert_eq!(HANDSHAKE_MAGIC, b"QUBEE_GHS\x01");
}

#[test]
fn group_message_magic_is_pinned() {
    assert_eq!(MAGIC_GROUP_MESSAGE, b"QUBEE_GMS\x01");
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
        timestamp: 0,
    };
    let canonical = canonical_state_sync_response(&body).unwrap();
    assert!(canonical.starts_with(b"qubee_handshake_state_sync_response_v1"));
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
