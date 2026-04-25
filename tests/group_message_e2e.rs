//! End-to-end test for the encrypted group-message pipeline.
//!
//! Two devices. Alice creates a group, Bob joins via the handshake,
//! both converge on the same group key. Alice sends a message via
//! `encrypt_group_message`; Bob round-trips the wire bytes through
//! `decrypt_group_message` and recovers the plaintext + sender id +
//! timestamp.

use qubee_crypto::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, RequestJoinBody,
};
use qubee_crypto::groups::group_invite::InvitePayload;
use qubee_crypto::groups::group_manager::{GroupManager, GroupSettings, GroupType, MemberStatus};
use qubee_crypto::groups::group_message::{decrypt_group_message, encrypt_group_message};
use qubee_crypto::groups::handshake_handlers::{
    process_join_accepted, process_request_join, HandshakeOutcome,
};
use qubee_crypto::identity::identity_key::IdentityKeyPair;
use qubee_crypto::storage::secure_keystore::SecureKeyStore;
use tempfile::TempDir;

fn fresh_device(label: &str) -> (TempDir, IdentityKeyPair, GroupManager) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(format!("{label}.db"));
    let ks = SecureKeyStore::new(&path).expect("keystore");
    let gm = GroupManager::new(ks).expect("group manager");
    let kp = IdentityKeyPair::generate().expect("identity");
    (dir, kp, gm)
}

/// Walk Bob through a join handshake against Alice's group. Returns
/// a fresh [`GroupManager`] for Bob with the group fully provisioned
/// (members, key, persisted Kyber secret) so the test can immediately
/// exchange encrypted messages.
fn join_bob_to_alice(
    alice_kp: &IdentityKeyPair,
    alice_gm: &mut GroupManager,
    group_id: qubee_crypto::groups::group_manager::GroupId,
    invitation_code: String,
    inviter_name: String,
) -> (TempDir, IdentityKeyPair, GroupManager) {
    let (bob_dir, bob_kp, mut bob_gm) = fresh_device("bob");
    bob_gm
        .record_external_invite_acceptance(
            group_id,
            "Test Group",
            alice_kp.identity_id(),
            &inviter_name,
            &invitation_code,
        )
        .unwrap();
    let (kyber_pub, kyber_secret) = generate_ephemeral_kyber();
    let (req_body, req_sig) = match sign_request_join(
        &bob_kp,
        RequestJoinBody {
            group_id,
            invitation_code,
            joiner_public_key: bob_kp.public_key(),
            joiner_display_name: "Bob".to_string(),
            joiner_kyber_pub: kyber_pub,
        },
    )
    .unwrap()
    {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        _ => unreachable!(),
    };
    let (acc_body, acc_sig) =
        match process_request_join(alice_gm, alice_kp, &req_body, &req_sig).unwrap() {
            HandshakeOutcome::Accept { body, signature } => (body, signature),
            other => panic!("expected Accept, got {other:?}"),
        };
    process_join_accepted(
        &mut bob_gm,
        alice_kp.identity_id(),
        &acc_body,
        &acc_sig,
        &kyber_secret,
    )
    .unwrap();
    (bob_dir, bob_kp, bob_gm)
}

#[test]
fn round_trip_encrypted_group_message() {
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_id = alice_kp.identity_id();
    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "Test Group".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    alice_gm.ensure_group_key(group_id).unwrap();
    let invitation = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();

    let (_bob_dir, bob_kp, bob_gm) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invitation.invitation_code,
        invitation.inviter_name,
    );

    // Sanity: same key on both sides.
    assert_eq!(
        alice_gm.export_group_key(&group_id).unwrap(),
        bob_gm.export_group_key(&group_id).unwrap()
    );

    let payload = b"Hello from Alice".as_slice();
    let wire = encrypt_group_message(&alice_gm, &alice_kp, group_id, payload).unwrap();

    let decrypted = decrypt_group_message(&bob_gm, &wire).expect("Bob decrypts");
    assert_eq!(decrypted.plaintext, payload);
    assert_eq!(decrypted.sender_id, alice_id);
    assert_eq!(decrypted.group_id, group_id);
    assert!(decrypted.timestamp > 0);
}

#[test]
fn rejects_message_from_non_member() {
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_id = alice_kp.identity_id();
    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "Test".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    alice_gm.ensure_group_key(group_id).unwrap();

    // Mallory has the group key (somehow — assume key compromise) but
    // is not a member of the group on Alice's local view. A signed
    // envelope from her must still be rejected.
    let mallory_kp = IdentityKeyPair::generate().unwrap();
    let key = alice_gm.export_group_key(&group_id).unwrap();

    // Mallory has the key but isn't a member of Alice's group. Set
    // up Mallory's local GroupManager with a Group entry at
    // `group_id` (so encrypt_group_message can find one) plus the
    // shared key. Confirm-via-snapshot is the easiest route.
    let (_m_dir, _m_unused, mut mallory_gm) = fresh_device("mallory");
    let mut mallory_members = std::collections::HashMap::new();
    mallory_members.insert(
        mallory_kp.identity_id(),
        qubee_crypto::groups::group_manager::GroupMember {
            identity_id: mallory_kp.identity_id(),
            identity_key: mallory_kp.public_key(),
            display_name: "Mallory".to_string(),
            role: qubee_crypto::groups::group_permissions::Role::Owner,
            joined_at: 0,
            last_seen: 0,
            invited_by: None,
            member_status: MemberStatus::Active,
            custom_permissions: None,
            kyber_pub: Vec::new(),
        },
    );
    mallory_gm
        .confirm_external_invite_acceptance(
            group_id,
            "Forged".to_string(),
            mallory_members,
            &key,
        )
        .unwrap();

    let wire = encrypt_group_message(&mallory_gm, &mallory_kp, group_id, b"forged").unwrap();

    // Alice's GM never enrolled Mallory — must reject.
    let result = decrypt_group_message(&alice_gm, &wire);
    assert!(result.is_err(), "Alice must reject message from non-member");
}

#[test]
fn wire_format_magic_prefix_is_stable() {
    // Stability check: a v1 GroupMessageEnvelope frame begins with
    // exactly the bytes `QUBEE_GMS\x01`. Any change here is a wire
    // break that needs a version bump and migration.
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_id = alice_kp.identity_id();
    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "Test".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    alice_gm.ensure_group_key(group_id).unwrap();

    let wire = encrypt_group_message(&alice_gm, &alice_kp, group_id, b"hi").unwrap();
    assert!(wire.starts_with(b"QUBEE_GMS\x01"));
}
