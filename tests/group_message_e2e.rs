//! End-to-end test for the encrypted group-message pipeline.
//!
//! Two devices. Alice creates a group, Bob joins via the handshake,
//! both converge on the same group key. Alice sends a message via
//! `encrypt_group_message`; Bob round-trips the wire bytes through
//! `decrypt_group_message` and recovers the plaintext + sender id +
//! timestamp.

use qubee_crypto::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, MemberAddedBody, RequestJoinBody,
};
use qubee_crypto::groups::group_manager::{GroupManager, GroupSettings, GroupType, MemberStatus};
use qubee_crypto::groups::group_message::{decrypt_group_message, encrypt_group_message};
use qubee_crypto::groups::handshake_handlers::{
    process_join_accepted, process_member_added, process_request_join, HandshakeOutcome,
};
use qubee_crypto::identity::identity_key::{HybridSignature, IdentityKeyPair};
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
/// (members, key, persisted Kyber secret) plus the inviter-broadcast
/// `MemberAdded` body+signature the caller may apply to other
/// existing members' GroupManagers (e.g. for the "Carol joins after
/// Bob" scenario).
fn join_bob_to_alice(
    alice_kp: &IdentityKeyPair,
    alice_gm: &mut GroupManager,
    group_id: qubee_crypto::groups::group_manager::GroupId,
    invitation_code: String,
    inviter_name: String,
) -> (
    TempDir,
    IdentityKeyPair,
    GroupManager,
    MemberAddedBody,
    HybridSignature,
) {
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
    let (acc_body, acc_sig, ma_body, ma_sig) =
        match process_request_join(alice_gm, alice_kp, &req_body, &req_sig).unwrap() {
            HandshakeOutcome::Accept {
                body,
                signature,
                member_added_body,
                member_added_signature,
            } => (body, signature, member_added_body, member_added_signature),
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
    (bob_dir, bob_kp, bob_gm, ma_body, ma_sig)
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

    let (_bob_dir, _bob_kp, bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
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
            // Match the same snapshot_version Alice sees, so the
            // generation-gate rejection happens on "non-member"
            // grounds (the real point of this test) rather than on
            // a generation mismatch we'd otherwise trip over first.
            1,
        )
        .unwrap();

    let wire = encrypt_group_message(&mallory_gm, &mallory_kp, group_id, b"forged").unwrap();

    // Alice's GM never enrolled Mallory — must reject.
    let result = decrypt_group_message(&alice_gm, &wire);
    assert!(result.is_err(), "Alice must reject message from non-member");
}

/// Build a [`GroupMessageEnvelope`] whose canonical signing payload
/// uses an explicit generation counter. We can't use
/// `encrypt_group_message` for this because it always reads
/// `group.version` — we need to forge a frame with a chosen
/// generation to test the receiver's gate. So we duplicate the
/// minimum framing logic here, mirroring `encrypt_group_message`.
fn forge_message_with_generation(
    gm: &GroupManager,
    sender_kp: &IdentityKeyPair,
    group_id: qubee_crypto::groups::group_manager::GroupId,
    plaintext: &[u8],
    generation: u64,
) -> Vec<u8> {
    use qubee_crypto::groups::group_message::{
        canonical_group_message, GroupMessageBody, GroupMessageEnvelope,
    };
    let aead_payload = gm.encrypt_group_message(&group_id, plaintext).unwrap();
    let body = GroupMessageBody {
        group_id,
        sender_id: sender_kp.identity_id(),
        generation,
        aead_payload,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let payload = canonical_group_message(&body);
    let signature = sender_kp.sign(&payload).unwrap();
    GroupMessageEnvelope { body, signature }.to_wire().unwrap()
}

#[test]
fn stale_generation_after_rotation_is_rejected() {
    // Alice + Bob in a group at generation N. Alice forges a frame
    // claiming generation N-1 (as if it were already in flight when
    // a rotation landed) and tries to decrypt it on Bob's side. The
    // generation gate must reject the frame.
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
    let (_bob_dir, _bob_kp, bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invitation.invitation_code,
        invitation.inviter_name,
    );

    let local = bob_gm.get_group(&group_id).unwrap().version;
    assert!(local >= 1, "post-join group version must be at least 1");

    let stale = local - 1; // claim we sent this *before* the join landed
    let wire = forge_message_with_generation(&alice_gm, &alice_kp, group_id, b"stale", stale);
    let result =
        qubee_crypto::groups::group_message::decrypt_group_message(&bob_gm, &wire);
    assert!(
        result.is_err(),
        "decrypt must reject a frame whose generation is older than local",
    );
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("generation mismatch"),
        "expected 'generation mismatch' in error, got: {err}",
    );
}

#[test]
fn future_generation_is_rejected() {
    // Symmetric: a frame whose generation is *newer* than local
    // (because we missed a rotation) is rejected with the same
    // error. Strict policy — the alternative would be to buffer
    // until the matching KeyRotation arrives, which needs reorder-
    // safe state we don't yet have.
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
    let (_bob_dir, _bob_kp, bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invitation.invitation_code,
        invitation.inviter_name,
    );

    let local = bob_gm.get_group(&group_id).unwrap().version;
    let future = local + 5;
    let wire = forge_message_with_generation(&alice_gm, &alice_kp, group_id, b"future", future);
    let result =
        qubee_crypto::groups::group_message::decrypt_group_message(&bob_gm, &wire);
    assert!(
        result.is_err(),
        "decrypt must reject a frame whose generation is newer than local",
    );
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

// ---------------------------------------------------------------------
// A1 + A2 regressions. These tests describe the post-fix invariant for
// the bundled wire-format batch (per-member kem_pub plumbing in
// JoinAccepted and the new MemberAdded broadcast). They are expected
// to *fail* on `main` until that batch lands. The bug they pin:
//
//   - process_join_accepted reconstructs the snapshot members with
//     `kyber_pub: Vec::new()` (handshake_handlers.rs ~L202), so the
//     joiner's local view of every existing member has an empty Kyber
//     pubkey.
//   - rotate_group_key_after_removal silently filters out members
//     with an empty kyber_pub (group_manager.rs ~L602), so a
//     just-joined peer who tries to rotate ends up broadcasting a
//     rotation to nobody — without an error.
//   - There is no MemberAdded broadcast, so existing members (Bob)
//     never learn about a late joiner (Carol).
// ---------------------------------------------------------------------

#[test]
fn newly_joined_member_can_rotate_key_to_inviter() {
    // After Bob joins Alice's group via the handshake, Bob's local
    // GroupManager should know Alice's Kyber pubkey — so if Bob is
    // promoted to admin and rotates the group key, Alice ends up in
    // the recipients list. Today this list is silently empty.
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

    let (_bob_dir, bob_kp, mut bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invitation.invitation_code,
        invitation.inviter_name,
    );

    // Bob now plans a rotation on his own local view. The semantic
    // intent is "Bob is admin, removed someone, now rotates" — we
    // skip the role plumbing because rotate_group_key_after_removal
    // doesn't check permissions today (the role gate is upstream of
    // it). Whether Bob is technically allowed is the subject of A1's
    // promote_member API; here we only assert the *delivery* works
    // once a non-owner is doing the rotation.
    let recipients = bob_gm
        .rotate_group_key_after_removal(group_id, bob_kp.identity_id())
        .expect("rotation should succeed");

    assert!(
        recipients.iter().any(|(id, _)| *id == alice_id),
        "Bob's rotation must reach Alice (the inviter), but recipients are: {:?}",
        recipients.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
    );
}

#[test]
fn late_joiner_can_rotate_key_to_all_existing_members() {
    // Owner + Bob + Carol where Carol joins last. Today, Carol's
    // local snapshot of Owner and Bob both have empty Kyber pubkeys
    // (process_join_accepted hardcodes Vec::new()), so any rotation
    // Carol plans silently delivers to nobody. Post-fix, Carol's
    // snapshot must carry per-member kem_pub and her rotation must
    // reach Owner and Bob.
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
    let bob_invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_bob_dir, bob_kp, _bob_gm, _ma_body_bob, _ma_sig_bob) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        bob_invite.invitation_code,
        bob_invite.inviter_name,
    );
    let carol_invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_carol_dir, carol_kp, mut carol_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        carol_invite.invitation_code,
        carol_invite.inviter_name,
    );

    let recipients = carol_gm
        .rotate_group_key_after_removal(group_id, carol_kp.identity_id())
        .expect("rotation should succeed");
    let recipient_ids: std::collections::HashSet<_> =
        recipients.iter().map(|(id, _)| *id).collect();
    assert!(
        recipient_ids.contains(&alice_id),
        "Carol's rotation must reach Alice; recipients: {recipient_ids:?}",
    );
    assert!(
        recipient_ids.contains(&bob_kp.identity_id()),
        "Carol's rotation must reach Bob; recipients: {recipient_ids:?}",
    );
}

#[test]
fn existing_members_learn_about_late_joiners() {
    // Alice + Bob, then Carol joins via Alice. Today, Bob never
    // learns about Carol — there is no MemberAdded broadcast, and
    // JoinAccepted only reaches the new joiner. Post-fix, Alice
    // should publish a MemberAdded which Bob processes, so Bob's
    // local membership map contains Carol.
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
    let bob_invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_bob_dir, _bob_kp, mut bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        bob_invite.invitation_code,
        bob_invite.inviter_name,
    );
    let carol_invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_carol_dir, carol_kp, _carol_gm, ma_body_carol, ma_sig_carol) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        carol_invite.invitation_code,
        carol_invite.inviter_name,
    );

    // Simulate the MemberAdded broadcast hitting Bob's device — in a
    // real deployment this rides the per-group gossipsub topic.
    process_member_added(&mut bob_gm, &ma_body_carol, &ma_sig_carol)
        .expect("Bob applies Alice's MemberAdded broadcast");

    let bob_members = &bob_gm.get_group(&group_id).expect("bob has group").members;
    assert!(
        bob_members.contains_key(&carol_kp.identity_id()),
        "Bob must learn about Carol via MemberAdded broadcast; \
         Bob's members: {:?}",
        bob_members.keys().collect::<Vec<_>>(),
    );

    // Stronger invariant: after applying MemberAdded, Bob's local
    // generation must track Alice's so a subsequent encrypted message
    // from Alice doesn't bounce on the strict generation gate.
    let alice_v = alice_gm.get_group(&group_id).unwrap().version;
    let bob_v = bob_gm.get_group(&group_id).unwrap().version;
    assert_eq!(
        bob_v, alice_v,
        "After MemberAdded, Bob's group version must match Alice's (alice={alice_v}, bob={bob_v})",
    );
    let wire = encrypt_group_message(&alice_gm, &alice_kp, group_id, b"hello carol+bob").unwrap();
    let decrypted = decrypt_group_message(&bob_gm, &wire)
        .expect("Bob must decrypt Alice's post-join message");
    assert_eq!(decrypted.plaintext, b"hello carol+bob");
}

// ---------------------------------------------------------------------
// 5c — promote_member + RoleChange wire frame
// ---------------------------------------------------------------------

#[test]
fn owner_can_promote_member_and_broadcast_role_change() {
    use qubee_crypto::groups::group_handshake::{sign_role_change, GroupHandshake};
    use qubee_crypto::groups::group_permissions::Role;
    use qubee_crypto::groups::handshake_handlers::process_role_change;

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
    let invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_bob_dir, bob_kp, mut bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invite.invitation_code,
        invite.inviter_name,
    );

    // Alice promotes Bob to Admin.
    let role_change_body = alice_gm
        .promote_member(group_id, alice_id, bob_kp.identity_id(), Role::Admin)
        .expect("owner can promote member");

    // Sign + broadcast as a wire frame; Bob applies it.
    let signed = sign_role_change(&alice_kp, role_change_body.clone()).unwrap();
    let (rc_body, rc_sig) = match signed {
        GroupHandshake::RoleChange { body, signature } => (body, signature),
        _ => unreachable!(),
    };
    process_role_change(&mut bob_gm, &rc_body, &rc_sig).expect("Bob applies the role change");

    // Bob's local view of himself now has Admin role.
    let bob_view_of_self = bob_gm
        .get_group(&group_id)
        .unwrap()
        .members
        .get(&bob_kp.identity_id())
        .unwrap()
        .role
        .clone();
    assert_eq!(bob_view_of_self, Role::Admin);

    // And version coherence: Alice's post-promotion version equals Bob's.
    let alice_v = alice_gm.get_group(&group_id).unwrap().version;
    let bob_v = bob_gm.get_group(&group_id).unwrap().version;
    assert_eq!(alice_v, bob_v, "post-RoleChange version must agree");

    // Subsequent encrypted message round-trips fine.
    let wire = encrypt_group_message(&alice_gm, &alice_kp, group_id, b"role-change ok").unwrap();
    let decrypted =
        decrypt_group_message(&bob_gm, &wire).expect("post-RoleChange decryption works");
    assert_eq!(decrypted.plaintext, b"role-change ok");
}

#[test]
fn non_owner_cannot_promote_member() {
    use qubee_crypto::groups::group_permissions::Role;

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
    let invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_bob_dir, bob_kp, mut bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invite.invitation_code,
        invite.inviter_name,
    );

    // Bob (a Member, not Owner) tries to promote himself on his own
    // local view. Must fail with the owner-only gate.
    let result = bob_gm.promote_member(group_id, bob_kp.identity_id(), bob_kp.identity_id(), Role::Admin);
    assert!(result.is_err(), "non-owner must not be able to promote");
}

// ---------------------------------------------------------------------
// Replay-past-freshness gate (rev-3 priority 0).
//
// `decrypt_group_message` calls `verify_with_max_age(...,
// GROUP_MESSAGE_MAX_AGE_SECS)` so a captured frame older than five
// minutes can't be replayed back at the network. This test forges
// such a frame directly (bypassing `encrypt_group_message`'s
// always-now timestamp) and asserts the gate rejects it.
// ---------------------------------------------------------------------

#[test]
fn message_older_than_max_age_is_rejected() {
    use qubee_crypto::groups::group_message::{
        canonical_group_message, GroupMessageBody, GroupMessageEnvelope,
        GROUP_MESSAGE_MAX_AGE_SECS,
    };

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
    let invite = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let (_bob_dir, _bob_kp, bob_gm, _ma_body, _ma_sig) = join_bob_to_alice(
        &alice_kp,
        &mut alice_gm,
        group_id,
        invite.invitation_code,
        invite.inviter_name,
    );

    // The freshness gate sits on `HybridSignature.timestamp` (set by
    // IdentityKeyPair::sign at wall-clock now), and verify_with_max_age
    // rejects on the timestamp check *before* it does any
    // cryptography. So forging a stale frame is just: sign normally,
    // then mutate the public timestamp field on the signature struct
    // to a value past max_age_secs in the past.
    let aead_payload = alice_gm
        .encrypt_group_message(&group_id, b"stale")
        .unwrap();
    let body = GroupMessageBody {
        group_id,
        sender_id: alice_id,
        generation: alice_gm.get_group(&group_id).unwrap().version,
        aead_payload,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let payload = canonical_group_message(&body);
    let mut signature = alice_kp.sign(&payload).unwrap();
    // `+ 60` to put us a clean minute past the cliff so we don't race
    // with the wall clock's second granularity.
    signature.timestamp = signature.timestamp - GROUP_MESSAGE_MAX_AGE_SECS - 60;
    let wire = GroupMessageEnvelope { body, signature }.to_wire().unwrap();

    let result = decrypt_group_message(&bob_gm, &wire);
    assert!(
        result.is_err(),
        "stale-timestamp frame must be rejected by the freshness gate",
    );
}
