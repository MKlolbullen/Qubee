//! End-to-end integration test for the group invite + handshake flow.
//!
//! Two simulated devices (Alice as inviter, Bob as joiner) get their
//! own [`IdentityKeyPair`] and [`GroupManager`] backed by a temp-dir
//! `SecureKeyStore`. We hand-route the handshake messages between
//! them — no libp2p in this test, just the protocol logic — and
//! assert that they converge on the same group_id, the same member
//! list, and the same symmetric group key.
//!
//! This is the test that catches regressions in:
//!   * RequestJoin signature canonicalisation
//!   * JoinAccepted member-snapshot reconstruction
//!   * Kyber-768 KEM wrap/unwrap of the group key
//!   * GroupManager::confirm_external_invite_acceptance side effects

use qubee_crypto::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, RequestJoinBody,
};
use qubee_crypto::groups::group_invite::InvitePayload;
use qubee_crypto::groups::group_manager::{GroupManager, GroupSettings, GroupType};
use qubee_crypto::groups::handshake_handlers::{
    process_join_accepted, process_request_join, HandshakeOutcome,
};
use qubee_crypto::identity::identity_key::IdentityKeyPair;
use qubee_crypto::storage::secure_keystore::SecureKeyStore;
use tempfile::TempDir;

/// Convenience: spin up an `IdentityKeyPair` and a `GroupManager`
/// backed by a fresh temp-dir keystore.
fn fresh_device(label: &str) -> (TempDir, IdentityKeyPair, GroupManager) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(format!("{label}.db"));
    let ks = SecureKeyStore::new(&path).expect("keystore");
    let gm = GroupManager::new(ks).expect("group manager");
    let kp = IdentityKeyPair::generate().expect("identity");
    (dir, kp, gm)
}

#[test]
fn invite_handshake_converges_on_shared_group_state() {
    // -------- Alice (inviter) --------
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_pub = alice_kp.public_key();
    let alice_id = alice_kp.identity_id();

    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_pub.clone(),
            "Test Group".to_string(),
            "round-trip test".to_string(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .expect("create_group");
    alice_gm.ensure_group_key(group_id).expect("ensure key");

    let invitation = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .expect("create_invitation");
    let payload = InvitePayload::from_invitation(&invitation);
    let invite_link = payload.to_invite_link().expect("invite link");

    // -------- Bob (joiner) --------
    let (_bob_dir, bob_kp, mut bob_gm) = fresh_device("bob");
    let bob_id = bob_kp.identity_id();

    // Bob parses the link as he would after scanning the QR.
    let parsed = InvitePayload::from_invite_link(&invite_link).expect("parse link");
    assert_eq!(parsed.group_id, group_id);

    // Bob records the receipt locally so on_join_accepted can look up
    // the expected inviter id later.
    bob_gm
        .record_external_invite_acceptance(
            parsed.group_id,
            &parsed.group_name,
            parsed.inviter_id,
            &parsed.inviter_name,
            &parsed.invitation_code,
        )
        .expect("record receipt");

    // Bob mints an ephemeral Kyber-768 keypair, signs a RequestJoin.
    let (kyber_pub, kyber_secret) = generate_ephemeral_kyber();
    let request_body = RequestJoinBody {
        group_id: parsed.group_id,
        invitation_code: parsed.invitation_code.clone(),
        joiner_public_key: bob_kp.public_key(),
        joiner_display_name: "Bob".to_string(),
        joiner_kyber_pub: kyber_pub,
    };
    let signed_request = sign_request_join(&bob_kp, request_body.clone()).expect("sign request");
    let request_wire = signed_request.to_wire().expect("wire");

    // Round-trip through the gossipsub-equivalent (no real network).
    let decoded =
        GroupHandshake::from_wire(&request_wire).expect("RequestJoin should round-trip");
    let (req_body_in, req_sig_in) = match decoded {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        _ => panic!("expected RequestJoin"),
    };

    // -------- Alice processes the request --------
    let outcome = process_request_join(&mut alice_gm, &alice_kp, &req_body_in, &req_sig_in)
        .expect("process_request_join");
    let (accepted_body, accepted_sig) = match outcome {
        HandshakeOutcome::Accept { body, signature } => (body, signature),
        other => panic!("expected Accept, got {other:?}"),
    };

    // Sanity: Alice's GM now has Bob enrolled.
    let alice_view = alice_gm.get_group(&group_id).expect("group");
    assert!(alice_view.members.contains_key(&bob_id));
    assert_eq!(alice_view.members.len(), 2);

    // -------- Bob processes the acceptance --------
    process_join_accepted(
        &mut bob_gm,
        parsed.inviter_id,
        &accepted_body,
        &accepted_sig,
        &kyber_secret,
    )
    .expect("process_join_accepted");

    // -------- Convergence assertions --------
    let bob_view = bob_gm.get_group(&group_id).expect("bob has group");
    assert_eq!(bob_view.id, alice_view.id);
    assert_eq!(bob_view.name, alice_view.name);
    assert_eq!(bob_view.members.len(), alice_view.members.len());
    assert!(bob_view.members.contains_key(&alice_id));
    assert!(bob_view.members.contains_key(&bob_id));

    // Same symmetric group key on both sides — this is the whole point
    // of the Kyber wrap.
    let alice_key = alice_gm.export_group_key(&group_id).expect("alice key");
    let bob_key = bob_gm.export_group_key(&group_id).expect("bob key");
    assert_eq!(alice_key, bob_key, "group key did not transport");

    // The pending receipt on Bob's side should be gone after confirmation.
    let pending = bob_gm.list_accepted_external_invites().expect("list");
    assert!(
        pending.iter().all(|e| e.group_id != group_id),
        "receipt should have been cleared after confirmation",
    );

    // Invitation usage on Alice's side should have ticked up.
    let inv_after = alice_gm
        .get_invitation(&parsed.invitation_code)
        .expect("get_invitation")
        .expect("invitation persists");
    assert_eq!(inv_after.current_uses, 1);
}

#[test]
fn forged_request_join_is_rejected() {
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
    let invitation = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();

    // Mallory wants to claim Bob's identity. Builds a body that names
    // Bob's pubkey but signs it with Mallory's keypair.
    let bob_kp = IdentityKeyPair::generate().unwrap();
    let mallory_kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _kyber_secret) = generate_ephemeral_kyber();
    let body = RequestJoinBody {
        group_id,
        invitation_code: invitation.invitation_code.clone(),
        joiner_public_key: bob_kp.public_key(),
        joiner_display_name: "Bob (impersonated)".to_string(),
        joiner_kyber_pub: kyber_pub,
    };
    let signed = sign_request_join(&mallory_kp, body.clone()).unwrap();
    let (decoded_body, decoded_sig) = match signed {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        _ => panic!("expected RequestJoin"),
    };

    let result = process_request_join(&mut alice_gm, &alice_kp, &decoded_body, &decoded_sig);
    assert!(
        result.is_err(),
        "process_request_join must reject a request signed by a key other than the body's joiner_public_key",
    );

    // Bob should not be in the group.
    let alice_view = alice_gm.get_group(&group_id).unwrap();
    assert!(!alice_view.members.contains_key(&bob_kp.identity_id()));
}

#[test]
fn unknown_invitation_returns_silent_no_op() {
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_id = alice_kp.identity_id();
    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "Group".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    alice_gm.ensure_group_key(group_id).unwrap();
    // Don't create an invitation — Alice knows nothing about this code.

    let bob_kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _kyber_secret) = generate_ephemeral_kyber();
    let body = RequestJoinBody {
        group_id,
        invitation_code: "no-such-invite".to_string(),
        joiner_public_key: bob_kp.public_key(),
        joiner_display_name: "Bob".to_string(),
        joiner_kyber_pub: kyber_pub,
    };
    let signed = sign_request_join(&bob_kp, body.clone()).unwrap();
    let (req_body, req_sig) = match signed {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        _ => unreachable!(),
    };

    let outcome = process_request_join(&mut alice_gm, &alice_kp, &req_body, &req_sig).unwrap();
    assert!(matches!(outcome, HandshakeOutcome::UnknownInvitation));
}

#[test]
fn enforces_sixteen_member_cap_via_handshake() {
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_id = alice_kp.identity_id();
    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "Capped".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    alice_gm.ensure_group_key(group_id).unwrap();

    // Fill the group up to the 16-cap (creator + 15 members) using the
    // direct add_member API, then try a 17th via the handshake.
    use qubee_crypto::groups::group_permissions::Role;
    for _ in 0..15 {
        let m = IdentityKeyPair::generate().unwrap();
        alice_gm
            .add_member(
                group_id,
                alice_id,
                m.identity_id(),
                m.public_key(),
                "Filler".to_string(),
                Role::Member,
            )
            .unwrap();
    }
    assert_eq!(alice_gm.get_group(&group_id).unwrap().members.len(), 16);

    let invitation = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .unwrap();
    let bob_kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _) = generate_ephemeral_kyber();
    let body = RequestJoinBody {
        group_id,
        invitation_code: invitation.invitation_code.clone(),
        joiner_public_key: bob_kp.public_key(),
        joiner_display_name: "Bob".to_string(),
        joiner_kyber_pub: kyber_pub,
    };
    let signed = sign_request_join(&bob_kp, body.clone()).unwrap();
    let (req_body, req_sig) = match signed {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        _ => unreachable!(),
    };

    let outcome = process_request_join(&mut alice_gm, &alice_kp, &req_body, &req_sig).unwrap();
    match outcome {
        HandshakeOutcome::Reject { body, .. } => {
            assert!(
                body.reason.contains("limit") || body.reason.contains("max"),
                "expected cap-related reject, got {}",
                body.reason
            );
        }
        other => panic!("expected Reject for capped group, got {other:?}"),
    }

    // Group still has exactly 16 members.
    assert_eq!(alice_gm.get_group(&group_id).unwrap().members.len(), 16);
}
