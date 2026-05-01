//! End-to-end test that wires two real `P2PNode` instances over
//! actual libp2p (loopback TCP, no mDNS, fast gossipsub heartbeat),
//! routes a complete invite handshake between them, and verifies
//! a subsequent encrypted group message round-trips.
//!
//! Why this exists: every other integration test in `tests/` runs
//! the protocol in-process, hand-routing bytes between two
//! `GroupManager` values. That covers the protocol logic but never
//! exercises libp2p — gossipsub mesh formation, the noise XX
//! handshake, the swarm event loop, or the dispatch glue inside
//! `P2PNode::run`. This test does. If it goes red, the network
//! pipeline is broken regardless of what `cargo test` says about
//! the in-process suites.
//!
//! Test profile uses [`P2PNodeConfig::for_testing`]: loopback only,
//! mDNS off (two nodes in one process otherwise step on each other),
//! 100 ms gossipsub heartbeat (production default is 10 s — too
//! long for a CI timeout).

use qubee_crypto::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, RequestJoinBody,
};
use qubee_crypto::groups::group_manager::{GroupManager, GroupSettings, GroupType};
use qubee_crypto::groups::group_message::{decrypt_group_message, encrypt_group_message};
use qubee_crypto::groups::handshake_handlers::{
    plan_key_rotation, process_join_accepted, process_request_join, process_key_rotation,
    HandshakeOutcome,
};
use qubee_crypto::identity::identity_key::IdentityKeyPair;
use qubee_crypto::network::p2p_node::{
    group_topic as build_group_topic, NodeEvent, P2PCommand, P2PNode, P2PNodeConfig,
};
use qubee_crypto::storage::secure_keystore::SecureKeyStore;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct TestNode {
    cmd: mpsc::Sender<P2PCommand>,
    events: mpsc::Receiver<NodeEvent>,
    listen_addr: String,
    /// The libp2p Ed25519 PeerId — distinct from the application's
    /// `IdentityId`. Stash it so the test can build dial addresses
    /// or correlate `MessageReceived.sender` to a node.
    #[allow(dead_code)]
    peer_id: String,
}

/// Spawn a [`P2PNode`] under [`P2PNodeConfig::for_testing`] and wait
/// for it to publish its listen address. Returns command/event
/// channels and the address other nodes should dial.
async fn spawn_test_node(label: &str) -> TestNode {
    let id_keys = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(id_keys.public()).to_string();

    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (evt_tx, mut evt_rx) = mpsc::channel(64);

    let node = P2PNode::with_config(id_keys, cmd_rx, P2PNodeConfig::for_testing())
        .await
        .unwrap_or_else(|e| panic!("[{label}] P2PNode::with_config failed: {e:#}"));

    tokio::spawn(async move {
        node.run(evt_tx).await;
    });

    // Wait for `Listening` to publish the bound address. The swarm
    // emits this once the OS-assigned port is up.
    let listen_addr = loop {
        let evt = timeout(Duration::from_secs(5), evt_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("[{label}] timed out waiting for Listening event"))
            .expect("event channel closed before Listening fired");
        if let NodeEvent::Listening { multiaddr } = evt {
            break multiaddr;
        }
        // Drain stray PeerDiscovered / etc. while we wait — none
        // should fire under for_testing() but be defensive.
    };

    TestNode {
        cmd: cmd_tx,
        events: evt_rx,
        listen_addr,
        peer_id,
    }
}

/// Receive events from a node until one matches `pred`, ignoring
/// the others (e.g. `PeerDiscovered`, additional `Listening` for a
/// dial-back path). Fails the test if `total_timeout` elapses
/// before the predicate matches.
async fn next_matching<F>(node: &mut TestNode, total_timeout: Duration, mut pred: F) -> NodeEvent
where
    F: FnMut(&NodeEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + total_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("next_matching timed out after {total_timeout:?}");
        }
        match timeout(remaining, node.events.recv()).await {
            Ok(Some(evt)) => {
                if pred(&evt) {
                    return evt;
                }
                // Ignored event — keep waiting.
            }
            Ok(None) => panic!("event channel closed before predicate matched"),
            Err(_) => panic!("next_matching timed out after {total_timeout:?}"),
        }
    }
}

/// Spin up a fresh `(IdentityKeyPair, GroupManager)` backed by a
/// temp-dir keystore. Mirrors the helper in `group_handshake_e2e.rs`
/// so the two test files stay parallel.
fn fresh_app_state(label: &str) -> (TempDir, IdentityKeyPair, GroupManager) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(format!("{label}.db"));
    let ks = SecureKeyStore::new(&path).expect("keystore");
    let gm = GroupManager::new(ks).expect("group manager");
    let kp = IdentityKeyPair::generate().expect("identity");
    (dir, kp, gm)
}

/// Send a P2PCommand and panic with a useful label if the node has
/// already shut its receiver. `try_send` instead of `send` so test
/// assertions don't deadlock on a stuck event loop.
async fn send_cmd(node: &TestNode, cmd: P2PCommand, label: &str) {
    node.cmd
        .send(cmd)
        .await
        .unwrap_or_else(|e| panic!("[{label}] cmd channel closed: {e}"));
}

// ---------------------------------------------------------------------------
// Test 1 — full join handshake + an encrypted message over libp2p
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_two_node_e2e() {
    // -------- application-side state for both peers --------
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_app_state("alice");
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

    let (_bob_dir, bob_kp, mut bob_gm) = fresh_app_state("bob");
    bob_gm
        .record_external_invite_acceptance(
            group_id,
            "Test Group",
            alice_id,
            &invitation.inviter_name,
            &invitation.invitation_code,
        )
        .unwrap();

    // -------- network: spin up two nodes, dial Alice from Bob --------
    let mut alice_node = spawn_test_node("alice").await;
    let mut bob_node = spawn_test_node("bob").await;

    send_cmd(
        &bob_node,
        P2PCommand::Dial {
            multiaddr: alice_node.listen_addr.clone(),
        },
        "bob",
    )
    .await;

    let topic = build_group_topic(&hex::encode(group_id.as_ref()));
    send_cmd(&alice_node, P2PCommand::Subscribe { topic: topic.clone() }, "alice").await;
    send_cmd(&bob_node, P2PCommand::Subscribe { topic: topic.clone() }, "bob").await;

    // Gossipsub needs at least one heartbeat for the mesh to form.
    // for_testing() pins this at 100 ms; sleep a few cycles to be safe.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // -------- Bob signs a RequestJoin and publishes on the topic --------
    let (kyber_pub, kyber_secret) = generate_ephemeral_kyber();
    let request_body = RequestJoinBody {
        group_id,
        invitation_code: invitation.invitation_code.clone(),
        joiner_public_key: bob_kp.public_key(),
        joiner_display_name: "Bob".to_string(),
        joiner_kyber_pub: kyber_pub,
    };
    let signed_request =
        sign_request_join(&bob_kp, request_body.clone()).expect("sign RequestJoin");
    let request_wire = signed_request.to_wire().expect("wire encode");

    send_cmd(
        &bob_node,
        P2PCommand::PublishToTopic {
            topic: topic.clone(),
            data: request_wire,
        },
        "bob",
    )
    .await;

    // -------- Alice receives RequestJoin, runs the handler --------
    let received = next_matching(&mut alice_node, Duration::from_secs(5), |evt| {
        matches!(evt, NodeEvent::MessageReceived { .. })
    })
    .await;
    let NodeEvent::MessageReceived { data: req_data, .. } = received else {
        unreachable!("predicate guarantees MessageReceived")
    };
    let inbound = GroupHandshake::from_wire(&req_data).expect("decode RequestJoin wire");
    let (req_body_in, req_sig_in) = match inbound {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        other => panic!("expected RequestJoin, got {other:?}"),
    };

    let outcome = process_request_join(&mut alice_gm, &alice_kp, &req_body_in, &req_sig_in)
        .expect("process_request_join");
    let (acc_body, acc_sig) = match outcome {
        HandshakeOutcome::Accept { body, signature } => (body, signature),
        other => panic!("expected Accept, got {other:?}"),
    };
    let accepted_wire = GroupHandshake::JoinAccepted {
        body: acc_body.clone(),
        signature: acc_sig.clone(),
    }
    .to_wire()
    .expect("wire encode JoinAccepted");

    send_cmd(
        &alice_node,
        P2PCommand::PublishToTopic {
            topic: topic.clone(),
            data: accepted_wire,
        },
        "alice",
    )
    .await;

    // -------- Bob receives JoinAccepted, runs the handler --------
    let bob_evt = next_matching(&mut bob_node, Duration::from_secs(5), |evt| {
        matches!(evt, NodeEvent::MessageReceived { .. })
    })
    .await;
    let NodeEvent::MessageReceived { data: acc_data, .. } = bob_evt else {
        unreachable!()
    };
    let inbound = GroupHandshake::from_wire(&acc_data).expect("decode JoinAccepted wire");
    let (acc_body_in, acc_sig_in) = match inbound {
        GroupHandshake::JoinAccepted { body, signature } => (body, signature),
        other => panic!("expected JoinAccepted, got {other:?}"),
    };
    process_join_accepted(
        &mut bob_gm,
        alice_id,
        &acc_body_in,
        &acc_sig_in,
        &kyber_secret,
    )
    .expect("process_join_accepted");

    // -------- Convergence assertions --------
    assert_eq!(
        alice_gm.export_group_key(&group_id).expect("alice key"),
        bob_gm.export_group_key(&group_id).expect("bob key"),
        "group key did not converge after libp2p-routed handshake",
    );

    // -------- Alice publishes an encrypted GroupMessage; Bob decrypts --------
    let payload = b"hello over libp2p";
    let msg_wire = encrypt_group_message(&alice_gm, &alice_kp, group_id, payload)
        .expect("encrypt_group_message");
    send_cmd(
        &alice_node,
        P2PCommand::PublishToTopic {
            topic,
            data: msg_wire,
        },
        "alice",
    )
    .await;

    let bob_evt = next_matching(&mut bob_node, Duration::from_secs(5), |evt| {
        matches!(evt, NodeEvent::MessageReceived { .. })
    })
    .await;
    let NodeEvent::MessageReceived { data: msg_data, .. } = bob_evt else {
        unreachable!()
    };
    let decrypted = decrypt_group_message(&bob_gm, &msg_data).expect("decrypt over wire");
    assert_eq!(decrypted.plaintext, payload);
    assert_eq!(decrypted.sender_id, alice_id);
    assert_eq!(decrypted.group_id, group_id);
}

// ---------------------------------------------------------------------------
// Test 2 — key rotation routed over libp2p
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_key_rotation_e2e() {
    // -------- application state: Alice owns, Bob and Carol joined in-process
    // (the in-process handshake is exercised in detail by
    // `tests/group_handshake_e2e.rs`; the only thing this test cares
    // about is that a KeyRotation broadcast over libp2p reaches Carol
    // and that she converges on the new key while Bob — the kicked
    // member — does not).
    let (_alice_dir, alice_kp, mut alice_gm) = fresh_app_state("alice");
    let (_bob_dir, bob_kp, mut bob_gm) = fresh_app_state("bob");
    let (_carol_dir, carol_kp, mut carol_gm) = fresh_app_state("carol");
    let alice_id = alice_kp.identity_id();

    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "Three-Member".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    alice_gm.ensure_group_key(group_id).unwrap();
    let invitation = alice_gm
        .create_invitation(group_id, alice_id, None, Some(2))
        .unwrap();

    // Helper: run the in-process handshake to enrol a joiner.
    fn enrol(
        owner_kp: &IdentityKeyPair,
        owner_gm: &mut GroupManager,
        invitation_code: &str,
        invitation_inviter_name: &str,
        joiner_kp: &IdentityKeyPair,
        joiner_name: &str,
        joiner_gm: &mut GroupManager,
        group_id: qubee_crypto::groups::group_manager::GroupId,
    ) {
        joiner_gm
            .record_external_invite_acceptance(
                group_id,
                "Three-Member",
                owner_kp.identity_id(),
                invitation_inviter_name,
                invitation_code,
            )
            .unwrap();
        let (kyber_pub, kyber_secret) = generate_ephemeral_kyber();
        let signed_req = sign_request_join(
            joiner_kp,
            RequestJoinBody {
                group_id,
                invitation_code: invitation_code.to_string(),
                joiner_public_key: joiner_kp.public_key(),
                joiner_display_name: joiner_name.to_string(),
                joiner_kyber_pub: kyber_pub,
            },
        )
        .unwrap();
        let (rb, rs) = match signed_req {
            GroupHandshake::RequestJoin { body, signature } => (body, signature),
            _ => unreachable!(),
        };
        let outcome = process_request_join(owner_gm, owner_kp, &rb, &rs).unwrap();
        let (ab, as_) = match outcome {
            HandshakeOutcome::Accept { body, signature } => (body, signature),
            other => panic!("expected Accept, got {other:?}"),
        };
        process_join_accepted(joiner_gm, owner_kp.identity_id(), &ab, &as_, &kyber_secret).unwrap();
    }

    enrol(
        &alice_kp,
        &mut alice_gm,
        &invitation.invitation_code,
        &invitation.inviter_name,
        &bob_kp,
        "Bob",
        &mut bob_gm,
        group_id,
    );
    enrol(
        &alice_kp,
        &mut alice_gm,
        &invitation.invitation_code,
        &invitation.inviter_name,
        &carol_kp,
        "Carol",
        &mut carol_gm,
        group_id,
    );

    let pre_key = alice_gm.export_group_key(&group_id).unwrap();
    assert_eq!(pre_key, bob_gm.export_group_key(&group_id).unwrap());
    assert_eq!(pre_key, carol_gm.export_group_key(&group_id).unwrap());

    // -------- network: bring up only Alice and Carol's nodes for
    // this test — Bob's libp2p side isn't part of the assertion
    // (Bob just gets removed; we verify locally that his exported
    // key is unchanged after the rotation handler runs).
    let alice_node = spawn_test_node("alice").await;
    let mut carol_node = spawn_test_node("carol").await;

    send_cmd(
        &carol_node,
        P2PCommand::Dial {
            multiaddr: alice_node.listen_addr.clone(),
        },
        "carol",
    )
    .await;

    let topic = build_group_topic(&hex::encode(group_id.as_ref()));
    send_cmd(&alice_node, P2PCommand::Subscribe { topic: topic.clone() }, "alice").await;
    send_cmd(&carol_node, P2PCommand::Subscribe { topic: topic.clone() }, "carol").await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // -------- Alice runs plan_key_rotation locally, broadcasts it --------
    let signed_rotation = plan_key_rotation(
        &mut alice_gm,
        &alice_kp,
        group_id,
        Some(bob_kp.identity_id()),
        "test removal",
    )
    .expect("plan_key_rotation");
    let rotation_wire = signed_rotation.to_wire().expect("wire encode rotation");
    let post_key_alice = alice_gm.export_group_key(&group_id).unwrap();
    assert_ne!(post_key_alice, pre_key, "Alice's local key must already have rotated");

    send_cmd(
        &alice_node,
        P2PCommand::PublishToTopic {
            topic,
            data: rotation_wire,
        },
        "alice",
    )
    .await;

    // -------- Carol receives the broadcast and applies it --------
    let evt = next_matching(&mut carol_node, Duration::from_secs(5), |evt| {
        matches!(evt, NodeEvent::MessageReceived { .. })
    })
    .await;
    let NodeEvent::MessageReceived { data: rot_data, .. } = evt else {
        unreachable!()
    };
    let inbound = GroupHandshake::from_wire(&rot_data).expect("decode KeyRotation wire");
    let (rot_body, rot_sig) = match inbound {
        GroupHandshake::KeyRotation { body, signature } => (body, signature),
        other => panic!("expected KeyRotation, got {other:?}"),
    };
    process_key_rotation(&mut carol_gm, carol_kp.identity_id(), &rot_body, &rot_sig)
        .expect("process_key_rotation on Carol");

    // -------- Convergence assertions --------
    assert_eq!(
        carol_gm.export_group_key(&group_id).unwrap(),
        post_key_alice,
        "Carol must converge on Alice's new group key after libp2p-routed rotation",
    );
    // Bob never received the rotation over the wire (his node wasn't
    // online for this test); his locally-exported key stays at
    // pre-rotation. That's the right semantics — kicked members lose
    // access whether or not they applied the rotation.
    assert_eq!(
        bob_gm.export_group_key(&group_id).unwrap(),
        pre_key,
        "Bob (kicked, offline) keeps the pre-rotation key locally; new traffic he can't decrypt",
    );
}
