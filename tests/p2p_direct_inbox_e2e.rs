//! Network-level proof for the route-less QUBEE_DMS bootstrap path.
//!
//! A sender that does not yet know the recipient's authenticated libp2p
//! PeerId publishes the already-encrypted direct frame only to the
//! recipient's rotating blinded inbox topic. This test uses three real
//! libp2p nodes over loopback and proves that:
//!
//! * the intended recipient receives the frame;
//! * gossipsub authorship remains anonymous (`sender == ""`);
//! * a connected but unsubscribed third peer does not receive the frame.
//!
//! The payload here is an opaque marker rather than a real QUBEE_DMS frame:
//! this test owns the network isolation property. Ratchet recipient binding,
//! encrypted route hints, and wire parsing are covered in the direct-ratchet
//! integration/unit suites.

use qubee_crypto::network::p2p_node::{
    direct_inbox_topic, NodeEvent, P2PCommand, P2PNode, P2PNodeConfig,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};

struct TestNode {
    cmd: mpsc::Sender<P2PCommand>,
    events: mpsc::Receiver<NodeEvent>,
    listen_addr: String,
}

async fn spawn_test_node(label: &str) -> TestNode {
    let id_keys = libp2p::identity::Keypair::generate_ed25519();
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (evt_tx, mut evt_rx) = mpsc::channel(64);

    let node = P2PNode::with_config(id_keys, cmd_rx, P2PNodeConfig::for_testing())
        .await
        .unwrap_or_else(|e| panic!("[{label}] P2PNode::with_config failed: {e:#}"));

    tokio::spawn(async move {
        node.run(evt_tx).await;
    });

    let listen_addr = loop {
        let event = timeout(Duration::from_secs(5), evt_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("[{label}] timed out waiting for listen address"))
            .expect("event channel closed before node started listening");
        if let NodeEvent::Listening { multiaddr } = event {
            break multiaddr;
        }
    };

    TestNode {
        cmd: cmd_tx,
        events: evt_rx,
        listen_addr,
    }
}

async fn send_cmd(node: &TestNode, cmd: P2PCommand, label: &str) {
    node.cmd
        .send(cmd)
        .await
        .unwrap_or_else(|e| panic!("[{label}] command channel closed: {e}"));
}

async fn next_matching<F>(node: &mut TestNode, total: Duration, mut pred: F) -> NodeEvent
where
    F: FnMut(&NodeEvent) -> bool,
{
    let deadline = Instant::now() + total;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for matching event");
        match timeout(remaining, node.events.recv()).await {
            Ok(Some(event)) if pred(&event) => return event,
            Ok(Some(_)) => continue,
            Ok(None) => panic!("event channel closed before matching event"),
            Err(_) => panic!("timed out waiting for matching event"),
        }
    }
}

async fn assert_payload_not_received(node: &mut TestNode, payload: &[u8], total: Duration) {
    let deadline = Instant::now() + total;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        match timeout(remaining, node.events.recv()).await {
            Ok(Some(NodeEvent::MessageReceived { data, .. })) if data == payload => {
                panic!("unsubscribed peer received direct-inbox payload")
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blinded_direct_inbox_reaches_only_the_subscribed_recipient() {
    let mut alice = spawn_test_node("alice").await;
    let mut bob = spawn_test_node("bob").await;
    let mut carol = spawn_test_node("carol").await;

    // Bob and Carol are both connected to Alice. Carol is deliberately not
    // subscribed to Bob's inbox, so simple network adjacency must not be enough
    // to expose Bob's route-less direct frame.
    send_cmd(
        &bob,
        P2PCommand::Dial {
            multiaddr: alice.listen_addr.clone(),
        },
        "bob",
    )
    .await;
    send_cmd(
        &carol,
        P2PCommand::Dial {
            multiaddr: alice.listen_addr.clone(),
        },
        "carol",
    )
    .await;

    let bob_identity =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let expected_topic = direct_inbox_topic(&bob_identity);

    // Pre-follow on sender + recipient so the gossipsub mesh exists before the
    // first publish. Production PublishDirectInbox also follows automatically;
    // if that first enqueue beats mesh formation, the durable retry sends the
    // exact same wire again after the mesh has converged.
    send_cmd(
        &alice,
        P2PCommand::FollowDirectInbox {
            identity_id_hex: bob_identity.clone(),
        },
        "alice",
    )
    .await;
    send_cmd(
        &bob,
        P2PCommand::FollowDirectInbox {
            identity_id_hex: bob_identity.clone(),
        },
        "bob",
    )
    .await;

    // Test config uses a 100 ms gossipsub heartbeat. Several cycles makes the
    // test deterministic without depending on implementation timing.
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    let payload = b"opaque-qdm-bootstrap-frame".to_vec();
    send_cmd(
        &alice,
        P2PCommand::PublishDirectInbox {
            recipient_id_hex: bob_identity,
            data: payload.clone(),
        },
        "alice",
    )
    .await;

    let event = next_matching(&mut bob, Duration::from_secs(5), |event| {
        matches!(
            event,
            NodeEvent::MessageReceived { topic, data, .. }
                if topic == &expected_topic && data == &payload
        )
    })
    .await;

    let NodeEvent::MessageReceived {
        sender,
        topic,
        data,
    } = event
    else {
        unreachable!("predicate guarantees MessageReceived")
    };
    assert!(sender.is_empty(), "direct inbox must preserve anonymous gossip authorship");
    assert_eq!(topic, expected_topic);
    assert_eq!(data, payload);

    assert_payload_not_received(&mut carol, &payload, Duration::from_millis(800)).await;
}
