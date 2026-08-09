from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, got {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# Network: persistent subscription only for an identity's OWN inbox.
# Publishers subscribe transiently, wait for mesh formation, publish, then
# unsubscribe. This prevents a sender from becoming a permanent observer of
# every recipient inbox it has ever bootstrapped.
# ---------------------------------------------------------------------------
path = "src/network/p2p_node.rs"
replace_once(
    path,
    '''    /// Publish a route-less direct frame to one recipient's blinded inbox.
    /// The node also follows the inbox so mesh formation can complete before
    /// later exact-wire retries.
    PublishDirectInbox {
''',
    '''    /// Publish a route-less direct frame to one recipient's blinded inbox.
    /// The publisher subscribes only transiently: enough for gossipsub mesh
    /// formation + publish, then the topic is dropped unless it is this node's
    /// own persistently-followed inbox.
    PublishDirectInbox {
''',
)

replace_once(
    path,
    '''const TOPIC_RESYNC_INTERVAL: Duration = Duration::from_secs(300);
''',
    '''const TOPIC_RESYNC_INTERVAL: Duration = Duration::from_secs(300);
/// Gossipsub needs a local subscription + a few heartbeats before a newly
/// joined topic has peers to publish to. Keep bootstrap subscriptions short-
/// lived and retry locally a few times before handing recovery back to the
/// durable message retry loop.
const DIRECT_INBOX_PUBLISH_TICK: Duration = Duration::from_millis(100);
const DIRECT_INBOX_MESH_WAIT: Duration = Duration::from_millis(350);
const DIRECT_INBOX_MAX_LOCAL_ATTEMPTS: u8 = 3;
''',
)

replace_once(
    path,
    '''// --- The P2P Node ---

pub struct P2PNode {
''',
    '''// --- The P2P Node ---

struct PendingDirectInboxPublish {
    topic: String,
    data: Vec<u8>,
    ready_at: tokio::time::Instant,
    attempts: u8,
}

pub struct P2PNode {
''',
)

replace_once(
    path,
    '''    followed_direct_inboxes: HashSet<String>,
    live_direct_inbox_topics: HashSet<String>,
}
''',
    '''    followed_direct_inboxes: HashSet<String>,
    live_direct_inbox_topics: HashSet<String>,
    pending_direct_inbox_publishes: Vec<PendingDirectInboxPublish>,
}
''',
)

replace_once(
    path,
    '''            followed_direct_inboxes: HashSet::new(),
            live_direct_inbox_topics: HashSet::new(),
        })
''',
    '''            followed_direct_inboxes: HashSet::new(),
            live_direct_inbox_topics: HashSet::new(),
            pending_direct_inbox_publishes: Vec::new(),
        })
''',
)

replace_once(
    path,
    '''        self.live_direct_inbox_topics = desired;
    }

    /// Main event loop. Drives the swarm forward and translates
''',
    '''        self.live_direct_inbox_topics = desired;
    }

    /// Flush bootstrap publications after their short mesh-formation delay.
    /// A publisher must never become a long-lived subscriber to someone
    /// else's inbox: on success (or local retry exhaustion) remove the
    /// temporary subscription unless the topic is also one of our own live
    /// inbox-window topics.
    fn flush_pending_direct_inbox_publishes(&mut self) {
        let now = tokio::time::Instant::now();
        let pending = std::mem::take(&mut self.pending_direct_inbox_publishes);
        let mut keep = Vec::with_capacity(pending.len());

        for mut item in pending {
            if item.ready_at > now {
                keep.push(item);
                continue;
            }

            let topic = gossipsub::IdentTopic::new(item.topic.clone());
            match self
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), item.data.clone())
            {
                Ok(_) => {
                    if !self.live_direct_inbox_topics.contains(&item.topic) {
                        self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                    }
                }
                Err(e) => {
                    item.attempts = item.attempts.saturating_add(1);
                    if item.attempts < DIRECT_INBOX_MAX_LOCAL_ATTEMPTS {
                        item.ready_at = now + DIRECT_INBOX_MESH_WAIT;
                        keep.push(item);
                    } else {
                        eprintln!(
                            "PublishDirectInbox {} exhausted local attempts: {e:?}",
                            item.topic
                        );
                        if !self.live_direct_inbox_topics.contains(&item.topic) {
                            self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                        }
                    }
                }
            }
        }

        self.pending_direct_inbox_publishes = keep;
    }

    /// Main event loop. Drives the swarm forward and translates
''',
)

replace_once(
    path,
    '''        let mut topic_resync = tokio::time::interval(TOPIC_RESYNC_INTERVAL);
        topic_resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = topic_resync.tick() => {
                    self.resync_group_topics();
                    self.resync_direct_inbox_topics();
                }
''',
    '''        let mut topic_resync = tokio::time::interval(TOPIC_RESYNC_INTERVAL);
        topic_resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut direct_inbox_publish_tick = tokio::time::interval(DIRECT_INBOX_PUBLISH_TICK);
        direct_inbox_publish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = topic_resync.tick() => {
                    self.resync_group_topics();
                    self.resync_direct_inbox_topics();
                }
                _ = direct_inbox_publish_tick.tick() => {
                    self.flush_pending_direct_inbox_publishes();
                }
''',
)

replace_once(
    path,
    '''                    Some(P2PCommand::PublishDirectInbox { recipient_id_hex, data }) => {
                        if self.followed_direct_inboxes.insert(recipient_id_hex.clone()) {
                            self.resync_direct_inbox_topics();
                        }
                        let topic = gossipsub::IdentTopic::new(direct_inbox_topic(&recipient_id_hex));
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), data)
                        {
                            eprintln!("PublishDirectInbox {topic} error: {e:?}");
                        }
                    }
''',
    '''                    Some(P2PCommand::PublishDirectInbox { recipient_id_hex, data }) => {
                        let topic_name = direct_inbox_topic(&recipient_id_hex);
                        let topic = gossipsub::IdentTopic::new(topic_name.clone());
                        match self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                            Ok(_) => {
                                self.pending_direct_inbox_publishes.push(PendingDirectInboxPublish {
                                    topic: topic_name,
                                    data,
                                    ready_at: tokio::time::Instant::now() + DIRECT_INBOX_MESH_WAIT,
                                    attempts: 0,
                                });
                            }
                            Err(e) => {
                                eprintln!("PublishDirectInbox temporary subscribe {topic} failed: {e:?}");
                            }
                        }
                    }
''',
)

# ---------------------------------------------------------------------------
# Network e2e: remove publisher pre-follow and prove the publisher is gone from
# the inbox before another sender publishes a later message for Bob.
# ---------------------------------------------------------------------------
path = "tests/p2p_direct_inbox_e2e.rs"
p = Path(path)
text = p.read_text()
start = text.index('#[tokio::test(flavor = "multi_thread", worker_threads = 4)]')
prefix = text[:start]
new_test = r'''#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blinded_direct_inbox_reaches_only_the_recipient_and_publishers_leave() {
    let mut alice = spawn_test_node("alice").await;
    let mut bob = spawn_test_node("bob").await;
    let mut carol = spawn_test_node("carol").await;

    // Both potential senders connect directly to Bob. Only Bob follows Bob's
    // inbox persistently; publishers must not remain subscribed after use.
    send_cmd(
        &alice,
        P2PCommand::Dial {
            multiaddr: bob.listen_addr.clone(),
        },
        "alice",
    )
    .await;
    send_cmd(
        &carol,
        P2PCommand::Dial {
            multiaddr: bob.listen_addr.clone(),
        },
        "carol",
    )
    .await;

    let bob_identity =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let expected_topic = direct_inbox_topic(&bob_identity);
    send_cmd(
        &bob,
        P2PCommand::FollowDirectInbox {
            identity_id_hex: bob_identity.clone(),
        },
        "bob",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(700)).await;

    // Alice bootstraps a route-less frame without persistently following Bob.
    let first = b"opaque-qdm-bootstrap-from-alice".to_vec();
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
        matches!(
            event,
            NodeEvent::MessageReceived { topic, data, .. }
                if topic == &expected_topic && data == &first
        )
    })
    .await;
    let NodeEvent::MessageReceived { sender, .. } = event else {
        unreachable!("predicate guarantees MessageReceived")
    };
    assert!(
        sender.is_empty(),
        "direct inbox must preserve anonymous gossip authorship"
    );

    // Carol was connected to Bob but not subscribed, so Alice's inbox frame
    // must not be application-delivered to Carol.
    assert_payload_not_received(&mut carol, &first, Duration::from_millis(700)).await;

    // Alice's temporary publish subscription should now be gone. Let Carol
    // publish a second frame to Bob; Bob gets it, but Alice must not become a
    // passive observer merely because she used Bob's inbox earlier.
    let second = b"opaque-qdm-bootstrap-from-carol".to_vec();
    send_cmd(
        &carol,
        P2PCommand::PublishDirectInbox {
            recipient_id_hex: bob_identity,
            data: second.clone(),
        },
        "carol",
    )
    .await;

    let second_event = next_matching(&mut bob, Duration::from_secs(5), |event| {
        matches!(
            event,
            NodeEvent::MessageReceived { topic, data, .. }
                if topic == &expected_topic && data == &second
        )
    })
    .await;
    let NodeEvent::MessageReceived { sender, .. } = second_event else {
        unreachable!("predicate guarantees MessageReceived")
    };
    assert!(sender.is_empty());

    assert_payload_not_received(&mut alice, &second, Duration::from_millis(900)).await;
}
'''
p.write_text(prefix + new_test)

# ---------------------------------------------------------------------------
# Comments/docs correctness cleanup.
# ---------------------------------------------------------------------------
path = "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt"
replace_once(
    path,
    '''    /// Once an ack lands `applyAckTransactional` moves the row to DELIVERED and
    /// the row to `DELIVERED` on first ack and `nextRetryAt` is
    /// cleared then), carrying preserved `wireBytes`, with a retry
''',
    '''    /// Once an ack lands `applyAckTransactional` moves the row to `DELIVERED`
    /// and clears `nextRetryAt`; until then the preserved `wireBytes` remain
    /// eligible for bounded retry.
''',
)

path = "src/jni_api.rs"
replace_once(
    path,
    '''/// Forward-secret QUBEE_DMS frames are never gossip-published: their v2
/// envelope carries the intended Qubee IdentityId, which is resolved through
''',
    '''/// Forward-secret QUBEE_DMS frames are never published on the global gossip
/// topic: their v2 envelope carries the intended Qubee IdentityId, resolved through
''',
)

path = "docs/double-ratchet-design.md"
replace_once(
    path,
    '''published only to the recipient's rotating blinded direct-inbox topic — never to
`qubee-global`. The sender's current `PeerId` is carried inside the ratchet-encrypted
payload; after a successful decrypt the receiver binds that route to the
channel-authenticated Qubee identity and subsequent replies can upgrade to the
direct request/response transport.
''',
    '''published only to the recipient's rotating blinded direct-inbox topic — never to
`qubee-global`. The recipient follows that inbox persistently; publishers subscribe
only transiently for mesh formation + send, then drop it so prior senders cannot
passively observe later inbox traffic. The sender's current `PeerId` is carried inside
the ratchet-encrypted payload; after a successful decrypt the receiver binds that
route to the channel-authenticated Qubee identity and subsequent replies can upgrade
to the direct request/response transport.
''',
)

print("transient direct-inbox publisher patch applied")
