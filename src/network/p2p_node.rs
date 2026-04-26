// src/network/p2p_node.rs
//
// libp2p 0.55 swarm wired to gossipsub + Kademlia + (optional) mDNS.

use anyhow::{anyhow, Result};
use futures::StreamExt;
use libp2p::{
    gossipsub, identity::Keypair, kad, mdns, noise,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

// --- Data Structures ---

/// Commands sent from Android (Kotlin) -> Rust
#[derive(Debug)]
pub enum P2PCommand {
    /// Send a message to a specific peer or broadcast on the global topic.
    SendMessage { peer_id: String, data: Vec<u8> },
    /// Try to find a peer by their ID in the DHT
    FindPeer { peer_id: String },
    /// Subscribe to a named gossipsub topic. Idempotent.
    Subscribe { topic: String },
    /// Stop receiving traffic on a named gossipsub topic.
    Unsubscribe { topic: String },
    /// Publish bytes on a named gossipsub topic. The local node must be
    /// subscribed for the publish to actually go out — gossipsub
    /// silently drops publishes on topics with no local subscription.
    PublishToTopic { topic: String, data: Vec<u8> },
    /// Dial a peer at a known multiaddress. Used by integration tests
    /// that skip mDNS; production peers find each other via Kademlia
    /// or the local-network mDNS sweep.
    Dial { multiaddr: String },
}

/// Public helper so callers (JNI, tests) build the per-group topic
/// name in exactly one place.
pub fn group_topic(group_id_hex: &str) -> String {
    format!("qubee-group-{}", group_id_hex)
}

/// Events sent from Rust -> Android (Kotlin)
#[derive(Debug)]
pub enum NodeEvent {
    /// Received a message from the network
    MessageReceived {
        sender: String,
        topic: String,
        data: Vec<u8>,
    },
    /// Discovered a new peer (via mDNS or DHT)
    PeerDiscovered { peer_id: String },
    /// The swarm picked up a new listen address. Tests use this to
    /// learn what address node A bound to so node B can dial it.
    Listening { multiaddr: String },
}

/// Tunables for `P2PNode`. Production callers should use
/// [`P2PNodeConfig::default`]; tests should use
/// [`P2PNodeConfig::for_testing`] which (a) disables mDNS so two
/// nodes in the same process don't step on each other's discovery,
/// (b) binds to `127.0.0.1` so test runs don't leak onto the LAN,
/// and (c) shortens the gossipsub heartbeat so mesh formation
/// completes inside a normal test timeout.
#[derive(Clone)]
pub struct P2PNodeConfig {
    pub enable_mdns: bool,
    pub listen_addr: Multiaddr,
    pub gossipsub_heartbeat: Duration,
    pub gossipsub_validation_mode: gossipsub::ValidationMode,
    pub idle_connection_timeout: Duration,
}

impl Default for P2PNodeConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().expect("hardcoded multiaddr"),
            gossipsub_heartbeat: Duration::from_secs(10),
            gossipsub_validation_mode: gossipsub::ValidationMode::Strict,
            idle_connection_timeout: Duration::from_secs(60),
        }
    }
}

impl P2PNodeConfig {
    /// Test profile: loopback, no mDNS, 100 ms gossipsub heartbeat.
    /// Used by `tests/p2p_two_node_e2e.rs`.
    pub fn for_testing() -> Self {
        Self {
            enable_mdns: false,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().expect("hardcoded multiaddr"),
            gossipsub_heartbeat: Duration::from_millis(100),
            gossipsub_validation_mode: gossipsub::ValidationMode::Strict,
            idle_connection_timeout: Duration::from_secs(60),
        }
    }
}

/// Composed network behaviour. The derive expands a sibling
/// `QubeeBehaviourEvent` enum that we match on inside the run loop.
/// `mdns` is wrapped in `Toggle` so the test profile can disable it
/// without forking the behaviour struct.
#[derive(NetworkBehaviour)]
struct QubeeBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    mdns: Toggle<mdns::tokio::Behaviour>,
}

// --- The P2P Node ---

pub struct P2PNode {
    swarm: Swarm<QubeeBehaviour>,
    command_receiver: mpsc::Receiver<P2PCommand>,
}

const GLOBAL_TOPIC: &str = "qubee-global";

impl P2PNode {
    /// Create a new P2P node with production defaults.
    pub async fn new(
        id_keys: Keypair,
        command_receiver: mpsc::Receiver<P2PCommand>,
    ) -> Result<Self> {
        Self::with_config(id_keys, command_receiver, P2PNodeConfig::default()).await
    }

    /// Create a new P2P node from a custom [`P2PNodeConfig`]. Used by
    /// tests via [`P2PNodeConfig::for_testing`].
    pub async fn with_config(
        id_keys: Keypair,
        command_receiver: mpsc::Receiver<P2PCommand>,
        config: P2PNodeConfig,
    ) -> Result<Self> {
        let cfg_for_behaviour = config.clone();
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| anyhow!("tcp transport: {e}"))?
            .with_behaviour(|key| {
                let peer_id = PeerId::from(key.public());

                let gossipsub_cfg = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(cfg_for_behaviour.gossipsub_heartbeat)
                    .validation_mode(cfg_for_behaviour.gossipsub_validation_mode.clone())
                    .build()
                    .map_err(|s| std::io::Error::new(std::io::ErrorKind::Other, s))?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_cfg,
                )
                .map_err(|s| std::io::Error::new(std::io::ErrorKind::Other, s))?;

                let kad_store = kad::store::MemoryStore::new(peer_id);
                let mut kademlia = kad::Behaviour::new(peer_id, kad_store);
                kademlia.set_mode(Some(kad::Mode::Server));

                let mdns: Toggle<mdns::tokio::Behaviour> = if cfg_for_behaviour.enable_mdns {
                    Some(mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        peer_id,
                    )?)
                    .into()
                } else {
                    None.into()
                };

                Ok(QubeeBehaviour {
                    gossipsub,
                    kademlia,
                    mdns,
                })
            })
            .map_err(|e| anyhow!("behaviour: {e}"))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(config.idle_connection_timeout))
            .build();

        swarm.listen_on(config.listen_addr.clone())?;

        Ok(Self {
            swarm,
            command_receiver,
        })
    }

    /// Main event loop. Drives the swarm forward and translates
    /// behaviour events into [`NodeEvent`] messages for Kotlin.
    pub async fn run(mut self, event_sender: mpsc::Sender<NodeEvent>) {
        let chat_topic = gossipsub::IdentTopic::new(GLOBAL_TOPIC);
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&chat_topic)
        {
            eprintln!("Failed to subscribe to topic: {e:?}");
        }

        loop {
            tokio::select! {
                command = self.command_receiver.recv() => match command {
                    Some(P2PCommand::SendMessage { peer_id: _, data }) => {
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(chat_topic.clone(), data)
                        {
                            eprintln!("Publish error: {e:?}");
                        }
                    }
                    Some(P2PCommand::FindPeer { peer_id }) => {
                        match PeerId::from_str(&peer_id) {
                            Ok(pid) => { let _ = self.swarm.behaviour_mut().kademlia.get_closest_peers(pid); }
                            Err(e) => eprintln!("Invalid peer id {peer_id}: {e}"),
                        }
                    }
                    Some(P2PCommand::Subscribe { topic }) => {
                        let topic = gossipsub::IdentTopic::new(topic);
                        if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                            eprintln!("Subscribe error for {topic}: {e:?}");
                        }
                    }
                    Some(P2PCommand::Unsubscribe { topic }) => {
                        let topic = gossipsub::IdentTopic::new(topic);
                        // libp2p 0.55 changed `gossipsub.unsubscribe` to
                        // return `bool` (true if we were subscribed) —
                        // it no longer fails. Log a hint when we
                        // weren't subscribed so the dispatcher's
                        // intent is still observable.
                        if !self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                            eprintln!("Unsubscribe no-op for {topic} (not subscribed)");
                        }
                    }
                    Some(P2PCommand::PublishToTopic { topic, data }) => {
                        let topic = gossipsub::IdentTopic::new(topic);
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), data)
                        {
                            eprintln!("PublishToTopic {topic} error: {e:?}");
                        }
                    }
                    Some(P2PCommand::Dial { multiaddr }) => {
                        match multiaddr.parse::<Multiaddr>() {
                            Ok(addr) => {
                                if let Err(e) = self.swarm.dial(addr) {
                                    eprintln!("Dial error for {multiaddr}: {e:?}");
                                }
                            }
                            Err(e) => eprintln!("Invalid multiaddr {multiaddr}: {e}"),
                        }
                    }
                    None => return,
                },

                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let _ = event_sender
                            .send(NodeEvent::Listening { multiaddr: address.to_string() })
                            .await;
                    }
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                            let _ = event_sender
                                .send(NodeEvent::PeerDiscovered { peer_id: peer_id.to_string() })
                                .await;
                        }
                    }
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
                        let _ = event_sender
                            .send(NodeEvent::PeerDiscovered { peer_id: peer.to_string() })
                            .await;
                    }
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    })) => {
                        let _ = event_sender
                            .send(NodeEvent::MessageReceived {
                                sender: propagation_source.to_string(),
                                topic: message.topic.into_string(),
                                data: message.data,
                            })
                            .await;
                    }
                    _ => {}
                }
            }
        }
    }
}
