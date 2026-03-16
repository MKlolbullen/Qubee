// src/network/p2p_node.rs

use libp2p::{
    swarm::{NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent},
    PeerId,
    kad::{Kademlia, KademliaConfig, KademliaEvent, store::MemoryStore},
    gossipsub::{Gossipsub, GossipsubConfig, GossipsubEvent, MessageAuthenticity, IdentTopic},
    mdns::{Mdns, MdnsConfig, Event as MdnsEvent},
    identity::Keypair,
    futures::StreamExt,
};
use tokio::sync::mpsc;
use std::error::Error;
use std::time::Duration;

// --- Data Structures ---

/// Commands sent from Android (Kotlin) -> Rust
#[derive(Debug)]
pub enum P2PCommand {
    /// Send a message to a specific peer or broadcast
    SendMessage { peer_id: String, data: Vec<u8> },
    /// Try to find a peer by their ID in the DHT
    FindPeer { peer_id: String },
}

/// Events sent from Rust -> Android (Kotlin)
#[derive(Debug)]
pub enum NodeEvent {
    /// Received a message from the network
    MessageReceived { sender: String, topic: String, data: Vec<u8> },
    /// Discovered a new peer (via mDNS or DHT)
    PeerDiscovered { peer_id: String },
}

/// The network behaviour defining what protocols we use
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "QubeeBehaviourEvent")]
struct QubeeBehaviour {
    /// Gossipsub for efficient message broadcasting (Group Chats)
    gossipsub: Gossipsub,
    /// Kademlia DHT for finding peers by ID (Identity Resolution)
    kademlia: Kademlia<MemoryStore>,
    /// mDNS for local network discovery (Wi-Fi)
    mdns: Mdns,
}

/// Helper enum to wrap events from the different behaviours
#[derive(Debug)]
enum QubeeBehaviourEvent {
    Gossipsub(GossipsubEvent),
    Kademlia(KademliaEvent),
    Mdns(MdnsEvent),
}

impl From<GossipsubEvent> for QubeeBehaviourEvent {
    fn from(event: GossipsubEvent) -> Self {
        QubeeBehaviourEvent::Gossipsub(event)
    }
}

impl From<KademliaEvent> for QubeeBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        QubeeBehaviourEvent::Kademlia(event)
    }
}

impl From<MdnsEvent> for QubeeBehaviourEvent {
    fn from(event: MdnsEvent) -> Self {
        QubeeBehaviourEvent::Mdns(event)
    }
}

// --- The P2P Node ---

pub struct P2PNode {
    swarm: Swarm<QubeeBehaviour>,
    command_receiver: mpsc::Receiver<P2PCommand>,
}

impl P2PNode {
    /// Create a new P2P Node instance
    /// 
    /// # Arguments
    /// * `id_keys` - The cryptographic identity of this node
    /// * `command_receiver` - Channel to receive commands from JNI
    pub async fn new(
        id_keys: Keypair, 
        command_receiver: mpsc::Receiver<P2PCommand>
    ) -> Result<Self, Box<dyn Error>> {
        let peer_id = PeerId::from(id_keys.public());
        
        // 1. Configure Kademlia (DHT)
        // We use an in-memory store for routing tables
        let store = MemoryStore::new(peer_id);
        let mut kad_config = KademliaConfig::default();
        kad_config.set_query_timeout(Duration::from_secs(5 * 60));
        let kademlia = Kademlia::with_config(peer_id, store, kad_config);

        // 2. Configure Gossipsub (PubSub)
        // This handles the "chat room" logic efficiently
        let gossipsub_config = GossipsubConfig::default();
        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(id_keys.clone()), 
            gossipsub_config
        )?;

        // 3. Configure mDNS (Local Discovery)
        // Finds other Qubee users on the same Wi-Fi automatically
        let mdns = Mdns::new(MdnsConfig::default()).await?;

        let behaviour = QubeeBehaviour {
            gossipsub,
            kademlia,
            mdns,
        };

        // 4. Build the Swarm
        // Uses Tokio for async IO
        let swarm = SwarmBuilder::with_tokio_executor(
            libp2p::development_transport(id_keys).await?,
            behaviour,
            peer_id,
        ).build();

        Ok(Self {
            swarm,
            command_receiver,
        })
    }

    /// The main Event Loop
    /// 
    /// This method blocks the thread it runs on, processing network events
    /// and commands from the Android app.
    pub async fn run(mut self, event_sender: mpsc::Sender<NodeEvent>) {
        // Subscribe to a default global topic for testing/broadcasting
        // In a real app, you would subscribe to specific group ID topics
        let chat_topic = IdentTopic::new("qubee-global");
        
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&chat_topic) {
             eprintln!("Failed to subscribe to topic: {:?}", e);
        }

        loop {
            tokio::select! {
                // 1. Handle Commands from JNI (Kotlin)
                command = self.command_receiver.recv() => match command {
                    Some(P2PCommand::SendMessage { peer_id: _, data }) => {
                        // For this implementation, we broadcast everything to the global topic
                        // EncryptedMessage handles the privacy (only the holder of the session key can read it)
                        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(chat_topic.clone(), data) {
                            eprintln!("Publish error: {:?}", e);
                        }
                    }
                    Some(P2PCommand::FindPeer { peer_id }) => {
                        // Trigger a DHT lookup for a specific Peer ID
                        if let Ok(pid) = text_peer_id_to_peer_id(&peer_id) {
                            self.swarm.behaviour_mut().kademlia.get_closest_peers(pid);
                        }
                    }
                    None => return, // Channel closed, shut down node
                },

                // 2. Handle Network Events (Swarm)
                event = self.swarm.select_next_some() => match event {
                    // mDNS Discovery (Local Network)
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Mdns(MdnsEvent::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            // Add discovered peer to our routing tables
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                            
                            // Notify Kotlin that we found someone
                            let _ = event_sender.send(NodeEvent::PeerDiscovered { 
                                peer_id: peer_id.to_string() 
                            }).await;
                        }
                    },
                    
                    // Kademlia Discovery (DHT)
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Kademlia(KademliaEvent::RoutingUpdated { peer, .. })) => {
                        // Notify Kotlin when DHT finds a new route
                        let _ = event_sender.send(NodeEvent::PeerDiscovered { 
                            peer_id: peer.to_string() 
                        }).await;
                    },

                    // Gossipsub Message (Chat Data)
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Gossipsub(GossipsubEvent::Message {
                        propagation_source: peer_id,
                        message_id: _,
                        message,
                    })) => {
                        // Forward the encrypted blob to Kotlin for decryption
                        let _ = event_sender.send(NodeEvent::MessageReceived {
                            sender: peer_id.to_string(),
                            topic: message.topic.into_string(),
                            data: message.data,
                        }).await;
                    },
                    
                    _ => {} // Ignore debug/trace events
                }
            }
        }
    }
}

// Helper to parse string PeerId
fn text_peer_id_to_peer_id(text: &str) -> Result<PeerId, Box<dyn Error>> {
    use std::str::FromStr;
    Ok(PeerId::from_str(text)?)
}
