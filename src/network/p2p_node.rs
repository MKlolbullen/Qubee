use libp2p::{swarm::{NetworkBehaviour, Swarm}, PeerId};
use libp2p::kad::{Kademlia, KademliaConfig, store::MemoryStore};
use libp2p::gossipsub::{Gossipsub, GossipsubConfig};
use libp2p::mdns::{Mdns, MdnsConfig};

#[derive(NetworkBehaviour)]
struct QubeeBehaviour {
    gossipsub: Gossipsub, // For Group Chats
    kademlia: Kademlia<MemoryStore>, // For finding Peers by ID
    mdns: Mdns, // For local discovery (WiFi)
}

pub struct P2PNode {
    swarm: Swarm<QubeeBehaviour>,
}

impl P2PNode {
    pub async fn start(&mut self) {
        // Logic to spin up the node and listen for events
    }
    
    pub fn lookup_peer(&mut self, peer_id: PeerId) {
        self.swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
    }
}
