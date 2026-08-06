// src/network/p2p_node.rs

use anyhow::{anyhow, Result};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use libp2p::{
    gossipsub,
    identity::Keypair,
    kad, mdns, noise, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

/// Wire protocol id for the one-to-one direct-delivery stream.
const DIRECT_PROTOCOL: StreamProtocol = StreamProtocol::new("/qubee/direct/1");

/// Hard cap on a single direct frame. Group handshake frames are small
/// (a wrapped key + signatures); 1 MiB is comfortably above any real
/// frame while bounding what a peer can force us to buffer.
const MAX_DIRECT_FRAME: usize = 1 << 20;

/// Minimal request/response codec: a big-endian u32 length prefix
/// followed by the raw already-serialized frame bytes. The payloads are
/// the existing signed `GroupHandshake` wire frames — direct delivery is
/// a transport choice, not a new message format — and the response is a
/// zero-length ack so the sender learns the frame landed.
#[derive(Clone, Default)]
struct DirectCodec;

async fn write_len_prefixed<T>(io: &mut T, data: &[u8]) -> std::io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await?;
    Ok(())
}

async fn read_len_prefixed<T>(io: &mut T, max: usize) -> std::io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "direct frame exceeds size cap",
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

#[async_trait::async_trait]
impl request_response::Codec for DirectCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_len_prefixed(io, MAX_DIRECT_FRAME).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Ack only; cap tiny.
        read_len_prefixed(io, 64).await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_len_prefixed(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        res: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_len_prefixed(io, &res).await
    }
}

// --- Data Structures ---

/// Commands sent from Android (Kotlin) -> Rust
#[derive(Debug)]
pub enum P2PCommand {
    /// Send a message to a specific peer or broadcast on the global topic.
    SendMessage { peer_id: String, data: Vec<u8> },
    /// Deliver bytes to exactly one peer over the "/qubee/direct/1"
    /// request-response protocol, off any gossip topic. Used for frames
    /// addressed to a single recipient (JoinAccepted / JoinRejected)
    /// that must not be broadcast to the whole group.
    SendDirect { peer_id: String, data: Vec<u8> },
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

/// Epoch length for blinded group topics. The gossip topic rotates once
/// per epoch so the raw group id never appears on the wire and a passive
/// observer can't correlate a group's traffic across epochs. One day
/// balances that decorrelation against re-subscription churn — a node
/// stays subscribed to a 3-epoch window and refreshes it periodically.
pub const TOPIC_EPOCH_SECS: u64 = 24 * 60 * 60;

/// Domain-separation tag for the blinded-topic hash. Bumping this rolls
/// every group onto fresh topic strings (a coordinated, all-members
/// change) — treat it like a wire-format version.
const BLINDED_TOPIC_DOMAIN: &[u8] = b"qubee_blinded_group_topic_v1";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Epoch index for a Unix timestamp.
pub fn topic_epoch(now_unix_secs: u64) -> u64 {
    now_unix_secs / TOPIC_EPOCH_SECS
}

/// Blinded gossip topic for a group at a specific epoch: a domain-
/// separated BLAKE3 over the group id + epoch. All members derive the
/// same value from the shared wall clock, so no group id or stable
/// per-group identifier appears on the wire.
pub fn blinded_group_topic(group_id_hex: &str, epoch: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BLINDED_TOPIC_DOMAIN);
    hasher.update(group_id_hex.as_bytes());
    hasher.update(&epoch.to_le_bytes());
    format!(
        "qubee-g-{}",
        hex::encode(&hasher.finalize().as_bytes()[..16])
    )
}

/// The current-epoch blinded topic — used when **publishing**, a
/// point-in-time action. Callers (JNI, tests) build the per-group topic
/// name through here so blinding lives in exactly one place.
pub fn group_topic(group_id_hex: &str) -> String {
    blinded_group_topic(group_id_hex, topic_epoch(now_unix()))
}

/// The window of blinded topics a member **subscribes** to: previous,
/// current, and next epoch. Subscribing to the neighbours absorbs clock
/// skew (up to ~one epoch) and makes rollover seamless — the next
/// epoch's mesh is pre-warmed before it becomes current. Returned oldest
/// to newest.
pub fn group_topic_window(group_id_hex: &str) -> Vec<String> {
    let e = topic_epoch(now_unix());
    [e.saturating_sub(1), e, e + 1]
        .into_iter()
        .map(|epoch| blinded_group_topic(group_id_hex, epoch))
        .collect()
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

/// Transport privacy posture for the node.
///
/// `Direct` is the shipped behaviour: plain TCP/QUIC dials, so peers you
/// connect to (and on-path observers) learn your IP. `TorOnion` is the
/// Tier-2 target — reach and be reached as a Tor onion service so your
/// network location is hidden — but the transport is **not built yet**;
/// selecting it today fails closed (see [`P2PNode::with_config`]) rather
/// than silently falling back to `Direct` and leaking the IP the mode
/// exists to hide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TransportPrivacy {
    /// Plain TCP/QUIC. Peers learn your IP. (Current shipped behaviour.)
    #[default]
    Direct,
    /// Tor onion-service transport. Foundation only today — not yet
    /// functional; `with_config` refuses to start in this mode.
    TorOnion,
}

impl TransportPrivacy {
    fn is_tor(self) -> bool {
        matches!(self, TransportPrivacy::TorOnion)
    }
}

/// Effective discovery settings once the transport-privacy posture is
/// applied. Tor mode is *leaky-by-default* if you don't also silence the
/// address-advertising behaviours: mDNS broadcasts your LAN IP, and a
/// Kademlia server advertises its addresses to the DHT — both would
/// publish the real address Tor is meant to hide. So Tor forces mDNS off
/// and Kademlia into client mode (query the DHT without advertising).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedDiscovery {
    mdns_enabled: bool,
    kademlia_client_mode: bool,
}

/// Resolve discovery behaviour from the requested mDNS setting and the
/// transport-privacy posture. Pure + unit-tested so the leaky-by-default
/// guards are pinned independently of the (not-yet-built) Tor transport.
fn resolve_discovery(privacy: TransportPrivacy, enable_mdns: bool) -> ResolvedDiscovery {
    if privacy.is_tor() {
        // Force the address-leaking behaviours off regardless of the
        // caller's mDNS request — under Tor they would defeat the point.
        ResolvedDiscovery {
            mdns_enabled: false,
            kademlia_client_mode: true,
        }
    } else {
        ResolvedDiscovery {
            mdns_enabled: enable_mdns,
            kademlia_client_mode: false,
        }
    }
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
    /// Transport privacy posture. Defaults to [`TransportPrivacy::Direct`];
    /// [`TransportPrivacy::TorOnion`] is Tier-2 foundation-only and
    /// currently refuses to start.
    pub transport_privacy: TransportPrivacy,
    pub listen_addr: Multiaddr,
    /// Optional QUIC (UDP) listen address, bound *in addition to*
    /// `listen_addr` (TCP). `None` disables QUIC listening. QUIC dials
    /// out regardless once the transport is built; listening lets peers
    /// reach us over QUIC too.
    pub quic_listen_addr: Option<Multiaddr>,
    pub gossipsub_heartbeat: Duration,
    pub gossipsub_validation_mode: gossipsub::ValidationMode,
    pub idle_connection_timeout: Duration,
}

impl Default for P2PNodeConfig {
    fn default() -> Self {
        Self {
            // Privacy default: mDNS broadcasts the device's presence and
            // LAN IP to every host on the local network. Production peers
            // find each other via Kademlia / bootstrap, so mDNS is an
            // opt-in local-discovery convenience, not a requirement —
            // default it OFF and let a caller re-enable it explicitly.
            enable_mdns: false,
            transport_privacy: TransportPrivacy::Direct,
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().expect("hardcoded multiaddr"),
            quic_listen_addr: Some(
                "/ip4/0.0.0.0/udp/0/quic-v1"
                    .parse()
                    .expect("hardcoded multiaddr"),
            ),
            gossipsub_heartbeat: Duration::from_secs(10),
            // Anonymous authorship (no broadcast author PeerId) requires
            // ValidationMode::None — there is no transport-level signature
            // to verify. App-layer signatures still authenticate every
            // frame; see the gossipsub behaviour build.
            gossipsub_validation_mode: gossipsub::ValidationMode::None,
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
            transport_privacy: TransportPrivacy::Direct,
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().expect("hardcoded multiaddr"),
            quic_listen_addr: Some(
                "/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("hardcoded multiaddr"),
            ),
            gossipsub_heartbeat: Duration::from_millis(100),
            // Match production: anonymous authorship needs None.
            gossipsub_validation_mode: gossipsub::ValidationMode::None,
            idle_connection_timeout: Duration::from_secs(60),
        }
    }
}

/// Error for a [`TransportPrivacy::TorOnion`] request that can't be
/// honoured yet. Feature-aware so the message states the real reason,
/// but the outcome is the same either way: fail closed, never downgrade
/// to a direct transport that would expose the IP the caller asked to
/// hide.
fn tor_transport_unavailable() -> anyhow::Error {
    #[cfg(feature = "tor")]
    {
        anyhow!(
            "TransportPrivacy::TorOnion selected, but the onion-service transport is not \
             implemented yet (Tier-2 foundation). Refusing to start rather than fall back to a \
             direct transport that would expose your IP."
        )
    }
    #[cfg(not(feature = "tor"))]
    {
        anyhow!(
            "TransportPrivacy::TorOnion requires the `tor` Cargo feature — and the onion transport \
             itself is not implemented yet. Refusing to fall back to a direct transport that would \
             expose your IP."
        )
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
    direct: request_response::Behaviour<DirectCodec>,
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
        // Tier-2 foundation: the Tor onion-service transport isn't wired
        // yet. Fail CLOSED rather than fall back to a direct TCP/QUIC
        // node — a caller who asked for Tor did so to hide their IP, and
        // silently giving them a direct transport would expose the very
        // address they meant to protect. The `resolve_discovery` guards
        // (mDNS off, Kademlia client mode) are already in place for when
        // the transport lands; see docs/architecture/network-privacy.md.
        if config.transport_privacy.is_tor() {
            return Err(tor_transport_unavailable());
        }

        let cfg_for_behaviour = config.clone();
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| anyhow!("tcp transport: {e}"))?
            .with_quic()
            .with_behaviour(|key| {
                let peer_id = PeerId::from(key.public());

                let gossipsub_cfg = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(cfg_for_behaviour.gossipsub_heartbeat)
                    .validation_mode(cfg_for_behaviour.gossipsub_validation_mode.clone())
                    // Anonymous authorship carries no source PeerId or
                    // sequence number, so gossipsub's default message-id
                    // (source + seqno) would collapse every message to one
                    // id and dedupe all but the first away. Derive the id
                    // from the frame content instead so distinct frames
                    // stay distinct while identical re-broadcasts still
                    // dedupe. BLAKE3 over topic + payload, truncated.
                    .message_id_fn(|message: &gossipsub::Message| {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(message.topic.as_str().as_bytes());
                        hasher.update(&message.data);
                        gossipsub::MessageId::from(hasher.finalize().as_bytes()[..20].to_vec())
                    })
                    .build()
                    .map_err(std::io::Error::other)?;
                // Anonymous authorship: group frames are already
                // authenticated at the app layer (hybrid identity / sender-
                // key signatures), and the PeerId<->IdentityId linkage now
                // comes from the in-band member directory (RequestJoin +
                // roster snapshots) rather than gossipsub's `message.source`.
                // Publishing anonymously stops broadcasting the author
                // PeerId to every topic subscriber — the social-graph leak.
                // Requires ValidationMode::None (no transport signature to
                // check); the app-layer signatures remain the real gate.
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Anonymous,
                    gossipsub_cfg,
                )
                .map_err(std::io::Error::other)?;

                let discovery = resolve_discovery(
                    cfg_for_behaviour.transport_privacy,
                    cfg_for_behaviour.enable_mdns,
                );

                let kad_store = kad::store::MemoryStore::new(peer_id);
                let mut kademlia = kad::Behaviour::new(peer_id, kad_store);
                // Client mode under Tor: query the DHT without advertising
                // our own addresses (which would leak past the onion).
                kademlia.set_mode(Some(if discovery.kademlia_client_mode {
                    kad::Mode::Client
                } else {
                    kad::Mode::Server
                }));

                let mdns: Toggle<mdns::tokio::Behaviour> = if discovery.mdns_enabled {
                    Some(mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        peer_id,
                    )?)
                    .into()
                } else {
                    None.into()
                };

                let direct = request_response::Behaviour::<DirectCodec>::new(
                    std::iter::once((DIRECT_PROTOCOL, request_response::ProtocolSupport::Full)),
                    request_response::Config::default(),
                );

                Ok(QubeeBehaviour {
                    gossipsub,
                    kademlia,
                    mdns,
                    direct,
                })
            })
            .map_err(|e| anyhow!("behaviour: {e}"))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(config.idle_connection_timeout))
            .build();

        swarm.listen_on(config.listen_addr.clone())?;
        if let Some(quic_addr) = &config.quic_listen_addr {
            swarm.listen_on(quic_addr.clone())?;
        }

        Ok(Self {
            swarm,
            command_receiver,
        })
    }

    /// Main event loop. Drives the swarm forward and translates
    /// behaviour events into [`NodeEvent`] messages for Kotlin.
    pub async fn run(mut self, event_sender: mpsc::Sender<NodeEvent>) {
        let chat_topic = gossipsub::IdentTopic::new(GLOBAL_TOPIC);
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&chat_topic) {
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
                    Some(P2PCommand::SendDirect { peer_id, data }) => {
                        match PeerId::from_str(&peer_id) {
                            Ok(pid) => {
                                // request-response dials the peer if it
                                // isn't already connected, using addresses
                                // the other behaviours (Kademlia/mDNS) have
                                // learned. If none are known the outbound
                                // request fails and surfaces as an
                                // OutboundFailure event below — we never
                                // silently fall back to broadcasting a
                                // directed frame.
                                self.swarm
                                    .behaviour_mut()
                                    .direct
                                    .send_request(&pid, data);
                            }
                            Err(e) => eprintln!("SendDirect: invalid peer id {peer_id}: {e}"),
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
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Direct(request_response::Event::Message {
                        peer,
                        message,
                        ..
                    })) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                // A directed frame arrived. Surface it on the
                                // same path as gossip messages, attributed to
                                // the authenticated sending peer, then ack so
                                // the sender knows it landed. Direct frames
                                // carry no gossip topic.
                                let _ = event_sender
                                    .send(NodeEvent::MessageReceived {
                                        sender: peer.to_string(),
                                        topic: String::new(),
                                        data: request,
                                    })
                                    .await;
                                let _ = self
                                    .swarm
                                    .behaviour_mut()
                                    .direct
                                    .send_response(channel, Vec::new());
                            }
                            request_response::Message::Response { .. } => {
                                // Delivery ack for one of our own SendDirects.
                            }
                        }
                    }
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Direct(request_response::Event::OutboundFailure {
                        peer,
                        error,
                        ..
                    })) => {
                        // A directed frame could not be delivered. We do NOT
                        // fall back to broadcasting it — that would leak the
                        // very metadata this path exists to hide. The caller's
                        // retry/timeout logic is responsible for recovery.
                        eprintln!("Direct delivery to {peer} failed: {error}");
                    }
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
                        let _ = event_sender
                            .send(NodeEvent::PeerDiscovered { peer_id: peer.to_string() })
                            .await;
                    }
                    SwarmEvent::Behaviour(QubeeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        message,
                        ..
                    })) => {
                        // Gossip publishing is Anonymous: `message.source`
                        // is absent and `propagation_source` is only the
                        // relay hop, so neither is a trustworthy author.
                        // Emit an EMPTY sender to mark the peer as
                        // unauthenticated — downstream trust linkage
                        // (PeerId<->IdentityId) must come from the in-band
                        // member directory or the authenticated direct
                        // channel, never from a gossip peer. Frame
                        // authenticity itself is the app-layer signature,
                        // checked when the frame is decoded/verified.
                        let _ = event_sender
                            .send(NodeEvent::MessageReceived {
                                sender: String::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinded_topic_hides_group_id_and_rotates_by_epoch() {
        let gid = "aabbccddeeff00112233445566778899";
        let t0 = blinded_group_topic(gid, 100);
        // The raw group id must not appear anywhere in the topic string.
        assert!(!t0.contains(gid), "topic leaks the raw group id: {t0}");
        assert!(t0.starts_with("qubee-g-"));
        // Deterministic for the same (group, epoch).
        assert_eq!(t0, blinded_group_topic(gid, 100));
        // Different epoch → different topic (cross-time decorrelation).
        assert_ne!(t0, blinded_group_topic(gid, 101));
        // Different group → different topic.
        assert_ne!(
            t0,
            blinded_group_topic("00112233445566778899aabbccddeeff", 100)
        );
    }

    #[test]
    fn topic_window_is_prev_current_next() {
        let gid = "deadbeef";
        let e = topic_epoch(now_unix());
        let window = group_topic_window(gid);
        assert_eq!(window.len(), 3);
        assert_eq!(window[0], blinded_group_topic(gid, e - 1));
        assert_eq!(window[1], blinded_group_topic(gid, e));
        assert_eq!(window[2], blinded_group_topic(gid, e + 1));
        // The publish topic (current epoch) is the middle of the window a
        // subscriber joins, so a publisher and subscriber rendezvous.
        assert_eq!(group_topic(gid), window[1]);
        // Three distinct strings.
        assert_ne!(window[0], window[1]);
        assert_ne!(window[1], window[2]);
    }

    #[test]
    fn direct_mode_preserves_discovery_settings() {
        // Direct: honour the caller's mDNS choice, Kademlia stays in
        // server mode (advertise addresses to the DHT).
        let on = resolve_discovery(TransportPrivacy::Direct, true);
        assert_eq!(
            on,
            ResolvedDiscovery {
                mdns_enabled: true,
                kademlia_client_mode: false,
            }
        );
        let off = resolve_discovery(TransportPrivacy::Direct, false);
        assert_eq!(
            off,
            ResolvedDiscovery {
                mdns_enabled: false,
                kademlia_client_mode: false,
            }
        );
    }

    #[test]
    fn tor_mode_forces_address_leaking_behaviours_off() {
        // Tor forces mDNS off and Kademlia into client mode even when the
        // caller explicitly asked for mDNS — both would publish the real
        // address the onion is meant to hide.
        let resolved = resolve_discovery(TransportPrivacy::TorOnion, true);
        assert_eq!(
            resolved,
            ResolvedDiscovery {
                mdns_enabled: false,
                kademlia_client_mode: true,
            },
            "Tor mode must silence mDNS and DHT address advertisement",
        );
    }

    #[tokio::test]
    async fn tor_transport_fails_closed_until_implemented() {
        // Selecting Tor must refuse to start — never silently fall back to
        // a direct transport that would expose the IP the caller asked to
        // hide. This is the fail-closed seam for the not-yet-built Tier-2
        // onion transport.
        let id_keys = libp2p::identity::Keypair::generate_ed25519();
        let (_tx, rx) = mpsc::channel(1);
        let config = P2PNodeConfig {
            transport_privacy: TransportPrivacy::TorOnion,
            ..P2PNodeConfig::for_testing()
        };
        let result = P2PNode::with_config(id_keys, rx, config).await;
        assert!(
            result.is_err(),
            "TorOnion must fail closed until the onion transport is wired",
        );
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("expose your IP"),
            "error must explain the fail-closed rationale, got: {msg}",
        );
    }

    #[tokio::test]
    async fn direct_transport_still_builds() {
        // The default posture is unchanged: a Direct node builds fine.
        let id_keys = libp2p::identity::Keypair::generate_ed25519();
        let (_tx, rx) = mpsc::channel(1);
        let result = P2PNode::with_config(id_keys, rx, P2PNodeConfig::for_testing()).await;
        assert!(result.is_ok(), "Direct transport must still build");
    }
}
