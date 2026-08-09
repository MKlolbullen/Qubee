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
use std::collections::HashSet;
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
    /// Follow a group by id rather than by topic string. Topics are
    /// blinded and rotate per epoch, so a caller that subscribed to a
    /// fixed string would fall off the group at the next rotation; the
    /// node owns the window and re-derives it as epochs roll.
    SubscribeGroup { group_id_hex: String },
    /// Stop following a group and drop its whole topic window.
    UnsubscribeGroup { group_id_hex: String },
    /// Follow this identity's rotating blinded direct-inbox window.
    /// The identity id never appears in the topic string itself.
    FollowDirectInbox { identity_id_hex: String },
    /// Publish a route-less direct frame to one recipient's blinded inbox.
    /// The node also follows the inbox so mesh formation can complete before
    /// later exact-wire retries.
    PublishDirectInbox {
        recipient_id_hex: String,
        data: Vec<u8>,
    },
    /// Publish bytes on a named gossipsub topic. The local node must be
    /// subscribed for the publish to actually go out — gossipsub
    /// silently drops publishes on topics with no local subscription.
    PublishToTopic { topic: String, data: Vec<u8> },
    /// Dial a peer at a known multiaddress. Used by integration tests
    /// that skip mDNS; production peers find each other via Kademlia
    /// or the local-network mDNS sweep.
    Dial { multiaddr: String },
}

/// Rotation period for blinded group topics. All members derive the
/// same epoch from wall-clock time, so this doubles as the tolerated
/// clock skew budget: a day is long enough that a badly-set phone
/// still lands inside the subscribed window (see [`TOPIC_EPOCH_SKEW`]).
pub const TOPIC_EPOCH_SECS: u64 = 86_400;

/// How many epochs either side of the current one a member stays
/// subscribed to. 1 means the live window is {e-1, e, e+1}: a peer
/// whose clock is up to a full epoch fast or slow still shares a topic
/// with us, and messages in flight across a rotation boundary land.
pub const TOPIC_EPOCH_SKEW: u64 = 1;

const TOPIC_BLIND_DOMAIN: &[u8] = b"qubee-group-topic-blind-v1";
const DIRECT_INBOX_BLIND_DOMAIN: &[u8] = b"qubee-direct-inbox-blind-v1";

/// How often the node re-derives its topic window. Independent of the
/// epoch length: it only has to be fine-grained enough that a rotation
/// is picked up promptly, and cheap enough to run forever.
const TOPIC_RESYNC_INTERVAL: Duration = Duration::from_secs(300);

/// Current topic epoch. Saturates rather than panicking if the system
/// clock is before the Unix epoch.
pub fn topic_epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / TOPIC_EPOCH_SECS)
        .unwrap_or(0)
}

/// Blinded per-group topic for an explicit epoch.
///
/// The raw group id used to ride on the wire as the topic string, so
/// any passive observer could read it and correlate a group across its
/// whole lifetime. Hashing it under a rotating epoch keeps the value
/// derivable by every member while giving an observer neither the id
/// nor a stable handle to follow.
pub fn group_topic_for_epoch(group_id_hex: &str, epoch: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPIC_BLIND_DOMAIN);
    hasher.update(group_id_hex.as_bytes());
    hasher.update(&epoch.to_be_bytes());
    format!(
        "qubee-g-{}",
        hex::encode(&hasher.finalize().as_bytes()[..16])
    )
}

/// Public helper so callers (JNI, tests) build the per-group topic
/// name in exactly one place. Publishes always target the current
/// epoch; subscribers cover a window around it.
pub fn group_topic(group_id_hex: &str) -> String {
    group_topic_for_epoch(group_id_hex, topic_epoch_now())
}

/// Every topic a member should be subscribed to for `group_id_hex`
/// right now.
pub fn group_topic_window(group_id_hex: &str) -> Vec<String> {
    let now = topic_epoch_now();
    (now.saturating_sub(TOPIC_EPOCH_SKEW)..=now.saturating_add(TOPIC_EPOCH_SKEW))
        .map(|epoch| group_topic_for_epoch(group_id_hex, epoch))
        .collect()
}

/// Rotating inbox for a Qubee identity. The 32-byte identity is already a
/// high-entropy public identifier; hashing it with a domain + epoch prevents
/// the raw id becoming a stable topic label. Parties that know the identity
/// can derive the inbox, while unrelated subscribers cannot enumerate it from
/// the topic string alone.
pub fn direct_inbox_topic_for_epoch(identity_id_hex: &str, epoch: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECT_INBOX_BLIND_DOMAIN);
    hasher.update(identity_id_hex.as_bytes());
    hasher.update(&epoch.to_be_bytes());
    format!(
        "qubee-d-{}",
        hex::encode(&hasher.finalize().as_bytes()[..16])
    )
}

pub fn direct_inbox_topic(identity_id_hex: &str) -> String {
    direct_inbox_topic_for_epoch(identity_id_hex, topic_epoch_now())
}

pub fn direct_inbox_topic_window(identity_id_hex: &str) -> Vec<String> {
    let now = topic_epoch_now();
    (now.saturating_sub(TOPIC_EPOCH_SKEW)..=now.saturating_add(TOPIC_EPOCH_SKEW))
        .map(|epoch| direct_inbox_topic_for_epoch(identity_id_hex, epoch))
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

/// Tunables for `P2PNode`. Production callers should use
/// [`P2PNodeConfig::default`]; tests should use
/// [`P2PNodeConfig::for_testing`] which (a) disables mDNS so two
/// nodes in the same process don't step on each other's discovery,
/// (b) binds to `127.0.0.1` so test runs don't leak onto the LAN,
/// and (c) shortens the gossipsub heartbeat so mesh formation
/// completes inside a normal test timeout.
/// Transport privacy posture for the node.
///
/// `Direct` is the shipped behaviour: plain TCP/QUIC dials, so peers you
/// connect to (and on-path observers) learn your IP. The anonymising
/// modes are Tier-2/Tier-3 **foundations** — the config surface and the
/// leaky-by-default guards exist, but their transports are not wired, so
/// selecting one fails closed (see [`P2PNode::with_config`]) rather than
/// silently falling back to `Direct` and leaking the IP it exists to hide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TransportPrivacy {
    /// Plain TCP/QUIC. Peers learn your IP. (Current shipped behaviour.)
    #[default]
    Direct,
    /// Tor onion-service transport (Tier 2). Hides your IP/location.
    /// Foundation only — not yet functional.
    TorOnion,
    /// Nym mixnet transport (Tier 3). Hides your IP **and** resists
    /// traffic-analysis by a global passive adversary (Sphinx packets,
    /// per-hop mixing, cover traffic). A mixnet *replaces* the libp2p
    /// transport for the private path, so it's the heaviest option.
    /// Foundation only — not yet functional.
    NymMixnet,
}

impl TransportPrivacy {
    /// True only for the shipped `Direct` transport. The anonymising
    /// modes are foundation-only and fail closed until wired.
    fn is_direct(self) -> bool {
        matches!(self, TransportPrivacy::Direct)
    }
}

/// Effective discovery settings once the transport-privacy posture is
/// applied. An anonymising transport is *leaky-by-default* unless the
/// address-advertising behaviours are silenced: mDNS broadcasts your LAN
/// IP, and a Kademlia server advertises its addresses to the DHT — both
/// would publish the real address the overlay is meant to hide. So any
/// non-`Direct` posture forces mDNS off and Kademlia into client mode,
/// regardless of the caller's `enable_mdns` / `kademlia_client_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedDiscovery {
    mdns_enabled: bool,
    kademlia_client_mode: bool,
}

/// Resolve discovery behaviour from the caller's requested settings and
/// the transport-privacy posture. Pure + unit-tested so the leaky-by-
/// default guards are pinned independently of the (not-yet-built)
/// anonymising transports. For `Direct`, the caller's settings pass
/// through unchanged.
fn resolve_discovery(
    privacy: TransportPrivacy,
    enable_mdns: bool,
    kademlia_client_mode: bool,
) -> ResolvedDiscovery {
    if privacy.is_direct() {
        ResolvedDiscovery {
            mdns_enabled: enable_mdns,
            kademlia_client_mode,
        }
    } else {
        ResolvedDiscovery {
            mdns_enabled: false,
            kademlia_client_mode: true,
        }
    }
}

/// Error for an anonymising-transport request that can't be honoured yet.
/// Feature-aware so the message states the real reason, but the outcome
/// is the same either way: fail closed, never downgrade to a direct
/// transport that would expose the IP the caller asked to hide.
fn transport_unavailable(mode: TransportPrivacy) -> anyhow::Error {
    let (label, feature, enabled) = match mode {
        TransportPrivacy::Direct => return anyhow!("internal: Direct is always available"),
        TransportPrivacy::TorOnion => ("Tor onion-service", "tor", cfg!(feature = "tor")),
        TransportPrivacy::NymMixnet => ("Nym mixnet", "nym", cfg!(feature = "nym")),
    };
    if enabled {
        anyhow!(
            "TransportPrivacy::{mode:?} selected, but the {label} transport is not implemented yet \
             (foundation only). Refusing to start rather than fall back to a direct transport that \
             would expose your IP."
        )
    } else {
        anyhow!(
            "TransportPrivacy::{mode:?} requires the `{feature}` Cargo feature — and the {label} \
             transport itself is not implemented yet. Refusing to fall back to a direct transport \
             that would expose your IP."
        )
    }
}

#[derive(Clone)]
pub struct P2PNodeConfig {
    pub enable_mdns: bool,
    /// Transport privacy posture. Defaults to [`TransportPrivacy::Direct`];
    /// the anonymising modes are foundation-only and currently refuse to
    /// start (fail closed).
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
    /// Run Kademlia as a client: query the DHT without advertising our
    /// own addresses into it. Costs discoverability — a client-mode node
    /// can find peers but cannot be found through the DHT, and serves no
    /// routing for anyone else — so it stays opt-in for privacy-sensitive
    /// profiles rather than becoming the default. If every node ran as a
    /// client there would be no DHT left to query.
    pub kademlia_client_mode: bool,
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
            kademlia_client_mode: false,
        }
    }
}

impl P2PNodeConfig {
    /// Test profile: loopback, no mDNS, 100 ms gossipsub heartbeat.
    /// Used by `tests/p2p_two_node_e2e.rs`. Starts from `Default` and
    /// overrides only the test-specific fields, so a new config field
    /// doesn't need to be kept in sync in two places.
    pub fn for_testing() -> Self {
        Self {
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().expect("hardcoded multiaddr"),
            quic_listen_addr: Some(
                "/ip4/127.0.0.1/udp/0/quic-v1"
                    .parse()
                    .expect("hardcoded multiaddr"),
            ),
            gossipsub_heartbeat: Duration::from_millis(100),
            ..Default::default()
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
    direct: request_response::Behaviour<DirectCodec>,
}

// --- The P2P Node ---

pub struct P2PNode {
    swarm: Swarm<QubeeBehaviour>,
    command_receiver: mpsc::Receiver<P2PCommand>,
    followed_groups: HashSet<String>,
    live_group_topics: HashSet<String>,
    followed_direct_inboxes: HashSet<String>,
    live_direct_inbox_topics: HashSet<String>,
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
        // The anonymising transports (Tor onion service / Nym mixnet)
        // aren't wired yet — only their config surface + guards are. Fail
        // CLOSED rather than fall back to a direct TCP/QUIC node: a caller
        // who asked for Tor or Nym did so to hide their IP, and silently
        // giving them a direct transport would expose the very address
        // they meant to protect. See docs/architecture/network-privacy.md.
        if !config.transport_privacy.is_direct() {
            return Err(transport_unavailable(config.transport_privacy));
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

                // Fold the transport-privacy posture into the discovery
                // settings: any anonymising mode forces mDNS off + Kademlia
                // client, independently of the caller's bools. (For Direct
                // this is an identity over `enable_mdns` /
                // `kademlia_client_mode`.)
                let discovery = resolve_discovery(
                    cfg_for_behaviour.transport_privacy,
                    cfg_for_behaviour.enable_mdns,
                    cfg_for_behaviour.kademlia_client_mode,
                );

                let kad_store = kad::store::MemoryStore::new(peer_id);
                let mut kademlia = kad::Behaviour::new(peer_id, kad_store);
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
            followed_groups: HashSet::new(),
            live_group_topics: HashSet::new(),
            followed_direct_inboxes: HashSet::new(),
            live_direct_inbox_topics: HashSet::new(),
        })
    }

    /// Bring the subscribed topic set in line with the current epoch
    /// window for every followed group.
    fn resync_group_topics(&mut self) {
        let desired: HashSet<String> = self
            .followed_groups
            .iter()
            .flat_map(|g| group_topic_window(g))
            .collect();

        for topic in desired.difference(&self.live_group_topics) {
            let ident = gossipsub::IdentTopic::new(topic.clone());
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&ident) {
                eprintln!("Subscribe error for {topic}: {e:?}");
            }
        }
        for topic in self.live_group_topics.difference(&desired) {
            let ident = gossipsub::IdentTopic::new(topic.clone());
            self.swarm.behaviour_mut().gossipsub.unsubscribe(&ident);
        }

        self.live_group_topics = desired;
    }

    fn resync_direct_inbox_topics(&mut self) {
        let desired: HashSet<String> = self
            .followed_direct_inboxes
            .iter()
            .flat_map(|id| direct_inbox_topic_window(id))
            .collect();

        for topic in desired.difference(&self.live_direct_inbox_topics) {
            let ident = gossipsub::IdentTopic::new(topic.clone());
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&ident) {
                eprintln!("Direct-inbox subscribe error for {topic}: {e:?}");
            }
        }
        for topic in self.live_direct_inbox_topics.difference(&desired) {
            let ident = gossipsub::IdentTopic::new(topic.clone());
            self.swarm.behaviour_mut().gossipsub.unsubscribe(&ident);
        }
        self.live_direct_inbox_topics = desired;
    }

    /// Main event loop. Drives the swarm forward and translates
    /// behaviour events into [`NodeEvent`] messages for Kotlin.
    pub async fn run(mut self, event_sender: mpsc::Sender<NodeEvent>) {
        let chat_topic = gossipsub::IdentTopic::new(GLOBAL_TOPIC);
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&chat_topic) {
            eprintln!("Failed to subscribe to topic: {e:?}");
        }

        let mut topic_resync = tokio::time::interval(TOPIC_RESYNC_INTERVAL);
        topic_resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = topic_resync.tick() => {
                    self.resync_group_topics();
                    self.resync_direct_inbox_topics();
                }
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
                    Some(P2PCommand::SubscribeGroup { group_id_hex }) => {
                        if self.followed_groups.insert(group_id_hex) {
                            self.resync_group_topics();
                        }
                    }
                    Some(P2PCommand::UnsubscribeGroup { group_id_hex }) => {
                        if self.followed_groups.remove(&group_id_hex) {
                            self.resync_group_topics();
                        }
                    }
                    Some(P2PCommand::FollowDirectInbox { identity_id_hex }) => {
                        if self.followed_direct_inboxes.insert(identity_id_hex) {
                            self.resync_direct_inbox_topics();
                        }
                    }
                    Some(P2PCommand::PublishDirectInbox { recipient_id_hex, data }) => {
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

    const GROUP_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const GROUP_B: &str = "ffeeddccbbaa99887766554433221100";

    #[test]
    fn direct_mode_passes_discovery_settings_through() {
        // Direct honours the caller's mDNS + Kademlia-client choices.
        assert_eq!(
            resolve_discovery(TransportPrivacy::Direct, true, false),
            ResolvedDiscovery {
                mdns_enabled: true,
                kademlia_client_mode: false,
            },
        );
        assert_eq!(
            resolve_discovery(TransportPrivacy::Direct, false, true),
            ResolvedDiscovery {
                mdns_enabled: false,
                kademlia_client_mode: true,
            },
        );
    }

    #[test]
    fn anonymising_modes_force_address_leaking_behaviours_off() {
        // Tor and Nym both silence mDNS + DHT advertisement even when the
        // caller explicitly asked for mDNS and a Kademlia server.
        for mode in [TransportPrivacy::TorOnion, TransportPrivacy::NymMixnet] {
            assert_eq!(
                resolve_discovery(mode, true, false),
                ResolvedDiscovery {
                    mdns_enabled: false,
                    kademlia_client_mode: true,
                },
                "{mode:?} must force mDNS off + Kademlia client",
            );
        }
    }

    #[tokio::test]
    async fn anonymising_transports_fail_closed_until_implemented() {
        // Selecting Tor or Nym must refuse to start — never silently fall
        // back to a direct transport that would expose the IP the caller
        // asked to hide.
        for mode in [TransportPrivacy::TorOnion, TransportPrivacy::NymMixnet] {
            let id_keys = libp2p::identity::Keypair::generate_ed25519();
            let (_tx, rx) = mpsc::channel(1);
            let config = P2PNodeConfig {
                transport_privacy: mode,
                ..P2PNodeConfig::for_testing()
            };
            let result = P2PNode::with_config(id_keys, rx, config).await;
            assert!(result.is_err(), "{mode:?} must fail closed");
            let msg = format!("{:#}", result.err().unwrap());
            assert!(msg.contains("expose your IP"), "{mode:?}: {msg}");
            // The mode name must render (inline format-arg capture), not
            // appear as a literal `{mode:?}`.
            assert!(
                msg.contains(&format!("{mode:?}")),
                "mode should render: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn direct_transport_still_builds() {
        let id_keys = libp2p::identity::Keypair::generate_ed25519();
        let (_tx, rx) = mpsc::channel(1);
        let result = P2PNode::with_config(id_keys, rx, P2PNodeConfig::for_testing()).await;
        assert!(result.is_ok(), "Direct transport must still build");
    }

    /// The whole point of blinding: the group id must not be readable
    /// off the topic string by a passive observer.
    #[test]
    fn blinded_topic_never_contains_the_group_id() {
        for epoch in [0u64, 1, 20_000, u64::MAX] {
            let topic = group_topic_for_epoch(GROUP_A, epoch);
            assert!(!topic.contains(GROUP_A));
            // Any run of the id long enough to be recognisable.
            for window in GROUP_A.as_bytes().windows(8) {
                let frag = std::str::from_utf8(window).unwrap();
                assert!(!topic.contains(frag), "leaked {frag} in {topic}");
            }
        }
    }

    #[test]
    fn direct_inbox_topic_hides_identity_and_rotates() {
        let identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let t1 = direct_inbox_topic_for_epoch(identity, 42);
        let t2 = direct_inbox_topic_for_epoch(identity, 42);
        let t3 = direct_inbox_topic_for_epoch(identity, 43);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
        assert!(!t1.contains(identity));
        for window in identity.as_bytes().windows(8) {
            let frag = std::str::from_utf8(window).unwrap();
            assert!(!t1.contains(frag), "leaked {frag} in {t1}");
        }
        assert!(direct_inbox_topic_window(identity).contains(&direct_inbox_topic(identity)));
    }

    #[test]
    fn topic_is_stable_within_an_epoch_and_rotates_across_them() {
        assert_eq!(
            group_topic_for_epoch(GROUP_A, 42),
            group_topic_for_epoch(GROUP_A, 42),
        );
        assert_ne!(
            group_topic_for_epoch(GROUP_A, 42),
            group_topic_for_epoch(GROUP_A, 43),
        );
    }

    #[test]
    fn distinct_groups_get_distinct_topics_in_the_same_epoch() {
        assert_ne!(
            group_topic_for_epoch(GROUP_A, 7),
            group_topic_for_epoch(GROUP_B, 7),
        );
    }

    /// The publish target must always sit inside the subscribed window,
    /// or members would publish into a topic nobody listens on.
    #[test]
    fn window_covers_the_current_publish_topic() {
        let window = group_topic_window(GROUP_A);
        assert_eq!(window.len() as u64, TOPIC_EPOCH_SKEW * 2 + 1);
        assert!(window.contains(&group_topic(GROUP_A)));
    }

    /// A peer whose clock is a full epoch off still shares a topic with
    /// us — that overlap is what makes the skew budget real.
    #[test]
    fn windows_overlap_across_one_epoch_of_clock_skew() {
        let now = topic_epoch_now();
        let ours: HashSet<String> = group_topic_window(GROUP_A).into_iter().collect();
        for skewed in [now - 1, now + 1] {
            let theirs = group_topic_for_epoch(GROUP_A, skewed);
            assert!(ours.contains(&theirs));
        }
    }
}
