from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, got {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# 1) Ratchet-encrypted route hint inside the direct payload.
# ---------------------------------------------------------------------------
path = "src/ratchet/direct.rs"
replace_once(
    path,
    '''pub const PAYLOAD_TAG_TEXT: u8 = 0x01;
pub const PAYLOAD_TAG_SENDER_KEY_DIST: u8 = 0x02;
''',
    '''pub const PAYLOAD_TAG_TEXT: u8 = 0x01;
pub const PAYLOAD_TAG_SENDER_KEY_DIST: u8 = 0x02;
/// Version of the tagged payload envelope *inside* the ratchet ciphertext.
/// v1 adds an optional sender libp2p PeerId hint before the payload tag.
pub const DIRECT_PAYLOAD_ENVELOPE_VERSION: u8 = 0x01;
const DIRECT_ROUTE_HINT_MAX_LEN: usize = 256;
''',
)

old_payload_helpers = '''fn encode_payload(payload: &DirectPayload) -> Result<Vec<u8>> {
    match payload {
        DirectPayload::Text(text) => {
            let mut out = Vec::with_capacity(1 + text.len());
            out.push(PAYLOAD_TAG_TEXT);
            out.extend_from_slice(text.as_bytes());
            Ok(out)
        }
        DirectPayload::SenderKeyDistribution(dist) => {
            let body = dist.to_bytes()?;
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(PAYLOAD_TAG_SENDER_KEY_DIST);
            out.extend_from_slice(&body);
            Ok(out)
        }
    }
}

fn decode_payload(bytes: &[u8]) -> Result<DirectPayload> {
    let (tag, body) = bytes
        .split_first()
        .ok_or_else(|| anyhow!("empty direct payload"))?;
    match *tag {
        PAYLOAD_TAG_TEXT => Ok(DirectPayload::Text(
            String::from_utf8(body.to_vec()).map_err(|e| anyhow!("text payload not UTF-8: {e}"))?,
        )),
        PAYLOAD_TAG_SENDER_KEY_DIST => Ok(DirectPayload::SenderKeyDistribution(
            SenderKeyDistribution::from_bytes(body)?,
        )),
        other => bail!("unknown direct payload tag {other:#04x}"),
    }
}
'''
new_payload_helpers = '''fn encode_tagged_payload(payload: &DirectPayload) -> Result<Vec<u8>> {
    match payload {
        DirectPayload::Text(text) => {
            let mut out = Vec::with_capacity(1 + text.len());
            out.push(PAYLOAD_TAG_TEXT);
            out.extend_from_slice(text.as_bytes());
            Ok(out)
        }
        DirectPayload::SenderKeyDistribution(dist) => {
            let body = dist.to_bytes()?;
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(PAYLOAD_TAG_SENDER_KEY_DIST);
            out.extend_from_slice(&body);
            Ok(out)
        }
    }
}

fn decode_tagged_payload(bytes: &[u8]) -> Result<DirectPayload> {
    let (tag, body) = bytes
        .split_first()
        .ok_or_else(|| anyhow!("empty direct payload"))?;
    match *tag {
        PAYLOAD_TAG_TEXT => Ok(DirectPayload::Text(
            String::from_utf8(body.to_vec()).map_err(|e| anyhow!("text payload not UTF-8: {e}"))?,
        )),
        PAYLOAD_TAG_SENDER_KEY_DIST => Ok(DirectPayload::SenderKeyDistribution(
            SenderKeyDistribution::from_bytes(body)?,
        )),
        other => bail!("unknown direct payload tag {other:#04x}"),
    }
}

/// Encode the direct plaintext envelope. The PeerId is encrypted by the
/// Double Ratchet and therefore visible only to the intended recipient; it is
/// not an unauthenticated transport hint. Once the ratchet AEAD opens, the
/// receiver can bind this route to the channel-authenticated IdentityId.
fn encode_payload_with_route(
    payload: &DirectPayload,
    sender_peer_id: Option<&str>,
) -> Result<Vec<u8>> {
    let route = sender_peer_id.unwrap_or("").as_bytes();
    if route.len() > DIRECT_ROUTE_HINT_MAX_LEN || route.len() > u16::MAX as usize {
        bail!("direct route hint too long");
    }
    let tagged = encode_tagged_payload(payload)?;
    let mut out = Vec::with_capacity(3 + route.len() + tagged.len());
    out.push(DIRECT_PAYLOAD_ENVELOPE_VERSION);
    out.extend_from_slice(&(route.len() as u16).to_le_bytes());
    out.extend_from_slice(route);
    out.extend_from_slice(&tagged);
    Ok(out)
}

fn decode_payload_with_route(bytes: &[u8]) -> Result<(Option<String>, DirectPayload)> {
    if bytes.len() < 4 {
        bail!("direct payload envelope too short");
    }
    if bytes[0] != DIRECT_PAYLOAD_ENVELOPE_VERSION {
        bail!("unsupported direct payload envelope version {}", bytes[0]);
    }
    let route_len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
    if route_len > DIRECT_ROUTE_HINT_MAX_LEN {
        bail!("direct route hint exceeds maximum");
    }
    let route_end = 3usize
        .checked_add(route_len)
        .ok_or_else(|| anyhow!("direct route length overflow"))?;
    if route_end >= bytes.len() {
        bail!("truncated direct route hint or missing payload tag");
    }
    let route = if route_len == 0 {
        None
    } else {
        Some(
            std::str::from_utf8(&bytes[3..route_end])
                .map_err(|e| anyhow!("direct route hint not UTF-8: {e}"))?
                .to_string(),
        )
    };
    Ok((route, decode_tagged_payload(&bytes[route_end..])?))
}
'''
replace_once(path, old_payload_helpers, new_payload_helpers)

replace_once(
    path,
    '''pub fn encrypt_direct_text(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    text: &str,
    now: u64,
) -> Result<Vec<u8>> {
    let payload = encode_payload(&DirectPayload::Text(text.to_string()))?;
    encrypt_direct(ks, local_id, peer_id, &payload, now)
}
''',
    '''pub fn encrypt_direct_text(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    text: &str,
    now: u64,
) -> Result<Vec<u8>> {
    encrypt_direct_text_with_route(ks, local_id, peer_id, text, None, now)
}

/// Live-send flavour that carries this node's current libp2p PeerId *inside*
/// the ratchet ciphertext. A route-less first message can arrive through the
/// blinded direct inbox; after decrypt the recipient can upgrade replies to
/// `/qubee/direct/1` without a globally visible IdentityId↔PeerId binding.
pub fn encrypt_direct_text_with_route(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    text: &str,
    sender_peer_id: Option<&str>,
    now: u64,
) -> Result<Vec<u8>> {
    let payload =
        encode_payload_with_route(&DirectPayload::Text(text.to_string()), sender_peer_id)?;
    encrypt_direct(ks, local_id, peer_id, &payload, now)
}
''',
)

replace_once(
    path,
    '''pub fn encrypt_direct_distribution(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    dist: &SenderKeyDistribution,
    now: u64,
) -> Result<Vec<u8>> {
    let payload = encode_payload(&DirectPayload::SenderKeyDistribution(dist.clone()))?;
    encrypt_direct(ks, local_id, peer_id, &payload, now)
}
''',
    '''pub fn encrypt_direct_distribution(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    dist: &SenderKeyDistribution,
    now: u64,
) -> Result<Vec<u8>> {
    encrypt_direct_distribution_with_route(ks, local_id, peer_id, dist, None, now)
}

pub fn encrypt_direct_distribution_with_route(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    dist: &SenderKeyDistribution,
    sender_peer_id: Option<&str>,
    now: u64,
) -> Result<Vec<u8>> {
    let payload = encode_payload_with_route(
        &DirectPayload::SenderKeyDistribution(dist.clone()),
        sender_peer_id,
    )?;
    encrypt_direct(ks, local_id, peer_id, &payload, now)
}
''',
)

replace_once(
    path,
    '''pub fn decrypt_direct_payload(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, DirectPayload)> {
    let (sender, plaintext) = decrypt_direct(ks, local_id, wire, now)?;
    Ok((sender, decode_payload(&plaintext)?))
}
''',
    '''pub fn decrypt_direct_payload(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, DirectPayload)> {
    let (sender, _route, payload) =
        decrypt_direct_payload_with_route(ks, local_id, wire, now)?;
    Ok((sender, payload))
}

pub fn decrypt_direct_payload_with_route(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, Option<String>, DirectPayload)> {
    let (sender, plaintext) = decrypt_direct(ks, local_id, wire, now)?;
    let (route, payload) = decode_payload_with_route(&plaintext)?;
    Ok((sender, route, payload))
}
''',
)

replace_once(
    path,
    '''    #[test]
    fn initial_rides_every_frame_until_first_reply() {''',
    '''    #[test]
    fn encrypted_payload_binds_private_route_hint_to_authenticated_sender() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        let wire = encrypt_direct_text_with_route(
            &mut a.ks,
            aid,
            bid,
            "hello via inbox",
            Some("12D3KooWPrivateRoute"),
            1,
        )
        .unwrap();
        // The transport route must not be visible in the durable outer wire.
        assert!(!wire
            .windows(b"12D3KooWPrivateRoute".len())
            .any(|w| w == b"12D3KooWPrivateRoute"));
        let (sender, route, payload) =
            decrypt_direct_payload_with_route(&mut b.ks, bid, &wire, 1).unwrap();
        assert_eq!(sender, aid);
        assert_eq!(route.as_deref(), Some("12D3KooWPrivateRoute"));
        assert_eq!(payload, DirectPayload::Text("hello via inbox".to_string()));
    }

    #[test]
    fn initial_rides_every_frame_until_first_reply() {''',
)

# ---------------------------------------------------------------------------
# 2) Rotating blinded direct inboxes at the libp2p layer.
# ---------------------------------------------------------------------------
path = "src/network/p2p_node.rs"
replace_once(
    path,
    '''    /// Stop following a group and drop its whole topic window.
    UnsubscribeGroup { group_id_hex: String },
    /// Publish bytes on a named gossipsub topic. The local node must be
''',
    '''    /// Stop following a group and drop its whole topic window.
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
''',
)

replace_once(
    path,
    '''const TOPIC_BLIND_DOMAIN: &[u8] = b"qubee-group-topic-blind-v1";
''',
    '''const TOPIC_BLIND_DOMAIN: &[u8] = b"qubee-group-topic-blind-v1";
const DIRECT_INBOX_BLIND_DOMAIN: &[u8] = b"qubee-direct-inbox-blind-v1";
''',
)

replace_once(
    path,
    '''pub fn group_topic_window(group_id_hex: &str) -> Vec<String> {
    let now = topic_epoch_now();
    (now.saturating_sub(TOPIC_EPOCH_SKEW)..=now.saturating_add(TOPIC_EPOCH_SKEW))
        .map(|epoch| group_topic_for_epoch(group_id_hex, epoch))
        .collect()
}
''',
    '''pub fn group_topic_window(group_id_hex: &str) -> Vec<String> {
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
''',
)

replace_once(
    path,
    '''pub struct P2PNode {
    swarm: Swarm<QubeeBehaviour>,
    command_receiver: mpsc::Receiver<P2PCommand>,
    followed_groups: HashSet<String>,
    live_group_topics: HashSet<String>,
}
''',
    '''pub struct P2PNode {
    swarm: Swarm<QubeeBehaviour>,
    command_receiver: mpsc::Receiver<P2PCommand>,
    followed_groups: HashSet<String>,
    live_group_topics: HashSet<String>,
    followed_direct_inboxes: HashSet<String>,
    live_direct_inbox_topics: HashSet<String>,
}
''',
)

replace_once(
    path,
    '''        Ok(Self {
            swarm,
            command_receiver,
            followed_groups: HashSet::new(),
            live_group_topics: HashSet::new(),
        })
''',
    '''        Ok(Self {
            swarm,
            command_receiver,
            followed_groups: HashSet::new(),
            live_group_topics: HashSet::new(),
            followed_direct_inboxes: HashSet::new(),
            live_direct_inbox_topics: HashSet::new(),
        })
''',
)

replace_once(
    path,
    '''        self.live_group_topics = desired;
    }

    /// Main event loop. Drives the swarm forward and translates
''',
    '''        self.live_group_topics = desired;
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
''',
)

replace_once(
    path,
    '''                _ = topic_resync.tick() => {
                    self.resync_group_topics();
                }
''',
    '''                _ = topic_resync.tick() => {
                    self.resync_group_topics();
                    self.resync_direct_inbox_topics();
                }
''',
)

replace_once(
    path,
    '''                    Some(P2PCommand::UnsubscribeGroup { group_id_hex }) => {
                        if self.followed_groups.remove(&group_id_hex) {
                            self.resync_group_topics();
                        }
                    }
                    Some(P2PCommand::PublishToTopic { topic, data }) => {
''',
    '''                    Some(P2PCommand::UnsubscribeGroup { group_id_hex }) => {
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
''',
)

replace_once(
    path,
    '''    #[test]
    fn topic_is_stable_within_an_epoch_and_rotates_across_them() {''',
    '''    #[test]
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
    fn topic_is_stable_within_an_epoch_and_rotates_across_them() {''',
)

# ---------------------------------------------------------------------------
# 3) JNI: subscribe own inbox, direct when route known, mailbox fallback when
# route unknown, and learn an authenticated PeerId only after ratchet decrypt.
# ---------------------------------------------------------------------------
path = "src/jni_api.rs"
replace_once(
    path,
    '''use crate::ratchet::direct::{
    decrypt_direct_payload, encrypt_direct_distribution, encrypt_direct_text,
    inspect_direct_sender, install_peer_bundle, reset_direct_session, DirectPayload,
};
''',
    '''use crate::ratchet::direct::{
    decrypt_direct_payload_with_route, encrypt_direct_distribution_with_route,
    encrypt_direct_text_with_route, inspect_direct_sender, install_peer_bundle,
    reset_direct_session, DirectPayload,
};
''',
)

replace_once(
    path,
    '''                        // Re-subscribe to every group the local
                        // identity already belongs to so a process
                        // restart doesn't drop us off the topic mesh.
                        resubscribe_known_groups();

                        // Now that the node's PeerId is known, stamp it
''',
    '''                        // Re-subscribe to every group the local
                        // identity already belongs to so a process
                        // restart doesn't drop us off the topic mesh.
                        resubscribe_known_groups();

                        // Also follow this identity's rotating direct inbox.
                        // This is the fail-closed bootstrap path for a contact
                        // that knows our Qubee identity but not our PeerId yet.
                        subscribe_local_direct_inbox();

                        // Now that the node's PeerId is known, stamp it
''',
)

old_direct_send = '''            let route = match resolve_peer_id(&recipient_hex) {
                Some(peer) => peer,
                None => {
                    tracing::debug!(recipient = %recipient_hex, "direct recipient has no authenticated PeerId route yet");
                    return 0;
                }
            };
            if send_direct(route, data_vec) {
                return 1;
            }
            tracing::debug!(recipient = %recipient_hex, "direct frame could not be enqueued; caller will retry same wire");
            return 0;
'''
new_direct_send = '''            if let Some(route) = resolve_peer_id(&recipient_hex) {
                if send_direct(route, data_vec) {
                    return 1;
                }
                tracing::debug!(recipient = %recipient_hex, "direct frame could not be enqueued; caller will retry same wire");
                return 0;
            }

            // First-contact / route-lost bootstrap: publish only on the
            // recipient's rotating blinded inbox, never on qubee-global. The
            // frame is still end-to-end ratchet encrypted and recipient-bound.
            if publish_direct_inbox(recipient_hex.clone(), data_vec) {
                tracing::debug!(recipient = %recipient_hex, "queued direct frame on blinded recipient inbox");
                return 1;
            }
            tracing::debug!(recipient = %recipient_hex, "direct recipient route/inbox unavailable; caller will retry same wire");
            return 0;
'''
replace_once(path, old_direct_send, new_direct_send)

replace_once(
    path,
    '''fn subscribe_group(group_id_hex: String) -> bool {
    let commander_lock = P2P_COMMANDER.lock().unwrap();
    let commander = match commander_lock.as_ref() {
        Some(c) => c,
        None => return false,
    };
    matches!(
        commander.try_send(P2PCommand::SubscribeGroup { group_id_hex }),
        Ok(())
    )
}

/// Publish bytes on a named gossipsub topic.''',
    '''fn subscribe_group(group_id_hex: String) -> bool {
    let commander_lock = P2P_COMMANDER.lock().unwrap();
    let commander = match commander_lock.as_ref() {
        Some(c) => c,
        None => return false,
    };
    matches!(
        commander.try_send(P2PCommand::SubscribeGroup { group_id_hex }),
        Ok(())
    )
}

fn subscribe_local_direct_inbox() -> bool {
    let identity = match active_identity() {
        Ok(Some(id)) => id,
        _ => return false,
    };
    let identity_id_hex = hex::encode(identity.identity_id().as_ref() as &[u8]);
    let commander_lock = P2P_COMMANDER.lock().unwrap();
    let commander = match commander_lock.as_ref() {
        Some(c) => c,
        None => return false,
    };
    matches!(
        commander.try_send(P2PCommand::FollowDirectInbox { identity_id_hex }),
        Ok(())
    )
}

fn publish_direct_inbox(recipient_id_hex: String, data: Vec<u8>) -> bool {
    let commander_lock = P2P_COMMANDER.lock().unwrap();
    let commander = match commander_lock.as_ref() {
        Some(c) => c,
        None => return false,
    };
    matches!(
        commander.try_send(P2PCommand::PublishDirectInbox {
            recipient_id_hex,
            data,
        }),
        Ok(())
    )
}

/// Publish bytes on a named gossipsub topic.''',
)

replace_once(
    path,
    '''fn resolve_peer_id(identity_hex: &str) -> Option<String> {
    PEER_DIRECTORY.lock().unwrap().get(identity_hex).cloned()
}

/// Ingest the in-band PeerIds carried by a roster snapshot''',
    '''fn resolve_peer_id(identity_hex: &str) -> Option<String> {
    PEER_DIRECTORY.lock().unwrap().get(identity_hex).cloned()
}

/// Install a PeerId that arrived *inside* a successfully decrypted direct
/// ratchet payload. The AEAD/session already authenticated `sender`, so this
/// binding is stronger than a gossip propagation source and does not expose
/// the route to mailbox subscribers.
fn install_authenticated_direct_route(sender: IdentityId, peer_id: &str) -> anyhow::Result<()> {
    if peer_id.is_empty() {
        return Ok(());
    }
    let parsed: libp2p::PeerId = peer_id
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid encrypted direct PeerId: {e}"))?;
    let normalized = parsed.to_string();
    let identity_hex = hex::encode(sender.as_ref() as &[u8]);
    PEER_DIRECTORY
        .lock()
        .unwrap()
        .insert(identity_hex.clone(), normalized.clone());
    dispatch_peer_linked(normalized, identity_hex);
    Ok(())
}

/// Ingest the in-band PeerIds carried by a roster snapshot''',
)

replace_once(
    path,
    '''            let wire = encrypt_direct_text(ks, local_id, peer_id, &plaintext_str, now_secs())?;
''',
    '''            let local_peer_id = LOCAL_PEER_ID.lock().unwrap().clone();
            let wire = encrypt_direct_text_with_route(
                ks,
                local_id,
                peer_id,
                &plaintext_str,
                local_peer_id.as_deref(),
                now_secs(),
            )?;
''',
)

replace_once(
    path,
    '''            let dist = create_or_get_own_sender_key(ks, &group_id, local_id)?;
            let wire = encrypt_direct_distribution(ks, local_id, peer_id, &dist, now_secs())?;
''',
    '''            let dist = create_or_get_own_sender_key(ks, &group_id, local_id)?;
            let local_peer_id = LOCAL_PEER_ID.lock().unwrap().clone();
            let wire = encrypt_direct_distribution_with_route(
                ks,
                local_id,
                peer_id,
                &dist,
                local_peer_id.as_deref(),
                now_secs(),
            )?;
''',
)

replace_once(
    path,
    '''            let (sender, payload) = {
                let mut ks_guard = KEYSTORE.lock().unwrap();
                let ks = ks_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;
                decrypt_direct_payload(ks, local_id, &wire_bytes, now_secs())?
            };
            let sender_hex = hex::encode(sender.as_ref() as &[u8]);
''',
    '''            let (sender, encrypted_route, payload) = {
                let mut ks_guard = KEYSTORE.lock().unwrap();
                let ks = ks_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("keystore not initialised"))?;
                decrypt_direct_payload_with_route(ks, local_id, &wire_bytes, now_secs())?
            };
            if let Some(ref peer_id) = encrypted_route {
                install_authenticated_direct_route(sender, peer_id)?;
            }
            let sender_hex = hex::encode(sender.as_ref() as &[u8]);
''',
)

# ---------------------------------------------------------------------------
# 4) Durable network failures remain retryable. Encrypt failures still have no
# wireBytes and therefore remain excluded automatically.
# ---------------------------------------------------------------------------
path = "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt"
replace_once(
    path,
    '''    /// Outbound rows the offline-retry loop should re-publish: still
    /// `SENT` (no ack yet — the `applyAckTransactional` path moves
''',
    '''    /// Outbound rows the offline-retry loop should re-publish: `SENT` or
    /// a network-send `FAILED` row that still carries durable wire bytes.
    /// Encrypt failures never have `wireBytes`, so they remain excluded.
    /// Once an ack lands `applyAckTransactional` moves the row to DELIVERED and
''',
)
replace_once(
    path,
    '''            "WHERE isFromMe = 1 AND status = 'SENT' " +
''',
    '''            "WHERE isFromMe = 1 AND status IN ('SENT', 'FAILED') " +
''',
)

# ---------------------------------------------------------------------------
# 5) Wire/payload stability pins and docs.
# ---------------------------------------------------------------------------
path = "tests/wire_stability.rs"
replace_once(
    path,
    '''use qubee_crypto::ratchet::direct::{PAYLOAD_TAG_SENDER_KEY_DIST, PAYLOAD_TAG_TEXT};
''',
    '''use qubee_crypto::ratchet::direct::{
    DIRECT_PAYLOAD_ENVELOPE_VERSION, PAYLOAD_TAG_SENDER_KEY_DIST, PAYLOAD_TAG_TEXT,
};
''',
)
replace_once(
    path,
    '''    assert_eq!(PAYLOAD_TAG_TEXT, 0x01);
    assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);
''',
    '''    assert_eq!(DIRECT_PAYLOAD_ENVELOPE_VERSION, 0x01);
    assert_eq!(PAYLOAD_TAG_TEXT, 0x01);
    assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);
''',
)

path = "docs/double-ratchet-design.md"
p = Path(path)
text = p.read_text()
needle = "QUBEE_DMS\\x02"
if needle not in text:
    raise SystemExit("double-ratchet design no longer mentions QUBEE_DMS\\x02")
if "blinded direct inbox" not in text.lower():
    text += '''\n\n### Route bootstrap\n\n`QUBEE_DMS\\x02` is recipient-bound in the durable outer frame. When Rust already\nknows the recipient's authenticated libp2p `PeerId`, delivery uses\n`/qubee/direct/1`. If that route is not known yet, the exact same ratchet frame is\npublished only to the recipient's rotating blinded direct-inbox topic — never to\n`qubee-global`. The sender's current `PeerId` is carried inside the ratchet-encrypted\npayload; after a successful decrypt the receiver binds that route to the\nchannel-authenticated Qubee identity and subsequent replies can upgrade to the\ndirect request/response transport.\n'''
    p.write_text(text)

print("direct inbox routing patch applied")
