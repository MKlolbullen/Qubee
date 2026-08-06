# Network privacy: IP anonymisation & metadata leakage

Status: **Tier 1 landed; Tiers 2–3 not started.** The metadata
reductions that need no new overlay are in (§2, Tier 1). IP address is
*still* exposed to every peer you connect to — the README's
"IP-address privacy: No / traffic-analysis resistance: No" row stays
accurate until Tier 2 (Tor) and Tier 3 (mixnet) respectively, and
neither has begun. This document enumerates exactly what leaks today,
then lays out what can be done — with honest costs — in the order it's
worth doing.

The guiding rule matches the rest of the project: **name the threat
precisely, don't overclaim.** Content confidentiality is already strong
(hybrid PQ crypto, forward-secret ratchet). The gap is *metadata*: who
talks to whom, from what IP, when, and how much. That gap is not closed
by encryption — it needs transport-level work.

## 1. What leaks today

Qubee is direct libp2p (TCP + QUIC, Noise) with gossipsub for groups and
a `/qubee/direct/1` request-response channel. Concretely:

| Leak | Mechanism | Who sees it |
|---|---|---|
| **Your IP address** | Direct TCP/QUIC dials; no relay or onion layer | Every peer you connect to or gossip with; any on-path network observer |
| **LAN IP / presence** | mDNS (`enable_mdns`, default **on**) | Anyone on the same local network |
| **Address propagation** | Kademlia runs in `Mode::Server` — advertises its addresses and answers DHT queries | The whole DHT, transitively |
| ~~**Social graph + authorship**~~ | ✅ *Closed.* Group publishing is now `MessageAuthenticity::Anonymous` (`ValidationMode::None` + content-based message-id): no author PeerId rides on gossip. App-layer signatures still authenticate; the PeerId↔IdentityId linkage comes only from the in-band member directory + the authenticated direct channel | ~~Every member of a group topic~~ — authorship no longer on the wire |
| ~~**Group identity**~~ | ✅ *Closed.* The topic is a blinded rotating hash, and `QUBEE_GMS\x04` replaced the envelope's plaintext `group_id` with a per-message keyed selector | ~~Anyone who observes the topic string~~ — neither the topic nor the payload names the group, and neither is stable across messages |
| **Timing & size** | No batching, no cover traffic, envelope padding is "at the envelope" only | Any on-path observer |

What is **not** leaked: message content (sealed), and — usefully —
there is **no libp2p `identify` behaviour**, which is one of the most
common accidental IP/agent leakers in libp2p stacks.

The two headline problems were **(A) IP exposure** (any peer learns your
network location) and **(B) the gossipsub social graph** (any topic
subscriber learns which PeerId authored which message in which group).
**(B) is now closed** by anonymous gossip authorship (Tier 1, landed —
see §2); a topic subscriber still sees *that* a group topic has traffic,
but no longer *who* authored it. **(A) remains** and is Tier 2 (Tor)
work.

## 2. The spectrum of mitigations

There is no single switch. Three tiers, increasing in protection and
cost:

### Tier 1 — In-tree metadata reduction (no new overlay)

Cheap, self-contained, ships without a new network dependency. Does
**not** hide your IP from a peer you connect to, but shrinks what
*other peers and topic subscribers* learn.

- **Anonymous gossipsub authorship.** Switch group publishing from
  `MessageAuthenticity::Signed` to `Anonymous`, so `message.source` is
  no longer broadcast. Messages are *already* authenticated at the app
  layer — v2 carries a hybrid identity signature, v3 carries the
  ephemeral sender-key signature — so transport-level author
  attribution is redundant for security but is the direct cause of the
  social-graph leak. Investigation showed this is **not** a config flip:
  `message.source` is the *only* way peers learn each other's network
  PeerId today, and it feeds both the PeerId↔IdentityId trust linkage
  (a documented invariant) *and* all direct-message routing
  (`PEER_DIRECTORY` → JoinAccepted/KeyDelivery). Going anonymous forces
  distributing **authenticated PeerIds in-band** across the signed
  frames, plus flipping `ValidationMode::Strict`→`None` (which changes
  gossipsub's own dedup/spam gate — app-layer signatures still hold).
  So this lands as a *sequenced* change, not one edit:
  - **Step 1 (✅ landed).** `RequestJoinBody` now carries the joiner's
    own `joiner_peer_id`, self-attested and covered by the frame
    signature (`_v2` tag + pinned vector). The inviter routes the direct
    `JoinAccepted`/`JoinRejected` reply from the authenticated body
    rather than the gossip author, with a fallback to `message.source`
    for empty (legacy) peer ids while gossip is still Signed. This
    removes the join handshake's dependency on the broadcast author
    PeerId and makes that linkage authenticated instead of transport
    TOFU. Correction to an earlier note: this needs **no** invite-link
    change — the joiner knows its own PeerId; the invite is untouched.
  - **Step 2 (✅ landed).** Member PeerIds are distributed in-band: an
    authenticated `peer_id` on `GroupMemberSummary` (so the three tags
    bump — `join_accepted_v3`, `member_added_v2`,
    `state_sync_response_v3` — with pinned-vector updates), plus a
    durable `GroupMember::peer_id` set from the joiner's authenticated
    RequestJoin and from the local node's own PeerId. Receivers ingest
    each snapshot's PeerIds into the peer directory. `set_member_peer_id`
    deliberately does **not** bump `group.version` (routing metadata,
    not membership — a bump would trip the strict generation gate). Now
    every member can direct-route to every other member without the
    gossip author.
  - **Step 3 (✅ landed).** Group publishing is now
    `MessageAuthenticity::Anonymous` with `ValidationMode::None` and a
    content-based `message_id_fn` (BLAKE3 over topic + payload — required
    so anonymous frames, which carry no source/seqno, don't all collapse
    to one gossipsub message-id and get deduped away). The gossip receive
    path emits an **empty** sender, and every PeerId↔IdentityId linkage —
    Rust `PEER_DIRECTORY` and the Kotlin trust policy
    (`observePeerIdentityLink`) — now ignores gossip senders, taking peers
    only from the authenticated in-band directory (steps 1–2) or the
    authenticated `/qubee/direct/1` channel. A regression test pins that a
    gossip frame arrives with no author PeerId. App-layer hybrid /
    sender-key signatures remain the real authenticity gate; gossipsub's
    own signature spam-gate is gone (accepted trade-off).
  Security-sensitive — the single highest-value metadata win in our
  control, now shipped.
- **Fixed-size padding buckets.** ✅ *Landed (whole forward-secret path).*
  `security::padding` (length-prefix + zero-pad to a geometric size
  class: 256 / 1 K / 4 K / 16 K / 64 K, then 64 K steps) is applied to
  the v3 sender-key message plaintext **and** the 1:1 Double-Ratchet
  plaintext (which also carries the sender-key distributions), so
  distinct messages across the forward-secret path share one on-wire
  length. Scoped to the dark-launched ratchet paths (no live-wire /
  compat impact); the legacy v2 group path adopts the same primitive at
  the ratchet cutover, when its format changes once anyway.
- **Blinded topic ids.** ✅ *Landed.* The topic is now
  `qubee-g-<blake3(domain ‖ group_id_hex ‖ epoch)[..16]>` instead of
  `qubee-group-<group_id_hex>`, so the group id is no longer readable
  *from the topic string* and an observer gets no stable handle to
  follow a topic across time. The shared epoch clock is wall-clock time floored to
  `TOPIC_EPOCH_SECS` (24 h). Skew is absorbed by *subscribing to a
  window* rather than a point: a member follows `{e-1, e, e+1}` and
  publishes on `e`, so a peer whose clock is up to a full epoch off
  still shares a topic, and frames in flight across a rotation boundary
  still land. Because the window has to be re-derived as epochs roll,
  the node follows **group ids, not topic strings** — the new
  `P2PCommand::SubscribeGroup` / `UnsubscribeGroup`, with the node
  re-syncing its subscriptions on a 5-minute ticker. The receive path
  was already topic-agnostic (group id comes from the signed frame), so
  nothing downstream had to change.
  The envelope half followed: `QUBEE_GMS\x04` drops the plaintext
  `group_id` in favour of a per-message keyed selector
  (`blake3::keyed_hash(derive_key("qubee group selector v1",
  group_key), nonce)[..8]`), so the receiver picks a key by
  recomputing the selector per candidate group rather than being told
  which group the frame belongs to. Salting by the frame nonce is what
  keeps it from becoming a stable per-group handle. `\x03` is skipped
  — it is already the ratchet sender-key frame, and reusing it would
  route frames to the wrong decoder.
  *Compatibility:* both the topic string and the group-message frame
  change, so this build does not meet older ones on a group.
  Pre-alpha, no migration.
- **Tighter discovery defaults.** ✅ *Landed.* `P2PNodeConfig::default`
  sets `enable_mdns: false`, so a device no longer broadcasts its
  presence + LAN IP by default (Kademlia / bootstrap remain the
  discovery path; a caller can re-enable mDNS explicitly for local use).
  `kademlia_client_mode` now offers `kad::Mode::Client` — query the DHT
  without advertising our own addresses into it. It is **opt-in, default
  off** on purpose: a client-mode node cannot be found through the DHT
  and serves no routing for anyone else, so if every node ran as a
  client there would be no DHT left to query. It is a knob for
  privacy-sensitive profiles, not a new default.

### Tier 2 — IP anonymisation via Tor (Arti)

Hides your IP/location. The mature-enough Rust path is
[`libp2p-community-tor`](https://docs.rs/libp2p-community-tor)
(built on the Tor Project's [Arti](https://gitlab.torproject.org/tpo/core/arti)),
which since its #21 supports **listening as an onion service** — both
endpoints anonymous, and no router port-forwarding needed.

Honest costs and caveats (from the crate's own warnings + Arti's
status, 2025–26):

- **Leaky-by-default.** Running Tor "like a regular transport" gives
  *no* privacy: mDNS, Kademlia address advertisement, and any
  `identify` will publish your real address anyway. Tor is only
  meaningful if those are disabled and inbound is an onion service.
- **Experimental onion services.** Arti's onion services are marked
  experimental and "not as secure as C-Tor" — fine for a pre-alpha
  opt-in, not for life-critical traffic. Disclose it in-product.
- **Latency.** Bootstrapping a Tor client takes ~20–60 s; per-message
  latency rises. gossipsub over circuit-switched Tor is workable for
  small groups but is not what Tor is optimised for.
- **Version gap.** The crate currently pins `libp2p ^0.53` / `arti
  ^0.24`; we're on libp2p 0.56. Adoption means either waiting for /
  contributing a 0.56 bump, or embedding `arti-client` directly and
  wiring a custom `Transport` (the arti-client API is stable enough —
  `TorClient::create_bootstrapped`, `launch_onion_service`,
  `connect`).
- **What it does *not* do:** Tor is low-latency with no mixing or cover
  traffic, so it does **not** defeat traffic-analysis (timing/volume
  correlation) by a global passive adversary. It hides *where* you are,
  not *when/how much* you talk.

### Tier 3 — Full metadata protection via a mixnet (Nym / Loopix)

The only tier that targets a **global passive adversary** and
traffic-analysis. [Nym](https://docs.rs/nym-sdk)'s mixnet uses
fixed-size Sphinx packets, continuous-time mixing (random per-hop
delays), and tunable cover traffic to provide sender–receiver
unlinkability that *improves* as the network grows.

Costs (from Nym's own measurements):

- **Latency:** ~1.6 s end-to-end for a 5-hop path at default mixing —
  acceptable for a messenger, not for calls.
- **Cover traffic:** a steady ~1 Mbps stream whether or not you're
  sending, to keep idle and busy users indistinguishable — a real
  mobile battery/data cost.
- **Architecture shift:** Nym is a separate overlay reached through
  `nym-sdk`'s `MixnetClient`, not a libp2p transport. Messages would
  route through the mixnet (client → gateway → 3 mix layers → gateway →
  recipient) addressed by Nym `Recipient`, *replacing* gossip for the
  privacy-sensitive path rather than tunnelling under it. Largest
  integration effort, and a dependency on Nym's gateway infrastructure.
- Note: a naive P2P cover-traffic scheme cannot match a mixnet's
  anonymity without absurd cover volumes (Nym's study: ~10 cover
  packets per real packet at 100 K users to approximate what the mixnet
  gives 1.6 K users) — so "just add cover traffic to libp2p" is not a
  substitute for Tier 3.

## 3. Recommended order

1. **Tier 1 — ✅ complete.** All four pieces have landed: fixed-size
   padding buckets, tighter discovery defaults (mDNS off by default plus
   an opt-in Kademlia client mode), anonymous gossipsub authorship
   (steps 1–3), and blinded topic ids. The remaining Tier 1 debt is
   deliberate and recorded above: the legacy v2 group path still sends
   unpadded, adopting `security::padding` at the ratchet cutover when
   its format changes once anyway.
2. **Tier 2 (Tor/Arti)** as the first *IP*-anonymisation step: an
   opt-in onion-service transport, defaulted **off**, gated behind the
   same "experimental, device-validation-pending" discipline as the
   ratchet cutover and the DB-key binding. This is the biggest
   single win for "peers can see my IP" and is independently useful
   even before Tier 3.
3. **Tier 3 (Nym mixnet)** only if/when defeating a global passive
   adversary becomes a goal — it's the strongest and by far the
   heaviest, and it changes the transport model.

None of these should be advertised as done until validated, and the
README/SECURITY tables should move from "No" to a precise
"opt-in / experimental / validation-pending" wording as each lands —
never to an unqualified "Yes".

## 4. Explicitly out of scope for now

- Relay-based IP hiding (libp2p circuit-relay v2). It hides your IP
  from the *final* peer but the relay learns both ends — reintroducing
  the who-talks-to-whom custodian the no-central-server design exists
  to avoid. Not worth it as a privacy measure.
- Claiming any of this defeats a device-compromise or endpoint
  attacker. Metadata protection is about the *network*, not the
  endpoint.
