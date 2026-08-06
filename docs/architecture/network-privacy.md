# Network privacy: IP anonymisation & metadata leakage

Status: **assessment + staged plan.** Nothing here is shipped yet; the
current position is the "IP-address privacy: No / traffic-analysis
resistance: No" row in the README security table. This document
enumerates exactly what leaks today, then lays out what can be done —
with honest costs — in the order it's worth doing.

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
| **Social graph + authorship** | gossipsub `MessageAuthenticity::Signed` + `ValidationMode::Strict`: `message.source` is the **authenticated author PeerId**, delivered to every topic subscriber | Every member of a group topic (and any node that joins it) |
| **Group identity** | Topic name = `group_topic(group_id_hex)` — the group id in the clear | Anyone who observes the topic string |
| **Timing & size** | No batching, no cover traffic, envelope padding is "at the envelope" only | Any on-path observer |

What is **not** leaked: message content (sealed), and — usefully —
there is **no libp2p `identify` behaviour**, which is one of the most
common accidental IP/agent leakers in libp2p stacks.

The two headline problems are **(A) IP exposure** (any peer learns your
network location) and **(B) the gossipsub social graph** (any topic
subscriber learns which PeerId authored which message in which group).

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
  social-graph leak. **Caveat:** the receive path currently derives the
  PeerId↔IdentityId TOFU linkage from `message.source`
  (`p2p_node.rs`), and that linkage is a documented trust invariant;
  going anonymous requires re-deriving it from the inner frame's
  identity instead. Also loses gossipsub's own signature-based spam
  gate (app-layer signatures still hold). Medium effort, security-
  sensitive — the single highest-value metadata win in our control.
- **Fixed-size padding buckets.** Pad ciphertext to a small set of
  size classes (e.g. 256 B / 1 KiB / 4 KiB) so length stops
  fingerprinting message type. Cheap, safe, purely additive.
- **Blinded topic ids.** Derive the gossip topic from a rotating hash
  of the group id + an epoch (all members derive the same value)
  instead of the raw hex, so a passive observer can't read group ids
  or trivially correlate a topic across time. Medium; needs a shared
  epoch clock among members.
- **Tighter discovery defaults.** Default mDNS **off** outside explicit
  local-discovery use, and consider Kademlia `Mode::Client` (query the
  DHT without advertising) for privacy-sensitive profiles. Small, and
  directly cuts address propagation.

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

1. **Tier 1 first**, because it's in our control, needs no new overlay,
   and closes the *social-graph* leak that a plain VPN/Tor would not
   even address. Start with the two lowest-risk pieces — **fixed-size
   padding buckets** and **tighter discovery defaults** — then take on
   **anonymous gossipsub authorship** as a focused, separately-reviewed
   change (it touches the trust-linkage invariant). Blinded topic ids
   last within the tier.
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
