# Double Ratchet + sender keys — design

Item #5 of the comparator-gap list. The single biggest cryptographic
gap between Qubee and Signal / SimpleX is the lack of per-message
forward secrecy and post-compromise security. This document proposes
the protocol Qubee should adopt and the staged plan to land it
without an unsafe rushed implementation.

**Decision (locked):** Qubee moves to the **full-deniability** model.
Per-message long-term-key signatures are **removed**; messages are
authenticated only by the AEAD/MAC under the ratchet keys (both parties
derive them, so a transcript proves nothing about authorship). Identity
keys sign only the *prekey bundle* (binding the keys to an identity),
never messages. This reverses the earlier "keep non-repudiation" note
below — the research/evidence use case is dropped in favour of the
privacy-messenger default (Signal / SimpleX / Session all do this).

**Status:**
* **Stage 1 — LANDED.** The cryptographic core is implemented + tested
  in `src/ratchet/`:
  * `src/ratchet/double_ratchet.rs` — the Double Ratchet (X25519 DH
    ratchet, HKDF-SHA256 root KDF, BLAKE3 chain KDF, ChaCha20-Poly1305
    message AEAD with the header bound as AAD), out-of-order + skipped
    keys (bounded by `MAX_SKIP`), replay rejection, zeroization.
    Deniable by construction (no signatures; auth is the Poly1305 tag).
  * `src/ratchet/pqxdh.rs` — the PQXDH initial agreement (X3DH-style
    X25519 DHs + ML-KEM-768 encapsulation → shared secret). Deniable
    (DH-based) + post-quantum (KEM folded into the KDF).
  * 13 tests: full-duplex ping-pong across multiple ratchet steps,
    out-of-order within/across chains, tamper + wrong-AD + replay
    rejection, MAX_SKIP enforcement, PQXDH agreement (with/without
    one-time prekey), and the end-to-end PQXDH→ratchet handshake.
  This is a self-contained module — it does not yet touch the wire
  format, session store, JNI, or the group layer.
* **Stage 2 — LANDED.** The prekey infrastructure is wired into the
  wire format, encrypted keystore, and JNI bridge:
  * `src/groups/group_handshake.rs` — the `GroupHandshake::PrekeyBundle`
    frame (`PrekeyBundleBody` + hybrid identity signature),
    `canonical_prekey_bundle` (tag `qubee_handshake_prekey_bundle_v1`),
    `sign_prekey_bundle` / `verify_prekey_bundle` (30-day validity via
    `PREKEY_BUNDLE_MAX_AGE_SECS`).
  * `src/ratchet/prekey_store.rs` — persistence + conversion between the
    live PQXDH secret bundle, the signed publishable body, and an
    encrypted on-disk form; caches verified peer bundles keyed by
    `IdentityId`.
  * `src/jni_api.rs` — `process_handshake` verifies + caches inbound
    bundles (fail-closed, self-filtered); `nativeBuildLocalPrekeyBundle`
    produces the signed wire frame for the Android side to publish.
  Bundles are **published + cached but not consumed** by send/receive —
  the current v2 symmetric-group path is unchanged.
* **Stage 3 — DONE.** The full 1:1 path is implemented and callable
  over JNI. It shipped dark-launched (legacy envelope still live) until
  the device checklists passed; since the v0.2.0 cutover it is the
  default 1:1 send path.
  * *Foundation* — `DoubleRatchet::serialize_state` / `deserialize_state`
    so a session survives an app restart without reusing a message key.
  * *3b* — `src/ratchet/session.rs`: a `Session` ties PQXDH + the Double
    Ratchet + `prekey_store` into one conversation keyed by peer
    `IdentityId`, with `establish_initiator` / `establish_responder` /
    `encrypt` / `decrypt` and keystore persistence. A deterministic
    per-conversation AD (blake3 over the sorted id pair) binds every
    frame to its pair.
  * *3c* — `src/ratchet/direct_message.rs`: the `DirectMessage`
    (`QUBEE_DMS\x01`) wire frame carrying the optional PQXDH
    `InitialMessage`, the ratchet header, and the ciphertext. Unsigned
    (deniable); bounded decode on the unauth path.
  * *3d* — `src/ratchet/direct.rs` + four JNI symbols
    (`nativeInstallPeerPrekeyBundle`, `nativeEncryptDirectMessage`,
    `nativeDecryptDirectMessage`, `nativeInspectDirectMessageSender`).
    Session state persists only after a successful operation (garbage
    frames can't corrupt the stored ratchet); replays die on consumed
    message keys plus an accepted-initial hash record; responder
    establishment requires the initial's X25519 identity to match the
    sender's cached *verified* bundle (fail closed); simultaneous-open
    resolves byte-wise-smaller-id-wins. A peer who wipes state and
    re-initiates but loses the tie-break is unblocked via
    `nativeResetDirectSession` (user action / trust-state event), after
    which their next inbound initial re-establishes.
* **Stage 4 — DONE (dark-launched).** `src/ratchet/sender_keys.rs` +
  four JNI symbols (`nativeCreateSenderKeyDistribution`,
  `nativeInstallSenderKeyDistribution`, `nativeEncryptGroupMessageV3`,
  `nativeDecryptGroupMessageV3`). Per-sender BLAKE3 hash chains
  (`QUBEE_GMS\x03`) give in-group forward secrecy; a per-group
  *ephemeral* Ed25519 signing key — distributed only over the encrypted
  1:1 sessions — authenticates senders inside the group without
  reintroducing identity signatures, so transcripts stay deniable to
  outsiders. The v2 sealed outer envelope is retained (new KDF
  context). Live group traffic still rides v2; membership changes must
  call `reset_group_sender_state` + redistribute at cutover.
* **Stage 5 — plumbing LANDED (dark); flag-flip pending.** The 1:1
  plaintext is now a tagged payload (0x01 text / 0x02 sender-key
  distribution, pinned in wire-stability): distributions ride the
  encrypted 1:1 sessions via `nativeCreateDirectDistributionMessage`,
  and `nativeDecryptDirectMessage` returns typed JSON and auto-installs
  inbound distributions after checking the channel-authenticated sender
  against group membership. Rekey is automatic: member removal
  (`nativeRemoveMember`) and verified inbound `KeyRotation` frames both
  wipe the group's sender chains (`nativeResetGroupSenderState` exists
  for manual rekeys). **Receive side is live**:
  `MessageService.handleRatchetFrame` recognises
  `QUBEE_DMS`/`QUBEE_GMS\x03` frames unconditionally (receivers must
  understand v3 before any sender emits it), routes 1:1 text through
  the same peer↔identity trust observation as the legacy path, and
  persists v3 group messages through the shared handler. **Send side is
  now default**: `PreferenceRepository.ratchetSendEnabled` defaults to
  true since the v0.2.0 cutover (1:1 via `encryptDirectMessage`, groups
  via `encryptGroupMessageV3`, distribution fan-out via
  `RatchetSender`), retained as an emergency kill-switch for the soak
  window. What remains: dropping v2 emission entirely after the
  deprecation window.

## What's currently broken

The current group-message construction uses a single symmetric
ChaCha20-Poly1305 key per group, rotated only on member removal.
Compromise of any member's device today exposes every message
exchanged in that group since the last rotation — potentially the
entire history if no one's been removed. The same is true for 1:1
chats (which are modelled as a 1-member "group" with the same
shape).

Signal's Double Ratchet limits the blast radius to "messages within
the current chain" (typically one message) by deriving fresh message
keys via a symmetric ratchet on every send plus a Diffie-Hellman
ratchet whenever a new DH public arrives. Once a key is used to
decrypt, it's deleted; later compromise reveals nothing about
already-delivered messages.

## Target design

### 1:1 chats — PQXDH initial agreement + hybrid Double Ratchet

* **Initial key agreement (PQXDH)**: extend Signal's X3DH with an
  ML-KEM-768 encapsulation in parallel with the X25519 DH outputs.
  Inputs:
    - `IK_A`, `IK_B`: long-term identity keys (already exist as
      `IdentityKey` — Ed25519 + ML-DSA-44).
    - `SPK_B`: a signed X25519 prekey published by Bob. The
      signature is hybrid Ed25519+ML-DSA-44 by `IK_B`.
    - `OPK_B`: optionally a one-time X25519 prekey (rotated set).
    - `PQKEM_B`: an ML-KEM-768 prekey + an optional one-time
      ML-KEM prekey, signed under `IK_B`.
    - `EK_A`: Alice's ephemeral X25519.
    - `EKEM_A`: Alice encapsulates against `PQKEM_B`, producing a
      KEM shared secret `SS_PQ`.
  Initial root key:
    `RK_0 = HKDF(DH1 || DH2 || DH3 || (DH4) || SS_PQ, info)`
  where `DH1..DH4` mirror the X3DH derivations.

  The PQ contribution makes this **harvest-now-decrypt-later
  resistant** — current Signal's PQXDH does the same; SimpleX has it
  too.

* **Symmetric ratchet**: per-direction chain keys derived from the
  root key. `mk = HMAC(ck, "mk") ; ck' = HMAC(ck, "ck")`. Each
  message uses a fresh `mk`; receivers cache out-of-order `mk`s
  bounded by a skip window (`MAX_SKIP = 1000`).

* **DH ratchet step**: every time we send the first message after
  receiving one, generate a fresh `(EK_send, EKEM_send)` and include
  the public bits in the message header. Both sides re-derive `RK`
  from the new DH + KEM outputs, reset chain keys.

* **Header encryption**: encrypt the message header (containing the
  new public key bits) under a separate `HK` derived from the
  previous root key. Signal calls this the "header encryption
  variant"; it hides DH ratchet steps from passive observers — same
  motivation as the sealed-outer-envelope we just shipped for the
  current symmetric scheme.

* **Receiver-driven KEM rotation**: refresh the ML-KEM prekey on a
  cadence (e.g. every 50 received messages or every 30 days). The
  ratchet design lets the receiver advertise a fresh PQ public via
  the next header without breaking ongoing decryption.

### Groups — Sender Keys

* Each member maintains a **sender chain** for the group:
  `(sender_chain_key, sender_signing_key)`.
* Outbound message: derive `mk` from chain key, encrypt the body
  under `mk`, sign with the per-group `sender_signing_key`. Advance
  the chain key.
* The sender chain key + signing public are distributed to other
  members via the **per-member 1:1 Double Ratchet channel** that
  this same proposal lands for 1:1 chats. (Bootstrapping order:
  shipping 1:1 DR first, then groups, is the only viable sequence.)
* New-member onboarding: the inviter forwards every existing
  sender's current chain key + signing public to the new joiner
  via the 1:1 channel. Existing members each derive a fresh
  sender chain key on join (a forward-secrecy step) and re-share
  the new key.
* Member removal: every remaining member generates a fresh sender
  chain key and re-distributes via 1:1 channels. Same property as
  the current symmetric-group-key rotation, but per-sender — so a
  removed member loses access to *future* outbound from each
  current member, not retroactively to past content under the same
  chain.

This matches Signal's group-messaging design. The post-compromise
property here is "fresh chain keys after every rotation," which
bounds blast radius the same way the per-message ratchet does on
1:1.

## Wire-format implications

* New `GroupHandshake::PrekeyBundle { ik, spk, pq_kem_pk,
  signature, ... }` — published when an identity joins a group or
  acquires a new contact, fetched by anyone initiating a session.
* New direct-message wire variant `Direct1to1Message` with header
  encryption + DR header fields (chain index, previous chain
  length, DH/KEM publics encrypted under `HK`).
* New group-message wire variant `SenderKeyMessage` carrying the
  signed ciphertext + chain index. Replaces the current sealed
  outer envelope for groups.
* Existing sealed-envelope wire format (`MAGIC_GROUP_MESSAGE \x02`)
  remains for one release as a **migration overlap** — receivers
  accept both during the transition; senders pick based on a
  per-group capability flag.

## Migration plan (staged)

**Stage 1 (LANDED):** the Double Ratchet + PQXDH core, implemented and
exhaustively tested in `src/ratchet/` (`double_ratchet.rs`,
`pqxdh.rs`). Pure module; no wire format, session store, or JNI yet.

**Stage 2 (LANDED):** publish + fetch signed prekey bundles. The
`PrekeyBundle` wire frame carries the X25519 identity/signed-prekey/
one-time-prekey publics + the ML-KEM prekey public, signed by the
hybrid identity key. Receivers verify (`verify_prekey_bundle`) and cache
peer bundles in the keystore (`ratchet::prekey_store`). No live DR yet —
bundles are cached but not consumed.

**Stage 3 (LANDED, dark):** PQXDH initial agreement + DR per-1:1
session, end to end — ratchet-state serialisation, the `Session`
manager (`src/ratchet/session.rs`), the `MAGIC_DIRECT_MESSAGE \x01`
wire frame (`src/ratchet/direct_message.rs`), and the live orchestration
+ JNI bridge (`src/ratchet/direct.rs`, four `nativeDirect*`/bundle
symbols). Replay protection comes from consumed message keys plus an
accepted-initial hash record — a dedicated `(chain_idx, msg_idx)` window
proved unnecessary. Shipped dark; default 1:1 send path since the
v0.2.0 cutover.

**Stage 4 (LANDED):** sender-keys group messaging on top of DR —
`src/ratchet/sender_keys.rs`, wire `QUBEE_GMS\x03`; default group send
path since the v0.2.0 cutover.
Migration plan unchanged: existing groups keep the v2 symmetric key for
one release; new groups (and any group after a member-add /
member-remove) start on v3. Cleanup batch removes v2 support after a
deprecation window.

**Stage 5:** drop v2 group-message wire format. Remove the
symmetric-group-key path entirely.

## Testing strategy

* Property tests over the DR state machine — out-of-order delivery
  preserves correctness up to the skip window, beyond it fails
  cleanly.
* Wire-stability tests pinning each new magic byte and the
  canonical body-bytes layout for `PrekeyBundle`,
  `Direct1to1Message`, `SenderKeyMessage`.
* Compromise-recovery test: simulate Eve learning the current state
  of Alice's ratchet, verify she can decrypt only the current
  chain's queued messages and nothing in the next DH ratchet step.
* Two-device end-to-end manual test against the staged wire
  formats.

## What changes vs. stays

* **Per-message signatures: REMOVED.** This is the deliberate reversal
  of the earlier design. Messages are authenticated only by the
  ratchet AEAD (a MAC both parties can compute) → deniable. The
  hybrid Ed25519+ML-DSA-44 identity signature is retained **only** for
  signing prekey bundles (and onboarding/invite frames), where
  attesting "I published these keys" is correct and does not make
  messages non-repudiable.
* The `IdentityKey` shape stays as the signing identity. A parallel
  X25519 identity key (for the deniable DH handshake) comes from the
  existing `DeviceKey`; a new signed-prekey + one-time-prekey +
  ML-KEM-prekey bundle is published per identity.
* Sealed outer envelope stays (it lives below the wire-format
  layer and applies to either the v2 symmetric or v3 ratchet format).

## Separate track: IP-exposure / Tor transport

Chosen: an **optional, off-by-default** Tor transport (SOCKS5 to a
bundled/`arti` Tor, or an onion-address listener via `libp2p`), toggled
in Settings. Off by default because always-on onion routing adds
latency that hurts the live-P2P UX for users not under a hostile
network. This is independent of the ratchet work and lands as its own
batch (`src/network/p2p_node.rs` transport config + a Kotlin toggle);
it does not touch the crypto core.

## Risks + open questions

* **PQXDH state machine complexity.** Even Signal's reference
  implementation has had bugs (the 2024 PQXDH paper documented
  several). Approach: port `libsignal-protocol-rust`'s reference
  rather than write from scratch, then wrap with our hybrid PQ
  shim. Licence-compatible (GPLv3 → MIT/Apache; we'd vendor under
  GPLv3 module if pulled in; or re-implement against the spec).
* **Out-of-order delivery on lossy gossipsub.** DR's skip window
  protects against reordering but not infinite loss; we need a
  size-bound on cached skipped keys (`MAX_SKIP = 1000` is the
  Signal default).
* **Sender-keys distribution on member churn.** N members ⇒ N×N
  pairwise re-shares on every rotation. For Qubee's 16-member cap
  this is fine (256 1:1 sends max per churn event); for any future
  larger-group support this becomes a perf cliff.
* **Migration overlap window.** Devices on v2 and v3 in the same
  group during stage 4 need to interop. The straightforward answer
  is: a v3-capable sender sends v2 if any member of the group is
  still v2-only; the group migrates atomically on the first
  member-add after all members are v3-capable. Requires per-member
  capability flags in `GroupMember`.

## Why this doc and not the code

Shipping DR + sender keys safely is roughly 3–4 weeks of focused
work. Doing it in a rushed session would ship something that *looks*
like DR but might have subtle bugs in:
* skip-window bookkeeping (missing acks ⇒ memory blowup)
* replay protection (failure to dedupe ⇒ accept replays)
* header encryption (HK derivation error ⇒ plaintext header leakage)
* PQXDH transcript binding (wrong KDF info ⇒ unknown-key-share attack)

These are the standard ways that DR implementations have shipped
CVEs over the past decade. The safe move is to write the protocol
down, prove out the prekey infrastructure, then implement in two
or three carefully-reviewed PRs.
