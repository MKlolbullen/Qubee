# Double Ratchet + sender keys — design

Item #5 of the comparator-gap list. The single biggest cryptographic
gap between Qubee and Signal / SimpleX is the lack of per-message
forward secrecy and post-compromise security. This document proposes
the protocol Qubee should adopt and the staged plan to land it
without an unsafe rushed implementation.

**Status:** design pinned; prekey scaffolding lives in
`src/identity/identity_key.rs` (the `DeviceKey` / `DevicePublicKey`
types already carry X25519 + ML-KEM-768 prekey material). The
ratchet implementation itself has not yet shipped; see the staged
plan below.

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

**Stage 1 (this batch — landed):** prekey scaffolding pinned.
`DeviceKey` already carries the X25519 + ML-KEM material. No new
wire format yet.

**Stage 2 (next, ~1 week):** publish + fetch signed prekey bundles.
New `GroupHandshake::PrekeyBundle` wire variant. Receivers store
peer bundles in the keystore. Functions:
  - `IdentityKeyPair::sign_prekey_bundle(device_key, signing_key)`
  - `verify_prekey_bundle(bundle)`
No DR yet — these get cached but not used by send/receive.

**Stage 3 (~2 weeks):** PQXDH initial agreement + DR per-1:1
session. New wire `MAGIC_DIRECT_MESSAGE \x01`. Sender + receiver
state persistence in a new `RatchetStateDao`. Out-of-order skip
windows, replay protection (recently-used `(chain_idx, msg_idx)`
tuples per session).

**Stage 4 (~1 week):** sender-keys group messaging on top of DR.
New wire `MAGIC_GROUP_MESSAGE \x03`. Migration: existing groups
keep the v2 symmetric key for one release; new groups (and any
group after a member-add / member-remove) start on v3. Cleanup
batch removes v2 support after a deprecation window.

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

## What this proposal does NOT change

* The hybrid Ed25519+ML-DSA-44 signature on every message stays.
  That's Qubee's differentiator vs. Signal (Signal uses MACs and
  gets deniability; we want non-repudiation for the
  research-evidence use case — see `SECURITY.md`).
* The `IdentityKey` shape stays. Existing identities migrate by
  adding a fresh `DeviceKey` for the prekey material; the long-term
  identity stays bound to the current Ed25519+ML-DSA-44 pair.
* Sealed outer envelope stays (it lives below the wire-format
  layer and applies to either the v2 symmetric or v3 sender-keys
  format).

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
