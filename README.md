# Qubee

> **Post-quantum, peer-to-peer messaging, audio/video calls & file-sharing.**
> Built with **Android (Kotlin + Compose)** and **Rust** for maximum security and performance.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.86%2B-orange)
![Status](https://img.shields.io/badge/status-pre--alpha-red)

---

## Overview

Qubee is a research-grade secure messenger that eliminates centralized
infrastructure. It uses a **hybrid cryptographic scheme** combining
classical algorithms (Ed25519 for identity signatures, X25519 for
key agreement) with the NIST-standardised post-quantum primitives
**ML-KEM-768 (FIPS 203)** for key encapsulation and **ML-DSA-44
(FIPS 204)** for signatures.

The core protocol and cryptography are implemented in **Rust** for
memory safety and performance, exposed to the **Android** application
via JNI.

## Features

| Category | Qubee |
|----------|-------|
| **Post-quantum** | ML-KEM-768 (FIPS 203) + ML-DSA-44 (FIPS 204), with hybrid Ed25519+ML-DSA-44 signing on every onboarding bundle, invite, group handshake, key rotation, and message envelope. |
| **P2P transport** | libp2p 0.55 (TCP + DNS + Yamux + Noise XX + gossipsub + Kademlia + mDNS), no central server. |
| **Group messaging** | ChaCha20-Poly1305 under a per-group symmetric key, plus per-message hybrid signature. Strict generation-counter gate on receive. |
| **Membership** | Up to 16 members, role-based (Owner / Admin / Moderator / Member / Observer), signed `MemberAdded` / `RoleChange` / `KeyRotation` broadcasts so existing devices stay convergent. |
| **Identity** | 8-byte BLAKE3 fingerprint of `(classical_pub \|\| pq_pub)`, rendered in onboarding + add-contact UI for out-of-band comparison. |
| **Storage** | EncryptedSharedPreferences (Android Keystore-backed) for the onboarding bundle; local Rust keystore (XChaCha20-Poly1305 + BLAKE3 integrity) for group keys, per-group Kyber secrets, and pending invitations. |
| **Memory** | Sensitive material wrapped in `secrecy::SecretBox` with `Zeroize` on drop; `mlock`/`munlock` on Unix. |

## Tech stack

### Android (client)
* **Language:** Kotlin
* **UI:** Jetpack Compose (Material3) + a small set of Fragment + View
  shells for nav-graph integration.
* **Architecture:** MVVM, Hilt (DI), Coroutines/Flow.
* **Storage:** EncryptedSharedPreferences. (Room is **not** wired up
  today — the half-built data layer was replaced with compile-clean
  no-op stubs as part of the pre-alpha cleanup; see the Roadmap below.)
* **Networking:** libp2p P2P node runs in Rust; Android receives
  callbacks via JNI.

### Rust (core)
* **Crate:** `qubee_crypto`
* **Interface:** JNI (`jni` crate)
* **Async runtime:** Tokio
* **Cryptography:** `pqcrypto-mlkem`, `pqcrypto-mldsa`, `ed25519-dalek`,
  `x25519-dalek`, `chacha20poly1305`, `blake3`, `hkdf`/`sha2`.
* **P2P:** `libp2p 0.55`.
* **Toolchain:** Rust 1.86 (pinned in `rust-toolchain.toml`).

## Setup & build

### Prerequisites
1. **Android Studio** (Ladybug or newer recommended).
2. **Rust toolchain** — pinned to 1.86 via `rust-toolchain.toml`. Run `rustup show` from the repo root to install.
3. **Android NDK** (installed via SDK Manager).
4. **cargo-ndk:**
   ```bash
   cargo install cargo-ndk
   ```

### 1. Clone
```bash
git clone https://github.com/MKlolbullen/Qubee.git
cd Qubee
```

### 2. Build the Rust core
You must compile the Rust shared libraries (`.so`) before building the Android app.

**Bash (Linux/macOS/WSL):**
```bash
chmod +x build_rust.sh
./build_rust.sh
```

**PowerShell (Windows):**
```powershell
./build_rust.ps1
```

This compiles for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`
and drops the libs in `app/src/main/jniLibs`.

### 3. Run the Android app
1. Open `Qubee` in Android Studio.
2. Sync Gradle.
3. Pick a device/emulator and **Run**.

## Project structure

```text
Qubee/
├── app/                          # Android application
│   ├── src/main/java/            # Kotlin (UI, services, DB stubs)
│   ├── src/main/jniLibs/         # Compiled Rust libraries (.so)
│   └── build.gradle              # App-level build config
├── src/                          # Rust core (`qubee_crypto`)
│   ├── groups/                   # GroupManager, group_handshake,
│   │                             # group_message, group_crypto,
│   │                             # handshake_handlers,
│   │                             # group_permissions, group_invite
│   ├── identity/                 # IdentityKey + ContactManager
│   ├── network/                  # libp2p P2PNode, NetworkResolver
│   ├── onboarding/               # Onboarding bundles + invite-link
│   │                             # parsing
│   ├── storage/                  # SecureKeyStore (encrypted)
│   ├── security/                 # secure_memory, secure_rng
│   ├── jni_api.rs                # JNI bridge (Android-only)
│   └── lib.rs                    # Module wiring + feature gates
├── tests/                        # Rust integration tests
│   ├── group_handshake_e2e.rs    # In-process handshake protocol
│   ├── group_message_e2e.rs      # Encrypted messaging + A1/A2
│   ├── p2p_two_node_e2e.rs       # Real two-node libp2p E2E
│   └── wire_stability.rs         # Pinned canonical wire vectors
├── Cargo.toml                    # Rust dependencies
├── rust-toolchain.toml           # Pin to Rust 1.86
└── build_rust.sh / .ps1          # Build scripts
```

## Security model

### Three layers of defence

* **Transport.** Every libp2p connection negotiates **Noise XX** plus
  Yamux multiplexing (`p2p_node.rs`). Each peer authenticates with
  its libp2p Ed25519 identity, the channel is end-to-end encrypted
  and integrity-protected against a passive or active network
  attacker.
* **Group messages.** Members converge on a single symmetric group
  key (32 bytes, ChaCha20-Poly1305 keyed). Each frame carries a
  monotonically-increasing **generation counter** matching
  `group.version`; receivers reject stale or future generations
  outright (no buffering, no lock-step recovery — strict policy
  closes the kicked-then-rotated race). Every frame is signed with a
  hybrid **Ed25519 + ML-DSA-44** signature over canonical bytes
  (handcrafted, length-prefixed, NUL-separated, with a per-variant
  domain-separation tag — *not* `bincode`).
* **Identity.** The **8-byte BLAKE3 fingerprint** of
  `(classical_pub || pq_pub)` is rendered in `OnboardingScreen.kt`
  and `AddContactFragment.kt` for out-of-band comparison. The
  cryptographic guarantee is already in the wire format; what's
  missing is the verification *gesture* (tap-to-verify or SAS
  number-compare).

### Key rotation and convergence

Removing a member triggers `rotate_group_key_after_removal`: the
inviter generates a fresh 32-byte key, encapsulates it under each
remaining member's per-group ML-KEM-768 pubkey, signs the bundle
with hybrid Ed25519 + ML-DSA-44, and broadcasts a `KeyRotation`
frame on the group's gossipsub topic.

To keep every device's local view consistent across membership
churn, the inviter also broadcasts:
* `MemberAdded` after a successful `RequestJoin` so existing
  members learn the new joiner's per-group ML-KEM-768 pubkey
  (without it, their later rotations would silently exclude the
  joiner).
* `RoleChange` whenever the owner promotes / demotes a member, so
  receivers update their permission view in lock-step with the
  generation counter.

Each broadcast carries the inviter's post-mutation `group.version`
so receivers' generation counters stay synchronised with the
sender's; the strict gate in `decrypt_group_message` would otherwise
reject the very next message after a join or promotion.

### Why no application-layer Noise

We don't run an application-layer Noise tunnel on top of libp2p's
transport-layer Noise XX. Group messaging is one-to-many over
gossipsub multicast, which already needs a shared symmetric group
key (which `GroupCrypto` provides), and the per-message hybrid
signature already authenticates the sender. A second Noise pass
would add encrypted-twice redundancy plus per-recipient state we
don't have anywhere else to keep, with no security gain.

### Why no zero-knowledge proofs

An earlier prototype framed onboarding QRs as carrying a "ZK proof
of key ownership". They didn't — the math was a byte-wise
`wrapping_add` masquerading as a Schnorr proof. We removed the code,
the documentation, and the framing. The underlying reasoning so the
question doesn't get re-litigated:

ZK proofs are the right primitive when the prover wants to convince
a verifier of a statement *about hidden inputs*: anonymous
credentials, range proofs, set membership without revealing the
set. Qubee never needs to do that. Every claim it makes about an
identity is "I hold the secret for this advertised public key",
which is exactly what a signature is for. We sign canonical bytes
of every onboarding bundle, invite, group handshake, key rotation,
role change, member-added broadcast, and message envelope with a
hybrid Ed25519 + ML-DSA-44 signature; both halves must verify.
Adding a ZK layer on top would be more code, more failure modes,
and a strictly weaker security argument than the signature already
gives.

## Tests

### Rust
```bash
cargo test --locked
```
Currently **60 tests green** across:
* `lib` unit tests (33)
* `tests/group_handshake_e2e.rs` (5)
* `tests/group_message_e2e.rs` (10) — including the strict
  generation-counter gate, the A1/A2 regressions (promoted-admin
  rotation, late-joiner kem_pub plumbing, MemberAdded broadcast
  convergence), and the `promote_member` + `RoleChange` round-trip.
* `tests/p2p_two_node_e2e.rs` (2) — full libp2p between two
  in-process `P2PNode` instances over loopback TCP.
* `tests/wire_stability.rs` (10) — pinned canonical wire-format
  vectors for every signed payload.

### Android
Paparazzi JVM screenshot tests run without an emulator:
```bash
./gradlew test
```
There are **no Android instrumented tests yet** — see the Roadmap.

### CI
GitHub Actions runs `cargo test --locked` and `cargo audit` on
every PR (`.github/workflows/ci.yml`).

## Roadmap

Pre-alpha → alpha:
* OOB / SAS verification gesture (fingerprint tap-to-verify is
  recommended; SAS number-compare for non-QR exchanges).
* Two-device manual walkthrough doc (`docs/two-device-walkthrough.md`).
* Android instrumented tests (`app/src/androidTest/`) covering
  `nativeStartNetwork` on a real device + a Compose UI test for
  create-group → invite-QR → scan-QR.
* Replace the Android data-layer stubs (`data.model.*`,
  `ContactRepository`, `MessageRepository`, `ConversationRepository`,
  `MessageService`, the half-built ViewModels and Fragments) with a
  real implementation backed by Room + SQLCipher.
* Snapshot resync after extended offline (group-state convergence
  for a member who comes back after missing many `MemberAdded` /
  `RoleChange` / `KeyRotation` broadcasts).
* Port the legacy modules (`hybrid_ratchet`, `secure_message`,
  `file_transfer`, `audio`, `sas`, `oob_secrets`) to the current
  dependency versions — currently feature-gated behind `legacy` and
  documented as broken.

Post-alpha:
* Promoted-admin Kyber registration via a continuous re-broadcast
  loop (the immediate gap is closed by the per-member `kyber_pub`
  in JoinAccepted + `MemberAdded` broadcast, but a member who's
  been offline through several rotations still needs an explicit
  resync).
* Voice / video calls (libp2p WebRTC integration; the `webrtc`
  crate is currently feature-gated behind `calling` and not
  default-built).

## License

Distributed under the MIT License. See `LICENSE` for more
information.

---
*Disclaimer: Qubee is research-grade software. Do not use for
critical safety-of-life communications.*
