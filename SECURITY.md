# Security policy

Qubee is a research-grade post-quantum P2P messenger. The cryptographic
primitives we depend on (ML-KEM-768, ML-DSA-44, Ed25519, X25519,
ChaCha20-Poly1305, BLAKE3) are all standardised and well-audited; the
interesting attack surface is the glue around them — wire-format
parsers, the JNI bridge, the libp2p transport, the Android storage
layer, and the trust-state policy.

This document covers how to report a vulnerability and what's in scope.

## Project status

**Pre-alpha. Do not use Qubee for safety-of-life communications.** The
README is honest about which roadmap items aren't shipped. This policy
exists so that when you find something, you know how to tell us.

## Reporting a vulnerability

**Please do not open a public GitHub issue.** Use one of the following
private channels instead:

1. **GitHub private vulnerability report**:
   <https://github.com/MKlolbullen/Qubee/security/advisories/new>
   (preferred — keeps the disclosure log on the repo).
2. **Email** the maintainer directly. The contact address lives in
   the repo owner's GitHub profile; if you need a fixed address, open
   a placeholder issue titled "request security contact" and we'll
   reach out off-list.

Encrypt sensitive reports if you can. We'll publish a PGP key
fingerprint here once the maintainer has one rotated for this purpose.

### What to include

- A clear description of the issue.
- A minimal reproducer (a failing `cargo test`, a crafted wire-format
  blob, an `adb shell` command, etc.).
- The commit hash you tested against.
- The affected component (Rust core, Android client, build script,
  CI workflow).
- Your assessment of impact and exploitability.
- Whether you've shared the report elsewhere.

### What to expect

| Stage | Target turnaround |
|-------|-------------------|
| Acknowledgement of receipt | 72 hours |
| Initial triage / severity | 7 days |
| Fix + coordinated disclosure plan | 30 days for high/critical, 90 days otherwise |
| Public advisory | After a fix lands on `main` and a release is tagged |

These are targets, not guarantees — Qubee is maintained by volunteers.
We will tell you if a fix is taking longer than the target window and
why.

## Scope

### In scope

- The Rust core (`src/`) and its public APIs (lib + JNI).
- Wire-format parsers (`src/groups/group_handshake.rs`,
  `src/groups/group_message.rs`, `src/onboarding/`,
  `src/groups/group_invite.rs`).
- The libp2p transport configuration (`src/network/p2p_node.rs`).
- Cryptographic state machines (group key rotation, generation
  counter, trust-state policy).
- Android storage (`QubeeDatabase`, `SecureKeyStore`, Keystore-backed
  key derivation).
- The JNI bridge (`src/jni_api.rs` + `app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt`).
- Build scripts (`build_rust.sh`, `build_rust.ps1`) and CI workflows
  (`.github/workflows/`).

### Out of scope

- Side-channel resistance of the underlying `pqcrypto-mlkem` /
  `pqcrypto-mldsa` primitives. These crates wrap the NIST reference
  implementations; report side-channel issues upstream.
- Denial-of-service from a peer flooding the gossipsub topic. libp2p
  has its own backpressure knobs; Qubee doesn't add a second layer.
- Issues that require a rooted device with physical access *and* an
  unlocked screen. The threat model assumes a locked device; an
  attacker with full physical access has already won (see
  `docs/security/threat-model.md` once published).
- Bugs in the `calling` feature (WebRTC). It's gated, not yet ported
  to webrtc 0.14, and not built by default.
- Phishing / social-engineering of the OOB verification gesture. We
  document the gesture; users have to perform it.

### Already acknowledged limitations

These are known and are not vulnerabilities — they're the shape of
the pre-alpha:

- The Android `QubeeDatabase` SQLCipher passphrase is hardcoded in
  current `main`. This is being replaced with a Keystore-derived key
  in the next release; see `app/src/main/java/com/qubee/messenger/data/repository/database/QubeeDatabase.kt`
  and the project plan for "Real SQLCipher passphrase derivation".
- `MessageStatus.SENT` means "encrypted bytes left this device", not
  "the peer acked". A real ack roundtrip is post-alpha.
- Snapshot resync after extended offline still bounces a member who
  missed a `KeyRotation` while offline. The
  `RequestStateSync` / `StateSyncResponse` extension is in flight.

## Disclosure policy

We follow coordinated disclosure. After we ship a fix:

1. We file a GitHub Security Advisory with a CVSS score, affected
   versions, and credit to the reporter (unless they ask to stay
   anonymous).
2. We reference the fix commit and the advisory in `CHANGELOG.md`.
3. If the issue affected a published release, we file a CVE through
   GitHub's CNA.

If a vulnerability is being actively exploited in the wild we'll
disclose immediately and ship the fix; we won't sit on an active
exploit waiting for the 30/90 day window.

## Safe-harbour for researchers

We will not pursue legal action against good-faith security
researchers who:

- Report through the channels above.
- Don't access, modify, or destroy data that isn't theirs.
- Don't degrade service for other users.
- Give us reasonable time to fix before going public.

This isn't a bug bounty — there's no payout. Credit in advisories +
the changelog is the recognition we can offer.

## Cryptographic primitive sourcing

For transparency, the post-quantum primitives in the default build
are sourced as follows. Report supply-chain concerns about any of
them through the same channel as a vulnerability.

| Primitive | Crate | Upstream |
|-----------|-------|----------|
| ML-KEM-768 (FIPS 203) | `pqcrypto-mlkem` 0.1 | <https://github.com/rustpq/pqcrypto> |
| ML-DSA-44 (FIPS 204) | `pqcrypto-mldsa` 0.1 | <https://github.com/rustpq/pqcrypto> |
| Ed25519 | `ed25519-dalek` 2.1 | <https://github.com/dalek-cryptography/ed25519-dalek> |
| X25519 | `x25519-dalek` 2.0 | <https://github.com/dalek-cryptography/curve25519-dalek> |
| ChaCha20-Poly1305 | `chacha20poly1305` 0.10 | <https://github.com/RustCrypto/AEADs> |
| BLAKE3 | `blake3` 1.4 | <https://github.com/BLAKE3-team/BLAKE3> |
| HKDF / SHA-2 | `hkdf` 0.12 / `sha2` 0.10 | <https://github.com/RustCrypto/KDFs> |

Cargo.lock is committed; CI runs `cargo audit` on every PR plus a
weekly cron to catch new RustSec advisories on a green tree.
