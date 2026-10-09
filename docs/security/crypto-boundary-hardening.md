# Crypto boundaries and persistence hardening

Review baseline: main `a6dd3b910682a1aded8580bd79f92b286039b41f`.
This is an implementation review, not an independent audit or a security proof.

## 1. Implementation boundaries

`security::secure_rng` now delegates each request directly to `getrandom` 0.2.
It has no application PRNG state, timing/PID/ASLR mixers, filesystem entropy
collection or fallback. Requests return an error and wipe partially filled
output if entropy collection fails. `reseed()` is an OS availability probe;
it does not force kernel reseeding. Injectable-source tests exercise partial
failure and recovery without changing the production entropy source.

This does **not** replace the separate PQClean randomness boundary:
`pqcrypto-mlkem` 0.1.1 and `pqcrypto-mldsa` 0.1.2 use
`pqcrypto-internals` 0.2.11. Its `randombytes.h` maps calls to
`PQCRYPTO_RUST_randombytes`, which calls `getrandom::fill` (0.3) and
`expect("RNG Failed")`. The vendored `cfiles/randombytes.c` is not the RNG
compiled by that crate's build script. Entropy failure at this Rust/C boundary
can abort the process; JNI `catch_unwind` does not make this a fallible API.
There is no predictable-key fallback. A future dependency replacement must
provide an explicit, reviewed entropy/error contract; an application RNG
probe is not a guarantee that the next native request will succeed.

All current Qubee X25519 operations use `SharedSecret::was_contributory()`
before feeding a shared secret to a KDF. PQXDH checks every identity, signed,
one-time and ephemeral DH contribution; the Double Ratchet rejects low-order
new peer DH keys without modifying its live state. The device-key helper is
also fallible. Canonical ML-KEM-768 public coefficients are checked before
encapsulation, including group-key wrapping. Length-only `from_bytes` is
insufficient: each encoded 12-bit coefficient must be less than 3329.
This is the FIPS 203 section 7.2 modulus check, not a claim of FIPS module
validation or of complete secret-key validation.

Plaintext persistence mirrors, temporary DH/KDF/message keys, and sender-key
distributions have zeroization guards. Sender-key and decoded direct-payload
`Debug` implementations redact secrets and content. These changes reduce
avoidable copies; they do not establish complete erasure. The upstream
pqcrypto fixed-array secret/shared-secret types are `Copy` and have no wiping
`Drop`; their transient copies and C stack buffers remain a dependency-level
limitation. Compiler transformations, registers, crash dumps, Kotlin strings,
and a compromised unlocked device are outside the erasure guarantee.

The pinned Rust compiler remains 1.88.0, with release optimization 3, thin LTO,
one codegen unit and symbol stripping. Unwinding remains enabled because the
JNI panic guards depend on it. Rust path remapping remains in `build_rust.sh`.
This pass did not perform Android-ABI assembly or timing analysis; neither
these settings nor host tests establish constant-time native code.

## 2. Authentication and composition

An `IdentityId` is recomputed from **both** Ed25519 and ML-DSA-44 public keys
and the existing identity domain tag. Deserialization and signature verification
reject inconsistent IDs and weak Ed25519 public keys. Strict Ed25519 verification
and ML-DSA verification must both succeed; there is no single-component fallback.
This prevents self-signed attacker keys from claiming an existing contact ID.
Signing a prekey bundle also requires its publisher to match the signing keypair.

The existing signed bundle binds the DH identity, signed prekey, OTP presence
and value, ML-KEM public key, publisher ID and timestamp. Cached peer bundles
reject timestamp rollback and mismatched cache IDs. Equal timestamps remain
allowed because publication can occur more than once per second; they are not
an anti-equivocation mechanism. Signed bundle verification uses the existing
seven-day signature-age window. Long-lived cache expiry, prekey epochs and
cross-device key transparency are not implemented by this pass.

Existing conversation associated data binds the sorted pair of identity IDs.
Hybrid KDF and wire formats are unchanged. Failure must never silently invoke
a legacy send path. The active ratchet flags, old receive formats, and emergency
legacy emission switch still require retirement after interoperability testing.
Signature verification authenticates key ownership; the QR/SAS/fingerprint
ceremony is still needed to bind a key to the intended person.

## 3. Key lifecycle and recovery

Direct send/receive now commit all Rust keystore mutations in one transaction.
Authenticated first-message processing commits the session, OTP replacement,
accepted-initial replay marker and pending-initial cleanup together. Invalid
padding, failed OTP replacement and other pre-commit errors restore the previous
in-memory ciphertext map and leave the durable snapshot untouched. Plaintext is
not returned until commit succeeds. Unwinding also restores the map and clears
the transaction flag. Direct resets, group sends and group sender-state resets
are transactional. Counter exhaustion and malformed persisted skipped-key
stores fail closed.

The store has **no write-on-Drop**. Previously, a failed constructor could drop
a partially initialized empty store and overwrite the damaged database.
Missing master keys and empty existing databases now fail without replacement.
An uncertain snapshot/rotation write latches the handle into an unusable state;
secret reads and mutations require reopening. Master rotation stages a complete
new ciphertext map and retains the existing dual-master recovery protocol.
Encrypted snapshots can be opened under either rotation candidate, including
empty snapshots; legacy recovery checks every entry before choosing a key.

Writes use a fresh exclusive sibling file with Unix mode 0600, file fsync,
atomic rename and required parent-directory fsync on Unix. A failure after
rename can mean the commit happened; poisoning the handle avoids guessing.
Non-Unix directory durability is not claimed. The process must retain the
existing single-owner synchronization; separate handles/processes writing the
same store are unsupported and there is no interprocess locking here.

This is atomicity **within the Rust keystore**, not across Rust, SQLCipher/Room,
Kotlin callbacks and network transmission. A process death after a ratchet commit
but before storing the outgoing frame can still lose a send position. Existing
durable exact-ciphertext retry handling remains essential; cross-store delivery
atomicity is a separate design task. Restoring old authenticated snapshots can
roll ratchets back: no filesystem anti-rollback guarantee is provided.

The single-OTP model is unchanged. Concurrent initiators can fetch a consumed
OTP until the bundle is republished. A pool needs explicit prekey IDs, delivery
semantics, expiry/retention policy and a versioned wire migration. Medium-term
ML-KEM/signed-prekey rotation and cryptographic erasure of flash history also
remain open. Backups are disabled on Android; manual copying of live protocol
state risks rollback or key reuse.

PQXDH-style setup targets protection against recording today's traffic for
future quantum decryption. Subsequent DH ratchet recovery is **classical**;
there is no recurring PQ KEM ratchet or claim of quantum post-compromise
security. Groups use sender chains and classical ephemeral signatures, not MLS
or a PQ group-PCS proof. A removed member must be excluded from fresh key
distribution; confidentiality does not erase plaintext already received.

## 4. Metadata and attachments

The Rust `.db` now uses:

`QKS1 || nonce(12) || ChaCha20-Poly1305(serialized index, AAD="qubee_keystore_snapshot_v1")`

Inner entry AEAD remains bound to the key ID and type. The outer snapshot
protects key IDs, peer/group indices, algorithms, tags and timestamps as well
as ciphertext entries. Format, total size, paths and filesystem activity remain
observable. Header authentication failure never falls back to legacy decoding.
Old plaintext-index stores migrate on open; **older Qubee binaries cannot read
the new snapshot**. Legacy migration cannot retroactively authenticate old
metadata, and accepting old layouts is not downgrade/rollback protection.
Validate upgrades before distributing this change; reverting code alone does
not revert storage. Never replace a failed store with a fresh identity silently.

Attachment names and bytes already travel inside encrypted messages; the raw
attachment limit remains 256 KiB (Base64 adds roughly one third). Decoding now
bounds encoded size before allocation and rejects filename control characters.
Direct storage also validates size. Keystore-encrypted attachment files remain
in the app-private directory; the FileProvider exposes only viewer exports.
User-opened viewer exports use random opaque names, are deleted on failure,
expire after ten minutes while the process lives, and are purged at next process
startup. A killed process can leave plaintext until the next startup; an
external viewer can retain a copy. Streaming decryption through a provider
would eliminate the plaintext-cache requirement and is follow-up work.

Android minimum API is now 32 (Android 12L); compile/target API remains 34.
This reduces legacy platform scope but is not a substitute for security patch
freshness, OEM validation, at-rest key policy or endpoint integrity.

Direct peers and transport observers can still learn IPs, timing, traffic
volume and linkability. Padding reveals a size bucket. Public handshakes,
known-contact selector tests and libp2p routing also have observable metadata.
Calling remains gated and fail-closed pending TURN provisioning and a private
signaling carrier. Stored voice messages require a separate recording, codec,
encrypted-persistence and playback lifecycle; they are not enabled here.

## Validation and remaining release gates

Regression coverage includes partial RNG failures, non-contributory DHs,
non-canonical KEM publics, identity substitution, hybrid component failure,
counter exhaustion, invalid skipped-key stores, cache rollback, corrupted
keystore preservation, missing masters, snapshot secrecy/tampering, transactional
rollback/unwinding, uncertain-write poisoning, rotation recovery and Unix file
permissions. Android attachment tests cover bounds, unsafe names, encrypted
storage and restart cleanup and require an emulator/device.

Run `cargo test --locked --all-targets`, strict Clippy, the JNI type-check,
`bash scripts/check_jni_contracts.sh`, and calling-feature checks. Android builds
and `connectedDebugAndroidTest` must pass in CI. Record API 32/34, multi-OEM,
process-death, locked-key, upgrade/migration, low-storage, attachment-viewer and
two-peer tests before release. Host fault injection is not a physical power-loss
test. Measure whole-snapshot persistence cost with realistic peer/session counts.

## Primary references

- [FIPS 203, 13 August 2024, section 7.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
- [x25519-dalek 2.0.1 SharedSecret / was_contributory](https://docs.rs/x25519-dalek/2.0.1/x25519_dalek/struct.SharedSecret.html).
- [pqcrypto-internals 0.2.11 source](https://docs.rs/crate/pqcrypto-internals/0.2.11/source/src/lib.rs).
- [Qubee Double Ratchet design](../double-ratchet-design.md).
- [Network privacy](../architecture/network-privacy.md) and [calling threat model](../architecture/calling-threat-model.md).
