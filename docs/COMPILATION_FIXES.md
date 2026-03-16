# Compilation Fixes — Pass 7

This document describes the structural changes required to bring the Qubee crate
from a non-compiling state to a buildable module graph with correct JNI alignment.

## Problem Summary

The crate had four categories of structural issues:

1. **Orphaned modules** — 11 `.rs` files and 5 directories existed on disk but
   were not declared in `lib.rs`, making them invisible to the compiler.
2. **Missing `mod.rs` files** — `testing/` and `audit/` directories had no
   module declaration file.
3. **Name collision** — `src/identity.rs` (a file) and `src/identity/` (a
   directory) cannot coexist as the same module name.
4. **Wrong pqcrypto API** — Several files used `.0` field access and
   non-existent function names (`Signature`, `verify`, `sign`) from pqcrypto
   crates. The correct API uses trait methods (`as_bytes()`, `from_bytes()`)
   and free functions (`detached_sign`, `verify_detached_signature`,
   `DetachedSignature`).
5. **JNI mismatch** — Rust exported 25 JNI functions but Kotlin only declared
   14 `external fun` entries.

## Changes

### Cargo.toml

- Added `env-filter` and `json` features to `tracing-subscriber` (required by
  `logging.rs` and `qubee_relay_server.rs`).

### src/lib.rs — Module graph unification

Rewritten to wire all modules:

```rust
pub mod native_contract;      // core production path
pub mod relay_protocol;
pub mod relay_security;
pub mod security;              // secure_keystore, secure_memory, secure_rng
pub mod storage;               // re-exports security::secure_keystore
pub mod crypto;                // enhanced_ratchet, identity

pub mod config;
pub mod errors;
pub mod logging;
pub mod sas;
pub mod oob_secrets;
pub mod ephemeral_keys;

pub mod dilithium_identity;    // renamed from identity.rs
pub mod hybrid_ratchet;
pub mod secure_message;
pub mod file_transfer;
pub mod audio;

pub use hybrid_ratchet::{HybridRatchet, PQ_REKEY_PERIOD};

pub mod identity;              // identity/ directory
pub mod groups;
pub mod audit;
pub mod calling;
pub mod testing;

// Quarantined: network/ (libp2p 0.54 API incompatible)
```

### File renames

| Before | After | Reason |
|---|---|---|
| `src/identity.rs` | `src/dilithium_identity.rs` | Name collision with `src/identity/` directory |

### New files

| File | Content |
|---|---|
| `src/testing/mod.rs` | `pub mod security_tests;` |
| `src/audit/mod.rs` | `pub mod security_auditor;` |

### Module wiring fixes

| File | Change |
|---|---|
| `src/crypto/mod.rs` | Added `pub mod enhanced_ratchet;` |
| `src/security/mod.rs` | Added `pub mod secure_memory;` |

### Import fixes

| File | Old | New |
|---|---|---|
| `src/hybrid_ratchet.rs` | `use crate::secure_message; use crate::file_transfer; use crate::audio;` | Removed (dead imports) |
| `src/hybrid_ratchet.rs` | (none) | Added `use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};` |
| `src/calling/media_encryption.rs` | `chacha20poly1305::aead::OsRng` | `rand::rngs::OsRng` |
| `src/logging.rs` | `.with_env_filter("info")` | `EnvFilter::try_from_default_env().unwrap_or_else(...)` |

### pqcrypto API corrections

Applied across `secure_message.rs`, `audio.rs`, `file_transfer.rs`,
`dilithium_identity.rs`, and `hybrid_ratchet.rs`:

| Pattern | Old (wrong) | New (correct) |
|---|---|---|
| Public key bytes | `pk_obj.0.to_vec()` | `pk_obj.as_bytes().to_vec()` |
| Ciphertext bytes | `ct.0.to_vec()` | `ct.as_bytes().to_vec()` |
| Shared secret bytes | `ss.0.to_vec()` | `ss.as_bytes().to_vec()` |
| Signing | `dilithium2::sign(&msg, &sk).0.to_vec()` | `dilithium2::detached_sign(&msg, &sk)` + `.as_bytes().to_vec()` |
| Verifying | `dilithium2::Signature::from_bytes(...)` + `dilithium2::verify(...)` | `dilithium2::DetachedSignature::from_bytes(...)` + `dilithium2::verify_detached_signature(...)` |
| Keypair order | `let (sk, pk) = keypair();` (was inconsistent) | Verified correct order per crate: dilithium returns `(pk, sk)`, kyber returns `(pk, sk)` |
| Trait imports | Missing | Added `use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};` and `use pqcrypto_traits::kem::{...};` where needed |

### PQ_REKEY_PERIOD

Changed from `1` (every message — extremely expensive on mobile) to `50` in
`hybrid_ratchet.rs`.

### Quarantined: network/p2p_node.rs

The `network/` module uses libp2p types (`Kademlia`, `KademliaConfig`, `Mdns`,
`MdnsConfig`, `SwarmBuilder::with_tokio_executor`) that were removed in libp2p
0.54. The module is commented out in `lib.rs`. To re-enable it, rewrite against
the current libp2p API (`kad::Behaviour`, `mdns::tokio::Behaviour`,
`SwarmBuilder::with_tokio`).

### JNI ↔ Kotlin alignment

Rust `jni_api.rs` exports 25 functions. Kotlin `QubeeManager.kt` now declares
all 25 matching `external fun` entries:

| Category | Functions |
|---|---|
| Lifecycle | `nativeInitialize`, `nativeCleanup` |
| Identity (legacy) | `nativeGenerateIdentityBundle`, `nativeRestoreIdentityBundle` |
| Identity (result) | `nativeGenerateIdentityBundleResult`, `nativeRestoreIdentityBundleResult` |
| Relay auth | `nativeSignRelayChallenge`, `nativeSignRelayChallengeResult` |
| Session (legacy) | `nativeCreateRatchetSession`, `nativeRestoreSessionBundle`, `nativeEncryptMessage`, `nativeDecryptMessage` |
| Session (result) | `nativeCreateRatchetSessionResult`, `nativeRestoreSessionBundleResult`, `nativeExportSessionBundleResult`, `nativeMarkSessionRekeyRequiredResult`, `nativeMarkSessionRelinkRequiredResult`, `nativeRotateSessionBundleResult`, `nativeEncryptMessageResult`, `nativeDecryptMessageResult` |
| Hybrid PQ | `nativeCreateHybridSessionInit`, `nativeAcceptHybridSessionInit` |
| Invite/safety | `nativeExportInvitePayload`, `nativeInspectInvitePayload`, `nativeComputeSafetyCode` |

New Kotlin types:

- `NativeCallResult` — data class matching the Rust `NativeCallResult` JSON
  envelope, with `payloadOrNull()` and `isOkEmpty()` helpers.

New Kotlin wrapper methods on `QubeeManager.Companion`:

- `restoreSessionBundle(ByteArray): NativeCallResult`
- `exportSessionBundle(String): NativeCallResult`
- `markSessionRekeyRequired(String): NativeCallResult`
- `markSessionRelinkRequired(String): NativeCallResult`
- `rotateSessionBundle(String, ByteArray, Boolean): NativeCallResult`
- `encryptMessage(String, ByteArray): NativeCallResult`
- `decryptMessage(String, ByteArray): NativeCallResult`
- `generateIdentityBundle(...): NativeCallResult`
- `restoreIdentityBundle(ByteArray): NativeCallResult`
- `signRelayChallenge(ByteArray, ByteArray): NativeCallResult`
- `createRatchetSession(String, ByteArray, Boolean): NativeCallResult`

## Remaining Work

1. **`cargo check --lib`** — Run on a machine with the Rust toolchain and
   Android NDK targets to verify compilation.  The structural issues documented
   here are resolved, but type-level errors (e.g. trait bound mismatches in
   `double-ratchet` or `webrtc` crate APIs) may surface.

2. **`cargo check --bin qubee_relay_server`** — Verify the relay binary
   compiles against the hardened relay code.

3. **`cargo test`** — Run the 67 `#[test]` functions across the crate.

4. **Android build** — `./build_rust.sh` to cross-compile for ARM targets,
   then Gradle build to link the `.so` and run Kotlin unit tests.

5. **network/ rewrite** — If P2P is needed for alpha, rewrite `p2p_node.rs`
   against libp2p 0.54 current API.
