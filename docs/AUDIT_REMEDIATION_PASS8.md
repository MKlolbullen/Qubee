# Remediation Pass 8 — Compilation + Connection + Security Sweep

## Critical security bugs found and fixed

### 1. Kyber encapsulate return order (CRITICAL — shared secret leaked on wire)

**Every file** that called `kyber768::encapsulate()` destructured the return as
`(ciphertext, shared_secret)`. The actual `pqcrypto-traits` signature is:

```rust
fn encapsulate(pk: &PublicKey) -> (SharedSecret, Ciphertext)
```

This means the code was:
- **Transmitting the SharedSecret** in plaintext as `pq_ciphertext_base64`
- **Deriving keys from the Ciphertext** (a public value) instead of the SharedSecret

If anyone ever intercepted a hybrid session init, they would have the shared
secret in the clear. Fixed in 5 files:

| File | Status |
|---|---|
| `native_contract.rs` (`create_hybrid_session_init`) | Fixed |
| `crypto/enhanced_ratchet.rs` (`initialize_sender`) | Fixed |
| `crypto/enhanced_ratchet.rs` (`pq_ratchet`) | Fixed |
| `identity/identity_key.rs` (`kyber_encapsulate`) | Fixed |
| `hybrid_ratchet.rs` (`pq_reencap`) | Was already correct (`(ss, ct)`) |

### 2. Salt ordering (CRITICAL — Alice and Bob derived different keys)

`derive_session_material()` and `derive_hybrid_session_keys()` built the HKDF
salt from `self_handle || peer_handle || contact_id`. Since each party is
the other's peer, Alice computed `alice||bob||id` while Bob computed
`bob||alice||id` — producing different salts and therefore completely
different key material. Decryption would always fail.

Fixed by adding `canonical_session_salt()` which sorts the two handles
lexicographically before hashing.

### 3. All `thread_rng()` replaced with `OsRng` in production crypto

`thread_rng()` delegates to `OsRng` internally on most platforms, but using
it directly for key material is against best practice (it adds an unnecessary
reseeding layer, and on some configurations may use a weaker seed source).

| Site | Old | New |
|---|---|---|
| `native_contract.rs` DH secret | `thread_rng()` | `OsRng` |
| `native_contract.rs` nonce | `thread_rng()` | `OsRng` |
| `native_contract.rs` ratchet keypair | `thread_rng()` | `OsRng` + zeroize seed |
| `identity/signal_protocol.rs` prekey | `thread_rng()` | `OsRng` |

(Two remaining `thread_rng()` calls in `audio.rs` and `file_transfer.rs` are
for non-cryptographic timing jitter in cover traffic — safe to leave.)

### 4. All `Mutex::lock().unwrap()` eliminated (22 sites)

Every mutex lock in the production path now returns `Result` through helper
functions `lock_identity()` and `lock_sessions()`. A poisoned mutex returns
an error instead of panicking and killing the JNI thread.

Also fixed in `ephemeral_keys.rs` (1 site).

### 5. All `.0` field access on pqcrypto types → `.as_bytes()`

The `pqcrypto` crate types have private inner fields. Direct `.0` access
relies on an unstable implementation detail. Replaced with the trait method
`.as_bytes()` everywhere:

| File | Instances fixed |
|---|---|
| `native_contract.rs` | 2 (pq_shared_secret) |
| `crypto/enhanced_ratchet.rs` | 2 (shared_secret, pq_shared_secret) |
| `identity/identity_key.rs` | 2 (encapsulate + decapsulate) |
| `hybrid_ratchet.rs` | Already done in pass 7 |
| `dilithium_identity.rs` | Already done in pass 7 |
| `secure_message.rs` | Already done in pass 7 |
| `audio.rs` | Already done in pass 7 |
| `file_transfer.rs` | Already done in pass 7 |

## Enhanced ratchet chain tracking

The `EnhancedHybridRatchet` in `crypto/enhanced_ratchet.rs` had hardcoded
`chain_id: 0` everywhere, making out-of-order message handling broken
(all messages on all chains would collide in the skip cache).

Added fields: `send_chain_id`, `recv_chain_id`, `previous_send_chain_length`.

| Function | Old | New |
|---|---|---|
| `encrypt()` | `previous_chain_length: 0` | `self.previous_send_chain_length` |
| `decrypt()` | `chain_id: 0` | `self.recv_chain_id` |
| `get_recv_message_key()` | `chain_id: 0` | `self.recv_chain_id` |
| `dh_ratchet()` | just reset counter | saves `previous_send_chain_length`, increments `send_chain_id` |
| `pq_ratchet()` | no chain tracking | increments `recv_chain_id` |

## Code quality

All `println!`/`eprintln!` calls in production Rust code replaced with
`tracing` macros:

| File | Calls replaced |
|---|---|
| `bin/qubee_relay_server.rs` | 4 |
| `file_transfer.rs` | 4 |
| `audio.rs` | 1 |

(`network/p2p_node.rs` still has 2 but the module is quarantined.)

## Module wiring (from pass 7, carried forward)

- `src/lib.rs` wires all 22 modules
- `src/identity.rs` → `src/dilithium_identity.rs` (name collision resolved)
- `testing/mod.rs` and `audit/mod.rs` created
- `crypto/mod.rs` extended with `enhanced_ratchet`
- `security/mod.rs` extended with `secure_memory`
- `network/` quarantined (libp2p 0.54 API incompatible)

## Kotlin JNI alignment (from pass 7, carried forward)

`QubeeManager.kt` declares all 25 `external fun` entries matching Rust JNI
exports exactly. `NativeCallResult` data class parses JSON result envelopes.

## Files changed in this pass

| File | Changes |
|---|---|
| `src/native_contract.rs` | encapsulate order, canonical salt, OsRng, mutex safety, SharedSecret trait |
| `src/crypto/enhanced_ratchet.rs` | encapsulate order, chain tracking fields, SharedSecret trait |
| `src/identity/identity_key.rs` | encapsulate order, .0 → .as_bytes(), pqcrypto_traits import |
| `src/identity/signal_protocol.rs` | OsRng for prekey generation |
| `src/ephemeral_keys.rs` | mutex safety |
| `src/bin/qubee_relay_server.rs` | println → tracing |
| `src/file_transfer.rs` | println → tracing |
| `src/audio.rs` | eprintln → tracing |

## What remains before `cargo check` passes

1. The `double-ratchet` crate API (`Ratchet`, `RatchetInitOpts`) needs
   verification against the pinned version — `hybrid_ratchet.rs` uses it.
2. The `webrtc` crate API in `calling/peer_connection.rs` needs verification
   against version 0.11.
3. `network/p2p_node.rs` requires a full rewrite against libp2p 0.54 if P2P
   is needed for alpha. Currently quarantined.
