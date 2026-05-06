# Performance baseline

Microbenchmark numbers for the cryptographic hot paths. Use these to
spot regressions when bumping `pqcrypto-mlkem`, `pqcrypto-mldsa`,
`ed25519-dalek`, or `chacha20poly1305`.

## Methodology

```bash
cargo bench
# Reports land in target/criterion/<bench>/<group>/report/index.html.
# Numbers below are the median of the criterion estimate; the actual
# distribution is roughly Gaussian with a 1-2% standard deviation.
```

CI runs `cargo bench --no-run` on every PR (compile-only smoke). Full
runs are local-only; commit the new numbers here when they shift by
more than 5% on the same hardware.

## Reference hardware

These numbers are recorded on stock GitHub Actions `ubuntu-latest`
runners (Intel Xeon 2.6 GHz, 7 GB RAM, no hardware AES). Expect
roughly 2x faster on a modern AMD desktop, 3-4x faster on Apple M-series
(NEON crypto).

| Bench file | Hardware | Date |
|------------|----------|------|
| `kyber_kem.rs` | _record on first run_ | _record on first run_ |
| `mldsa_sign_verify.rs` | _record on first run_ | _record on first run_ |
| `group_encrypt_decrypt.rs` | _record on first run_ | _record on first run_ |

> **First-run note**: these tables are placeholders. Run the benches
> on your dev box, paste the criterion estimates here, and commit the
> result. Don't rely on rough estimates — the whole point of the file
> is reproducible numbers a future maintainer can compare against.

## What each bench measures

### `kyber_kem.rs` — ML-KEM-768 (Kyber)

| Bench | Path |
|-------|------|
| `kyber768_keypair` | `pqcrypto_mlkem::mlkem768::keypair()` — runs on every `accept_invite`, every `create_group`, every joiner-side `JoinAccepted` reply. |
| `kyber768_encapsulate` | Sender side of the per-group key wrap. Runs once per remaining member on every `KeyRotation`, plus once on every `JoinAccepted` and every wrapped `StateSyncResponse`. |
| `kyber768_decapsulate` | Receiver side. Runs once on every inbound `JoinAccepted`, every inbound `KeyRotation`, every wrapped `StateSyncResponse`. |

### `mldsa_sign_verify.rs` — Hybrid Ed25519 + ML-DSA-44

| Bench | Path |
|-------|------|
| `hybrid_sign_256b` | `IdentityKeyPair::sign` over 256 bytes (representative of a small group message after canonical encoding). Dilithium dominates total cost. |
| `hybrid_verify_256b` | `IdentityKey::verify_with_max_age` over the same input + signature. Both halves of the hybrid signature are verified; both must succeed. |

### `group_encrypt_decrypt.rs` — Full group-message round trip

| Bench | Path |
|-------|------|
| `group_encrypt_256b` | `encrypt_group_message`: canonical body bytes → ChaCha20-Poly1305 AEAD encrypt → hybrid Ed25519+ML-DSA-44 sign → wire framing. |
| `group_decrypt_256b` | `decrypt_group_message`: parse → generation gate → member-active check → hybrid verify → AEAD decrypt. |

## Regression budget

Bumps that cross the budget should land with an explicit note in the
PR description and updated numbers in this file:

- ±5% within-version noise: ignore.
- ±5-15%: investigate, document in PR.
- > +15% slowdown: requires a justification and a perf-tracking issue.

The Dilithium signing cost dominates `group_encrypt_256b`; if that
moves more than 5% it's almost certainly because `pqcrypto-mldsa`
shipped a new version. Check `Cargo.lock` first.
