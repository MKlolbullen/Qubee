# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Qubee is a post-quantum P2P messenger split across two languages connected by JNI:

- **Rust core** (`src/`, crate `qubee_crypto`, crate-types `cdylib` + `rlib`) — owns all cryptography, the wire format, the libp2p transport, and the encrypted local keystore. This is the authoritative cryptographic layer.
- **Android client** (`app/`, Kotlin + Jetpack Compose + Hilt + Room/SQLCipher) — orchestration, UI, persistence metadata. Loads `libqubee_crypto.so` and calls into Rust via `QubeeManager`.
- **JNI bridge** — `src/jni_api.rs` (Rust exports) ↔ `app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt` (Kotlin `external fun native*` declarations). The two sides must declare the same symbol set; this is enforced mechanically (see "JNI contract" below).

The hard architectural rule is **Rust is the cryptographic authority**: Kotlin must never implement fallback crypto, plaintext compatibility envelopes, or substitute primitives. If a JNI symbol is missing, the Kotlin side fails closed. See `docs/architecture/protocol-map.md` for the full list of product security invariants.

## Common commands

### Rust core (run from repo root)

```bash
# Full local check (matches CI)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --features _typecheck_jni   # type-checks src/jni_api.rs on host
cargo bench --no-run                    # compile-only smoke test
./scripts/check_jni_contracts.sh        # Kotlin↔Rust symbol parity
./scripts/audit_message_file_bridge.sh  # P0 message/file bridge symbols

# One-shot: runs everything above + optional Gradle if ANDROID_HOME is set
./scripts/qubee_doctor.sh

# Run a single Rust test by name
cargo test --test group_message_e2e lagging_member_resyncs_after_missing_key_rotation
cargo test --lib group_crypto::tests::round_trip_encrypt_decrypt
```

Default features compile clean; `legacy` and `calling` are **broken** today (deliberately gated — see `docs/build-status.md`). Don't enable them unless you're actively porting those modules.

### Android (requires Android SDK + NDK)

```bash
# 1. Always rebuild the Rust .so first — Gradle does NOT trigger this.
./build_rust.sh                         # bash; build_rust.ps1 on Windows
                                        # → app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64}/

# 2. Build / install the app
./gradlew :app:assembleDebug
./gradlew :app:installDebug

# Paparazzi JVM screenshot tests (no emulator needed; CI runs verify)
./gradlew :app:recordPaparazziDebug     # regenerate baselines
./gradlew :app:verifyPaparazziDebug     # diff against committed PNGs

# Unit tests
./gradlew :app:testDebugUnitTest
./gradlew :app:lintDebug
```

Failing screenshots write side-by-side diffs to `app/build/paparazzi/failures/`. Baselines live under `app/src/test/snapshots/` and are committed.

### Release build / signing

`./gradlew assembleRelease -PqubeeVersionName=$tag -PqubeeVersionCode=$(git rev-list --count HEAD)`. `versionCode` must be monotonic for Android's upgrade comparator. Signing pulls `RELEASE_KEYSTORE_FILE`/`_PASSWORD`/`_KEY_ALIAS`/`_KEY_PASSWORD` from env; without them, the release build is unsigned but installable for emulator smoke testing.

## Architecture invariants worth knowing before editing

### Rust module layout (`src/`)

- `groups/` — group state machine. The relevant types are re-exported from `groups/mod.rs`. `GroupManager` owns membership; `group_handshake` defines the `RequestJoin`/`JoinAccepted`/`MemberAdded`/`KeyRotation`/`RoleChange`/`RequestStateSync`/`StateSyncResponse` frames; `group_message` defines the `GroupMessageEnvelope` (with magic + generation counter + hybrid sig); `handshake_handlers` is where inbound frames mutate state; `group_crypto` owns the per-group ChaCha20-Poly1305 key.
- `identity/` — `IdentityKeyPair` (hybrid Ed25519 + ML-DSA-44 + ML-KEM-768), `ContactManager`, fingerprint computation. `identity_key.rs` round-trips pqcrypto types through hand-written `WireIdentityKey`/`WireHybridSignature` shadow structs (pqcrypto types don't impl serde or `Debug`).
- `network/p2p_node.rs` — libp2p 0.55 node (TCP + DNS + Yamux + Noise XX + gossipsub + Kademlia + mDNS). `P2PNode` runs on its own Tokio task; the JNI layer talks to it through an mpsc command channel and forwards events back to Kotlin via JNI callbacks.
- `onboarding/` — onboarding bundle format (`qubee://identity/<token>`) and invite-link parsing.
- `storage/secure_keystore.rs` — `SecureKeyStore` (XChaCha20-Poly1305 + BLAKE3 integrity). Two separate stores: identity and groups, so each can be reset independently.
- `security/` — `secure_memory` (mlock/munlock on Unix), `secure_rng` (uses BLAKE3 XOF for additional entropy — the `copy_from_slice` bug fix from round-9 is documented in `docs/build-status.md`).
- `jni_api.rs` — only compiled `cfg(target_os = "android")` or `feature = "_typecheck_jni"`. Uses `lazy_static` for global state (active identity, `GroupManager`, JVM ref, callback handler, P2P command channel, pending Kyber secrets keyed by invitation code with TTL eviction).
- `lib.rs` — feature gates the legacy modules (`audio`, `file_transfer`, `hybrid_ratchet`, `oob_secrets`, `sas`, `secure_message`) and `calling` behind their respective Cargo features.

### Wire format stability

`tests/wire_stability.rs` pins canonical bytes for every signed payload. **Any wire-format change is a `_v2` tag bump and a vector update, not a silent edit.** Canonical bytes are hand-rolled (length-prefixed, NUL-separated, per-variant domain-separation tag) — *not* `bincode` or `serde` — and the property-based round-trip tests (`proptest`) catch encode/decode asymmetries the pinned vectors miss.

### Group messaging strict generation gate

`decrypt_group_message` rejects any frame whose generation counter doesn't equal `group.version` exactly — no buffering, no lock-step recovery. This is the kicked-then-rotated race fix. Whenever membership or roles change, the inviter broadcasts the post-mutation `group.version` (via `MemberAdded`, `RoleChange`, `KeyRotation`) so receivers stay synchronised. If you add a mutation path, you must add the matching broadcast or the next message will get rejected.

Membership cap: `QUBEE_MAX_GROUP_MEMBERS = 16`. Roles: Owner / Admin / Moderator / Member / Observer. Owner-only mints invites and promotes/demotes.

### JNI contract

Two scripts gate the JNI surface; both run in CI (`.github/workflows/jni-contracts.yml`) and locally via `qubee_doctor.sh`:

- `scripts/check_jni_contracts.sh` — every Kotlin `external fun nativeX(...)` must have a matching Rust `Java_com_qubee_messenger_crypto_QubeeManager_nativeX` export, and vice versa.
- `scripts/audit_message_file_bridge.sh` — the four P0 symbols `nativeEncryptMessage` / `nativeDecryptMessage` / `nativeEncryptFile` / `nativeDecryptFile` must exist on both sides.

When you add a JNI method, edit both files in the same change and run the two scripts. The `_typecheck_jni` Cargo feature lets CI compile `jni_api.rs` on the host without the NDK so JNI surface drift fails CI before someone tries an Android build.

### Android data layer

Real Room + SQLCipher, not stubs (the README's old "no-op stubs" warning is stale). Database opens through `data/repository/database/QubeeDatabase.kt` using `SqlCipherKeyProvider` (passphrase derived per-install from the Android Keystore). Hilt providers in `di/DatabaseModule.kt`. Migration is `fallbackToDestructiveMigration` until v0.2.0 — schema changes wipe local data on upgrade.

Repositories: `ContactRepository`, `MessageRepository`, `ConversationRepository`, `GroupRepository`, `VerificationRepository`, `CallRepository`, `PreferenceRepository`. `MessageService` is the Android foreground service that owns the P2P node lifetime and decrypts inbound packets into the message store via `nativeRegisterCallback` → `NetworkCallback`.

PeerId ↔ IdentityId linkage has two population paths: handshake-time (`NetworkCallback.onPeerLinked`) and receive-path TOFU (`nativeInspectEnvelopeSender`). They must agree; a divergence is a trust-state event.

### Trust state

`security/TrustStatePolicy.kt` (Kotlin) plus the verification protocol in `docs/architecture/protocol-map.md`. The hard invariant: **Verified + changed identity key = `KeyChanged`, never `Verified`**. The user must re-verify to re-promote. Imported contacts default to `Unverified`.

## Pinned dependencies — don't bump casually

The Rust dependency set has been deliberately pinned to keep `rand_core 0.6` consistent across `chacha20poly1305 0.10`, `rand_chacha 0.3`, and `ed25519-dalek 2.x`. Bumping `rand` to 0.9 (or `secrecy` away from 0.10, or `pqcrypto-{mlkem,mldsa}` to a non-0.1 line) cascades into trait-bound mismatches across half the crate. `Cargo.toml` has inline comments explaining each pin. Don't bump these without a reason called out in the PR.

The Android side similarly pins AGP 8.4 / Kotlin 1.9.22 / Hilt 2.48 / Compose BOM 2023.10.01 / Paparazzi 1.3.4 / SQLCipher 4.6.0. Same rule.

## Conventions that bite if you don't know them

- **`rust-toolchain.toml` pins 1.86.** Run `rustup show` from the repo root once; that's all you need.
- **Default to writing no comments.** Names are documentation. Comments are for the *why*: a hidden invariant, a workaround, surprising behavior. Don't restate what the code does. `CONTRIBUTING.md` is explicit about this; the rev-3 cleanup paid off a year of accreted-fiction comments and the project actively avoids reopening that account.
- **No half-finished implementations.** If you're scaffolding, say so explicitly with a TODO + tracking issue rather than letting a silent stub merge.
- **No new dependencies for trivia.** A 30 MB transitive tree to format a string is not worth it.
- **Cryptographic primitive substitutions** (replacing ML-KEM-768 / ML-DSA-44 / Ed25519 / X25519 / ChaCha20-Poly1305 / BLAKE3) are project-level decisions, not drive-by PRs.
- **No ZK proof framing on onboarding bundles.** An earlier prototype faked a Schnorr proof with `wrapping_add`; the code, docs, and framing have been removed and should not return. The README's "Why no zero-knowledge proofs" section is the canonical reasoning.
- **Don't bypass safety checks** (`--no-verify`, `--no-gpg-sign`, etc.). If a hook fails, fix the underlying issue.

## Where to look first

- New JNI method: `src/jni_api.rs` + `app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt` + both scripts in `scripts/`.
- New wire frame: `src/groups/group_handshake.rs` (frame def + signed canonical bytes) + `tests/wire_stability.rs` (pin a vector) + `src/groups/handshake_handlers.rs` (inbound state mutation) + JNI dispatch.
- New Compose screen: `app/src/main/java/com/qubee/messenger/ui/<feature>/` + a Paparazzi snapshot test under `app/src/test/java/.../ui/`.
- Cryptographic state machine question: `docs/architecture/crypto-flow.md` and `docs/architecture/protocol-map.md`.
- "Did this build break recently?": `docs/build-status.md` is the verification snapshot, including the migration list for the legacy modules.
- Two-device manual E2E checklist: `docs/two-device-walkthrough.md` (this is the surface that's actually shipped today; deferred items are called out).
