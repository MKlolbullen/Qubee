# Changelog

All notable changes to Qubee are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it leaves the `0.x` line. Until then, expect breaking changes
between minor versions.

## [Unreleased]

### Added

- **Ownership transfer** — owner-only atomic role swap that
  promotes an existing active member to `Owner` and demotes the
  current owner to `Admin` in a single signed wire frame
  (`qubee_handshake_ownership_transfer_v1`). Surfaced from the
  Group Details role picker via a "Transfer ownership →" entry
  with its own confirmation dialog. JNI export
  `nativeTransferOwnership(group_id_hex, new_owner_id_hex)`,
  Kotlin wrapper `GroupRepository.transferOwnership`, ViewModel
  action `ChatViewModel.transferOwnership`. Group key isn't
  rotated; the donor keeps full read access as Admin. Receivers
  re-check that the donor was the current Owner at apply time,
  so a forged "transfer back" signed under the now-Admin's key
  is rejected.
- **Delivery confirmation** — every successful
  `decrypt_group_message` auto-fires a signed
  `qubee_handshake_message_ack_v1` frame with a 16-byte BLAKE3
  message id; senders look up the row by `Message.wireId` and
  flip status `SENT → DELIVERED` on first ack arrival. Receivers
  dedupe by `(message_id, acker_id)`. Acks for unknown ids and
  acks from non-members are silently dropped.
- **Android instrumented tests** — emulator-based CI workflow
  (`.github/workflows/instrumented-tests.yml`) running on PRs to
  `main` and push to `main`. First DAO test
  (`MessageDaoInstrumentedTest`) validates the wireId lookup +
  deliveredAckers persistence path. First migration test
  (`MigrationsInstrumentedTest`) validates that v2→v3 preserves
  existing message rows.
- **Schema migrations** — real `MIGRATION_2_3` in
  `Migrations.kt` adds `wireId` + `deliveredAckers` columns to
  the existing `messages` table without dropping data.
  `fallbackToDestructiveMigration` retained as a safety net for
  unknown version pairs. `exportSchema = true` so future
  migrations can be schema-validated by `MigrationTestHelper`.

### Changed

- `eprintln!` / `println!` debug log lines in `src/jni_api.rs`
  + `src/groups/handshake_handlers.rs` converted to structured
  `tracing` calls (error / warn / info by signal class). The
  one secret-leak-risk line dropped its `{e:#}` interpolation.

### Build / tooling

- **Reproducible-build procedure** pinned end-to-end. New
  `docs/reproducible-builds.md` documents the inputs (toolchain,
  NDK, JDK, Gradle, cargo-ndk, release profile) and the verification
  recipe. Concrete pinning:
  * `app/build.gradle` declares `ndkVersion '26.1.10909125'` (r26b)
    in addition to the existing CI pin.
  * `gradle/wrapper/gradle-wrapper.properties` adds
    `distributionSha256Sum` so a hostile mirror can't substitute
    a tampered Gradle.
  * `Cargo.toml` adds an explicit `[profile.release]` with
    `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`,
    `panic = "abort"`, `incremental = false`.
  * `build_rust.sh` rewritten to use `--locked`, apply
    `--remap-path-prefix` for `$CARGO_HOME` and `$PWD`, set
    `SOURCE_DATE_EPOCH=0`, and print the SHA-256 of each produced
    `.so` for cross-machine comparison.
  README + RELEASE.md cross-link to the new doc.

### Security

- **Sealed outer envelope on group messages.** Pre-this-change, every
  group message put `sender_id`, `generation`, `timestamp`, the hybrid
  signature, and the inner AEAD ciphertext on the wire as plaintext
  bincode; anyone subscribed to the gossipsub topic could read sender
  identity per message even without the group key. The wire format
  bumped to `MAGIC_GROUP_MESSAGE \x02` and now wraps the existing
  signed envelope in a second ChaCha20-Poly1305 layer keyed off
  `BLAKE3::derive_key("qubee outer envelope v1", group_key)` with the
  `group_id` as AEAD associated data. Only `group_id` (already
  revealed by the topic name) and the outer nonce stay plaintext.
  Inner signature verification + generation gate are unchanged. New
  tests pin (a) sender_id is not byte-recoverable from the wire, (b)
  any tampering past the magic prefix is rejected by the outer AEAD,
  (c) the observer-without-key path returns Err.

- **Private identity keys now genuinely encrypted at rest.** The Rust
  core keystore (`qubee_keys.db` / `qubee_groups.db`) previously
  wrapped its master key under a hardcoded `"default_password"`,
  making the on-disk Ed25519 + ML-DSA private keys recoverable by
  anyone with the files. `nativeInitialize` now takes a 256-bit
  passphrase derived in the Android hardware Keystore
  (`SqlCipherKeyProvider.getOrCreateCoreKeystorePassphrase`,
  independent from the SQLCipher DB key — key separation). The
  wrapping KDF moved to BLAKE3 `derive_key`. Existing installs
  migrate transparently from the legacy passphrase on first launch
  (non-destructive, one-directional). Init fails closed if the
  Keystore is unavailable.
- **StrongBox-backed Keystore master key** where the device supports
  it, falling back to TEE-backed otherwise. Pure hardening — the key
  material never leaves secure hardware either way.
- **Foreground service hardened for Android 14.**
  `MessageService.onStartCommand` now binds the `dataSync` foreground
  type explicitly via `ServiceCompat.startForeground(..., FOREGROUND_SERVICE_TYPE_DATA_SYNC)`
  and catches `ForegroundServiceStartNotAllowedException` (API 31+)
  so a mistimed background start degrades to "service not started"
  instead of crashing the process. `MessageService.start()` guards
  the same case at the call site.

### Fixed

- **Lost-update race in `MessageRepository.applyAck`** — two acks
  from different recipients arriving simultaneously could lose
  one to a stale-read race. The read-modify-write now happens
  inside a single SQLite transaction via
  `MessageDao.applyAckTransactional` (returns a typed
  `ApplyAckResult` so the repo layer can branch without re-doing
  the work).
- **Send-path ordering** — `ChatViewModel.sendMessage` previously
  saved the row with `wireId = null`, then encrypted, then
  back-filled the `wireId`. A loopback-fast peer could ack
  before the back-fill committed and `applyAck` would miss the
  row. Encrypt now happens first; the row is saved with
  `wireId` already populated.
- **`kapt {}` block scope** — was nested inside
  `defaultConfig {}` where AGP silently ignores it; moved to
  the top level so `room.schemaLocation` actually takes effect.
- **`androidTest.assets.srcDirs` syntax** — switched from `+=`
  (relies on a groovy implicit-collection-add that's fragile
  across AGP bumps) to the canonical `srcDirs(...)` call.
- **Removed `MigrationsInstrumentedTest`** — depended on
  committed Room schema JSON snapshots that aren't yet in the
  tree. `MIGRATION_2_3` itself is reviewed by inspection until
  the second real migration lands and we set up the snapshot
  workflow. `app/schemas/` is gitignored in the meantime.

## [0.1.0-alpha] — 2026-05

First public-installable cut. Research-grade pre-alpha — see
`SECURITY.md` for the threat model and current limitations.

### Cryptography

- ML-KEM-768 (FIPS 203) for KEM, via `pqcrypto-mlkem`.
- ML-DSA-44 (FIPS 204) for post-quantum signatures, via
  `pqcrypto-mldsa`. Hybrid signatures (Ed25519 ⊕ ML-DSA-44) on
  every signed wire frame.
- ChaCha20-Poly1305 AEAD, BLAKE3, HKDF/SHA-512.
- libp2p Noise XX transport (libp2p 0.55).
- All canonical wire payloads tagged `qubee_*_v2`; pinned vectors
  in `tests/wire_stability.rs`.

### Group messaging

- Owner-only invite minting + invite QR codes (`qubee://invite/<token>`).
- Per-member ML-KEM public keys threaded through `JoinAccepted`
  snapshots and signed `MemberAdded` broadcasts.
- Strict generation-counter equality on `decrypt_group_message`;
  no fallback / leniency.
- 5-minute freshness window (`GROUP_MESSAGE_MAX_AGE_SECS`) on
  every group message envelope.
- `RequestStateSync` / `StateSyncResponse` for offline-then-rejoin
  recovery; the `StateSyncResponse` carries the wrapped current
  group key so a lagging member catches up without an inviter
  hand-off.
- Owner-only `promote_member` API + `RoleChange` wire frame.
- `nativeListGroups` for cold-start inbox hydration from the Rust
  core's local view.

### Android

- Onboarding → Inbox → Contacts → Settings, all live against
  Room + SQLCipher 4.6.
- Group Details bottom sheet with live member roster, Add member
  shortcut (mints fresh single-use 24h invite), per-row Remove
  + Role picker (owner-only), "You" badge, Leave-group flow.
- Settings → My identity panel with fingerprint, share-link QR,
  Copy / Share buttons.
- Contact verification screen hosted by `ContactVerificationActivity`:
  fingerprint compare, scan-peer-QR, six-digit SAS, persisted
  `TrustLevel.VERIFIED` flag.
- SQLCipher passphrase derived per-install from the Android
  Keystore via `SqlCipherKeyProvider`. Headless boot decryption
  for `MessageService`; no user-auth gate.
- `nativeRegisterCallback` routes inbound P2P + group traffic
  through `MessageRepository` so messages land in the local store
  without manual refresh.
- `PENDING_JOIN_KEMS` evicts stale ephemeral KEM secrets after
  10 minutes; explicit zeroize on reset.
- SQLCipher v4 defaults pinned via a Room `onOpen` canary
  (cipher_compatibility = 4, cipher_page_size = 4096).

### Build / release

- Cross-compiled for `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`
  via `cargo-ndk`.
- R8 / ProGuard enabled for release builds.
- GitHub Actions release workflow signs every tag-pushed APK from
  GitHub Secrets; release artifacts attached automatically.
- `_typecheck_jni` Cargo feature + JNI contract scripts gate the
  Kotlin ↔ Rust surface on every PR.

### Known gaps (tracked for v0.1.x / v0.2.x)

- `audio` / `file_transfer` / legacy-Signal modules are
  feature-gated, not built in default features. They use
  `thread_rng()` and need migrating before they're un-gated.
- No Android instrumented tests yet (need emulator/device CI).
- No Play Store AAB; sideload-only APK.
- Migration strategy is `fallbackToDestructiveMigration` until
  v0.2.0 ships the first stable schema.
- Ownership transfer flow not implemented; an owner can only be
  the original creator.

[Unreleased]: https://github.com/MKlolbullen/Qubee/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/MKlolbullen/Qubee/releases/tag/v0.1.0-alpha
