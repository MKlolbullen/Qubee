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

### Added

- **Double Ratchet + sender keys design.** New
  `docs/double-ratchet-design.md` documents the target protocol
  (PQXDH initial agreement reusing existing `DeviceKey` X25519 +
  ML-KEM material; hybrid Double Ratchet with header encryption
  for 1:1; sender keys for groups distributed over the 1:1
  channel) and the four-stage migration plan from the current
  symmetric-group-key model. Prekey scaffolding (`DeviceKey` /
  `DevicePublicKey`) was already present from earlier identity
  work; this document pins how it's used. The ratchet
  implementation itself ships in a follow-on batch — landing it
  in a single rushed session is the standard way DR
  implementations have shipped CVEs (skip-window bugs, replay
  acceptance, header-encryption derivation errors, unknown-key-
  share attacks); the safe path is design first, port reference
  code second, ship in carefully reviewed slices.

- **Offline retry queue for outbound messages.** A peer offline at
  send-time used to lose the message — there was no store-and-forward
  layer. `ChatViewModel.sendMessage` now stamps the row with the
  exact encrypted wire bytes + initial retry schedule
  (`wireBytes`, `retryAttempt`, `nextRetryAt`; v3 → v4 schema bump
  via `MIGRATION_3_4`). `MessageService` runs a 30s-tick loop that
  re-publishes due rows up to a five-attempt budget on a
  30s/2m/10m/30m/2h backoff. The retry preserves the original
  `wireId` so any late `MessageAck` still correlates back to the
  same row. First ack clears the retry state inside the same
  `applyAckTransactional` transaction. Documented group caveat: a
  partially-online group is treated as delivered after the first
  ack — per-recipient delivery tracking lands with the sender-keys
  rewrite later.

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

- **Release-build R8 would have broken every inbound message.** The
  Rust core invokes five `NetworkCallback` methods
  (`onMessageReceived`, `onGroupMessageReceived`, `onMessageAcked`,
  `onPeerLinked`, `onPeerDiscovered`) by name via JNI `call_method`,
  but `proguard-rules.pro` only kept `QubeeManager`'s native methods,
  not the callback interface or its `MessageService` implementor —
  so a `minifyEnabled` release build would rename those overrides and
  silently drop all inbound traffic (no crash, just no messages). A
  second latent break: zero `-keepattributes`, so `Gson`'s
  `TypeToken<List<…>>` / `TypeToken<Map<…>>` deserialisation (group
  rosters, summaries, Room converters) would throw at runtime for
  lack of the `Signature` attribute. Both fixed; rules also extended
  to cover `data.model`/`identity` Gson packages, model enums,
  SQLCipher native, and Room entities. None of this surfaced earlier
  because debug builds and tests run un-minified.
- **`android-smoke` CI now builds an unsigned release APK** in
  addition to debug, so the full R8 pipeline runs on every PR — the
  class of break above is caught pre-tag instead of at release time.
  Needs no signing secrets (the `hasReleaseSigning` gate leaves it
  unsigned but still shrunk/obfuscated). RELEASE.md checklist gains
  the R8 dry-run + a post-install "did an inbound message actually
  arrive" sanity step (the only way to confirm the callbacks
  survived, since their loss is silent).
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

### Foundational

The baseline feature set the entries above build on. Listed here so
the first release's notes read as a complete picture rather than only
the most recent deltas. (Nothing has shipped yet, so there is no
prior released version — `[Unreleased]` *is* the upcoming
`v0.1.0-alpha`; the maintainer renames this single heading at tag
time per `RELEASE.md`.)

- Cryptography: ML-KEM-768 (FIPS 203, `pqcrypto-mlkem`) + ML-DSA-44
  (FIPS 204, `pqcrypto-mldsa`); hybrid Ed25519 ⊕ ML-DSA-44 signature
  on every signed wire frame; ChaCha20-Poly1305 AEAD, BLAKE3,
  HKDF/SHA-512; libp2p Noise XX transport (libp2p 0.55). Pinned wire
  vectors in `tests/wire_stability.rs`.
- Group messaging: owner-only invite minting + QR
  (`qubee://invite/<token>`); per-member ML-KEM keys in
  `JoinAccepted` + signed `MemberAdded`; strict generation-counter
  equality on decrypt; 5-minute message freshness window;
  `RequestStateSync` / `StateSyncResponse` offline-rejoin recovery;
  cold-start inbox hydration via `nativeListGroups`.
- Android: Onboarding → Inbox → Contacts → Settings on Room +
  SQLCipher 4.6; Group Details sheet (live roster, add/remove/role,
  "You" badge, leave); Settings identity panel (fingerprint,
  share-link QR); SQLCipher v4 PRAGMA canary.
- Build: cross-compiled for `arm64-v8a` / `armeabi-v7a` / `x86` /
  `x86_64` via `cargo-ndk`; R8 enabled for release; signed-APK
  release workflow; `_typecheck_jni` + JNI contract scripts gate
  the Kotlin ↔ Rust surface on every PR.

[Unreleased]: https://github.com/MKlolbullen/Qubee/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/MKlolbullen/Qubee/releases/tag/v0.1.0-alpha
