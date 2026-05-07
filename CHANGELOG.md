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

### Changed

- `eprintln!` / `println!` debug log lines in `src/jni_api.rs`
  + `src/groups/handshake_handlers.rs` converted to structured
  `tracing` calls (error / warn / info by signal class). The
  one secret-leak-risk line dropped its `{e:#}` interpolation.

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
