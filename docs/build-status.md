# Build status — verification snapshot

This document captures what `cargo` and Gradle reported when run
against the repo on the rounds q–t verification pass. Re-run the
commands below to refresh.

```
cargo check
cargo test
./gradlew :app:assembleDebug
./gradlew :app:recordPaparazziDebug
```

## Rust core — `cargo check` + `cargo test`

**Result: GREEN.** Default `cargo build` compiles clean, all 33
in-tree unit tests pass, all 16 integration tests pass.

```
$ cargo test
   Compiling qubee_crypto v0.2.0 (/home/user/Qubee)
    Finished `test` profile [unoptimized + debuginfo] target(s)
     Running unittests src/lib.rs
test result: ok. 33 passed; 0 failed; 0 ignored
     Running tests/group_handshake_e2e.rs
test result: ok. 5 passed; 0 failed; 0 ignored
     Running tests/group_message_e2e.rs
test result: ok. 3 passed; 0 failed; 0 ignored
     Running tests/wire_stability.rs
test result: ok. 8 passed; 0 failed; 0 ignored
```

### What it took to get here

The verification pass started at 162 errors. Steps:

1. **Feature-gated the legacy modules** behind `#[cfg(feature =
   "legacy")]`: `audio`, `hybrid_ratchet`, `secure_message`,
   `file_transfer`, `signal_protocol`, `sas`, `oob_secrets`,
   `secure_memory`. They reference dependency APIs that have since
   drifted; nothing on the JNI surface uses them. Compile them when
   you're ready to port: `cargo check --features legacy`. (Today
   that's still a 100+ error fix-up project — the gating is
   protective, not a green light.)
2. **Upgraded `secrecy 0.8` → `0.10`** and switched
   `Secret<NonCopyType>` to `SecretBox<NonCopyType>` everywhere it
   appeared: `identity/identity_key.rs`, `groups/group_crypto.rs`,
   `storage/secure_keystore.rs`, `identity/contact_manager.rs`.
3. **Pinned `rand` to 0.8** because `chacha20poly1305 = "0.10"`,
   `rand_chacha = "0.3"`, and `ed25519-dalek = "2.x"` all standardise
   on `rand_core 0.6` which `rand 0.8` re-exports. Added
   `rand_chacha = "0.3"` and `getrandom = "0.2"` as direct deps.
4. **Added `libc` as a `cfg(unix)`** dep so `secure_rng.rs` compiles
   on Linux/macOS/Android.
5. **Ed25519-dalek**: enabled `serde` + `zeroize` features so
   `IdentityKey` and `HybridSignature` can derive serde + zeroise
   private bytes.
6. **Custom serde for `IdentityKey` and `HybridSignature`** —
   pqcrypto types don't impl `serde::{Serialize, Deserialize}`, so
   `identity/identity_key.rs` round-trips them through their byte
   form via `WireIdentityKey` / `WireHybridSignature` shadow structs.
7. **Custom `Debug` impls** for `IdentityKey`, `HybridSignature`,
   `DevicePublicKey` (the contained pqcrypto types don't impl
   `Debug` either; we print summary fields without the opaque
   secrets).
8. **Refactored `IdentityKeyPair` internals** to store private key
   material as raw byte buffers (`[u8; 32]` and `Vec<u8>`) wrapped in
   manual `Drop` + `zeroize`. The pqcrypto secret types don't impl
   `Zeroize` directly, so `SecretBox<DilithiumSecret>` would have
   needed an orphan-rule-bypassing wrapper. Storing bytes is cleaner.
9. **Bug fix**: `secure_rng::collect_additional_entropy` was filling
   a `[u8; 64]` buffer from BLAKE3's 32-byte digest via
   `copy_from_slice`, which panicked on every call. Switched to BLAKE3
   XOF mode (`finalize_xof().fill(...)`). This is why every test that
   touched `IdentityKeyPair::generate()` had been crashing.
10. **Borrow-checker fix** in `group_manager::update_member_role` —
    moved `log_group_event` outside the `&mut group` borrow scope.
11. **Misc**: `chacha20poly1305::aead::Aead` import in
    `group_crypto.rs`, `chacha20poly1305::Error` doesn't impl
    `Display` so swapped `.context(...)` for `.map_err(...)`,
    `MemberStatus` got `Debug` for the `assert_eq!` in tests,
    `IdentityKey` lost `Eq` (the pq pubkey doesn't impl it).

## Android module — Gradle

**Result: scaffolding works, plugin resolution downloads, build
needs the Android SDK.**

* The Gradle wrapper now exists (`gradlew`, `gradlew.bat`,
  `gradle/wrapper/gradle-wrapper.{jar,properties}`). Generated with
  `gradle wrapper --gradle-version 8.7`.
* Plugin metadata downloaded successfully: AGP 8.4.0,
  Kotlin 1.9.22, Hilt 2.48, Navigation 2.7.7, Paparazzi 1.3.4.
* `gradle :app:recordPaparazziDebug` now fails on:
  ```
  SDK location not found. Define a valid SDK location with an
  ANDROID_HOME environment variable or by setting the sdk.dir path
  in your project's local properties file at
  '/home/user/Qubee/local.properties'.
  ```
  …which is the expected message on a machine without the Android
  SDK installed. The sandbox doesn't have it; running this on a real
  dev/CI machine with `ANDROID_HOME=/path/to/sdk` should succeed.

### Bootstrapping the Android build on a clean machine

```bash
# Install Android SDK + cmdline-tools + platform-tools, then:
echo "sdk.dir=$ANDROID_HOME" > local.properties

# First-time wrapper bootstrap (just downloads gradle 8.7 to ~/.gradle):
./gradlew --version

# Build the debug APK and run unit tests (Rust .so files must already
# be in app/src/main/jniLibs — built by `build_rust.sh`):
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest

# Compose screenshot baselines (first time):
./gradlew :app:recordPaparazziDebug
git add app/src/test/snapshots/
git commit -m "Add Paparazzi baselines"

# CI (every PR):
./gradlew :app:verifyPaparazziDebug
```

## Recommended next steps

* (q-tail) Port the legacy modules behind `--features legacy` once
  there's an actual consumer. Today's gating is honest; the modules
  have ~100 errors waiting and aren't worth fixing speculatively.
* (s-cont) Run Paparazzi on a real machine to commit the baseline
  PNGs. With the SDK present and the wrapper jar already in the
  repo, this is one command on a dev box.
* (u) CI: add a GitHub Actions workflow that runs `cargo test` on
  every PR. The Android side requires more setup but a pure-Rust CI
  job is two lines of YAML and immediately catches future regressions.
