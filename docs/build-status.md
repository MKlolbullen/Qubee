# Build status — verification snapshot

This document captures what `cargo check` and Gradle plugin resolution
reported when run against the repo on the verification pass that
followed rounds 8–9 + the "fix all 4 UI gaps" work. It is a snapshot,
not a continuous status — re-run the commands below to refresh.

```
RUSTUP_TOOLCHAIN=stable cargo check
gradle --offline tasks
```

## Rust core

**Result**: still does not compile. The pass started at **162 errors**
and got down to **141** after the fixes listed under "addressed in
this pass" below. The remaining errors are *not* from the recent
rounds — they're long-standing API-drift between the dependencies
declared in `Cargo.toml` and the code that uses them.

### Addressed in this pass

* **Removed the duplicate `src/security/secure_keystore.rs`.** Two
  identical copies of `SecureKeyStore` lived under `security/` and
  `storage/`; both derived `ZeroizeOnDrop` *and* declared a manual
  `impl Drop`, producing a hard E0119 conflict. `crate::storage::*`
  is the canonical path (every caller already used it); the
  `security` copy is gone.
* **Fixed the Drop conflict in `storage/secure_keystore.rs`.** The
  `#[derive(ZeroizeOnDrop)]` was redundant with the manual `impl
  Drop` (which flushes keys to disk on drop). The derive is gone;
  `master_key: Secret<[u8;32]>` already zeroises on its own drop.
* **Added `libc` as a target-conditional dep** for `cfg(unix)`.
  `secure_memory.rs` was calling `libc::mlock`/`munlock` and
  `secure_rng.rs` was calling `libc::getpid` from inside `unsafe {}`
  blocks without ever declaring the dep, so the crate failed to
  resolve before reaching the type checker.
* **Replaced the unstable `ThreadId::as_u64()` call** in
  `secure_rng.rs` with a comment + a lean on the existing
  `std::process::id` + stack-address + timing entropy sources. The
  thread-id contribution was a few bits at most and not worth
  carrying an unstable feature for.
* **Added the missing `kyber_pub` field** to one `GroupMember`
  literal in `handshake_handlers.rs::process_join_accepted` that
  Round 9f had introduced without updating its struct-literal
  initialisation.

### Remaining categories (~141 errors, all pre-existing)

These are **dependency-API drift**, not regressions from any recent
round. The grouped histogram from `cargo check`:

| count | error / cause |
|------:|--------------|
| 8 | `HybridSignature` / `IdentityKey` doesn't implement `Debug` — used in error formatting (`{e:?}`); add `#[derive(Debug)]` upstream. |
| 6 | `pqcrypto_kyber::PublicKey: serde::Deserialize` not satisfied — `IdentityKey` derives `Serialize/Deserialize` but contains a Kyber pubkey that doesn't impl them. Either drop the derive or wrap the pubkey in a custom `(De)Serialize` for byte-encoded form. |
| 5 | `OsRng::fill_bytes` trait bound — `chacha20poly1305 = "0.10"` expects `rand_core 0.6` traits, but `Cargo.toml` pins `rand = "0.9"` which uses 0.9 traits. Pin `rand` to 0.8 or upgrade chacha20poly1305 (and the rest of the AEAD chain) to a version that follows rand 0.9. |
| 5 | `SigningKey: DefaultIsZeroes` / `SecretKey: DefaultIsZeroes` — `Secret<T>` requires `T: DefaultIsZeroes` in `secrecy = "0.8"`. The wrapped types don't satisfy it. Either upgrade `secrecy` to 0.10 (which dropped the trait) or wrap with `Box<dyn ...>`. |
| 4 | `ChaChaPoly1305::encrypt`/`decrypt` not found — `chacha20poly1305 = "0.10"` requires the `aead` feature for those methods. Add `features = ["aead"]` to the dep. |
| 4 | `pqcrypto_dilithium::PublicKey::from_bytes` not found — `pqcrypto-dilithium = "0.5"` moved that to the `pqcrypto-traits` `sign::PublicKey` trait. `use pqcrypto_traits::sign::PublicKey as _;` in the consuming files. |
| 4 | `type annotations needed` — cascades from the others; resolve the upstream and these go away. |
| ~ | smaller counts: `crate::HybridRatchet` not at crate root, `crate::PQ_REKEY_PERIOD` missing, `double_ratchet` crate not declared, `dilithium2::Signature` / `dilithium2::verify` removed, `Secret::expose_secret` on the wrong wrapper type in `contact_manager.rs`, etc. All in modules my recent rounds don't touch (`audio`, `hybrid_ratchet`, `secure_message`, `file_transfer`, `signal_protocol`, `sas`, `oob_secrets`, `logging`). |

### What actually runs today

Nothing. `cargo check` doesn't pass, so neither do the integration
tests under `tests/group_handshake_e2e.rs`,
`tests/group_message_e2e.rs`, or `tests/wire_stability.rs`. Those
test files are written against the public API I added in rounds
8–9 and *should* pass cleanly the moment the lib compiles, but I
can't claim that until someone actually runs them.

### Recommended cleanup order

1. **Pin `secrecy = "0.10"`** + clean up the `Secret<...>` API at the
   call sites. This removes 5+ errors.
2. **Pin `rand = "0.8"`** OR upgrade the AEAD stack. Removes ~9
   errors.
3. **Add `features = ["aead"]` to chacha20poly1305**. Removes 4
   errors.
4. **Add `use pqcrypto_traits::sign::{PublicKey, SecretKey, ...} as _;`**
   to every file that touches Dilithium. Removes 4+ errors.
5. **Custom `Serialize`/`Deserialize` for `IdentityKey`** that
   round-trips the Kyber + Dilithium pubkeys as byte arrays. Removes
   6 errors.
6. **Feature-gate the legacy modules** (`audio`, `hybrid_ratchet`,
   `secure_message`, `file_transfer`, `signal_protocol`, `sas`,
   `oob_secrets`) behind a `legacy` feature so default `cargo
   build` doesn't try to compile them. They're not on any code
   path the JNI surface reaches today.

After steps 1–4 the recent rounds' code should cleanly build and the
integration tests should run.

## Android module (Gradle)

**Result**: scaffolding parses, plugin resolution fails offline.

* Added `settings.gradle`, `build.gradle`, and `gradle.properties` at
  the repo root for the first time. Without them, `app/build.gradle`
  was unbuildable — nothing was telling Gradle that `:app` exists or
  what plugin versions to use.
* The build now gets through bootstrap and tries to resolve
  `com.android.application:8.4.0`, `org.jetbrains.kotlin.android:1.9.22`,
  `com.google.dagger.hilt.android:2.48`,
  `androidx.navigation.safeargs.kotlin:2.7.7`, and
  `app.cash.paparazzi:1.3.4`. With the sandbox in `--offline` mode
  resolution fails, but that's expected — on a machine with internet
  access the plugin downloads succeed.
* No Gradle wrapper (`gradlew` + `gradle/wrapper/*.jar`) is committed
  yet because the wrapper jar is binary and I can't generate one
  without running `gradle wrapper`. **First step on a new clone**:
  ```
  cd Qubee
  gradle wrapper --gradle-version 8.7
  git add gradlew gradlew.bat gradle/wrapper
  git commit -m "Add Gradle wrapper"
  ```

## Paparazzi

A minimal screenshot test (`ResetButtonScreenshotTest.kt`) exists as
the baseline. It snapshots the destructive "Reset identity" button so
later UI changes have something to diff against. Once `:app` builds
end-to-end, run:

```bash
./gradlew :app:recordPaparazziDebug
git add app/src/test/snapshots/
```

…to commit the baseline PNGs. The pattern for adding more tests is
documented in `docs/screenshot-tests.md`.
