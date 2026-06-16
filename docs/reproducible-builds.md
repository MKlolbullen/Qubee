# Reproducible builds

Given the same source tree, every machine running the documented
toolchain should produce a byte-identical APK and set of `.so`
shared libraries. This lets any third party verify that the
`qubee-<version>.apk` attached to a GitHub Release was built from
the corresponding source tag — no need to trust the maintainer's
machine.

## Pinned inputs

| Layer | What | Where pinned |
|---|---|---|
| Rust toolchain | `1.86.0` + `clippy` + `rustfmt` | `rust-toolchain.toml` |
| Rust dependencies | locked at exact versions | `Cargo.lock` (committed) |
| Rust release profile | `opt-level=3`, `lto=thin`, `codegen-units=1`, `strip=symbols`, `panic=abort`, `incremental=false` | `[profile.release]` in `Cargo.toml` |
| Path remapping | `$CARGO_HOME → /__cargo`, `$PWD → /__src` | `RUSTFLAGS` in `build_rust.sh` |
| Source date | `SOURCE_DATE_EPOCH=0` | `build_rust.sh` |
| Android NDK | `r26b` (`26.1.10909125`) | `app/build.gradle` (`ndkVersion`) + `.github/workflows/*.yml` (`ndk-version`) |
| `cargo-ndk` | `^3`, installed `--locked` | `.github/workflows/release.yml` step `Install cargo-ndk` |
| JDK | Temurin 17 | `.github/workflows/release.yml` step `Set up JDK 17` |
| Android compileSdk | 34 | `app/build.gradle` |
| Gradle | `8.7` with pinned SHA-256 | `gradle/wrapper/gradle-wrapper.properties` |
| Compose compiler | `1.5.4` | `app/build.gradle` (`composeOptions`) |

## Canonical build command

From a clean checkout of the tag:

```bash
./build_rust.sh                                # cross-compile all 4 ABIs
./gradlew :app:assembleRelease --no-daemon \
  -PqubeeVersionName=$VERSION \
  -PqubeeVersionCode=$CODE
```

`$VERSION` is the tag minus the leading `v` (e.g. `0.1.0-alpha`).
`$CODE` is `git rev-list --count HEAD` from the tagged commit. The
release workflow (`.github/workflows/release.yml`) sets both
automatically.

`build_rust.sh` prints the SHA-256 of every produced `.so` file at the
end of its run; compare those against the values from the release
workflow's logs to verify cross-machine reproducibility before opening
a discrepancy report.

## What's NOT reproducible (acknowledged)

* **APK signing.** The signing certificate is the maintainer's; you
  won't be able to produce a byte-identical signed APK. To compare,
  unzip both APKs, drop `META-INF/*.SF`, `META-INF/*.RSA`, and
  `META-INF/MANIFEST.MF`, then diff the rest. The
  `apk-verify-reproducibility.sh` script (when it lands) automates
  this.
* **`gradle-wrapper.jar`.** The wrapper jar in `gradle/wrapper/` is
  the upstream artifact for Gradle 8.7. Its sha is pinned via the
  `distributionSha256Sum` in `gradle-wrapper.properties` so a
  hostile mirror can't substitute a different one.
* **Compose runtime artifacts.** Pulled from Maven Central; sha256
  pinning across the Compose BOM happens at the M2 repository
  level (which is signed by Google). Out of scope for this project
  to re-pin further.

## Verifying a release

Given a published `qubee-<version>.apk` from
[Releases](https://github.com/MKlolbullen/qubee/releases):

1. Check out the matching tag locally:
   ```bash
   git checkout v<version>
   ```
2. Run the canonical build above. The release workflow stamps
   `versionName` from the tag and `versionCode` from
   `git rev-list --count HEAD` — re-derive both.
3. Compare:
   ```bash
   # .so files (deterministic)
   sha256sum app/src/main/jniLibs/*/libqubee_crypto.so
   # ↑ must match the SHAs printed in the release workflow's
   # "Build Rust shared libraries" step.

   # APK content (excluding signatures)
   unzip -d /tmp/local app/build/outputs/apk/release/app-release.apk
   unzip -d /tmp/release qubee-<version>.apk
   diff -r /tmp/local /tmp/release \
     --exclude='META-INF/CERT.*' \
     --exclude='META-INF/QUBEE.*' \
     --exclude='META-INF/MANIFEST.MF'
   ```
4. If anything differs, file an issue with:
   * the host OS + Rust + NDK + JDK versions you used
   * the diff output
   * the SHA-256 of both APKs

## Known sources of non-determinism

These have bitten reproducible builds in the past and are explicitly
defended against above:

* **Embedded paths.** Solved by `--remap-path-prefix` in
  `build_rust.sh`.
* **Build timestamps in metadata.** Solved by `SOURCE_DATE_EPOCH=0`
  + `strip = "symbols"` + Gradle's documented zero-timestamp policy
  for APK entries.
* **HashMap iteration order in code-gen.** Mitigated by
  `codegen-units = 1`. Rust's hashmap iteration is random per process
  but the *codegen output* doesn't depend on iteration of any
  user-visible HashMap; we set the codegen-units knob anyway because
  rustc internally has used per-CGU randomness for symbol naming in
  some versions.
* **Parallel ar packing.** `cargo build` on the same single-CGU
  release profile uses deterministic `llvm-ar` behaviour by default.
* **NDK linker version skew.** Two different NDKs ship two different
  `ld.lld` and `libc++`; output differs. Pinning the NDK fixes this.
