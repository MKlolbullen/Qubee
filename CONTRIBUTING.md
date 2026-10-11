# Contributing to Qubee

Thanks for considering a contribution. Qubee is a small project right
now and the bar for contributions is "make it land cleanly with the
existing tests still green and a clear PR description". Everything
below is the long form of that.

## Quick start

```bash
# 1. Clone and check the toolchain Qubee expects.
git clone https://github.com/MKlolbullen/Qubee.git
cd Qubee
rustup show           # honours rust-toolchain.toml (1.88.0)

# 2. Sanity-check your environment (Rust, Android NDK, cargo-ndk, etc.).
./scripts/qubee_doctor.sh

# 3. Run the Rust suite used by CI.
cargo test --locked --all-targets

# 4. (Optional) Build the Android side. Requires the Android SDK.
./build_rust.sh        # bash; build_rust.ps1 on Windows
./gradlew :app:assembleDebug
```

## Optional local release signing

Debug builds require no release-signing secrets. Gradle reads
`RELEASE_KEYSTORE_FILE`, `RELEASE_KEYSTORE_PASSWORD`, `RELEASE_KEY_ALIAS`, and
`RELEASE_KEY_PASSWORD` from the current process environment; it does not load
`.env` or other dotenv files automatically.

`.env.example` lists these optional variables with blank values. If you use a
local `.env` copy, keep it private and never commit it or real credentials.
In Bash or Zsh, export values from that shell-compatible file before building:

```bash
cp .env.example .env
# Fill .env locally, then:
set -a
. ./.env
set +a
./gradlew :app:assembleRelease
unset RELEASE_KEYSTORE_FILE RELEASE_KEYSTORE_PASSWORD RELEASE_KEY_ALIAS RELEASE_KEY_PASSWORD
```

In PowerShell, set `$env:RELEASE_KEYSTORE_FILE`, `$env:RELEASE_KEYSTORE_PASSWORD`,
`$env:RELEASE_KEY_ALIAS`, and `$env:RELEASE_KEY_PASSWORD` in the current session
(or configure them in your IDE's run environment) before invoking
`.\gradlew.bat :app:assembleRelease`. Do not save passwords in scripts or
commit them. Without these variables, a local release build uses the debug
keystore and is not suitable for distribution; the tagged-release workflow
requires its signing secrets.

## Before you open a PR

Run these locally; they're the same checks CI runs (`.github/workflows/ci.yml`):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --features _typecheck_jni
cargo bench --no-run
./scripts/check_jni_contracts.sh
./scripts/audit_message_file_bridge.sh
```

If you touched the JNI surface (`src/jni_api.rs` or
`app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt`):
- The Kotlin and Rust sides must declare/export the same set of
  `native*` symbols. `check_jni_contracts.sh` enforces this.
- The `_typecheck_jni` feature lets you compile the JNI module on
  the host without an Android target. CI runs it; please do too.

## Coding standards

- **Default to writing no comments.** Names are documentation; reach
  for a comment only when the *why* is non-obvious (a hidden invariant,
  a workaround for a specific bug, behavior that would surprise a
  reader). Don't restate what the code does.
- **No new dependencies for trivia.** Adding a 30-MB transitive tree
  to format a string is not worth it. We've consciously stuck with
  `secrecy 0.10`, `rand 0.8`, `pqcrypto-mlkem 0.1`, etc., because the
  ecosystem locks together cleanly at those versions; bumps need a
  reason in the PR.
- **No half-finished implementations.** If a feature is scoped down
  to "the structure is in place but the actual call doesn't fire", say
  so explicitly with a TODO and a tracking issue rather than letting a
  silent stub merge. The `// TODO(rev-4)` discipline that the rev-3
  cleanup paid off a year of accreted fiction; please don't reopen
  that account.
- **Never bypass safety checks** (`--no-verify`, `--no-gpg-sign`,
  etc.) in commits. If a hook fails, fix the underlying issue.

## What we accept

- Bug fixes with a regression test.
- Performance improvements with a `cargo bench` baseline.
- Documentation improvements, especially in `docs/security/` and
  `docs/architecture/`.
- New features that have been discussed in an issue first.

## What we don't accept

- "Modernizations" that change every file but don't add or fix
  anything. We'll merge a small refactor inside a feature PR;
  standalone style sweeps are noise.
- Cryptographic primitive substitutions without a compelling reason
  (FIPS compliance, side-channel mitigation, etc.). The current set
  is ML-KEM-768 + ML-DSA-44 + Ed25519 + X25519 + ChaCha20-Poly1305 +
  BLAKE3; replacing any of them is a project-level decision, not a
  drive-by PR.
- Changes that re-introduce ZK proof framing onto onboarding bundles.
  See the README's "Why no zero-knowledge proofs" section for the
  reasoning.

## Reporting a security issue

**Don't open a public issue.** Follow `SECURITY.md`.

## Code review

PRs need at least one maintainer approval. Reviews focus on:
- Correctness of the cryptographic state machine (group key generation
  counter, member status transitions, signature verification).
- Wire-format compatibility (`tests/wire_stability.rs` must stay green;
  any pinned vector that changes needs a `_v2` tag bump).
- JNI contract drift (the script enforces this mechanically).
- Test coverage for the behavior change.

Reviewers will ask for: a short PR description that explains *why*,
test output proving the fix or feature works, and confirmation that
the local equivalents of the CI checks above passed.

## License

By contributing, you agree your contribution will be licensed under
the MIT License (the same license as the project — see `LICENSE.md`).
