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
rustup show           # honours rust-toolchain.toml (1.86 stable)

# 2. Sanity-check your environment (Rust, Android NDK, cargo-ndk, etc.).
./scripts/qubee_doctor.sh

# 3. Run the Rust suite. Should print "60+ passed" green.
cargo test --locked

# 4. (Optional) Build the Android side. Requires the Android SDK.
./build_rust.sh        # bash; build_rust.ps1 on Windows
./gradlew :app:assembleDebug
```

## Before you open a PR

Run these locally; they're the same checks CI runs (`.github/workflows/ci.yml`):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
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
