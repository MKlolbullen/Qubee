#!/bin/bash
# Build the Rust shared library for all four Android ABIs we ship.
#
# Reproducible-build inputs (must stay in sync with the values
# documented in `docs/reproducible-builds.md`):
#   - Rust toolchain: pinned in `rust-toolchain.toml` (1.86.0)
#   - Cargo.lock: committed; `--locked` enforces it
#   - NDK: r26b (`ndkVersion` in `app/build.gradle`, `ndk-version`
#     in the GitHub Actions workflows)
#   - cargo-ndk: ^3 (CI installs with --locked)
#
# Path remapping: any absolute path baked into debug info (e.g. the
# user's $HOME for the registry) is rewritten to a stable token so
# two machines produce byte-identical .so files. Applied to:
#   - $CARGO_HOME (typically ~/.cargo) → /__cargo
#   - $PWD (the source tree)             → /__src
#
# This isn't perfect — `strip = true` in the release profile already
# removes most debug info — but the remap makes the few remaining
# embedded strings deterministic.
set -euo pipefail

ANDROID_JNI_DIR="app/src/main/jniLibs"

mkdir -p "$ANDROID_JNI_DIR/arm64-v8a"
mkdir -p "$ANDROID_JNI_DIR/armeabi-v7a"
mkdir -p "$ANDROID_JNI_DIR/x86"
mkdir -p "$ANDROID_JNI_DIR/x86_64"

CARGO_HOME_REMAP="${CARGO_HOME:-$HOME/.cargo}"
SRC_REMAP="$(pwd)"
export RUSTFLAGS="${RUSTFLAGS:-} \
  --remap-path-prefix=$CARGO_HOME_REMAP=/__cargo \
  --remap-path-prefix=$SRC_REMAP=/__src"

# Disable timestamp metadata in the .rmeta files so an otherwise
# identical compile produces byte-identical bytes.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

echo "Building Rust shared library for Android (release, --locked) ..."
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
    echo "  → $abi"
    cargo ndk -t "$abi" -o "$ANDROID_JNI_DIR" build --release --locked
done

echo
echo "Built libraries:"
find "$ANDROID_JNI_DIR" -name '*.so' -printf '  %p (%s bytes)\n'

if command -v sha256sum >/dev/null 2>&1; then
    echo
    echo "SHA-256 of each .so (compare across machines to verify reproducibility):"
    find "$ANDROID_JNI_DIR" -name '*.so' -print0 | sort -z | xargs -0 sha256sum
fi
