#!/bin/bash
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
REQUIRED_RUST_MAJOR=1
REQUIRED_RUST_MINOR=88
ANDROID_JNI_DIR="app/src/main/jniLibs"
TARGETS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")

# ─── Prerequisite checks ────────────────────────────────────────────────────

# 1. Verify rustc is installed and meets the minimum version requirement
if ! command -v rustc &>/dev/null; then
    echo "ERROR: rustc is not installed. Install Rust via https://rustup.rs" >&2
    exit 1
fi

RUSTC_VERSION=$(rustc --version | sed 's/rustc \([0-9]*\.[0-9]*\.[0-9]*\).*/\1/')
RUSTC_MAJOR=$(echo "$RUSTC_VERSION" | cut -d. -f1)
RUSTC_MINOR=$(echo "$RUSTC_VERSION" | cut -d. -f2)

if [ "$RUSTC_MAJOR" -lt "$REQUIRED_RUST_MAJOR" ] || \
   { [ "$RUSTC_MAJOR" -eq "$REQUIRED_RUST_MAJOR" ] && [ "$RUSTC_MINOR" -lt "$REQUIRED_RUST_MINOR" ]; }; then
    echo "ERROR: rustc ${REQUIRED_RUST_MAJOR}.${REQUIRED_RUST_MINOR}+ required (found ${RUSTC_VERSION})." >&2
    echo "       Run: rustup update stable" >&2
    exit 1
fi
echo "✓ rustc ${RUSTC_VERSION} (>= ${REQUIRED_RUST_MAJOR}.${REQUIRED_RUST_MINOR})"

# 2. Verify cargo-ndk is installed
if ! command -v cargo-ndk &>/dev/null; then
    echo "ERROR: cargo-ndk is not installed." >&2
    echo "       Run: cargo install cargo-ndk" >&2
    exit 1
fi
echo "✓ cargo-ndk found"

# 3. Verify ANDROID_NDK_HOME is set
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    if [ -n "${ANDROID_NDK_ROOT:-}" ]; then
        export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
    elif [ -d "$HOME/Android/Sdk/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "$HOME/Android/Sdk/ndk"/*/ 2>/dev/null | sort -V | tail -1)
        export ANDROID_NDK_HOME="${ANDROID_NDK_HOME%/}"
    else
        echo "ERROR: ANDROID_NDK_HOME is not set and no NDK found at ~/Android/Sdk/ndk." >&2
        echo "       Install the Android NDK via Android Studio SDK Manager or set ANDROID_NDK_HOME." >&2
        exit 1
    fi
fi
echo "✓ ANDROID_NDK_HOME=${ANDROID_NDK_HOME}"

# 4. Ensure Android Rust targets are installed
for target_triple in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android; do
    if ! rustup target list --installed | grep -q "$target_triple"; then
        echo "  Installing target: ${target_triple}"
        rustup target add "$target_triple"
    fi
done
echo "✓ All Android Rust targets installed"

# ─── Build ───────────────────────────────────────────────────────────────────

for arch in "${TARGETS[@]}"; do
    mkdir -p "$ANDROID_JNI_DIR/$arch"
done

echo ""
echo "Building Rust libraries for Android (release)..."
echo ""

for arch in "${TARGETS[@]}"; do
    echo "── Building: ${arch} ──"
    cargo ndk -t "$arch" -o "$ANDROID_JNI_DIR" build --release
    echo ""
done

echo "✓ Done. Native libraries are in ${ANDROID_JNI_DIR}"
ls -lhR "$ANDROID_JNI_DIR"
