#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

section() {
  printf '\n\033[1;36m==> %s\033[0m\n' "$1"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    return 1
  fi
}

run_optional_gradle() {
  if [[ ! -x ./gradlew ]]; then
    echo "skip: ./gradlew is missing or not executable"
    return 0
  fi

  if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
    echo "skip: Android SDK not configured; set ANDROID_HOME or ANDROID_SDK_ROOT to run Gradle checks"
    return 0
  fi

  section "Android assembleDebug"
  ./gradlew :app:assembleDebug

  section "Android unit tests"
  ./gradlew :app:testDebugUnitTest

  section "Android lint"
  ./gradlew :app:lintDebug
}

section "Environment"
echo "repo: ${ROOT_DIR}"
echo "rustc: $(command -v rustc >/dev/null 2>&1 && rustc --version || echo missing)"
echo "cargo: $(command -v cargo >/dev/null 2>&1 && cargo --version || echo missing)"
echo "java:  $(command -v java >/dev/null 2>&1 && java -version 2>&1 | head -n 1 || echo missing)"
echo "ANDROID_HOME: ${ANDROID_HOME:-<unset>}"
echo "ANDROID_SDK_ROOT: ${ANDROID_SDK_ROOT:-<unset>}"

section "JNI Kotlin/Rust symbol contract"
bash scripts/check_jni_contracts.sh

section "Rust toolchain availability"
require_cmd cargo

section "Rust format"
cargo fmt --all --check

section "Rust clippy"
cargo clippy --all-targets --all-features -- -D warnings

section "Rust JNI typecheck"
if grep -q '^_typecheck_jni = ' Cargo.toml; then
  cargo build --features _typecheck_jni
else
  echo "note: Cargo feature _typecheck_jni not declared; running cargo check instead"
  cargo check
fi

section "Rust tests"
cargo test

run_optional_gradle

section "Doctor complete"
echo "Qubee bridge checks completed. If Android checks were skipped, rerun on a machine with ANDROID_HOME configured."
