#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KOTLIN_FILE="${ROOT_DIR}/app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt"
RUST_FILE="${ROOT_DIR}/src/jni_api.rs"
CLASS_PREFIX="Java_com_qubee_messenger_crypto_QubeeManager_"

required=(
  nativeEncryptMessage
  nativeDecryptMessage
  nativeEncryptFile
  nativeDecryptFile
)

if [[ ! -f "${KOTLIN_FILE}" ]]; then
  echo "error: missing Kotlin bridge file: ${KOTLIN_FILE}" >&2
  exit 2
fi

if [[ ! -f "${RUST_FILE}" ]]; then
  echo "error: missing Rust JNI bridge file: ${RUST_FILE}" >&2
  exit 2
fi

failed=0

echo "Message/file JNI bridge audit"
echo "  Kotlin: ${KOTLIN_FILE#${ROOT_DIR}/}"
echo "  Rust:   ${RUST_FILE#${ROOT_DIR}/}"
echo

for symbol in "${required[@]}"; do
  kotlin_ok=0
  rust_ok=0

  if grep -Eq "external[[:space:]]+fun[[:space:]]+${symbol}[[:space:]]*\(" "${KOTLIN_FILE}"; then
    kotlin_ok=1
  fi

  if grep -Eq "${CLASS_PREFIX}${symbol}\b" "${RUST_FILE}"; then
    rust_ok=1
  fi

  printf '%-28s Kotlin=%s Rust=%s\n' "${symbol}" "${kotlin_ok}" "${rust_ok}"

  if [[ "${kotlin_ok}" -ne 1 || "${rust_ok}" -ne 1 ]]; then
    failed=1
  fi
done

echo

if [[ "${failed}" -ne 0 ]]; then
  cat >&2 <<'EOF'
ERROR: message/file JNI bridge is incomplete.

Required invariant:
  Kotlin QubeeManager external declarations and Rust #[no_mangle]
  Java_com_qubee_messenger_crypto_QubeeManager_* exports must both exist
  for all four direct payload bridge methods:

  - nativeEncryptMessage
  - nativeDecryptMessage
  - nativeEncryptFile
  - nativeDecryptFile

Qubee must fail here rather than discovering a missing native symbol during
Android runtime message sending. JNI runtime surprises are bad. JNI runtime
surprises in crypto code are cursed.
EOF
  exit 1
fi

cat <<'EOF'
OK: message/file JNI bridge symbol presence looks complete.

This audit only verifies symbol presence. It does not prove that encryption,
decryption, envelope format, sender inspection, or transport routing are
semantically correct. Run the Rust tests, Android build, and two-device E2E
plan next.
EOF
