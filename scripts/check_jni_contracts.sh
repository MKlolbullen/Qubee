#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KOTLIN_FILE="${ROOT_DIR}/app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt"
RUST_FILE="${ROOT_DIR}/src/jni_api.rs"
CLASS_PREFIX="Java_com_qubee_messenger_crypto_QubeeManager_"

if [[ ! -f "${KOTLIN_FILE}" ]]; then
  echo "error: Kotlin JNI surface not found: ${KOTLIN_FILE}" >&2
  exit 2
fi

if [[ ! -f "${RUST_FILE}" ]]; then
  echo "error: Rust JNI surface not found: ${RUST_FILE}" >&2
  exit 2
fi

python3 - "${KOTLIN_FILE}" "${RUST_FILE}" "${CLASS_PREFIX}" <<'PY'
import re
import sys
from pathlib import Path

kotlin_path = Path(sys.argv[1])
rust_path = Path(sys.argv[2])
class_prefix = sys.argv[3]

kotlin = kotlin_path.read_text(encoding="utf-8")
rust = rust_path.read_text(encoding="utf-8")

# Strip comments enough to avoid obvious false positives while keeping the parser intentionally simple.
def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text

kotlin_clean = strip_comments(kotlin)
rust_clean = strip_comments(rust)

# Kotlin side: private/public external fun nativeX(...)
kotlin_natives = set(re.findall(r"\bexternal\s+fun\s+(native[A-Za-z0-9_]+)\s*\(", kotlin_clean))

# Rust side: #[no_mangle] Java_com_qubee_messenger_crypto_QubeeManager_nativeX(...)
rust_natives = set(re.findall(re.escape(class_prefix) + r"(native[A-Za-z0-9_]+)\b", rust_clean))

missing_in_rust = sorted(kotlin_natives - rust_natives)
missing_in_kotlin = sorted(rust_natives - kotlin_natives)

print("JNI contract check")
print(f"  Kotlin declarations: {len(kotlin_natives)}")
print(f"  Rust exports:        {len(rust_natives)}")

if kotlin_natives:
    print("\nKotlin native declarations:")
    for name in sorted(kotlin_natives):
        print(f"  - {name}")

if rust_natives:
    print("\nRust JNI exports:")
    for name in sorted(rust_natives):
        print(f"  - {name}")

failed = False

if missing_in_rust:
    failed = True
    print("\nERROR: Kotlin declares native methods that Rust does not export:", file=sys.stderr)
    for name in missing_in_rust:
        print(f"  - {name} -> expected {class_prefix}{name}", file=sys.stderr)

if missing_in_kotlin:
    failed = True
    print("\nERROR: Rust exports JNI methods that Kotlin does not declare:", file=sys.stderr)
    for name in missing_in_kotlin:
        print(f"  - {class_prefix}{name} -> expected external fun {name}(...) in QubeeManager.kt", file=sys.stderr)

if not kotlin_natives:
    failed = True
    print("\nERROR: no Kotlin native declarations found; parser or file layout is wrong.", file=sys.stderr)

if not rust_natives:
    failed = True
    print("\nERROR: no Rust JNI exports found; parser or file layout is wrong.", file=sys.stderr)

if failed:
    sys.exit(1)

print("\nOK: Kotlin/Rust JNI native symbol sets match.")
PY

# ---------------------------------------------------------------------
# Reverse callbacks: Rust -> Kotlin.
#
# The Rust core invokes NetworkCallback methods by name + hand-written
# JNI descriptor via `env.call_method(obj, "onX", "(...)V", ...)`. A
# descriptor that drifts from the Kotlin signature fails silently at
# runtime (the call_method result is discarded), dropping messages.
# Verify each Rust descriptor matches the Kotlin method's signature.
# ---------------------------------------------------------------------
CALLBACK_FILE="${ROOT_DIR}/app/src/main/java/com/qubee/messenger/network/NetworkCallback.kt"
if [[ ! -f "${CALLBACK_FILE}" ]]; then
  echo "error: NetworkCallback not found: ${CALLBACK_FILE}" >&2
  exit 2
fi

python3 - "${CALLBACK_FILE}" "${RUST_FILE}" <<'PY'
import re
import sys
from pathlib import Path

callback = Path(sys.argv[1]).read_text(encoding="utf-8")
rust = Path(sys.argv[2]).read_text(encoding="utf-8")

def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text

callback = strip_comments(callback)
rust = strip_comments(rust)

# Kotlin type -> JNI descriptor fragment.
KT2JNI = {
    "String": "Ljava/lang/String;",
    "ByteArray": "[B",
    "Long": "J",
    "Int": "I",
    "Boolean": "Z",
    "Float": "F",
    "Double": "D",
    "Short": "S",
    "Byte": "B",
    "Char": "C",
}

# Parse Kotlin: fun onX(a: T, b: U): all callbacks return Unit -> ")V".
kotlin_desc = {}
for m in re.finditer(r"\bfun\s+(on[A-Za-z0-9_]+)\s*\((.*?)\)", callback, flags=re.S):
    name = m.group(1)
    params = m.group(2).strip()
    frags = []
    ok = True
    if params:
        for part in params.split(","):
            part = part.strip()
            if not part:
                continue  # trailing comma in multi-line signatures
            # "ident: Type" (ignore default values / nullability marks)
            t = part.split(":", 1)[1].strip().rstrip("?").split("=")[0].strip() if ":" in part else ""
            if t not in KT2JNI:
                ok = False
                break
            frags.append(KT2JNI[t])
    if ok:
        kotlin_desc[name] = "(" + "".join(frags) + ")V"

# Parse Rust: call_method(obj, "onX", "(...)V", ...) — name + descriptor
# may be on adjacent lines, so scan a small window after each name.
rust_desc = {}
for m in re.finditer(r'"(on[A-Za-z0-9_]+)"\s*,', rust):
    name = m.group(1)
    window = rust[m.end():m.end() + 200]
    d = re.search(r'"(\([^"]*\)V)"', window)
    if d:
        rust_desc[name] = d.group(1)

print("\nReverse-callback contract check (Rust call_method -> NetworkCallback)")
failed = False
for name, rdesc in sorted(rust_desc.items()):
    kdesc = kotlin_desc.get(name)
    if kdesc is None:
        failed = True
        print(f"  ERROR: Rust calls '{name}' but NetworkCallback has no such method", file=sys.stderr)
    elif kdesc != rdesc:
        failed = True
        print(f"  ERROR: '{name}' descriptor mismatch: Rust={rdesc} Kotlin={kdesc}", file=sys.stderr)
    else:
        print(f"  - {name}: {rdesc} OK")

if not rust_desc:
    failed = True
    print("  ERROR: no Rust call_method descriptors found; parser drift", file=sys.stderr)

if failed:
    sys.exit(1)
print("OK: reverse-callback descriptors match NetworkCallback.")
PY
