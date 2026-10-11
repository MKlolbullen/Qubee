#!/usr/bin/env bash
# Refuse a release whose SECURITY.md does not publish the signer
# certificate fingerprint the workflow pins. Testers compare an APK's
# signer digest against SECURITY.md, so the pin must be there before
# the APK is.
#
#   scripts/check_security_pin.sh SECURITY.md <sha256-fingerprint>
#
# The fingerprint may carry keytool's colons and any letter case; the
# file may too.
set -euo pipefail

file="${1:?usage: check_security_pin.sh FILE FINGERPRINT}"
pin="${2:?usage: check_security_pin.sh FILE FINGERPRINT}"
pin="${pin//:/}"
pin="${pin,,}"

if ! [[ "$pin" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::'$2' is not a SHA-256 certificate fingerprint." >&2
    exit 1
fi
if ! tr -d ':' < "$file" | tr '[:upper:]' '[:lower:]' | grep -qF "$pin"; then
    echo "::error::$file does not contain the pinned signer fingerprint $pin. Add it under 'Release signing' before tagging (RELEASE.md, One-time setup, step 3)." >&2
    exit 1
fi
echo "$file publishes the pinned signer fingerprint."
