#!/usr/bin/env python3
"""Issue ephemeral Coturn TURN REST credentials on a trusted backend.

Never embed the shared secret or invoke this issuer on an Android client.
The caller is responsible for authenticating the device and delivering the
returned JSON over a protected channel.
"""

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import stat
import time
from pathlib import Path

DEFAULT_TTL = 3 * 60 * 60  # Covers the 2 h soak test until renewal exists.
MAX_TTL = 6 * 60 * 60


def issue(secret: bytes, now: int, ttl: int) -> dict[str, object]:
    if not secret or not 60 <= ttl <= MAX_TTL:
        raise ValueError("nonempty secret and TTL between 60 s and 6 h required")
    expires = now + ttl
    # Random opaque username suffix: no stable Qubee IdentityId or PeerId.
    username = f"{expires}:{secrets.token_hex(12)}"
    digest = hmac.new(secret, username.encode("ascii"), hashlib.sha1).digest()
    return {
        "username": username,
        "credential": base64.b64encode(digest).decode("ascii"),
        "expires_at": expires,
    }


def read_secret(path: Path) -> bytes:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("TURN secret must be a regular file readable only by its owner")
    secret = path.read_bytes().strip()
    if len(secret) < 32 or b"\n" in secret or b"\r" in secret:
        raise ValueError("TURN secret must be at least 32 bytes and one line")
    return secret


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-file", required=True, type=Path)
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL)
    args = parser.parse_args()
    print(json.dumps(issue(read_secret(args.secret_file), int(time.time()), args.ttl_seconds)))


if __name__ == "__main__":
    main()
