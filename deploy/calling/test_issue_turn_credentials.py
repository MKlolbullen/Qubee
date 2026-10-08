import base64
import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path

from issue_turn_credentials import MAX_TTL, issue, read_secret


class CredentialTests(unittest.TestCase):
    def test_coturn_rest_signature_expiry_and_rotation(self):
        key = b"a" * 32
        a = issue(key, 1_000_000, 10_800)
        b = issue(key, 1_000_000, 10_800)
        self.assertEqual(a["expires_at"], 1_010_800)
        self.assertTrue(str(a["username"]).startswith("1010800:"))
        self.assertNotEqual(a["username"], b["username"])
        expected = hmac.new(key, str(a["username"]).encode(), hashlib.sha1).digest()
        self.assertEqual(base64.b64decode(str(a["credential"])), expected)
        for ttl in (0, 59, MAX_TTL + 1):
            with self.assertRaises(ValueError):
                issue(key, 1_000_000, ttl)

    def test_secret_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret"
            path.write_bytes(b"a" * 32)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_secret(path)
            path.chmod(0o600)
            self.assertEqual(read_secret(path), b"a" * 32)


if __name__ == "__main__":
    unittest.main()
