"""Test product signer admission against realistic apksigner report shapes."""
import unittest
from sign_product_apk import validate_report

DIGEST = 'ab' * 32
REPORT = f'''Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Signer #1 certificate DN: CN=Qubee
Signer #1 certificate SHA-256 digest: {DIGEST}
'''

class ProductSigningTests(unittest.TestCase):
    def test_expected_owner_and_both_schemes(self):
        validate_report(REPORT, ':'.join(['AB'] * 32))

    def test_wrong_signer_debug_signer_missing_scheme_and_multiple_signers(self):
        cases = [REPORT.replace(DIGEST, 'cd' * 32),
                 REPORT.replace('CN=Qubee', 'CN=Android Debug'),
                 REPORT.replace('v3): true', 'v3): false'),
                 REPORT.replace('v2): true', 'v2): false'),
                 REPORT + f'Signer #2 certificate SHA-256 digest: {DIGEST}\n']
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report(report, DIGEST)

if __name__ == '__main__':
    unittest.main()
