"""Test signer admission reports and optionally a real Android smoke APK."""
import unittest
import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
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

    @unittest.skipUnless(os.environ.get('QUBEE_SIGNING_TEST_APK'), 'Requires the Android smoke APK')
    def test_real_apk_signatures_owner_pin_and_debug_rejection(self):
        """Sign the smoke APK with owner and debug keystores and check acceptance/rejection."""
        apk = str(Path(os.environ['QUBEE_SIGNING_TEST_APK']).resolve())
        helper = str(Path(__file__).with_name('sign_product_apk.py'))
        env = os.environ.copy()
        env['QUBEE_SIGN_TEST_PASSWORD'] = secrets.token_urlsafe(40)
        with tempfile.TemporaryDirectory(prefix='qubee-signing-test-') as directory:
            directory = Path(directory)
            for label, dn in [('owner', 'CN=Qubee Signing Regression'), ('debug', 'CN=Android Debug')]:
                keystore = directory / f'{label}.p12'
                subprocess.run(['keytool', '-genkeypair', '-noprompt', '-keystore', str(keystore),
                                '-storetype', 'PKCS12', '-alias', label, '-keyalg', 'RSA', '-keysize', '2048',
                                '-sigalg', 'SHA256withRSA', '-validity', '2', '-dname', dn,
                                '-storepass:env', 'QUBEE_SIGN_TEST_PASSWORD',
                                '-keypass:env', 'QUBEE_SIGN_TEST_PASSWORD'], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                certificate = subprocess.check_output(['keytool', '-exportcert', '-keystore', str(keystore),
                                                      '-alias', label, '-storepass:env', 'QUBEE_SIGN_TEST_PASSWORD'],
                                                     env=env, stderr=subprocess.DEVNULL)
                pin = hashlib.sha256(certificate).hexdigest()
                env.update(RELEASE_KEYSTORE_FILE=str(keystore), RELEASE_KEY_ALIAS=label,
                           RELEASE_KEYSTORE_PASSWORD=env['QUBEE_SIGN_TEST_PASSWORD'],
                           RELEASE_KEY_PASSWORD=env['QUBEE_SIGN_TEST_PASSWORD'])
                if label == 'debug':
                    # Pin the actual signed certificate to test debug rejection
                    # independently of the certificate-mismatch gate.
                    sdk = env.get('ANDROID_HOME') or env.get('ANDROID_SDK_ROOT')
                    signer = str(Path(sdk) / 'build-tools' / '34.0.0' / 'apksigner')
                    probe = directory / 'debug-probe.apk'
                    subprocess.run([signer, 'sign', '--ks', str(keystore), '--ks-key-alias', label,
                                    '--ks-pass', 'env:RELEASE_KEYSTORE_PASSWORD',
                                    '--key-pass', 'env:RELEASE_KEY_PASSWORD', '--out', str(probe), apk],
                                   env=env, check=True, stdout=subprocess.DEVNULL)
                    report = subprocess.check_output([signer, 'verify', '--print-certs', str(probe)], text=True)
                    pin = re.search(r'^Signer #1 certificate SHA-256 digest: ([0-9a-f]+)
    unittest.main()
, report, re.M).group(1)
                out = directory / f'{label}.apk'
                result = subprocess.run(['python3', helper, apk, str(out), '--certificate-sha256', pin],
                                        env=env, capture_output=True, text=True)
                if label == 'debug':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('debug certificate', result.stderr)
                    self.assertFalse(out.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(out.is_file())
                    wrong = directory / 'wrong-pin.apk'
                    result = subprocess.run(['python3', helper, apk, str(wrong),
                                             '--certificate-sha256', '0' * 64],
                                            env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('does not match', result.stderr)
                    self.assertFalse(wrong.exists())

if __name__ == '__main__':
    unittest.main()
