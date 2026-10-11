#!/usr/bin/env python3
"""Sign a built APK with the owner's keystore and pin its public certificate.
No key generation, credential logging, existing-file replacement or publication.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def fingerprint(value):
    result = value.replace(':', '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', result):
        raise ValueError('Expected a 64-digit SHA-256 certificate fingerprint')
    return result


def validate_report(report, expected):
    digests = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)$', report, re.M)
    if len(digests) != 1 or fingerprint(digests[0]) != fingerprint(expected):
        raise ValueError('APK signer does not match the pinned owner certificate')
    for scheme in ['v2', 'v3']:
        if not re.search(rf'^Verified using {scheme} scheme .*: true$', report, re.M):
            raise ValueError(f'APK does not have a verified {scheme} signature')
    if re.search(r'certificate DN:.*CN=Android Debug', report, re.I):
        raise ValueError('Android debug certificate cannot sign a product APK')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--certificate-sha256', required=True)
    parser.add_argument('--build-tools', type=Path)
    args = parser.parse_args()
    expected = fingerprint(args.certificate_sha256)
    names = ['RELEASE_KEYSTORE_FILE', 'RELEASE_KEYSTORE_PASSWORD', 'RELEASE_KEY_ALIAS', 'RELEASE_KEY_PASSWORD']
    if not all(os.environ.get(name) for name in names):
        parser.error('All four RELEASE_* signing credentials are required')
    keystore = Path(os.environ['RELEASE_KEYSTORE_FILE'])
    if not keystore.is_file() or not args.apk.is_file():
        parser.error('Input APK or owner keystore is unavailable')
    if args.output.exists():
        parser.error('Output already exists; choose a new filename')
    tools = args.build_tools
    if tools is None:
        sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
        if not sdk:
            parser.error('Set ANDROID_HOME or pass --build-tools')
        tools = Path(sdk) / 'build-tools' / '34.0.0'
    if not all((tools / tool).is_file() for tool in ['zipalign', 'apksigner']):
        parser.error('Pinned Android build tools are unavailable')
    with zipfile.ZipFile(args.apk) as apk:
        if 'lib/arm64-v8a/libqubee_crypto.so' not in apk.namelist():
            parser.error('APK lacks the Samsung arm64 Rust library')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='qubee-sign-', dir=args.output.parent) as temp:
        aligned = Path(temp) / 'aligned.apk'
        signed = Path(temp) / 'signed.apk'
        subprocess.run([str(tools / 'zipalign'), '-f', '-p', '4', str(args.apk), str(aligned)], check=True)
        subprocess.run([str(tools / 'apksigner'), 'sign', '--ks', str(keystore),
                        '--ks-key-alias', os.environ['RELEASE_KEY_ALIAS'],
                        '--ks-pass', 'env:RELEASE_KEYSTORE_PASSWORD',
                        '--key-pass', 'env:RELEASE_KEY_PASSWORD',
                        '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
                        '--v3-signing-enabled', 'true', '--min-sdk-version', '32',
                        '--out', str(signed), str(aligned)], check=True)
        report = subprocess.check_output([str(tools / 'apksigner'), 'verify', '--verbose', '--print-certs',
                                          '--min-sdk-version', '32', str(signed)], text=True)
        validate_report(report, expected)
        # Exclusive creation protects an existing release if paths raced.
        with args.output.open('xb') as output:
            output.write(signed.read_bytes())
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f'Verified owner certificate SHA-256: {expected}')
    print(f'{digest}  {args.output.name}')


if __name__ == '__main__':
    main()
