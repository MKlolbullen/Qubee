#!/usr/bin/env python3
"""Record APK identity and two-device Samsung preflight; never infer physical PASS.
Read-only unless --install is explicitly used. Never uninstalls or clears app data.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--certificate-sha256', required=True)
    p.add_argument('--samsung', required=True, help='adb serial of physical Samsung')
    p.add_argument('--peer', required=True, help='adb serial of second physical phone')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--install', action='store_true')
    args = p.parse_args()
    if args.samsung == args.peer:
        p.error('Two different physical phones are required')
    if args.output.exists():
        p.error('Evidence output exists; choose a new filename')
    if not re.fullmatch(r'[0-9a-fA-F]{40}', args.source_commit):
        p.error('Supply the complete reviewed source commit SHA')
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk:
        p.error('ANDROID_HOME is required')
    sdk = Path(sdk)
    adb = sdk / 'platform-tools/adb'
    apksigner = sdk / 'build-tools/34.0.0/apksigner'
    cert = args.certificate_sha256.replace(':', '').lower()
    if not re.fullmatch(r'[0-9a-f]{64}', cert):
        p.error('Supply the exact APK certificate SHA-256 fingerprint')
    report = subprocess.check_output([str(apksigner), 'verify', '--verbose', '--print-certs', str(args.apk)], text=True)
    digests = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)$', report, re.M)
    if len(digests) != 1 or digests[0].lower() != cert:
        p.error('APK certificate mismatch')
    connected = subprocess.check_output([str(adb), 'devices'], text=True).splitlines()
    available = {line.split()[0] for line in connected if line.endswith('\tdevice')}
    if args.samsung not in available or args.peer not in available:
        p.error('Both physical devices must be attached, authorized and online')

    def shell(serial, *command):
        return subprocess.check_output([str(adb), '-s', serial, 'shell', *command], text=True).strip()

    devices = []
    for serial in [args.samsung, args.peer]:
        if shell(serial, 'getprop', 'ro.kernel.qemu') == '1':
            p.error('Emulator results cannot satisfy physical gates')
        manufacturer = shell(serial, 'getprop', 'ro.product.manufacturer')
        api = int(shell(serial, 'getprop', 'ro.build.version.sdk'))
        if api < 34:
            p.error('First acceptance run requires API 34+ on both phones')
        devices.append({
            'manufacturer': manufacturer,
            'model': shell(serial, 'getprop', 'ro.product.model'),
            'android': shell(serial, 'getprop', 'ro.build.version.release'),
            'api': api,
            'one_ui_code': shell(serial, 'getprop', 'ro.build.version.oneui'),
            'page_size': shell(serial, 'getconf', 'PAGESIZE'),
        })
    if devices[0]['manufacturer'].lower() != 'samsung':
        p.error('The Samsung slot must identify a Samsung device')
    if args.install:
        for serial in [args.samsung, args.peer]:
            subprocess.run([str(adb), '-s', serial, 'install', '-r', str(args.apk)], check=True)
    gates = ['signer_and_upgrade', 'cold_launch_jni_r8', 'identity_verification',
             'bidirectional_ratchet', 'pool_consumption_and_refresh', 'process_death_reboot',
             'network_switch_offline_delivery', 'samsung_doze_background',
             'calling_turn_relay_policy', 'calling_ice_restart', 'calling_background_media',
             'calling_thermal_battery']
    evidence = {'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source_commit': args.source_commit, 'apk_sha256': hashlib.sha256(args.apk.read_bytes()).hexdigest(),
                'certificate_sha256': cert, 'devices': devices,
                'preflight': 'PASS', 'physical_acceptance': 'NOT RUN',
                'install_requested': args.install,
                'gates': {gate: {'status': 'NOT RUN', 'evidence': ''} for gate in gates}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as out:
        json.dump(evidence, out, indent=2); out.write('\n')
    print(f'Preflight recorded: {args.output}. Physical acceptance remains NOT RUN.')


if __name__ == '__main__':
    main()
