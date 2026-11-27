#!/usr/bin/env python3
"""Build a single-signature native approval client; never deploy or run it."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # Each native bputil and live LA/SystemPolicy encoding was audited
    # separately, including the arm64e slice of 25G83's universal executable.
    # Do not infer another build's owner-authentication contract.
    parser.add_argument('--guest-build', choices=['24G90', '25G83', '26A5416b', '26B131'], required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    driver = args.driver.resolve()
    info = plistlib.loads((driver / 'Contents/Info.plist').read_bytes())
    if info['CFBundleIdentifier'] != 'com.virtualmac.SharedRadioNativeV1':
        raise ValueError('only the reviewed native radio driver is supported')
    builds = info['IOKitPersonalities']['VirtualMac native Wi-Fi']['MtkNativeAbi']['Builds']
    if len(builds) != 1 or builds[0]['Build'] != args.guest_build:
        raise ValueError('driver is for a different guest build')
    # Finder may attach resource metadata after the driver was built. The
    # deployment archive omits it; inspect the same clean copy, leaving the
    # original artifact and its signature untouched.
    with tempfile.TemporaryDirectory(prefix='vm27-approval-driver-', dir='/private/tmp') as temporary:
        clean = Path(temporary) / driver.name
        shutil.copytree(driver, clean, symlinks=True)
        subprocess.run(['xattr', '-cr', str(clean)], check=True)
        subprocess.run(['codesign', '--verify', '--strict', str(clean)], check=True)
        signature = subprocess.run(['codesign', '-d', '--verbose=4', str(clean)],
                                   capture_output=True, text=True, check=True)
    hashes = re.findall(r'^CDHash=([0-9a-f]{40})$', signature.stderr, re.M)
    if len(hashes) != 1:
        raise ValueError('requires one unambiguous driver CodeDirectory hash')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[3]
    source = root / 'VirtualMac/vz/shared-radio/guest/VM27RadioGuestApprovedDriverV1.m'
    entitlements = {key: True for key in (
        'com.apple.private.security.syspolicy.kext-policy-management',
        'com.apple.private.CoreAuthentication.SPI',
        'com.apple.private.applecredentialmanager.allow')}
    entitlement_path = out / 'Entitlements.plist'
    entitlement_path.write_bytes(plistlib.dumps(entitlements))
    binary = out / 'approved-driver-v1'
    subprocess.run(['xcrun', 'clang', '-target', 'arm64e-apple-macos15.0',
                    '-fobjc-arc', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-DVM27_APPROVAL_GUEST_BUILD="' + args.guest_build + '"',
                    '-DVM27_APPROVAL_DRIVER_CDHASH="' + hashes[0] + '"',
                    str(source), '-framework', 'Foundation', '-framework',
                    'LocalAuthentication', '-framework', 'Security', '-o', str(binary)], check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                    '--entitlements', str(entitlement_path), str(binary)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True)
    receipt = {'schema': 1, 'guestBuild': args.guest_build,
               'target': info['CFBundleIdentifier'], 'targetCDHash': hashes[0],
               'sourceSHA256': hashlib.sha256(source.read_bytes()).hexdigest(),
               'binarySHA256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'entitlements': list(entitlements), 'guestExecutionPerformed': False,
               'credentialsOrContextPersisted': False,
               'otherGuestBuildsRequireNativeAuthenticationAudit': True}
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
