#!/usr/bin/env python3
"""Build separate account-aware helpers against the working restore launcher.

Does not replace the ordinary installer or deploy to a device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]

def build(output):
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'VirtualMac/vz'
    account = source / 'apple-account'
    commands = []
    def run(label, args):
        args = list(map(str, args))
        result = subprocess.run(args, capture_output=True, timeout=120)
        (output / (label + '.log')).write_bytes(result.stdout + result.stderr)
        commands.append(dict(label=label, argv=args, exit=result.returncode))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode: raise RuntimeError(label + ': ' + result.stderr.decode()[-3500:])
    flags = ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64-apple-ios16.1',
             '-O2', '-Wall', '-Wextra', '-Werror', '-fblocks']
    objects = []
    for name in ['VMAppleAccountProfileV1', 'VMAppleAccountInstallerV1']:
        obj = output / (name + '.o')
        run('compile-' + name, flags + ['-fobjc-arc', '-c', account / (name + '.m'), '-o', obj])
        objects.append(obj)
    installer = output / 'install-account-v1'
    run('link-installer', flags + ['-DVM_APPLE_ACCOUNT_INSTALLER_V1=1',
        '-Wl,-export_dynamic', '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'UIKit',
        source / 'host/NSViewShim.m', source / 'install/install_macos.m', *objects, '-o', installer])
    launcher = output / 'install-account-launcher-v1'
    run('compile-launcher', flags + ['-DVM_INSTALL_SCRIPT="/var/root/VirtualMac/install/start-install-account-v1.sh"',
        source / 'install/install_launcher.c', '-o', launcher])
    script = (source / 'install/start-install.sh').read_bytes()
    if hashlib.sha256(script).hexdigest() != '5310f360c667a10d38244cfedd7788faca5c7a273b58bc877e19d1a18ce3a6f2':
        raise ValueError('working restore launcher source changed; inspect before porting')
    script = script.replace(b'killall install-macos 2>/dev/null || true',
        b'killall install-macos 2>/dev/null || true\nkillall install-account-v1 2>/dev/null || true')
    old = b'exec "$remote/install/install-macos" "$ipsw" "$staging" "$final"'
    if script.count(old) != 1: raise ValueError('restore launch point changed')
    script = script.replace(old, b'exec "$remote/install/install-account-v1" "$ipsw" "$staging" "$final"')
    script_path = output / 'start-install-account-v1.sh'
    script_path.write_bytes(script)
    run('validate-shell', ['sh', '-n', script_path])
    rows = []
    for path in [launcher, script_path, installer]:
        if path != script_path:
            run('sign-' + path.name, ['codesign', '--force', '--sign', '-', '--timestamp=none',
                '--digest-algorithm=sha256', '--entitlements', source / 'host/VirtualMac.entitlements',
                '--generate-entitlement-der', path])
            run('verify-' + path.name, ['codesign', '--verify', '--strict', path])
        data = path.read_bytes()
        row = dict(path=str(path), remote='/var/root/VirtualMac/install/' + path.name,
            bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), mode='04755' if path == launcher else '0755')
        if path != script_path:
            proof = run('identity-' + path.name, ['codesign', '-d', '--verbose=4', path])
            import re
            result = subprocess.run(['codesign', '-d', '--verbose=4', path], capture_output=True, text=True, check=True)
            row['cdhash'] = re.search(r'^CDHash=([0-9a-f]+)$', result.stderr, re.M)[1]
        rows.append(row)
    pin = output / 'installer-anchor.c'
    pin.write_text('#include <stdint.h>\nconst char *const VMAppleAccountInstallerPathsV1[3]={' +
        ','.join(json.dumps(r['remote']) for r in rows) + '};\n'
        'const uint64_t VMAppleAccountInstallerBytesV1[3]={' + ','.join(str(r['bytes']) for r in rows) + '};\n'
        'const uint8_t VMAppleAccountInstallerHashesV1[3][32]={' +
        ','.join('{' + ','.join(str(v) for v in bytes.fromhex(r['sha256'])) + '}' for r in rows) + '};\n')
    (output / 'candidate.json').write_text(json.dumps(dict(files=rows, anchor=str(pin)), indent=2) + '\n')
    return output / 'candidate.json'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(build(parser.parse_args().output.resolve()))
