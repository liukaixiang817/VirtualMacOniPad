#!/usr/bin/env python3
"""Build/test 10 typed unavailable desktop Security APIs, without DI2 loading."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands
SHA = lambda data: hashlib.sha256(data).hexdigest()
NAMES = ['AuthorizationCreate', 'AuthorizationFree', 'AuthorizationMakeExternalForm',
         'SessionGetInfo', 'SecAccessCreate', 'SecKeychainCopyDefault', 'SecKeychainGetPath',
         'SecKeychainOpen', 'SecKeychainItemCopyKeychain', 'SecTrustedApplicationCreateFromPath']
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', default='/var/root/VirtualMac2/testing/di2-security-unavailable-v1')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'; source.mkdir()
    pins = {}
    for path in [ROOT / 'VirtualMac/vz/host/modern_diskimages2_security_unavailable.h',
                 ROOT / 'VirtualMac/vz/host/modern_diskimages2_security_unavailable.c',
                 ROOT / 'VirtualMac/scripts/tests/test-modern-diskimages2-security.c', Path(__file__)]:
        (source / path.name).write_bytes(path.read_bytes()); pins[str(path)] = SHA(path.read_bytes())
    provenance = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-desktop-services-static-contract-v1/sdk-prototypes.json'
    sdk_contract = json.loads(provenance.read_bytes())
    assert set(sdk_contract['prototypes']) == set(NAMES)
    (source / provenance.name).write_bytes(provenance.read_bytes())
    for row in sdk_contract['headers']:
        path = Path(row['path']); data = path.read_bytes()
        assert SHA(data) == row['sha256']
        (source / path.name).write_bytes(data)
    processes = []
    def run(label, argv):
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); raise
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        processes.append({'label': label, 'argv': argv, 'directChildPID': child.pid,
                          'observedWaitExit': child.returncode, 'reaped': True})
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')
        return stdout, stderr
    def sign(label, path, rights=None):
        argv = ['codesign', '--force', '--sign', '-', '--timestamp=none', str(path)]
        if rights:
            entitlement = out / (label + '.entitlements.plist')
            entitlement.write_bytes(plistlib.dumps(rights))
            argv = argv[:-1] + ['--entitlements', str(entitlement), str(path)]
        run(label + '-sign', argv)
        run(label + '-strict', ['codesign', '--verify', '--strict', str(path)])
        run(label + '-validate', ['xcrun', 'dyld_info', '-validate_only', str(path)])
        _, info = run(label + '-signature', ['codesign', '-d', '--verbose=4', str(path)])
        actual, _ = run(label + '-rights', ['codesign', '-d', '--entitlements', ':-', str(path)])
        assert plistlib.loads(actual) == rights if rights else not actual
        return re.search(rb'CDHash=([0-9a-f]{40})', info)[1].decode()
    def identity(path):
        data = path.read_bytes()
        uuid = next(data[at + 8:at + 24].hex() for cmd, at, _ in commands(data) if cmd == 0x1b)
        return {'path': str(path), 'bytes': len(data), 'sha256': SHA(data), 'UUID': uuid}
    result = []
    for role, sdk, target in [('macos', 'macosx', 'arm64e-apple-macos13.0'),
                              ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
        folder = out / role; folder.mkdir()
        sdk_path = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path'])[0].decode().strip()
        flags = ['xcrun', 'clang', '-target', target, '-isysroot', sdk_path, '-std=c11',
                 '-O2', '-fptrauth-abi-version=0', '-Wall', '-Wextra', '-Werror',
                 '-Wno-deprecated-declarations', '-fvisibility=hidden',
                 '-fno-typed-memory-operations-experimental', '-I' + str(source), '-I' + str(folder)]
        library = folder / 'VM27DI2SecurityUnavailable.dylib'
        run(role + '-provider-build', flags + ['-dynamiclib', '-Wl,-no_adhoc_codesign',
            '-Wl,-install_name,@rpath/VM27DI2SecurityUnavailable.dylib',
            str(source / 'modern_diskimages2_security_unavailable.c'), '-o', str(library)])
        if role == 'ios':
            data = bytearray(library.read_bytes()); at = next(at for cmd, at, _ in commands(data) if cmd == 0x32)
            struct.pack_into('<III', data, at + 8, 2, 0x100100, 0x100100); library.write_bytes(data)
        cd = sign(role + '-provider', library)
        exports = run(role + '-provider-exports', ['xcrun', 'dyld_info', '-exports', str(library)])[0]
        nm = run(role + '-provider-nm', ['xcrun', 'nm', '-gU', str(library)])[0].decode()
        assert {line.split()[-1] for line in nm.splitlines()} == {'_' + name for name in NAMES} | {'_VM27DI2SecurityCallCount'}
        record = identity(library); record['CDHash'] = cd; record['entitlements'] = {}
        rvas = [int(re.search(rb'(0x[\da-fA-F]+)\s+_' + name.encode() + rb'\b', exports)[1], 16) for name in NAMES]
        runtime_path = args.native_directory.rstrip('/') + '/' + library.name if role == 'ios' else str(library)
        literal = lambda values: '{' + ','.join(hex(v) for v in values) + '}'
        pin = 'static const char ProviderPath[]=' + json.dumps(runtime_path) + ';\n'
        pin += 'static const size_t ProviderBytes=' + str(record['bytes']) + ';\n'
        pin += 'static const unsigned char ProviderSHA[32]=' + literal(bytes.fromhex(record['sha256'])) + ';\n'
        pin += 'static const unsigned char ProviderUUID[16]=' + literal(bytes.fromhex(record['UUID'])) + ';\n'
        pin += 'static const char ProviderUUIDString[]=' + json.dumps(record['UUID']) + ';\n'
        pin += 'static const uintptr_t ProviderRVAs[10]=' + literal(rvas) + ';\n'
        (folder / 'di2-security-pins.h').write_text(pin)
        probe = folder / 'di2-security-unavailable-probe'
        run(role + '-probe-build', flags + [str(source / 'test-modern-diskimages2-security.c'),
            str(library), '-framework', 'CoreFoundation', '-Wl,-rpath,@loader_path',
            '-Wl,-no_adhoc_codesign', '-o', str(probe)])
        if role == 'ios':
            data = bytearray(probe.read_bytes()); at = next(at for cmd, at, _ in commands(data) if cmd == 0x32)
            struct.pack_into('<III', data, at + 8, 2, 0x100100, 0x100100); probe.write_bytes(data)
        probe_cd = sign(role + '-probe', probe, RIGHTS if role == 'ios' else None)
        imports = run(role + '-probe-imports', ['xcrun', 'dyld_info', '-imports', str(probe)])[0].decode()
        for name in NAMES + ['VM27DI2SecurityCallCount']:
            matches = [line for line in imports.splitlines() if re.search(r'_' + name + r'\b', line)]
            assert matches and all('VM27DI2SecurityUnavailable' in line and 'weak' not in line.lower() for line in matches), matches
        probe_record = identity(probe); probe_record.update(CDHash=probe_cd, entitlements=RIGHTS if role == 'ios' else {})
        item = {'role': role, 'provider': record, 'probe': probe_record, 'nativeRuntimePath': runtime_path,
                'all10StrongPositiveProviderImports': True, 'deviceExecuted': False}
        if role == 'macos':
            stdout, _ = run('macos-real-typed-unavailable', [str(probe)])
            rows = [json.loads(line) for line in stdout.decode().splitlines()]
            summary = rows[-1]
            assert summary['record'] == 'summary' and summary['passed'] and summary['failures'] == 0
            assert summary['providerCalls'] == 2571 and summary['frameworkAPICalls'] == 0
            assert len([r for r in rows if r['record'] == 'identity']) == 10
            assert rows[0]['PID'] == processes[-1]['directChildPID'] == summary['PID']
            item['actualMacFixture'] = summary
        result.append(item)
    manifest = {'candidates': result, 'sourceSHA256': pins, 'SDKPrototypesVerified': 10,
                'positiveProviderBindings': True, 'processes': processes, 'SecuritySuccessReturned': False,
                'AuthorizationRefsCreated': 0, 'keychainObjectsCreated': 0,
                'quarantineImplemented': False, 'DI2Loaded': False, 'DI2FrameworkAPICalls': 0,
                'deviceOperations': False, 'productionModified': False, 'full27Backend': False}
    (out / 'candidate.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'candidate': str(out / 'candidate.json'), 'candidates': result}, indent=2))

if __name__ == '__main__':
    main()
