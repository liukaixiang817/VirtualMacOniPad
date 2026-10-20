#!/usr/bin/env python3
"""Build the private loader with the real consumers' minimum dylib ABI version.

This builds only owned fixtures and never deploys, loads VZ/VMM, or changes an
existing frozen build. The implementation is the already tested project source.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import plistlib
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = N / 'softlinking-app-private-local-v1/build-v4'
sys.path.insert(0, str(R / 'VirtualMac/scripts/development'))
from vz_import_addend_image import commands, export_trie, imports, cstring
import struct


def pin(path):
    raw = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def dylib_id(raw):
    rows = [(at, size) for cmd, at, size in commands(raw) if cmd == 13]
    assert len(rows) == 1
    at, size = rows[0]
    off = struct.unpack_from('<I', raw, at + 8)[0]
    stamp, current, compatible = struct.unpack_from('<3I', raw, at + 12)
    return dict(name=cstring(raw, at + off, at + size), timestamp=stamp,
                current=current, compatibility=compatible)


def uuid(raw):
    return next(raw[at + 8:at + 24].hex() for cmd, at, size in commands(raw) if cmd == 27)


def provider_rva(raw):
    ranges = []
    for cmd, offset, length in commands(raw):
        if cmd == 0x80000033:
            ranges.append(struct.unpack_from('<II', raw, offset + 8))
        elif cmd == 0x80000022:
            ranges.append(struct.unpack_from('<II', raw, offset + 40))
    assert len(ranges) == 1
    at, size = ranges[0]
    rows = export_trie(raw[at:at + size])
    assert len(rows) == 1 and rows[0]['symbol'] == '__sl_dlopen' and rows[0]['flags'] == 0
    return rows[0]['address']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(N) and not out.exists() and not out.is_symlink()
    original_candidate = B / 'candidate.json'
    assert pin(original_candidate)['sha256'] == 'bc4978b41232facb49007d2ab0f4f00cf83c4f88adb4c662d8afe92da3aa9cc4'
    old = json.loads(original_candidate.read_bytes())
    out.mkdir(parents=True, mode=0o700)
    src = out / 'source'
    src.mkdir()
    for name in ('scoped_softlinking.c', 'scoped_softlinking.h', 'consumer.c'):
        source = (R / 'VirtualMac/vz/host' / name) if name.startswith('scoped_') else B / 'source' / name
        assert not source.is_symlink()
        assert source.read_bytes() == (B / 'source' / name).read_bytes()
        shutil.copy2(source, src / name)
    processes = []

    def run(label, argv):
        child = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        so, se = child.communicate(timeout=45)
        (out / (label + '.stdout')).write_bytes(so)
        (out / (label + '.stderr')).write_bytes(se)
        processes.append(dict(label=label, PID=child.pid, wait=child.returncode,
                              argv=list(map(str, argv)), stdout=pin(out / (label + '.stdout')),
                              stderr=pin(out / (label + '.stderr'))))
        assert child.returncode == 0, (label, se.decode(errors='replace'))
        return so, se

    rights = {'platform-application': True, 'com.apple.private.security.no-container': True,
              'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
    runtime = '/private/var/root/VirtualMac2/testing/softlinking-consumer-abi-v1'
    roles = []
    for role, sdk, target in [('mac', 'macosx', 'arm64-apple-macos15.0'),
                              ('ios', 'iphoneos', 'arm64e-apple-ios16.0')]:
        folder = out / role
        folder.mkdir()
        sdk_path = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path'])[0].decode().strip()
        common = ['xcrun', 'clang', '-target', target, '-isysroot', sdk_path,
                  '-O2', '-Wall', '-Wextra', '-Werror', '-Wl,-no_fixup_chains']
        provider = folder / 'VM27ScopedSoftLinking.dylib'
        run(role + '-provider-build', common + ['-dynamiclib', src / 'scoped_softlinking.c',
            '-Wl,-install_name,@loader_path/' + provider.name, '-Wl,-exported_symbol,__sl_dlopen',
            '-Wl,-current_version,1.0.0', '-Wl,-compatibility_version,1.0.0', '-o', provider])
        raw = provider.read_bytes()
        identity = dylib_id(raw)
        assert identity['current'] == identity['compatibility'] == 65536
        assert identity['name'] == '@loader_path/' + provider.name
        rva = provider_rva(raw)
        header = folder / 'provider_pins.h'
        header.write_text('#define ALLOW_MAC_ORACLE ' + ('1' if role == 'mac' else '0') + '\n' +
                          '#define PRIVATE_PROVIDER_PATH ' + json.dumps(str(provider) if role == 'mac' else runtime + '/' + provider.name) + '\n' +
                          '#define PRIVATE_PROVIDER_UUID ' + json.dumps(uuid(raw)) + '\n' +
                          '#define PRIVATE_PROVIDER_RVA ' + str(rva) + 'ULL\n')
        cli = folder / 'scoped-softlinking-consumer'
        run(role + '-consumer-build', common + ['-I', folder, '-I', src, src / 'consumer.c', provider, '-o', cli])
        paths = [('provider', provider)]
        previous = next(row for row in old['roles'] if row['role'] == role)
        for label in ('dependency', 'main', 'late'):
            item = next(row for row in previous['files'] if row['label'] == label)
            source = Path(item['path'])
            assert pin(source) == {k: item[k] for k in ('path', 'bytes', 'sha256')}
            path = folder / source.name
            shutil.copy2(source, path)
            paths.append((label, path))
        paths.append(('consumer', cli))
        ent = folder / 'Probe.entitlements'
        ent.write_bytes(plistlib.dumps(rights))
        products = []
        for label, path in paths:
            permission = rights if role == 'ios' and label == 'consumer' else {}
            if label in ('provider', 'consumer'):
                run(role + '-' + label + '-sign', ['codesign', '--force', '--sign', '-', '--timestamp=none',
                    '--generate-entitlement-der', *(['--entitlements', ent] if permission else []), path])
            run(role + '-' + label + '-strict', ['codesign', '--verify', '--strict', path])
            sig = run(role + '-' + label + '-describe', ['codesign', '-dv', '--verbose=4', path])[1]
            products.append(dict(label=label, name=path.name, **pin(path), UUID=uuid(path.read_bytes()),
                                 CDHash=re.search(rb'CDHash=([0-9a-f]{40})', sig)[1].decode(), entitlements=permission))
        # Strong positive import, with the consumer requesting ABI 1.0.0.
        so = run(role + '-consumer-imports', ['xcrun', 'dyld_info', '-imports', cli])[0]
        assert b'VM27ScopedSoftLinking' in so and b'__sl_dlopen' in so
        loads = run(role + '-consumer-loads', ['xcrun', 'otool', '-l', cli])[0].decode()
        assert 'compatibility version 1.0.0' in loads
        run(role + '-provider-dyld', ['xcrun', 'dyld_info', '-validate_only', provider])
        roles.append(dict(role=role, files=products, providerRVA=rva, providerID=identity))
        if role == 'mac':
            for mode in ('private', 'oracle'):
                run('mac-actual-' + mode, [cli, '--' + mode, folder])
    candidate = dict(schema='VM27 scoped SoftLinking consumer ABI 1 v1', roles=roles,
        source=[pin(p) for p in sorted(src.iterdir())], buildScript=pin(Path(__file__)),
        onlyProviderExports=['__sl_dlopen'], providerHasNoConstructor=True, providerHasNoInterpose=True,
        ABICompatibilityVersion=65536, originalMacConsumerRecordedCurrentVersion=4718592,
        advertisedWholeSystemFrameworkVersion=False, implementationSourceUnchanged=True,
        originalVZCalls=0, originalVMMExecuted=False, guestInstructions=0, full27=False, deviceExecuted=False)
    (out / 'candidate.json').write_text(json.dumps(candidate, indent=2) + '\n')
    plan = dict(schema='VM27 scoped SoftLinking consumer ABI 1 owned plan v1', candidate=pin(out / 'candidate.json'),
        runtimeRoot=runtime, executable='scoped-softlinking-consumer', args=['--private', runtime],
        files=next(row['files'] for row in roles if row['role'] == 'ios'),
        missingFileNames=['vm27-never-created-missing-A.dylib', 'vm27-never-created-missing-B.dylib'],
        targetAPICalls=7, ownedFixtureCalls=4, errorReleases=2, cpuLimitSoft=3, cpuLimitHard=4,
        wallWatchdogSeconds=10, externalWatchdogSeconds=12, fileWrites=0,
        originalConsumerSystemPathListsExecuted=False, originalVMMExecuted=False, guestInstructions=0, full27=False)
    (out / 'consumer-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    (out / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), plan=pin(out / 'consumer-plan.json'), deviceExecuted=False)))


if __name__ == '__main__':
    main()
