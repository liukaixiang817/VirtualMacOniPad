#!/usr/bin/env python3
"""Separate Large route: inert original VMM data, owned small service only."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
N = ROOT.parent / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CAPACITY = N / 'xpc-original-capacity8-v1/build-v4'
V6 = N / 'xpc-original-instance-transport-v1/build-v6'
RIGHTS = {'platform-application': True,
          'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True,
          'com.apple.private.amfi.can-execute-cdhash': True,
          'com.apple.private.virtualization.plugin': True,
          'com.apple.private.virtualization': True}
DEVICE = '/var/root/VirtualMac2/testing/large-original-xpc-instance-v1'
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(output):
    out = Path(output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / 'source'
    source.mkdir()
    source_paths = [Path(__file__),
        ROOT / 'scripts/tests/test-modern-large-original-xpc-instance-transport.c',
        ROOT / 'scripts/tests/validate-modern-large-original-xpc-instance-transport.py',
        ROOT / 'vz/host/modern_xpc_large_original_instance_transport.c',
        ROOT / 'vz/host/modern_xpc_large_original_instance_transport.h']
    source_paths += [ROOT / 'vz/host' / name for name in (
        'modern_xpc_large_bundle_registry.h', 'modern_xpc_large_private_consumer.h',
        'modern_xpc_large_original_parent.h', 'modern_xpc_private_endpoint.h',
        'modern_xpc_approved_code.h', 'modern_xpc_lwcr_policy.h')]
    for path in source_paths:
        shutil.copyfile(path, source / path.name)
    shutil.copyfile(V6 / 'source/modern_xpc_original_instance_pins.h',
                    source / 'modern_xpc_original_instance_pins.h')
    spec = importlib.util.spec_from_file_location('target', ROOT / 'scripts/development/build-modern-xpc-lwcr-policy.py')
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    capacity = json.loads((CAPACITY / 'candidate.json').read_text())
    frozen = {name: sha(path) for name, path in [('capacityFreeze', CAPACITY / 'freeze.json'),
                                                ('instanceV6Freeze', V6 / 'freeze.json')]}
    original = next(row for row in capacity['candidates'] if row['role'] == 'data')
    original_path = out / 'OriginalVMM27.data'
    shutil.copyfile(original['path'], original_path)
    os.chmod(original_path, 0o600)
    assert sha(original_path) == original['sha256']
    data = {**original, 'path': str(original_path), 'source': original['path'],
            'unchanged': True, 'code': False, 'trustcache': False, 'deploymentMode': '0600'}
    candidates, processes, native_runs = [data], [], []

    def run(label, argv):
        env = {key: value for key, value in os.environ.items() if not key.startswith('DYLD_')}
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            stdout, stderr = child.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate()
            raise
        (out / (label + '.argv.json')).write_text(json.dumps(argv, indent=2) + '\n')
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        processes.append({'label': label, 'directChildPID': child.pid,
                          'observedWaitExit': child.returncode, 'reaped': True})
        assert child.returncode == 0, (label, child.returncode,
            stdout.decode(errors='replace')[-4000:], stderr.decode(errors='replace')[-4000:])
        return stdout, stderr

    def sign(role, path, rights, label):
        if role == 'ios':
            target.target16(path)
        entitlements = path.parent / (path.name + '.entitlements')
        entitlements.write_bytes(plistlib.dumps(rights))
        run(label + '-sign', ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
            '--identifier', 'com.virtualmac.diagnostics.large-original-instance.' + path.name,
            '--entitlements', str(entitlements), str(path)])
        run(label + '-strict', ['/usr/bin/codesign', '--verify', '--strict', str(path)])
        run(label + '-validate', ['xcrun', 'dyld_info', '-validate_only', str(path)])
        _, description = run(label + '-signature', ['/usr/bin/codesign', '-dvvv', str(path)])
        return {'role': role, 'name': path.name, 'path': str(path), 'bytes': path.stat().st_size,
            'sha256': sha(path), 'UUID': target.uuid(path.read_bytes()),
            'CDHash': re.search(rb'CDHash=([a-f0-9]{40})', description)[1].decode(),
            'entitlements': rights, 'code': True, 'trustcache': True,
            'deploymentMode': '0700' if path.name.endswith('-probe') else '0644'}

    for role, sdk, triple in [('macos', 'macosx', 'arm64e-apple-macos13'),
                              ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
        folder = out / role
        folder.mkdir()
        libraries = {}
        for name in ['VM27ApprovedCode.dylib', 'VM27LWCRPolicy.dylib', 'VM27PrivateEndpoint.dylib',
                     'VM27LargeRegistry.dylib', 'VM27LargeConsumer.dylib', 'VM27LargeParent.dylib']:
            original_row = next(row for row in capacity['candidates']
                                if row['role'] == role and row['name'] == name)
            path = folder / name
            shutil.copyfile(original_row['path'], path)
            assert sha(path) == original_row['sha256']
            row = {**original_row, 'path': str(path), 'source': original_row['path'],
                   'unchanged': True, 'code': True, 'trustcache': True, 'deploymentMode': '0644'}
            candidates.append(row)
            libraries[name] = row
        sdk_path = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path'])[0].decode().strip()
        base = ['xcrun', 'clang', '-target', triple, '-isysroot', sdk_path,
                '-fptrauth-abi-version=0', '-std=c11', '-fblocks', '-O2', '-Wall', '-Wextra',
                '-Werror', '-Wno-deprecated-declarations', '-I', str(source),
                '-DVM27_ENABLE_DIAGNOSTIC_ENDPOINT_FAILURE=1', '-Wl,-no_adhoc_codesign']
        transport = folder / 'VM27LargeOriginalTransport.dylib'
        run(role + '-transport-compile', base + [str(source / 'modern_xpc_large_original_instance_transport.c'),
            str(folder / 'VM27LargeConsumer.dylib'), str(folder / 'VM27LargeParent.dylib'),
            str(folder / 'VM27ApprovedCode.dylib'), '-framework', 'Security', '-framework', 'CoreFoundation',
            '-dynamiclib', '-Wl,-install_name,@rpath/VM27LargeOriginalTransport.dylib', '-o', str(transport)])
        transport_row = sign(role, transport, {}, role + '-transport')
        candidates.append(transport_row)
        libraries[transport.name] = transport_row
        macros = []
        for key, name in [('TRANSPORT', transport.name), ('CONSUMER', 'VM27LargeConsumer.dylib'),
                          ('REGISTRY', 'VM27LargeRegistry.dylib'), ('ENDPOINT', 'VM27PrivateEndpoint.dylib'),
                          ('APPROVED', 'VM27ApprovedCode.dylib'), ('POLICY', 'VM27LWCRPolicy.dylib'),
                          ('LPARENT', 'VM27LargeParent.dylib')]:
            row = libraries[name]
            macros += ['#define VM27_' + key + '_SHA256 "' + row['sha256'] + '"',
                       '#define VM27_' + key + '_BYTES ' + str(row['bytes']) + 'ULL',
                       '#define VM27_' + key + '_UUID "' + row['UUID'] + '"']
        data_path = DEVICE + '/OriginalVMM27.data' if role == 'ios' else str(original_path)
        macros += ['#define VM27_INERT_DATA_PATH "' + data_path + '"',
                   '#define VM27_INERT_DATA_SHA256 "' + data['sha256'] + '"',
                   '#define VM27_INERT_DATA_BYTES ' + str(data['bytes']) + 'ULL',
                   '#define VM27_INERT_DATA_CDHASH "' + data['CDHash'] + '"',
                   '#define VM27_INERT_DATA_UUID "' + data['UUID'] + '"']
        (folder / 'modern_xpc_large_factory_pins.h').write_text('\n'.join(macros) + '\n')
        probe = folder / 'large-original-xpc-instance-transport-probe'
        runtime_path = DEVICE if role == 'ios' else str(folder)
        run(role + '-probe-compile', base + ['-I', str(folder),
            str(source / 'test-modern-large-original-xpc-instance-transport.c')]
            + [str(folder / name) for name in libraries]
            + ['-framework', 'Security', '-Wl,-rpath,@executable_path',
               '-Wl,-rpath,' + runtime_path, '-o', str(probe)])
        row = sign(role, probe, RIGHTS if role == 'ios' else {}, role + '-probe')
        candidates.append(row)
        for name in ('VM27LargeOriginalTransport.dylib', 'large-original-xpc-instance-transport-probe'):
            run(role + '-' + name + '-imports', ['xcrun', 'dyld_info', '-imports', str(folder / name)])
            run(role + '-' + name + '-exports', ['xcrun', 'dyld_info', '-exports', str(folder / name)])
        if role == 'macos':
            native_runs = [[str(probe), row['sha256'], str(row['bytes']), row['CDHash'], variant]
                           for variant in ('normal', 'deny-handshake', 'timeout-handshake',
                                           'deny-instance', 'timeout-instance')]
    for command in native_runs:
        run('macos-' + command[-1] + '-native', command)
    assert sha(CAPACITY / 'freeze.json') == frozen['capacityFreeze']
    assert sha(V6 / 'freeze.json') == frozen['instanceV6Freeze']
    result = {'candidates': candidates, 'sourceSHA256': {path.name: sha(path) for path in source.iterdir()},
              'processes': processes, 'frozenUpstreamHashes': frozen, 'deviceOperations': False,
              'iOSExecuted': False, 'originalVMMExecuted': False, 'originalDataOnly': True,
              'onlyOwnedSmallProbeSpawned': True, 'originalPluginLoaderExecuted': False,
              'completeBundleRegistration': False, 'systemModified': False,
              'bootstrapChanges': 0, 'launchdRegistrations': 0, 'MacNativePositiveCovered': False,
              'MacNativeStrictDenialCovered': True, 'originalVMWireProtocolExecuted': False}
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(out), 'candidateSHA256': sha(out / 'candidate.json'),
                      'originalVMMExecuted': False, 'deviceOperations': False}))


if __name__ == '__main__':
    assert len(sys.argv) == 2
    main(sys.argv[1])
