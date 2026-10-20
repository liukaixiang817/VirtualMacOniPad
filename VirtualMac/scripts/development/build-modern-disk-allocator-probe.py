#!/usr/bin/env python3
"""Build a frozen disk allocator test; no deployment, trust update or execution."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    records = []

    def run(label, command):
        result = subprocess.run(command, capture_output=True)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        records.append({'label': label, 'argv': command, 'exit': result.returncode})
        if result.returncode:
            raise RuntimeError(label + ': ' + result.stderr.decode(errors='replace'))
        return result

    builder = project / 'scripts/development/build-modern-typed-allocator.py'
    run('provider-build', [sys.executable, str(builder), '--all-five', '--with-valloc',
                           '--output', str(output / 'provider')])
    provider = json.loads((output / 'provider/manifest.json').read_bytes())['library']
    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).stdout.decode().strip()
    test = project / 'scripts/tests/test-modern-disk-allocator.c'
    executable = output / 'disk-allocator-probe'
    run('compile', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1',
        '-isysroot', sdk, '-O2', '-std=c11', '-fno-typed-memory-operations-experimental',
        '-Wall', '-Wextra', '-Werror',
        '-DVM27_DISK_ALLOCATOR_UUID="' + provider['uuid'] + '"',
        '-Wl,-platform_version,ios,16.1,16.1', str(test), '-o', str(executable)])
    rights = {'platform-application': True, 'com.apple.private.security.no-container': True,
        'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
    entitlement_file = output / 'Probe.entitlements'
    entitlement_file.write_bytes(plistlib.dumps(rights))
    run('sign', ['codesign', '--force', '--sign', '-', '--timestamp=none',
                 '--entitlements', str(entitlement_file), str(executable)])
    run('strict', ['codesign', '--verify', '--strict', str(executable)])
    run('dyld', ['xcrun', 'dyld_info', '-validate_only', '-imports', '-linked_dylibs', str(executable)])
    signature = run('signature', ['codesign', '-d', '--verbose=4', str(executable)]).stderr
    code_hash = re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode()
    inputs = [test, builder, Path(__file__).resolve(),
        project / 'vz/host/modern_typed_allocator_compat.c',
        project / 'vz/host/modern_typed_allocator.h',
        project / 'vendor/libmalloc-typed-backport/upstream/SDK27.1-_malloc.h',
        project / 'vendor/libmalloc-typed-backport/LICENSE.txt']
    source_freeze = []
    for source in inputs:
        relative = source.relative_to(project)
        frozen = output / 'source' / relative
        frozen.parent.mkdir(parents=True, exist_ok=True)
        frozen.write_bytes(source.read_bytes())
        source_freeze.append({'path': str(frozen), 'sha256': hashlib.sha256(frozen.read_bytes()).hexdigest(),
                              'bytes': frozen.stat().st_size})
    files = [dict(path=str(executable), name=executable.name, bytes=executable.stat().st_size,
        sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), cdhash=code_hash,
        entitlements=rights, code=True),
        dict(path=provider['path'], name='VM27DiskAllocatorProvider.dylib', bytes=provider['bytes'],
             sha256=provider['sha256'], cdhash=provider['cdhash'], entitlements={}, code=True)]
    (output / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    manifest = dict(files=files, providerUUID=provider['uuid'], sourceFreeze=source_freeze,
        runtimeEntryIdentitiesRequired=4, maxConcurrentWorkers=4, iterations=256,
        individualAllocationMaximum=49152, VMCalls=0, diskCalls=0, GPUCalls=0,
        genuine27DI2Loaded=False, productionModified=False, full27Backend=False, iOSExecuted=False)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'files': files, 'providerUUID': provider['uuid'], 'deployed': False}, indent=2))


if __name__ == '__main__':
    main()
