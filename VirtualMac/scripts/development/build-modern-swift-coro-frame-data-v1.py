#!/usr/bin/env python3
"""Build a finite genuine old-host coroutine entry and ordinary Mac fixture."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('coro_build_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
HOST = p.ROOT / 'VirtualMac/vz/host'
ABI = p.NODE / 'swift-coro-allocation-original-abi-v4/audit.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    for row in json.loads((ABI.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    abi = json.loads(ABI.read_bytes())
    assert abi['originalCallerCounts'] == dict(UniversalHID=52, UniversalHIDKit=6)
    images = s.primary.captured_images()
    source = HOST / 'modern_swift_coro_frame_compat.c'
    fixture = HOST / 'modern_swift_coro_frame_fixture.c'
    exports = out / 'exports.list'
    exports.write_text('_swift_coroFrameAlloc\n')
    inputs = [p.pin(x) for x in (Path(__file__), source, fixture, ABI)]
    commands = []
    def run(label, argv, expected=True):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(), stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out / 'commands.json', commands)
        if expected:
            assert result.returncode == 0, (label, result.stderr.decode())
        return result
    roles = []
    for role, sdk, target in (('mac', 'macosx', 'arm64e-apple-macos13.0'), ('ios', 'iphoneos', 'arm64e-apple-ios16.1')):
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.decode().strip()
        provider = directory / ('VM27CoroFrames.dylib' if role == 'mac' else 'CR.unsigned.inert.macho-data')
        argv = ['xcrun', '--sdk', sdk, 'clang', '-target', target, '-isysroot', sdkpath,
            '-O2', '-fvisibility=hidden', '-dynamiclib', source, '-L' + sdkpath + '/usr/lib/swift', '-lswiftCore',
            '-Wl,-install_name,@rpath/VM27CoroFrames.dylib', '-Wl,-exported_symbols_list,' + str(exports), '-o', provider]
        if role == 'ios':
            argv.append('-Wl,-no_adhoc_codesign')
        run(role + '-build', argv)
        run(role + '-dyld', ['xcrun', 'dyld_info', '-validate_only', provider])
        raw = provider.read_bytes()
        definitions = {row['symbol']: row for command, at, size in p.commands(raw) if command == 0x80000033
            for off, length in [struct.unpack_from('<II', raw, at + 8)] for row in p.export_trie(raw[off:off + length])}
        assert set(definitions) == {'_swift_coroFrameAlloc'} and definitions['_swift_coroFrameAlloc']['flags'] == 0
        imports = p.imports(raw)['imports']
        assert len(imports) == 1 and imports[0]['name'] == '_swift_slowAlloc'
        assert imports[0]['ordinal'] > 0 and not imports[0]['weak'] and imports[0].get('addend', 0) == 0
        deps = {x['ordinal']: x['path'] for x in p.dependencies(raw)}
        proof = s.primary.resolve(images, deps[imports[0]['ordinal']], imports[0]['name'])
        assert proof['status'] == 'actualDirectExport'
        record = dict(role=role, provider=p.pin(provider), exports=definitions,
            currentNativeImports=[dict(imports[0], dependency=deps[imports[0]['ordinal']], proof=proof)],
            genuineNativeSingleAllocation=True, typedAllocatorTelemetryPreserved=False, nativeIOSExecuted=False)
        if role == 'ios':
            assert not any(c == 0x1d for c, at, size in p.commands(raw))
            record['unsignedInertData'] = True
        else:
            executable = out / 'coro-frame-mac-fixture'
            run('mac-fixture-build', ['xcrun', '--sdk', sdk, 'clang', '-target', target, '-isysroot', sdkpath,
                '-O2', fixture, provider, '-Wl,-rpath,@executable_path/mac', '-o', executable])
            positive = run('mac-positive', [executable])
            summary = json.loads(positive.stdout)
            assert summary == dict(allocations=6048, freedFrames=6048, checks=36288, failures=0, workers=4)
            failure = run('mac-allocation-failure', [executable, '--allocation-failure'], expected=False)
            assert failure.returncode == -6 and b'failed to allocate' in failure.stderr and not failure.stdout
            record.update(actualOrdinaryMac=summary, fixture=p.pin(executable),
                genuineImpossibleAllocationRejected=dict(exit=failure.returncode, stderrSHA256=hashlib.sha256(failure.stderr).hexdigest()))
        roles.append(record)
    assert all(p.pin(Path(row['path'])) == row for row in inputs)
    report = dict(schema='Finite genuine old-host coroutine allocation entry build v1', inputs=inputs, roles=roles,
        originalCallerABI=abi['ABI'], sourceABI=p.pin(ABI), ordinaryMacExecuted=True,
        zeroSizeNormalizedByNativeRuntime=True, fatalOOMDelegatedToNativeRuntime=True,
        typedAllocatorTelemetryPreserved=False, allCoroutineLifecycleValidated=False,
        fullSwift27RuntimeEquivalent=False, fullCurrentLoadGraphProven=False, originalUHLoaded=False,
        nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(__file__), source, fixture, ABI, exports, out / 'commands.json', out / 'candidate.json']
    files += [Path(row['provider']['path']) for row in roles]
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), actualMac=roles[0]['actualOrdinaryMac'], iosStrongImports=1)))


if __name__ == '__main__':
    main()
