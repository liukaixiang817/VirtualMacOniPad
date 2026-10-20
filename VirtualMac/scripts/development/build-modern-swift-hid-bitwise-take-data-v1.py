#!/usr/bin/env python3
"""Build an inert finite HID take provider and ordinary genuine Mac comparisons."""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('take_build_route', HERE / 'prepare-modern-hid-pod-layout-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
s, p = r.s, r.p
HOST = p.ROOT / 'VirtualMac/vz/host'
ABI = p.NODE / 'universalhid-bitwise-take-original-readonly-v1/audit.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    abi = r.checked(ABI)
    assert abi['finiteCompletedPODDefaultTakeSemanticsImplementable'] and not abi['remainingFiveCVWBindingsClosed']
    source, header, fixture, swift = [HOST / ('modern_swift_hid_bitwise_take_' + suffix) for suffix in
        ('compat.cpp', 'compat.h', 'fixture.cpp', 'fixture.swift')]
    inputs = [p.pin(x) for x in (Path(__file__), source, header, fixture, swift, ABI)]
    exports = out / 'exports.list'
    exports.write_text('_swift_cvw_initWithTake\n')
    cache = out / 'swift-module-cache'
    cache.mkdir()
    commands, roles = [], []
    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(), stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out / 'commands.json', commands)
        assert result.returncode == 0, (label, result.stderr.decode())
        return result
    images = s.primary.captured_images()
    current_pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        current_pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    assert len(images) == 16
    expected = dict(nativeComparedCases=3072, genuineRetainCountChecks=8192, counterexamplesRejected=144,
                    productionWrongOwnerRejections=32, nativeNonBitwiseMetadataRejected=8,
                    realObjectsCreated=8, realObjectsDestroyed=8, productionHIDEntryExecuted=False)
    for role, sdk, target in [('mac', 'macosx', 'arm64e-apple-macos13.0'), ('ios', 'iphoneos', 'arm64e-apple-ios16.1'),
                              ('mac-sanitized', 'macosx', 'arm64e-apple-macos13.0')]:
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.decode().strip()
        provider = directory / ('BT.unsigned.inert.macho-data' if role == 'ios' else 'VM27HIDBitwiseTake.dylib')
        compile = ['xcrun', '--sdk', sdk, 'clang++', '-std=c++17', '-target', target, '-isysroot', sdkpath,
                   '-O2', '-fno-exceptions', '-fno-rtti', '-fvisibility=hidden']
        sanitizers = ['-fsanitize=address,undefined'] if role == 'mac-sanitized' else []
        argv = compile + sanitizers + ['-dynamiclib', source, '-Wl,-install_name,@rpath/VM27HIDBitwiseTake.dylib',
                                      '-Wl,-exported_symbols_list,' + str(exports), '-o', provider]
        if role == 'ios': argv.append('-Wl,-no_adhoc_codesign')
        run(role + '-build', argv)
        run(role + '-dyld', ['xcrun', 'dyld_info', '-validate_only', provider])
        raw = provider.read_bytes()
        definitions = {x['symbol']: x for cmd, at, length in p.commands(raw) if cmd == 0x80000033
            for off, size in [struct.unpack_from('<II', raw, at + 8)] for x in p.export_trie(raw[off:off + size])}
        assert set(definitions) == {'_swift_cvw_initWithTake'}
        record = dict(role=role, provider=p.pin(provider), exports=definitions)
        if role == 'ios':
            assert not any(cmd == 0x1d for cmd, at, size in p.commands(raw))
            deps = {x['ordinal']: x['path'] for x in p.dependencies(raw)}
            imports = []
            for x in p.imports(raw)['imports']:
                assert x['ordinal'] > 0 and not x['weak'] and not x.get('addend', 0)
                proof = s.primary.resolve(images, deps[x['ordinal']], x['name'])
                imports.append(dict(x, dependency=deps[x['ordinal']], proof=proof))
            ir = directory / 'entry.ll'
            run(role + '-ir', compile + ['-S', '-emit-llvm', source, '-o', ir])
            text = ir.read_text()
            entry = re.search(r'^define ([^\n]*)@swift_cvw_initWithTake\(([^\n]*)\)', text, re.M)
            assert entry and 'ptr' in entry[1] and 'swiftcc' not in entry[1] and entry[2].count('ptr noundef') == 3
            assert 'ProductionMetadata' in text and 'call void @llvm.trap()' in text
            assert 'llvm.memcpy' in text and 'i64 11839' in text and 'i16 noundef zeroext -29851' in text
            record.update(unsignedInertData=True, nativeIOSExecuted=False, entryIR=p.pin(ir),
                currentExactNativeImports=imports, currentAllNativeDefinitionsProven=all(x['proof']['status'] == 'actualDirectExport' for x in imports))
        else:
            obj = directory / 'fixture.o'
            run(role + '-fixture-cpp', compile + sanitizers + ['-c', fixture, '-o', obj])
            executable = out / (role + '-bitwise-take-fixture')
            argv = ['xcrun', '--sdk', sdk, 'swiftc', '-target', target, '-sdk', sdkpath, '-module-cache-path', cache,
                    '-O', swift, obj, '-Xlinker', '-lc++', '-o', executable]
            if role == 'mac-sanitized':
                argv.append('-sanitize=address')
                resource = run('clang-resource', ['xcrun', '--sdk', sdk, 'clang', '--print-resource-dir']).stdout.decode().strip()
                argv.append(Path(resource) / 'lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib')
            run(role + '-fixture-link', argv)
            result = run(role + '-real-runtime-compare', [executable])
            actual = json.loads(result.stdout)
            assert {k: actual[k] for k in expected} == expected and actual['checks'] >= 26000
            assert not result.stderr
            record.update(actualOrdinaryMac=actual, fixture=p.pin(executable), addressAndUndefinedSanitized=role == 'mac-sanitized')
        roles.append(record)
    assert all(p.pin(Path(x['path'])) == x for x in inputs)
    report = dict(schema='Finite genuine original HID completed POD initWithTake provider data build v1', inputs=inputs,
        originalABI=p.pin(ABI), roles=roles, ordinaryMacGenuineDefaultTakeCompared=True,
        ordinaryMacRealARCTransfersAndDestroysProven=True, sourceOwnershipTransferredWithoutRetainOrSourceDestroy=True,
        productionIdentityIsExactOriginalCompletedHIDMetadata=True, productionHIDIdentityGatePassed=False,
        actualCurrentIOSUUIDAndUInt64TypeLayoutsRead=True, originalPODInitializerMustCompleteBeforeTakeUse=True,
        productionOriginalHIDEntryExecuted=False, generalNonBitwiseInterpreterProvided=False,
        remainingFiveCVWBindingsClosed=False, processGlobalRuntimeOverrideHookIdentityPreserved=False,
        currentCompleteProviderDependencyGraphValidated=False, candidateReadyForNativeLoading=False,
        originalHIDLoaded=False, originalVZLoaded=False, nativeIOSExecuted=False, deviceOperations=0, codeSigned=False, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(x['path']) for x in inputs] + [exports, out / 'commands.json', out / 'candidate.json']
    files += [directory / (command['label'] + '.' + suffix) for directory in [out] for command in commands for suffix in ('stdout', 'stderr')]
    files += [path for path in out.rglob('*') if path.is_file() and 'swift-module-cache' not in path.parts and path.name not in ('candidate.json', 'commands.json')]
    unique = {row['path']: row for row in current_pins + [p.pin(x) for x in files]}
    p.save(out / 'freeze.json', dict(files=list(unique.values()), deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), mac=[x['actualOrdinaryMac'] for x in roles if 'actualOrdinaryMac' in x],
                         iosImports=next(x['currentExactNativeImports'] for x in roles if x['role'] == 'ios'))))


if __name__ == '__main__':
    main()
