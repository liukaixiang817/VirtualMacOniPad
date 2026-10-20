#!/usr/bin/env python3
"""Build a finite HID POD initializer; compare its core to genuine Mac runtime."""
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
spec = importlib.util.spec_from_file_location('pod_build_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
HOST = p.ROOT / 'VirtualMac/vz/host'
ABI = p.NODE / 'universalhid-pod-layout-original-abi-readonly-v6/audit.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    for row in json.loads((ABI.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    names = ['modern_swift_hid_pod_layout_compat.cpp', 'modern_swift_hid_pod_layout_compat.h',
             'modern_swift_hid_pod_layout_fixture.cpp', 'modern_swift_hid_pod_layout_fixture.swift']
    source, header, fixture, swift = [HOST / name for name in names]
    inputs = [p.pin(x) for x in [Path(__file__), source, header, fixture, swift, ABI]]
    exports = out / 'exports.list'
    exports.write_text('_swift_cvw_initStructMetadataWithLayoutString\n')
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
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        current_pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        current_pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v2/headers.json'))
    for role, sdk, target in [('mac', 'macosx', 'arm64e-apple-macos13.0'),
                              ('ios', 'iphoneos', 'arm64e-apple-ios16.1'),
                              ('mac-sanitized', 'macosx', 'arm64e-apple-macos13.0')]:
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.decode().strip()
        provider = directory / ('PL.unsigned.inert.macho-data' if role == 'ios' else 'VM27HIDPODLayout.dylib')
        compile = ['xcrun', '--sdk', sdk, 'clang++', '-std=c++17', '-target', target, '-isysroot', sdkpath,
                   '-O2', '-fno-exceptions', '-fno-rtti', '-fvisibility=hidden']
        sanitizers = ['-fsanitize=address,undefined'] if role == 'mac-sanitized' else []
        link = compile + sanitizers + ['-dynamiclib', source, '-framework', 'Foundation',
            '-L' + sdkpath + '/usr/lib/swift', '-lswiftCore', '-Wl,-install_name,@rpath/VM27HIDPODLayout.dylib',
            '-Wl,-exported_symbols_list,' + str(exports), '-o', provider]
        if role == 'ios':
            link.append('-Wl,-no_adhoc_codesign')
        run(role + '-build', link)
        run(role + '-dyld', ['xcrun', 'dyld_info', '-validate_only', provider])
        body = provider.read_bytes()
        definitions = {x['symbol']: x for cmd, at, size in p.commands(body) if cmd == 0x80000033
            for off, length in [struct.unpack_from('<II', body, at + 8)] for x in p.export_trie(body[off:off + length])}
        assert set(definitions) == {'_swift_cvw_initStructMetadataWithLayoutString'}
        record = dict(role=role, provider=p.pin(provider), exports=definitions)
        if role != 'mac-sanitized':
            deps = {x['ordinal']: x['path'] for x in p.dependencies(body)}
            actual_imports = []
            for x in p.imports(body)['imports']:
                assert x['ordinal'] > 0 and not x['weak'] and not x.get('addend', 0)
                proof = s.primary.resolve(images, deps[x['ordinal']], x['name'])
                actual_imports.append(dict(x, dependency=deps[x['ordinal']], proof=proof))
            assert {x['name'] for x in actual_imports} >= {'_swift_initStructMetadata', '_$s10Foundation4UUIDVN', '_$ss6UInt64VN'}
            record.update(currentExactNativeImports=actual_imports,
                          currentAllNativeDefinitionsProven=all(x['proof']['status'] == 'actualDirectExport' for x in actual_imports))
            ir = directory / 'entry.ll'
            run(role + '-ir', compile + ['-S', '-emit-llvm', source, '-o', ir])
            text = ir.read_text()
            assert 'call void @swift_initStructMetadata(ptr' in text and 'i64 noundef 256, i64 noundef 2' in text
            assert 'i32 2' in text and 'llvm.ptrauth.sign' in text
            record['entryIR'] = p.pin(ir)
        if role == 'ios':
            assert not any(cmd == 0x1d for cmd, at, size in p.commands(body))
            record.update(unsignedInertData=True, nativeIOSExecuted=False)
        else:
            obj = directory / 'fixture.o'
            run(role + '-fixture-cpp', compile + sanitizers + ['-c', fixture, '-o', obj])
            executable = out / (role + '-pod-layout-fixture')
            argv = ['xcrun', '--sdk', sdk, 'swiftc', '-target', target, '-sdk', sdkpath,
                '-module-cache-path', cache, '-O', swift, obj, '-Xlinker', '-lc++', '-o', executable]
            if role == 'mac-sanitized':
                argv.append('-sanitize=address')
                resource = run('clang-resource', ['xcrun', '--sdk', sdk, 'clang', '--print-resource-dir']).stdout.decode().strip()
                argv.append(Path(resource) / 'lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib')
            run(role + '-fixture-link', argv)
            result = run(role + '-real-runtime-compare', [executable])
            actual = json.loads(result.stdout)
            assert actual == dict(nativeComparedCases=1024, checks=21586, fieldCounterexamplesRejected=48,
                productionWrongOwnerRejections=1024, productionHIDEntryExecuted=False, nativeCallbacksExecuted=True)
            assert not result.stderr
            record.update(actualOrdinaryMac=actual, fixture=p.pin(executable), addressAndUndefinedSanitized=role == 'mac-sanitized')
        roles.append(record)
    assert all(p.pin(Path(x['path'])) == x for x in inputs)
    report = dict(schema='Finite genuine HID POD initializer component data build v1', inputs=inputs,
        originalABI=p.pin(ABI), roles=roles, ordinaryMacNativeCoreCompared=True,
        productionIdentityIsExactOriginalHIDMetadata=True, productionHIDIdentityGatePassed=False,
        actualCurrentIOSUUIDAndUInt64TypeLayoutsRead=False,
        privateImmutablePODProgramIsMetadataABIAdaptation=True, fullOriginal27RuntimeOverrideHookIdentity=False,
        originalResolvedLayoutStringPointerTagAndDAAuthenticationPreserved=True,
        documentedAddressableForDependenciesFlagPropagated=True,
        actualCurrentOldNativeCommonWitness988BRead=True,
        originalDIKOrVZIdentityChecksChanged=False, generalCVWInterpreterProvided=False,
        originalHIDLoaded=False, originalVZLoaded=False, nativeIOSExecuted=False, deviceOperations=0,
        candidateReadyForNativeLoading=False, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(x['path']) for x in inputs] + [exports, out / 'commands.json', out / 'candidate.json']
    files += [Path(x['provider']['path']) for x in roles]
    files += [Path(x['fixture']['path']) for x in roles if 'fixture' in x]
    files += [Path(x['entryIR']['path']) for x in roles if 'entryIR' in x]
    files += [out / (x['label'] + '.' + suffix) for x in commands for suffix in ('stdout', 'stderr')]
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files] + current_pins,
        deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), actualMac=roles[0]['actualOrdinaryMac'],
        iosStrongImports=len(roles[1]['currentExactNativeImports']))))


if __name__ == '__main__':
    main()
