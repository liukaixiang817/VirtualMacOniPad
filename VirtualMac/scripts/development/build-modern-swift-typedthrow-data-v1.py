#!/usr/bin/env python3
"""Build a true finite typed-throw entry and compare real Mac callbacks/ARC."""
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
spec = importlib.util.spec_from_file_location('typed_build_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
HOST = p.ROOT / 'VirtualMac/vz/host'
ABI = p.NODE / 'swift-typedthrow-original-abi-readonly-v1/audit.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    for row in json.loads((ABI.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    abi = json.loads(ABI.read_bytes())
    source, header = HOST / 'modern_swift_typed_throw_compat.cpp', HOST / 'modern_swift_typed_throw_compat.h'
    fixture, swift = HOST / 'modern_swift_typed_throw_fixture.cpp', HOST / 'modern_swift_typed_throw_fixture.swift'
    inputs = [p.pin(x) for x in (Path(__file__), source, header, fixture, swift, ABI)]
    exports = out / 'exports.list'
    exports.write_text('_swift_willThrowTypedImpl\n__swift_willThrowTypedImpl\n')
    commands = []
    module_cache = out / 'swift-module-cache'
    module_cache.mkdir()
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
    roles = []
    for role, sdk, target in (('mac', 'macosx', 'arm64e-apple-macos13.0'), ('ios', 'iphoneos', 'arm64e-apple-ios16.1'),
                              ('mac-sanitized', 'macosx', 'arm64e-apple-macos13.0')):
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.decode().strip()
        provider = directory / ('TT.unsigned.inert.macho-data' if role == 'ios' else 'VM27TypedThrow.dylib')
        compile = ['xcrun', '--sdk', sdk, 'clang++', '-std=c++17', '-target', target, '-isysroot', sdkpath,
                   '-O2', '-fno-exceptions', '-fno-rtti', '-fvisibility=hidden']
        flags = ['-fsanitize=address,undefined'] if role == 'mac-sanitized' else []
        build = compile + flags + ['-dynamiclib', source, '-L' + sdkpath + '/usr/lib/swift', '-lswiftCore',
            '-Wl,-install_name,@rpath/VM27TypedThrow.dylib', '-Wl,-exported_symbols_list,' + str(exports), '-o', provider]
        if role == 'ios':
            build.append('-Wl,-no_adhoc_codesign')
        run(role + '-build', build)
        run(role + '-dyld', ['xcrun', 'dyld_info', '-validate_only', provider])
        raw = provider.read_bytes()
        definitions = {row['symbol']: row for command, at, size in p.commands(raw) if command == 0x80000033
            for off, length in [struct.unpack_from('<II', raw, at + 8)] for row in p.export_trie(raw[off:off + length])}
        assert set(definitions) == {'_swift_willThrowTypedImpl', '__swift_willThrowTypedImpl'}
        assert all(row['flags'] == 0 for row in definitions.values())
        record = dict(role=role, provider=p.pin(provider), exports=definitions, nativeIOSExecuted=False)
        if role != 'mac-sanitized':
            native = p.imports(raw)['imports']
            assert {row['name'] for row in native} == {'__swift_willThrow', '_swift_allocError', '_swift_errorRelease'}
            assert len(native) == 3
            deps = {row['ordinal']: row['path'] for row in p.dependencies(raw)}
            proofs = []
            for row in native:
                assert row['ordinal'] > 0 and not row['weak'] and row.get('addend', 0) == 0
                proof = s.primary.resolve(images, deps[row['ordinal']], row['name'])
                assert proof['status'] == 'actualDirectExport'
                proofs.append(dict(row, dependency=deps[row['ordinal']], proof=proof))
            record['currentNativeImports'] = proofs
            ir = directory / 'entry.ll'
            run(role + '-ir', compile + ['-S', '-emit-llvm', source, '-o', ir])
            irtext = ir.read_text()
            assert 'define swiftcc void @swift_willThrowTypedImpl(ptr' in irtext
            assert 'call swiftcc { ptr, ptr } @swift_allocError' in irtext and 'i1 noundef false' in irtext
            assert 'call void @swift_errorRelease' in irtext
            assert irtext.count('load atomic i64') == 2 and irtext.count('acquire, align 8') == 2
            assert 'store atomic' not in irtext
            assert irtext.count('[ "ptrauth"(i32 0, i64 0) ]') == 2
            record['entryIR'] = p.pin(ir)
        if role == 'ios':
            assert not any(command == 0x1d for command, at, size in p.commands(raw))
            record['unsignedInertData'] = True
        else:
            obj = directory / 'fixture.o'
            run(role + '-fixture-cpp', compile + flags + ['-c', fixture, '-o', obj])
            executable = out / (role + '-typedthrow-fixture')
            link = ['xcrun', '--sdk', sdk, 'swiftc', '-target', target, '-sdk', sdkpath,
                    '-module-cache-path', module_cache, '-O', swift, obj, provider,
                    '-Xlinker', '-lc++', '-Xlinker', '-rpath', '-Xlinker', '@executable_path/' + role, '-o', executable]
            if role == 'mac-sanitized':
                link += ['-sanitize=address']
                resource = run('clang-resource', ['xcrun', '--sdk', sdk, 'clang', '--print-resource-dir']).stdout.decode().strip()
                link.append(Path(resource) / 'lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib')
            run(role + '-fixture-link', link)
            result = run(role + '-actual-callback-ownership', [executable])
            summary = json.loads(result.stdout)
            expected = dict(noHookCalls=512, typedCalls=1536, legacyCalls=1536, realCopiedBoxes=1536,
                            retainedARCValueCases=256, workers=4, nativeMacCompared=True, nativeCallbacksRestored=True)
            assert summary == expected and not result.stderr
            record.update(actualOrdinaryMac=summary, fixture=p.pin(executable), ordinaryProcessCallbackSlotsTemporarilyWritten=True,
                          nativeCallbacksRestored=True, addressAndUndefinedSanitized=(role == 'mac-sanitized'))
        roles.append(record)
    assert all(p.pin(Path(row['path'])) == row for row in inputs)
    report = dict(schema='Finite true typed-throw old-host entry data build v1', inputs=inputs, roles=roles,
                  genuineOriginalABI=p.pin(ABI), ordinaryMacExecuted=True, actualBranchesComparedToNativeCore=3,
                  actualNativeCopyWitnessAndARCValidated=True, productionNativeCallbackSlotWritten=False,
                  providerPrivateTypedCallbackSlot=True, processGlobalTypedHookIdentityPreserved=False,
                  fullSwift27RuntimeEquivalent=False, fullCurrentLoadGraphProven=False,
                  originalUHLoaded=False, nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(__file__), source, header, fixture, swift, ABI, exports, out / 'commands.json', out / 'candidate.json']
    files += [Path(row['provider']['path']) for row in roles]
    files += [Path(row['entryIR']['path']) for row in roles if 'entryIR' in row]
    p.save(out / 'freeze.json', dict(files=[p.pin(path) for path in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), actualMac=roles[0]['actualOrdinaryMac'], iosStrongImports=3)))


if __name__ == '__main__':
    main()
