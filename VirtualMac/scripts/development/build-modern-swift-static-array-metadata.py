#!/usr/bin/env python3
"""Build a genuine Swift subclass-metadata factory and CPU-only probe.

This does not provide a StaticArray CN data binding or load DIKit. It never
installs, trusts or executes anything on a device. Output must be new.
"""
import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import struct
import subprocess


def add_private_overrides(ir):
    """Add two exact compiler-schema override records, not forged metadata.

    Parent descriptor/Tq offsets and PAC discriminators are independently
    confirmed in real old iPad Swift Core and genuine27 Swift Core. The genuine
    runtime allocates/completes metadata and signs all method pointers.
    """
    symbol = '$s15VM27StaticArray0abC7StorageCMn'
    old_type = '<{ ' + ', '.join(['i32']*17 + ['%swift.method_descriptor', 'i32'] +
                                ['%swift.method_override_descriptor']*3 + ['i32']) + ' }>'
    new_type = '<{ ' + ', '.join(['i32']*17 + ['%swift.method_descriptor', 'i32'] +
                                ['%swift.method_override_descriptor']*5 + ['i32']) + ' }>'
    assert old_type in ir and new_type not in ir
    ir = ir.replace(old_type, new_type)
    assert ir.count('i32 3, %swift.method_override_descriptor { i32 add') == 1
    ir = ir.replace('i32 3, %swift.method_override_descriptor { i32 add',
                    'i32 5, %swift.method_override_descriptor { i32 add', 1)
    assert ir.count('ptr @"' + symbol + '", i32 0, i32 22)') == 1
    ir = ir.replace('ptr @"' + symbol + '", i32 0, i32 22)',
                    'ptr @"' + symbol + '", i32 0, i32 24)')

    def relative(source, index, subfield):
        return ('i32 trunc (i64 sub (i64 ptrtoint (ptr ' + source + ' to i64), '
                'i64 ptrtoint (ptr getelementptr inbounds (' + new_type + ', ptr @"' +
                symbol + '", i32 0, i32 ' + str(index) + ', i32 ' + str(subfield) +
                ') to i64)) to i32)')

    extra = []
    globals = []
    for index, offset, implementation in [(22, 60, 'VM27StaticArrayVerbatimNil'),
                                         (23, 68, 'VM27StaticArrayForbiddenBridge')]:
        parent = relative('@"got.$ss28__ContiguousArrayStorageBaseCMn"', index, 0)
        method = relative('@"got.VM27PrivateBridge' + str(offset) + '"', index, 1)
        body = relative('@' + implementation, index, 2)
        extra.append('%swift.method_override_descriptor { i32 add (' + parent +
                     ', i32 1), i32 add (' + method + ', i32 1), ' + body + ' }')
        globals += [
            '@"got.VM27PrivateBridge' + str(offset) + '" = private unnamed_addr constant ptr @"VM27PrivateBridge' + str(offset) + '.ptrauth"',
            '@"VM27PrivateBridge' + str(offset) + '.ptrauth" = private constant { ptr, i32, i64, i64 } { ptr getelementptr inbounds (i8, ptr @"$ss28__ContiguousArrayStorageBaseCMn", i64 ' + str(offset) + '), i32 2, i64 ptrtoint (ptr @"got.VM27PrivateBridge' + str(offset) + '" to i64), i64 26458 }, section "llvm.ptrauth", align 8',
        ]
    lines = [line for line in ir.splitlines() if line.startswith('@"' + symbol + '" =')]
    assert len(lines) == 1
    line = lines[0]
    marker = ' }, i32 trunc (i64 sub (i64 ptrtoint (ptr getelementptr inbounds (i8, ptr @"$s15VM27StaticArray0abC7StorageCMt"'
    assert line.count(marker) == 1
    replacement = line.replace(marker, ' }, ' + ', '.join(extra) + ', ' + marker[4:])
    ir = ir.replace(line, replacement)
    first_global = ir.index('\n@')
    ir = ir[:first_global] + '\n' + '\n'.join(globals) + ir[first_global:]
    return ir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[3]
    host = root / 'VirtualMac/vz/host'
    source = host / 'modern_swift_static_array_metadata_compat.swift'
    probe = host / 'modern_swift_static_array_metadata_native_probe.cpp'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    logs = []
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    receipts = [root / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/static-array-base-descriptor-native-v1/native.stdout',
                root / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/static-array-base-descriptor-probe-build-v1/mac-native.stdout']
    inputs = [{'path': str(p), 'sha256': digest(p)} for p in (source, probe, pathlib.Path(__file__), *receipts)]
    # Exact original flags and two private parent slots, checked before building.
    for receipt in receipts:
        evidence = receipt.read_text()
        assert 'DESCWORD $ss28__ContiguousArrayStorageBaseCN +60 raw=b6080010' in evidence
        assert 'DESCWORD $ss28__ContiguousArrayStorageBaseCN +68 raw=4a020010' in evidence
    (out / 'exports.list').write_text('_VM27StaticArrayMetadataOracle\n_VM27StaticArrayVerbatimNil\n_VM27StaticArrayForbiddenBridge\n')

    def run(label, argv, timeout=60):
        argv = list(map(str, argv))
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        logs.append({'label': label, 'argv': argv, 'exit': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr})
        (out / 'commands.json').write_text(json.dumps(logs, indent=2) + '\n')
        assert r.returncode == 0, (label, r.stderr)
        return r

    files = []
    for role, target, sdk in [('mac', 'arm64e-apple-macos13.0', 'macosx'),
                              ('ios', 'arm64e-apple-ios16.1', 'iphoneos')]:
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.strip()
        original_ir, edited_ir = out / (role + '.original.ll'), out / (role + '.ll')
        run(role + '-ir', ['xcrun', '--sdk', sdk, 'swiftc', '-parse-as-library', '-target', target,
            '-sdk', sdkpath, '-Xfrontend', '-disable-access-control',
            '-Xfrontend', '-disable-layout-string-value-witnesses',
            '-Xfrontend', '-disable-layout-string-value-witnesses-instantiation',
            '-module-name', 'VM27StaticArray', '-module-cache-path', out / (role + '-cache'),
            '-O', source, '-emit-ir', '-o', original_ir])
        original = original_ir.read_text()
        edited = add_private_overrides(original)
        definitions = lambda text: [line for line in text.splitlines() if line.startswith('define ')]
        assert definitions(original) == definitions(edited)
        assert 'declare swiftcc %swift.metadata_response @swift_initClassMetadata2(ptr, i64, i64, ptr, ptr)' in edited
        assert 'define swiftcc void @VM27StaticArrayVerbatimNil(ptr noalias sret(%swift.opaque)' in edited
        edited_ir.write_text(edited)
        run(role + '-object', ['xcrun', '--sdk', sdk, 'clang', '-target', target,
            '-isysroot', sdkpath, '-x', 'ir', '-c', edited_ir, '-o', out / (role + '.o')])
        library = directory / 'VM27StaticArrayMetadata.dylib'
        run(role + '-library', ['xcrun', '--sdk', sdk, 'swiftc', '-target', target, '-sdk', sdkpath,
            out / (role + '.o'), '-emit-library', '-Xlinker', '-exported_symbols_list',
            '-Xlinker', out / 'exports.list', '-Xlinker', '-install_name', '-Xlinker',
            '@rpath/VM27StaticArrayMetadata.dylib', '-o', library])
        run(role + '-sign-library', ['codesign', '--force', '--sign', '-', '--timestamp=none', library])
        run(role + '-strict-library', ['codesign', '--verify', '--strict', library])
        run(role + '-dyld-library', ['xcrun', 'dyld_info', '-validate_only', '-imports', '-inits', library])
        b = library.read_bytes()
        at = 32
        uuids = []
        for unused in range(struct.unpack_from('<I', b, 16)[0]):
            c, size = struct.unpack_from('<II', b, at)
            assert size >= 8 and size % 8 == 0
            if c == 27:
                uuids.append(b[at+8:at+24].hex())
            at += size
        assert len(uuids) == 1
        binary = out / ('static-array-metadata-' + role)
        run(role + '-probe', ['xcrun', '--sdk', sdk, 'clang++', '-target', target, '-isysroot', sdkpath,
            '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
            '-DVM27_STATIC_LIBRARY_UUID="' + uuids[0] + '"', probe, '-lobjc', '-o', binary])
        if role == 'ios':
            rights = {'platform-application': True, 'com.apple.private.security.no-container': True,
                'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
            ent = out / 'Probe.entitlements'
            ent.write_bytes(plistlib.dumps(rights))
            run(role + '-sign-probe', ['codesign', '--force', '--sign', '-', '--timestamp=none', '--entitlements', ent, binary])
            signed = run(role + '-probe-rights', ['codesign', '-d', '--entitlements', ':-', binary])
            assert plistlib.loads(signed.stdout.encode()) == rights
        run(role + '-strict-probe', ['codesign', '--verify', '--strict', binary])
        run(role + '-dyld-probe', ['xcrun', 'dyld_info', '-validate_only', binary])
        for p in (library, binary):
            s = run(role + '-' + p.name + '-signature', ['codesign', '-dvvv', p]).stderr
            files.append({'path': str(p), 'bytes': p.stat().st_size, 'sha256': digest(p),
                'CDHash': re.search(r'CDHash=([0-9a-f]{40})', s)[1], 'uuid': uuids[0] if p == library else None})
    result = json.loads(run('mac-native', [out / 'static-array-metadata-mac', out / 'mac/VM27StaticArrayMetadata.dylib'], 15).stdout.splitlines()[-1])
    assert result['failures'] == 0 and result['externalFactoryCalls'] == 101 and result['classAddressPoint'] == 24
    assert all(digest(pathlib.Path(r['path'])) == r['sha256'] for r in inputs)
    manifest = {'files': files, 'inputs': inputs, 'nativeMac': result, 'actualIOSRun': False,
        'completedMetadataIsRuntimeAllocatedRealSwiftSubclass': True, 'CNDataExportProvided': False,
        'DIKitStaticIsaBindingsChanged': False, 'privateOverrideRecords': 2,
        'parentTqOffsets': [60, 68], 'parentTqFlags': ['0xb6080010', '0x4a020010'],
        'descriptorGOTAuthentication': 'DA address-diverse 0x675a for MethodDescriptor; real runtime owns vtable PAC',
        'classInitialization': 'real swift_getSingletonMetadata and swift_initClassMetadata2; no metadata memcpy',
        'scope': 'class metadata initialization only; no static objects, virtual method calls or NSArray bridging',
        'completeStaticArrayImplementation': False, 'completeSwift27Runtime': False,
        'completeDIKitClosure': False, 'fullVZ27Closure': False, 'productionModified': False}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'files': files, 'nativeMac': result, 'actualIOSRun': False}, indent=2))


if __name__ == '__main__':
    main()
