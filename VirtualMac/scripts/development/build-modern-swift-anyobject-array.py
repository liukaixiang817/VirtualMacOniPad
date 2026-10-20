#!/usr/bin/env python3
"""Build and locally test eight exact private Swift AnyObject entry contracts.

Never installs, trusts or executes anything on a device. Output must be new.
"""
import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import subprocess
import struct

NAMES = [
    '$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5',
    '$sSa16_createNewBuffer14bufferIsUnique15minimumCapacity13growForAppendySb_SiSbtFyXl_Ts5',
    '$sSa37_appendElementAssumeUniqueAndCapacity_03newB0ySi_xntFyXl_Ts5',
    '$ss12_ArrayBufferV19_getElementSlowPathyyXlSiFyXl_Ts5',
    '$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5',
    '$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5',
    '$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5',
    '$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[3]
    host = root / 'VirtualMac/vz/host'
    source = host / 'modern_swift_anyobject_array_compat.swift'
    fixture = host / 'modern_swift_anyobject_array_native_fixture.swift'
    identity_source = host / 'modern_swift_anyobject_array_fixture_identity.cpp'
    identity_header = host / 'modern_swift_anyobject_array_fixture_identity.h'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    logs = []
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    inputs = [{'path': str(p), 'sha256': digest(p)} for p in
              (source, fixture, identity_source, identity_header, pathlib.Path(__file__))]
    (out / 'exports.list').write_text(''.join('_' + n + '\n' for n in NAMES))

    def run(label, argv, timeout=60, success=True):
        argv = list(map(str, argv))
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        logs.append({'label': label, 'argv': argv, 'exit': r.returncode,
                     'stdout': r.stdout, 'stderr': r.stderr})
        (out / 'commands.json').write_text(json.dumps(logs, indent=2) + '\n')
        if success:
            assert r.returncode == 0, (label, r.stderr)
        return r

    roles = [('mac', 'arm64e-apple-macos13.0', 'macosx'),
             ('ios', 'arm64e-apple-ios16.1', 'iphoneos')]
    for role, target, sdk in roles:
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.strip()
        interface = pathlib.Path(sdkpath) / ('usr/lib/swift/Swift.swiftmodule/' +
            ('arm64e-apple-macos.swiftinterface' if role == 'mac' else 'arm64e-apple-ios.swiftinterface'))
        if not interface.exists() and role == 'mac':
            interface = pathlib.Path(sdkpath) / 'usr/lib/swift/Swift.swiftmodule/arm64e-apple-macosx.swiftinterface'
        assert interface.is_file()
        inputs.append({'path': str(interface), 'sha256': digest(interface)})
        base = ['xcrun', '--sdk', sdk, 'swiftc', '-parse-as-library', '-target', target,
                '-sdk', sdkpath, '-Xfrontend', '-disable-access-control',
                '-Xfrontend', '-disable-layout-string-value-witnesses',
                '-Xfrontend', '-disable-layout-string-value-witnesses-instantiation',
                '-module-name', 'VM27AnyObjectArray', '-module-cache-path', out / (role + '-cache'),
                '-O', source]
        original_ir = out / (role + '.original.ll')
        edited_ir = out / (role + '.ll')
        run(role + '-ir', base + ['-emit-ir', '-o', original_ir])
        run(role + '-module', base + ['-emit-module', '-emit-module-path', directory / 'VM27AnyObjectArray.swiftmodule'])
        ir = original_ir.read_text()
        # _ArrayBuffer is internal to Swift, so its correctly compiled member
        # has hidden linkage. Promote only that one definition's visibility;
        # arguments, SwiftCC, ownership, body and helpers remain exact.
        old = 'define hidden swiftcc ptr @"' + NAMES[3] + '"'
        assert ir.count(old) == 1
        ir = ir.replace(old, old.replace('hidden ', ''))
        assert ir != original_ir.read_text() and 'tailrecurse' not in ir
        for name in NAMES:
            definition = re.search(r'^define .*@"' + re.escape(name) + r'"\([^\n]+', ir, re.M)
            assert definition and 'swiftcc ' in definition[0]
        assert 'define swiftcc ptr @"' + NAMES[3] + '"(i64 ' in ir
        assert 'ret void' in ir[ir.index('@"' + NAMES[5] + '"', ir.index('; Function Attrs:')):]
        edited_ir.write_text(ir)
        run(role + '-object', ['xcrun', '--sdk', sdk, 'clang', '-target', target,
            '-isysroot', sdkpath, '-x', 'ir', '-c', edited_ir, '-o', out / (role + '.o')])
        library = directory / 'VM27AnyObjectArray.dylib'
        run(role + '-library', ['xcrun', '--sdk', sdk, 'swiftc', '-target', target,
            '-sdk', sdkpath, out / (role + '.o'), '-emit-library', '-Xlinker', '-exported_symbols_list',
            '-Xlinker', out / 'exports.list', '-Xlinker', '-install_name', '-Xlinker',
            '@rpath/VM27AnyObjectArray.dylib', '-o', library])
        run(role + '-sign-library', ['codesign', '--force', '--sign', '-', '--timestamp=none', library])
        run(role + '-strict-library', ['codesign', '--verify', '--strict', library])
        run(role + '-dyld-library', ['xcrun', 'dyld_info', '-validate_only', library])
        exports = run(role + '-exports', ['xcrun', 'dyld_info', '-exports', library]).stdout
        assert set(re.findall(r'\b(_\$s\S+)\s*$', exports, re.M)) == {'_' + n for n in NAMES}
        imports = run(role + '-imports', ['xcrun', 'dyld_info', '-imports', '-linked_dylibs', library]).stdout
        assert all(n not in imports for n in NAMES)
        assert all(bad not in imports for bad in ['_swift_cvw_', 'Virtualization', 'Hypervisor', 'VM27SwiftLookup', 'flat-namespace'])
        data = library.read_bytes()
        at = 32
        uuids = []
        for unused in range(struct.unpack_from('<I', data, 16)[0]):
            command, length = struct.unpack_from('<II', data, at)
            assert length >= 8 and length % 8 == 0
            if command == 27:
                uuids.append(data[at+8:at+24].hex())
            at += length
        assert len(uuids) == 1
        identity_object = out / (role + '-identity.o')
        run(role + '-identity', ['xcrun', '--sdk', sdk, 'clang++', '-target', target,
            '-isysroot', sdkpath, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
            '-Wno-deprecated-declarations', '-fno-rtti', '-fno-exceptions',
            '-DVM27_ARRAY_LIBRARY_UUID="' + uuids[0] + '"',
            '-DVM27_ARRAY_LIBRARY_SUBDIR="' + role + '"',
            '-c', identity_source, '-o', identity_object])
        executable = out / ('array-fixture-' + role)
        fixture_base = ['xcrun', '--sdk', sdk, 'swiftc', '-target', target, '-sdk', sdkpath,
            '-Xfrontend', '-disable-access-control', '-Xfrontend', '-disable-layout-string-value-witnesses',
            '-Xfrontend', '-disable-layout-string-value-witnesses-instantiation',
            '-module-cache-path', out / ('fixture-' + role + '-cache'), '-O', '-I', directory,
            '-import-objc-header', identity_header, identity_object,
            library, '-Xlinker', '-rpath', '-Xlinker', '@executable_path/' + role,
            fixture, '-o', executable]
        run(role + '-fixture', fixture_base)
        if role == 'ios':
            entitlements = {'platform-application': True, 'com.apple.private.security.no-container': True,
                'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
            ent = out / 'Probe.entitlements'
            ent.write_bytes(plistlib.dumps(entitlements))
            run(role + '-sign-fixture', ['codesign', '--force', '--sign', '-', '--timestamp=none',
                '--entitlements', ent, executable])
        run(role + '-strict-fixture', ['codesign', '--verify', '--strict', executable])
        if role == 'ios':
            signed_ent = run('ios-fixture-entitlements', ['codesign', '-d', '--entitlements', ':-', executable])
            assert plistlib.loads(signed_ent.stdout.encode()) == entitlements
        fixture_imports = run(role + '-fixture-imports', ['xcrun', 'dyld_info', '-imports', executable]).stdout
        for name in NAMES:
            assert '_' + name + '  (from VM27AnyObjectArray)' in fixture_imports
    native = run('mac-native', [out / 'array-fixture-mac'], timeout=15)
    native_result = json.loads(native.stdout.strip().splitlines()[-1])
    native_identity = json.loads(native.stdout.strip().splitlines()[-2])
    assert native_identity['runtimeEntryIdentities'] == 8 and native_identity['SwiftEntryCallsDuringIdentity'] == 0
    assert native_result == {'checks': 5120, 'failures': 0, 'iterations': 512,
        'destroyedObjects': 4608, 'VMCalls': 0, 'diskCalls': 0}
    controls = []
    for arg in ('--invalid-index-negative', '--invalid-index-count'):
        r = run('mac-' + arg[2:], [out / 'array-fixture-mac', arg], timeout=15, success=False)
        assert r.returncode == -5, (arg, r.returncode)
        controls.append({'mode': arg, 'exit': r.returncode, 'passed': True})
    files = []
    for p in (out / 'ios/VM27AnyObjectArray.dylib', out / 'array-fixture-ios',
              out / 'mac/VM27AnyObjectArray.dylib', out / 'array-fixture-mac'):
        s = run(p.name + '-signature', ['codesign', '-dvvv', p]).stderr
        files.append({'path': str(p), 'bytes': p.stat().st_size, 'sha256': digest(p),
            'CDHash': re.search(r'CDHash=([0-9a-f]{40})', s)[1]})
    assert all(digest(pathlib.Path(r['path'])) == r['sha256'] for r in inputs)
    result = {'files': files, 'inputs': inputs, 'exports': NAMES, 'nativeMac': native_result,
        'nativeMacIdentity': native_identity, 'iosFixtureEntitlements': entitlements,
        'negativeMac': controls, 'actualIOSRun': False, 'productionModified': False,
        'scope': 'eight exact AnyObject-specialized contracts only; real stock Swift owns allocation, metadata and ownership',
        'visibilityEdit': 'one hidden ArrayBuffer SwiftCC definition becomes public; no body or ABI edit',
        'deploymentTargets': {'mac': '13.0', 'ios': '16.1'},
        'sourceBodyGeneration': 'deployment targets predate exported specialization availability, avoiding same-symbol recursion',
        'endMutation': 'real serialized Builtin.endCOWMutation body compiles to ret; no handwritten successful stub',
        'allEightFixtureImportsStrongFromPrivateProvider': True, 'completeSwift27Runtime': False,
        'fullVZ27Closure': False, 'staticArrayStorageClassProvided': False}
    (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'files': files, 'nativeMac': native_result, 'actualIOSRun': False}, indent=2))


if __name__ == '__main__':
    main()
