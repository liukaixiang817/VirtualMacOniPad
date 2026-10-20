#!/usr/bin/env python3
"""Prepare a new isolated DIKit27 bootstrap + genuine DI2 load-only closure. Never executes it."""
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
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'diskimagekit-static-bootstrap-build-v12'
DI2 = N / 'diskimages2-foundation-loadonly-build-v2'
RAW = N / 'diskimages2-foundation-owned-raw-v2-saved-adjudication-v2'
HOST = ROOT / 'VirtualMac/vz/host'
SHA = lambda data: hashlib.sha256(data).hexdigest()
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', default='/var/root/VirtualMac2/testing/diskimagekit27-genuine-di2-loadonly-v1')
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir()
    ios = output / 'ios'; ios.mkdir(); source = output / 'source'; source.mkdir()
    runtime = args.native_directory.rstrip('/')
    assert re.fullmatch(r'/var/root/VirtualMac2/testing/diskimagekit27-genuine-di2-loadonly-v[0-9]+', runtime)
    original_manifest = BASE / 'manifest.json'
    assert SHA(original_manifest.read_bytes()) == 'b3912bf69ac9a1cd37a80dbcf4ee4693e859847264dcfd9fac8cc34cd8fa0dc6'
    base = json.loads(original_manifest.read_bytes())
    assert base['actualIOSRun'] is False and base['completeOriginalClosure'] is False
    for item in base['inputs']:
        assert SHA(Path(item['path']).read_bytes()) == item['sha256']
    assert SHA((RAW / 'result.json').read_bytes()) == '6caf216bc8038fcd7636bbe410d56c8b5ef05cea9ecb46c9b6265ce0151f9650'
    actual = json.loads((RAW / 'result.json').read_bytes())
    assert actual['passed'] is True and actual['actualPID'] == 46014 and actual['actualWait'] == 0
    assert actual['frameworkClosedBothBorrowedFDs'] is True and actual['allOwnRAWFilesExternallyAbsent'] is True
    assert actual['oldWrapperPassed'] is False and actual['JSONCoercionOrNormalization'] is False
    for item in json.loads((RAW / 'freeze.json').read_bytes())['files']:
        content = Path(item['path']).read_bytes(); assert SHA(content) == item['sha256'] and len(content) == item['bytes']
    original_di2 = DI2 / 'candidate.json'
    assert SHA(original_di2.read_bytes()) == '57bb57ac60d4777092e6637ad4ca62707f3d15f79a3e2434c4fe55218de24fe4'
    di2 = json.loads(original_di2.read_bytes())
    files = []
    for item in di2['files'][:-1]:
        content = Path(item['path']).read_bytes(); assert SHA(content) == item['sha256'] and len(content) == item['bytes']
        path = ios / item['name']; path.write_bytes(content)
        files.append(dict(item, path=str(path), unchangedFromActualGenuineDI2Closure=True))
    assert len(files) == 13
    old_ios = {Path(item['path']).name: item for item in base['files'] if '/ios/' in item['path']}
    for name in ['VM27DIKCVW.dylib', 'VM27AnyObjectArray.dylib', 'VM27StaticArrayMetadata.dylib']:
        item = old_ios[name]; content = Path(item['path']).read_bytes()
        assert SHA(content) == item['sha256'] and len(content) == item['bytes']
        (ios / name).write_bytes(content)
    assert old_ios['VM27SwiftLookup.dylib']['sha256'] == files[8]['sha256'] and files[8]['name'] == 'VM27SwiftLookup.dylib'
    sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
    from compiler_image import commands, segments, imports, chain_entries
    image_source = Path(old_ios['DiskImageKit27.dylib']['path'])
    before = image_source.read_bytes(); assert SHA(before) == 'd67600850db5fdcd4c0dfa9ac47f515ef17a40508f3b4c667e4beb435001a4ae'
    candidate = bytearray(before); changes = []; dependencies = []
    for command, at, count in commands(before):
        if command in (12, 0x80000018, 0x8000001f, 0x80000023):
            offset = struct.unpack_from('<I', before, at + 8)[0]
            path = before[at + offset:at + count].split(b'\0')[0].decode(); dependencies.append(path)
            if path == '/System/Library/PrivateFrameworks/DiskImages2.framework/DiskImages2':
                after = '@loader_path/DiskImages227.dylib'; encoded = after.encode() + b'\0'
                assert command == 12 and len(dependencies) == 4 and len(encoded) <= count - offset
                candidate[at + offset:at + count] = encoded + bytes(count - offset - len(encoded))
                changes.append(dict(ordinal=4, command=command, fileoff=at, before=path, after=after))
    assert len(changes) == 1 and len(dependencies) == 16
    assert imports(candidate)['imports'] == imports(before)['imports']
    assert list(chain_entries(candidate)) == list(chain_entries(before))
    image = ios / 'DiskImageKit27.dylib'; image.write_bytes(candidate)
    processes = []
    def run(label, argv):
        child = subprocess.Popen([str(value) for value in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); raise
        (output / (label + '.stdout')).write_bytes(stdout); (output / (label + '.stderr')).write_bytes(stderr)
        processes.append(dict(label=label, argv=[str(value) for value in argv], PID=child.pid, wait=child.returncode, reaped=True))
        (output / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')[-4000:]
        return stdout, stderr
    def sign(path, entitlement=None):
        arguments = ['codesign', '--force', '--sign', '-', '--timestamp=none']
        if entitlement: arguments += ['--entitlements', entitlement]
        run('sign-' + path.name, arguments + [path])
    sign(image)
    after = image.read_bytes()
    assert imports(after)['imports'] == imports(before)['imports']
    assert list(chain_entries(after)) == list(chain_entries(before))
    sections = []
    for group in segments(before):
        for section in group['sections']:
            if not section['size'] or not section['fileoff']: continue
            content = before[section['fileoff']:section['fileoff'] + section['size']]
            assert content == after[section['fileoff']:section['fileoff'] + section['size']]
            sections.append(dict(segment=group['name'], name=section['name'], address=section['address'],
                fileoff=section['fileoff'], bytes=section['size'], sha256=SHA(content)))
    assert sections
    for name in ['diskimagekit_bootstrap_required_imports.h', 'diskimagekit_required_imports.h']:
        (ios / name).write_bytes((BASE / 'ios' / name).read_bytes())
    (output / 'bootstrap-exports.txt').write_bytes((BASE / 'bootstrap-exports.txt').read_bytes())
    source_paths = [HOST / 'modern_swift_static_array_bootstrap.cpp', HOST / 'modern_swift_static_array_bootstrap.h',
        HOST / 'modern_diskimages2_hpke_loadonly_probe.c', HOST / 'modern_diskimagekit_genuine_di2_loadonly_probe.cpp', Path(__file__),
        original_manifest, original_di2, RAW / 'result.json', RAW / 'freeze.json']
    inputs = []
    for path in source_paths:
        content = path.read_bytes(); (source / path.name).write_bytes(content)
        inputs.append(dict(path=str(path), bytes=len(content), sha256=SHA(content)))
    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'])[0].decode().strip()
    common = ['xcrun', 'clang++', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-std=c++17', '-O2',
        '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-fno-exceptions', '-fno-rtti', '-nostdlib++',
        '-fno-typed-memory-operations', '-fno-typed-cxx-new-delete', '-I', ios, '-I', source]
    provider = ios / 'VM27StaticArrayBootstrap.dylib'; factory = ios / 'VM27StaticArrayMetadata.dylib'
    defines = ['-DVM27_DIKit_SHA="' + SHA(image.read_bytes()) + '"', '-DVM27_FACTORY_SHA="' + SHA(factory.read_bytes()) + '"',
        '-DVM27_FACTORY_UUID="' + old_ios[factory.name]['uuid'] + '"']
    run('bootstrap-build', common + defines + [source / 'modern_swift_static_array_bootstrap.cpp', '-dynamiclib', '-lobjc',
        '-Wl,-install_name,@rpath/VM27StaticArrayBootstrap.dylib', '-Wl,-exported_symbols_list,' + str(output / 'bootstrap-exports.txt'),
        '-o', provider]); sign(provider)
    def identity(path, entitlement):
        _, signature = run('identity-' + path.name, ['codesign', '-d', '--verbose=4', path])
        rights, _ = run('rights-' + path.name, ['codesign', '-d', '--entitlements', ':-', path])
        assert (plistlib.loads(rights) if rights.strip() else {}) == entitlement
        data = path.read_bytes()
        return dict(name=path.name, path=str(path), bytes=len(data), sha256=SHA(data),
            UUID=next(data[at + 8:at + 24].hex() for command, at, _ in commands(data) if command == 27),
            CDHash=re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode(), entitlements=entitlement)
    for name in ['VM27DIKCVW.dylib', 'VM27AnyObjectArray.dylib', 'VM27StaticArrayMetadata.dylib', 'VM27StaticArrayBootstrap.dylib', 'DiskImageKit27.dylib']:
        files.append(identity(ios / name, {}))
    assert len(files) == 18
    symbols = ['VM27DIKCVWQuery', '$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5', 'VM27StaticArrayMetadataOracle',
               'VM27StaticArrayBootstrapLoad', '$s12DiskImageKit17OpenConfigurationVMa']
    header = 'struct ClosurePin { const char *path; unsigned long long bytes; const char *uuid; unsigned char sha[32]; const char *symbol; bool data; };\n'
    header += 'static const ClosurePin ClosureImages[]={\n'
    for item, symbol in zip(files[13:], symbols):
        header += '{' + json.dumps(runtime + '/' + item['name']) + ',' + str(item['bytes']) + ',' + json.dumps(item['UUID']) + ',{' + \
            ','.join('0x' + item['sha256'][offset:offset + 2] for offset in range(0, 64, 2)) + '},' + json.dumps(symbol) + ',false},\n'
    header += '};\n'
    for name, filename in [('DIKitPath', image.name), ('FactoryPath', factory.name), ('SecurityPath', files[6]['name'])]:
        header += 'static const char ' + name + '[]=' + json.dumps(runtime + '/' + filename) + ';\n'
    (ios / 'diskimagekit_genuine_di2_pins.h').write_text(header)
    header = (DI2 / 'ios/diskimages227-pins.h').read_text().replace(di2['nativeDirectory'], runtime)
    (ios / 'diskimages227-pins.h').write_text(header)
    di2_object = output / 'di2-loadonly.o'
    run('di2-immutable-c-object', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-std=c11', '-O2',
        '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-fptrauth-abi-version=0',
        '-fno-typed-memory-operations-experimental', '-I', ios, '-Dmain=VM27FoundationDI2LoadOnly',
        '-c', source / 'modern_diskimages2_hpke_loadonly_probe.c', '-o', di2_object])
    executable = ios / 'diskimagekit27-genuine-di2-loadonly-probe'
    run('probe-build', common + [source / 'modern_diskimagekit_genuine_di2_loadonly_probe.cpp', di2_object, provider,
        '-lobjc', '-Wl,-rpath,@executable_path', '-Wl,-no_adhoc_codesign', '-o', executable])
    entitlement = output / 'Probe.entitlements'; entitlement.write_bytes(plistlib.dumps(RIGHTS)); sign(executable, entitlement)
    files.append(identity(executable, RIGHTS))
    for item in files:
        run('strict-' + item['name'], ['codesign', '--verify', '--strict', item['path']])
        run('dyld-' + item['name'], ['xcrun', 'dyld_info', '-validate_only', item['path']])
    for item in inputs:
        content = Path(item['path']).read_bytes(); assert SHA(content) == item['sha256'] and len(content) == item['bytes']
    manifest = dict(scope='private-genuine27-DIKit-genuineDI2-loadonly', nativeDirectory=runtime, files=files,
        executable=executable.name, arguments=['--load-only'], inputs=inputs,
        genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e', genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',
        prerequisiteRAWActualPID=46014, prerequisiteRAWActualWait=0, prerequisiteSavedAdjudicationSHA256=SHA((RAW / 'result.json').read_bytes()),
        prerequisiteOriginalFailedWrapperPreserved=True, original13GenuineDI2LibrariesByteIdentical=True,
        originalThreeSwiftProvidersByteIdentical=True, originalBootstrapSourceByteIdentical=True,
        bootstrapRecompiledOnlyForNewDIKitSHA=True, originalDIKitDependencyPathChanges=changes,
        original16DependencyOrdinalsRetained=True, original164ImportRowsUnchanged=True,
        originalAllChainWordsAndAuthenticationUnchanged=True, originalAllNonemptySectionsUnchanged=sections,
        originalHeaderOnlyDependencyPathChanged=True, originalCNProvided=False,
        privateCNBridge='audited invalid sentinel followed by three completed-metadata ISA bindings before handle publication',
        pageScope='one owned __AUTH_CONST page; original current/maximum protection restored',
        CPUSecondsSoft=3, CPUSecondsHard=4, wallSecondsLimit=10, actualExternalWaitAndAbsenceRequired=True,
        DIKitAPICalls=0, DI2APICalls=0, originalMetadataCalls=0, diskVMGPUCalls=0,
        nativeExecutionPending=True, actualIOSRun=False, completeOriginalClosure=False,
        fullDIKit27=False, fullSwift27Runtime=False, fullVZ27Backend=False, full27Backend=False, deviceOperations=False)
    (output / 'candidate.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(candidate=str(output / 'candidate.json'), files=len(files),
        candidateSHA256=SHA((output / 'candidate.json').read_bytes()), nativeExecutionPending=True), indent=2))


if __name__ == '__main__': main()
