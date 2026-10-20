#!/usr/bin/env python3
"""Build one opt-in Foundation Swift method alias and its original SDK fixture.

The implementation delegates real conversion to system NSString. No DI2 APIs,
device operation, Foundation binary replacement, metadata fabrication or hook.
"""
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
SOURCE = ROOT / 'VirtualMac/vz/host'
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, cstring, export_trie, imports
SHA = lambda data: hashlib.sha256(data).hexdigest()
ORIGINAL = '_$sSS10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF'
NATURAL = '_$sSS14VM27FoundationE8vm27Data5using20allowLossyConversion0B00D0VSgSSAEE8EncodingV_SbtF'
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}


def exports(data):
    at = next(a for c, a, _ in commands(data) if c == 0x80000033)
    offset, length = struct.unpack_from('<II', data, at + 8)
    return {row['symbol']: row for row in export_trie(data[offset:offset + length])}


def dylibs(data):
    return [cstring(data, at + struct.unpack_from('<I', data, at + 8)[0])
            for c, at, _ in commands(data) if c in (12, 0x80000018, 0x8000001f, 0x80000023)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', default='/var/root/VirtualMac2/testing/foundation-stringdata-sdk-v1')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'; source.mkdir()
    for name in ['modern_foundation_stringdata_compat.swift', 'modern_foundation_stringdata_sdk_probe.swift',
                 'modern_foundation_stringdata_sdk_identity.c', 'modern_foundation_stringdata_sdk_identity.h']:
        (source / name).write_bytes((SOURCE / name).read_bytes())
    (source / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    processes = []

    def run(label, argv):
        child = subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + '.stdout')).write_bytes(stdout); (out / (label + '.stderr')).write_bytes(stderr)
        processes.append(dict(label=label, argv=[str(a) for a in argv], PID=child.pid, wait=child.returncode, reaped=True))
        (out / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')[-5000:]
        return stdout, stderr

    def sign(label, item, rights):
        argv = ['codesign', '--force', '--sign', '-', '--timestamp=none']
        if rights:
            ent = out / (label + '.entitlements.plist'); ent.write_bytes(plistlib.dumps(rights)); argv += ['--entitlements', ent]
        run(label + '-sign', argv + [item])
        run(label + '-strict', ['codesign', '--verify', '--strict', item])
        run(label + '-dyld', ['xcrun', 'dyld_info', '-validate_only', item])
        _, signature = run(label + '-signature', ['codesign', '-d', '--verbose=4', item])
        actual, _ = run(label + '-rights', ['codesign', '-d', '--entitlements', ':-', item])
        assert (plistlib.loads(actual) if actual else {}) == rights
        data = item.read_bytes()
        return dict(name=item.name, path=str(item), bytes=len(data), sha256=SHA(data),
                    UUID=next(data[a + 8:a + 24].hex() for c, a, _ in commands(data) if c == 0x1b),
                    CDHash=re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode(), entitlements=rights)

    files = []; abi = []
    for role, sdk, target in [('mac', 'macosx', 'arm64e-apple-macos14.0'), ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
        directory = out / role; directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path'])[0].decode().strip()
        common = ['xcrun', 'swiftc', '-parse-as-library', '-target', target, '-sdk', sdkpath,
                  '-module-cache-path', out / (role + '-cache'), '-module-name', 'VM27Foundation',
                  '-Xfrontend', '-disable-layout-string-value-witnesses',
                  '-Xfrontend', '-disable-layout-string-value-witnesses-instantiation',
                  '-Xfrontend', '-disable-availability-checking', '-O']
        provider = source / 'modern_foundation_stringdata_compat.swift'
        provider_ir = directory / 'provider.ll'
        run(role + '-provider-ir', common + [provider, '-emit-ir', '-o', provider_ir])
        library = directory / 'VM27FoundationCompat.dylib'
        run(role + '-provider-library', common + [provider, '-emit-library', '-Xlinker', '-alias',
            '-Xlinker', NATURAL, '-Xlinker', ORIGINAL, '-Xlinker', '-install_name',
            '-Xlinker', '@rpath/VM27FoundationCompat.dylib', '-o', library])
        pin = sign(role + '-provider', library, {}); pin['role'] = role; files.append(pin)
        table = exports(library.read_bytes())
        assert table[ORIGINAL] == dict(table[NATURAL], symbol=ORIGINAL)
        runtime = str(directory) if role == 'mac' else args.native_directory.rstrip('/')
        header = 'static const char PrivateProviderPath[]=' + json.dumps(runtime + '/' + library.name) + ';\n'
        header += 'static const size_t PrivateProviderBytes=' + str(pin['bytes']) + ';\n'
        header += 'static const unsigned char PrivateProviderSHA[32]={' + ','.join(str(v) for v in bytes.fromhex(pin['sha256'])) + '};\n'
        header += 'static const char PrivateProviderUUID[]=' + json.dumps(pin['UUID']) + ';\n'
        header += 'static const char OriginalSymbol[]=' + json.dumps(ORIGINAL) + ';\n'
        header += 'static const char NaturalSymbol[]=' + json.dumps(NATURAL) + ';\n'
        header += 'static const uintptr_t PrivateAliasRVA=' + str(table[ORIGINAL]['address']) + ';\n'
        (directory / 'foundation-sdk-pins.h').write_text(header)
        identity = directory / 'identity.o'
        run(role + '-identity', ['xcrun', 'clang', '-c', '-target', target, '-isysroot', sdkpath,
            '-fptrauth-abi-version=0', '-fno-typed-memory-operations-experimental', '-Wall', '-Wextra', '-Werror',
            '-Wno-deprecated-declarations', '-I', directory, source / 'modern_foundation_stringdata_sdk_identity.c', '-o', identity])
        caller = source / 'modern_foundation_stringdata_sdk_probe.swift'
        ir = directory / 'original-sdk.ll'
        run(role + '-caller-ir', common + ['-import-objc-header', source / 'modern_foundation_stringdata_sdk_identity.h', caller,
            '-emit-ir', '-o', ir])
        before = ir.read_text()
        lines = [line for line in before.splitlines(keepends=True) if line.startswith('declare extern_weak swiftcc') and '"' + ORIGINAL[1:] + '"' in line]
        assert len(lines) == 1
        after = before.replace(lines[0], lines[0].replace('extern_weak', 'external'))
        strong = directory / 'original-sdk-strong.ll'; strong.write_text(after)
        definition = next(line for line in provider_ir.read_text().splitlines() if line.startswith('define swiftcc') and '"' + NATURAL[1:] + '"' in line)
        declaration = lines[0].rstrip('\n')
        # The original concrete method uses four arguments: resilient Encoding
        # storage, Bool, then String's two words. Optional<Data> is two words.
        signature = re.search(r'swiftcc (.*?) @', declaration)[1]
        params = re.search(r'\"\((.*?)\)', declaration)[1]
        assert signature == '{ i64, i64 }' and params == 'ptr noalias, i1, i64, ptr'
        normalized = re.sub(r' %[0-9]+', '', re.search(r'\"\((.*?)\)', definition)[1])
        assert normalized == params and re.search(r'swiftcc (.*?) @', definition)[1] == signature
        record = dict(role=role, originalIRSHA256=SHA(before.encode()), strongIRSHA256=SHA(after.encode()),
            upgradedNames=[ORIGINAL], instructionsChanged=False, originalSDKDeclarations=True,
            originalDeclaration=declaration, naturalDefinition=definition, sameSwiftCC=True,
            returnIR=signature, parameterIR=params, losslessOptionalABI=True)
        (directory / 'abi-contract.json').write_text(json.dumps(record, indent=2) + '\n'); abi.append(record)
        swift_object = directory / 'original-sdk.o'
        run(role + '-caller-object', ['xcrun', 'clang', '-target', target, '-isysroot', sdkpath,
            '-Wno-override-module', '-c', '-x', 'ir', strong, '-o', swift_object])
        executable = directory / 'foundation-stringdata-sdk-probe'
        run(role + '-caller-link', ['xcrun', 'swiftc', '-target', target, '-sdk', sdkpath, swift_object, identity,
            library, '-Xlinker', '-rpath', '-Xlinker', '@executable_path', '-o', executable])
        probe = sign(role + '-probe', executable, RIGHTS if role == 'ios' else {}); probe['role'] = role; files.append(probe)
        data = executable.read_bytes(); owners = dylibs(data)
        used = [row for row in imports(data)['imports'] if row['name'] == ORIGINAL]
        assert len(used) == 1 and not used[0]['weak'] and owners[used[0]['ordinal'] - 1] == '@rpath/VM27FoundationCompat.dylib'
        (directory / 'original-caller-import.json').write_text(json.dumps(used[0], indent=2) + '\n')
        run(role + '-provider-imports', ['xcrun', 'dyld_info', '-imports', '-linked_dylibs', library])
    run('mac-actual', [out / 'mac/foundation-stringdata-sdk-probe'])
    manifest = dict(scope='private-foundation-String-data-original-SDK',
        nativeDirectory=args.native_directory.rstrip('/'), executable='foundation-stringdata-sdk-probe', arguments=[],
        files=[row for row in files if row['role'] == 'ios'], MacFiles=[row for row in files if row['role'] == 'mac'],
        aliases=[dict(originalSymbol=ORIGINAL, naturalSymbol=NATURAL)], abiContracts=abi,
        originalSDKDeclarations=True, nativeStringEncodingDataTypes=True, realNSStringConversion=True,
        privateAliases=1, originalFoundationBinaryClaimed=False, instructionsRewritten=False,
        expectedChecks=6824, expectedSDKCalls=3368, diskVMGPUCalls=0,
        iOSExecuted=False, genuine27DI2Loaded=False, full27Backend=False, processes=processes)
    (out / 'consumer-plan.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print((out / 'mac-actual.stdout').read_text())


if __name__ == '__main__': main()
