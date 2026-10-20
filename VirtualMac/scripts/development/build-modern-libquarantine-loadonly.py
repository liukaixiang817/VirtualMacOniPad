#!/usr/bin/env python3
"""Build genuine27 libquarantine strong closure and metadata-only probes.

Mac executes inventory and load-only, never an original qtn function. iOS is
built for Root's separate system symbol gate and load-only execution.
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
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, segments, imports, cstring
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SHA = lambda data: hashlib.sha256(data).hexdigest()
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
NAMES = ['__qtn_file_alloc', '__qtn_file_free', '__qtn_file_init', '__qtn_file_init_with_fd',
         '__qtn_file_set_identifier', '__qtn_file_set_timestamp', '__qtn_file_set_flags',
         '__qtn_file_apply_to_mount_point', '__qtn_file_to_data']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', default='/var/root/VirtualMac2/testing/libquarantine27-loadonly-v1')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'; source.mkdir()
    rebuilt_path = N / 'libquarantine-reconstruct-v2/libquarantine.reconstructed.mac'
    original = rebuilt_path.read_bytes(); contract_path = N / 'libquarantine-genuine27-contract-v1/contract.json'
    contract = json.loads(contract_path.read_bytes())
    cache_symbols_path = N / 'libquarantine-reconstruct-v2/symbols.a2s.batch.json'
    cache_symbols = json.loads(cache_symbols_path.read_bytes())
    assert cache_symbols['uuid'] == 'c284a291b68b3d0da1a03f866f87efdc'
    owners = {}
    for name, owner in cache_symbols['symbols'].values():
        name = name.removeprefix('__got.')
        assert name not in owners or owners[name] == owner
        owners[name] = owner
    before = imports(original)['imports']; assert len(before) == 42 and all(not r['weak'] and r['ordinal'] == -2 for r in before)
    assert {r['name'] for r in before} == set(owners)
    linked = [cstring(original, a + struct.unpack_from('<I', original, a + 8)[0])
              for c, a, _ in commands(original) if c == 0xc]
    assert len(linked) == 8 and linked == [r['name'] for r in contract['linkedImages']]
    assert not contract['initializerSections'] and not contract['initializerCommands']
    exports = {r['symbol']: r['address'] for r in contract['exports']}
    assert all(name in exports for name in NAMES)
    allocator_manifest = json.loads((N / 'di2-typed-allocator-build-v1/manifest.json').read_bytes())
    allocator = Path(allocator_manifest['library']['path'])
    assert SHA(allocator.read_bytes()) == allocator_manifest['library']['sha256'] == '5c5f4a403525b04b980ef7e572f759afed58624c003d2afb1872fab8d861ec8b'
    ledger = json.loads((N / 'di2-native-import-ledger-root-v2/ledger.json').read_bytes())
    native_reallocf = next(r['native'] for r in ledger['rows'] if r['original']['name'] == '_reallocf')
    assert native_reallocf['found'] and native_reallocf['ownerPath'] == '/usr/lib/system/libsystem_c.dylib'
    for path in [Path(__file__), ROOT / 'VirtualMac/vz/host/modern_libquarantine_loadonly_probe.c',
                 contract_path, cache_symbols_path, N / 'libquarantine-reconstruct-v2/uncache-source.py']:
        (source / path.name).write_bytes(path.read_bytes())
    processes = []
    def run(label, argv):
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + '.stdout')).write_bytes(stdout); (out / (label + '.stderr')).write_bytes(stderr)
        processes.append({'label': label, 'argv': argv, 'directChildPID': child.pid, 'observedWaitExit': child.returncode, 'reaped': True})
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')[-3000:]
        return stdout, stderr
    def identity(path):
        data = path.read_bytes()
        uuid = next(data[a + 8:a + 24].hex() for c, a, _ in commands(data) if c == 0x1b)
        return dict(path=str(path), bytes=len(data), sha256=SHA(data), UUID=uuid)
    def sign(label, path, rights=None):
        argv = ['codesign', '--force', '--sign', '-', '--timestamp=none']
        if rights:
            ent = out / (label + '.entitlements.plist'); ent.write_bytes(plistlib.dumps(rights)); argv += ['--entitlements', str(ent)]
        run(label + '-sign', argv + [str(path)])
        run(label + '-strict', ['codesign', '--verify', '--strict', str(path)])
        run(label + '-dyld', ['xcrun', 'dyld_info', '-validate_only', str(path)])
        _, signature = run(label + '-signature', ['codesign', '-d', '--verbose=4', str(path)])
        actual, _ = run(label + '-rights', ['codesign', '-d', '--entitlements', ':-', str(path)])
        assert plistlib.loads(actual) == rights if rights else not actual
        return re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode()
    candidates = []
    for role, sdk, target in [('macos', 'macosx', 'arm64e-apple-macos13.0'), ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
        folder = out / role; folder.mkdir()
        data = bytearray(original); desired = []
        for row in before:
            owner = owners[row['name']]
            if role == 'ios' and row['name'] == '_reallocf': owner = native_reallocf['ownerPath']
            ordinal = linked.index(owner) + 1
            if role == 'ios' and row['name'] in ('_malloc_type_malloc', '_malloc_type_calloc'): ordinal = 9
            word = struct.unpack_from('<I', data, row['command'])[0]
            struct.pack_into('<I', data, row['command'], word & ~255 | ordinal)
            desired.append({'name': row['name'], 'ordinal': ordinal, 'owner': owner,
                            'privateAllocator': ordinal == 9, 'weak': False})
        if role == 'ios':
            first_payload = min(s['fileoff'] for g in segments(original) if g['name'] != '__LINKEDIT'
                                for s in g['sections'] if s['fileoff'] and s['size'])
            ncmds, sizeofcmds = struct.unpack_from('<II', data, 16); at = 32 + sizeofcmds
            path = b'@loader_path/VM27DiskAllocatorProvider.dylib\0'; size = (24 + len(path) + 7) & ~7
            assert not any(data[at:first_payload]) and at + size + 16 <= first_payload
            command = struct.pack('<6I', 0xc, size, 24, 2, 0x10000, 0x10000) + path
            data[at:at + size] = command + bytes(size - len(command))
            struct.pack_into('<II', data, 16, ncmds + 1, sizeofcmds + size)
            platform_at = next(a for c, a, _ in commands(data) if c == 0x32)
            struct.pack_into('<III', data, platform_at + 8, 2, 0x100100, 0x100100)
            # This genuine system library advertises Mac+MacCatalyst. A
            # private iOS derivative must keep exactly one iOS declaration;
            # leaving Catalyst next to iOS is rejected by dyld validation.
            before_commands = list(commands(data))
            rejected = [(c, a, s) for c, a, s in before_commands
                        if c == 0x32 and struct.unpack_from('<I', data, a + 8)[0] == 6]
            assert len(rejected) == 1 and rejected[0][2] == 32
            packed = b''.join(data[a:a + s] for c, a, s in before_commands if (c, a, s) not in rejected)
            old_end = 32 + struct.unpack_from('<I', data, 20)[0]
            data[32:old_end] = packed + bytes(old_end - 32 - len(packed))
            struct.pack_into('<II', data, 16, len(before_commands) - 1, len(packed))
            (folder / allocator.name).write_bytes(allocator.read_bytes())
        id_at, id_size = next((a, s) for c, a, s in commands(data) if c == 0xd)
        id_offset = struct.unpack_from('<I', data, id_at + 8)[0]
        new_id = b'@rpath/Libquarantine27.dylib\0'; assert id_offset + len(new_id) <= id_size
        data[id_at + id_offset:id_at + id_size] = new_id + bytes(id_size - id_offset - len(new_id))
        for section in [s for g in segments(original) for s in g['sections'] if s['size']]:
            offset, size = section['fileoff'], section['size']
            assert data[offset:offset + size] == original[offset:offset + size]
        library = folder / 'Libquarantine27.dylib'; library.write_bytes(data)
        cd = sign(role + '-qtn', library)
        record = identity(library); record['CDHash'] = cd; record['entitlements'] = {}
        assert record['UUID'] == contract['UUID'] == '7fd4ae2286ef382b83f5adf9336c1160'
        current = imports(library.read_bytes())['imports']
        assert [(r['name'], r['ordinal'], r['weak']) for r in current] == [(r['name'], r['ordinal'], r['weak']) for r in desired]
        run(role + '-qtn-imports', ['xcrun', 'dyld_info', '-imports', '-exports', '-linked_dylibs', str(library)])
        runtime_dir = args.native_directory.rstrip('/') if role == 'ios' else str(folder)
        literal = lambda seq: '{' + ','.join(str(v) for v in seq) + '}'
        header = 'static const char *SystemImages[8]=' + '{' + ','.join(json.dumps(v) for v in linked) + '};\n'
        header += 'struct Symbol {const char *name; unsigned owner; int data; int allocator;};\n'
        header += 'static const struct Symbol RequiredSymbols[42]={\n'
        for row in desired:
            system_owner = owners[row['name']]
            if role == 'ios' and row['name'] == '_reallocf': system_owner = native_reallocf['ownerPath']
            header += '{' + json.dumps(row['name']) + ',' + str(linked.index(system_owner)) + ','
            header += str(int(row['name'] in ('__NSConcreteGlobalBlock', '__DefaultRuneLocale', '___stack_chk_guard'))) + ','
            header += str(int(role == 'ios' and row['privateAllocator'])) + '},\n'
        header += '};\nstatic const unsigned ExpectedMissingSystemAllocator=' + ('2' if role == 'ios' else '0') + ';\n'
        header += 'static const char QuarantinePath[]=' + json.dumps(runtime_dir + '/' + library.name) + ';\n'
        header += 'static const size_t QuarantineBytes=' + str(record['bytes']) + ';\n'
        header += 'static const unsigned char QuarantineSHA[32]=' + literal(bytes.fromhex(record['sha256'])) + ';\n'
        header += 'static const char *QtnNames[9]={' + ','.join(json.dumps(v) for v in NAMES) + '};\n'
        header += 'static const uintptr_t QtnRVAs[9]=' + literal(exports[v] for v in NAMES) + ';\n'
        if role == 'ios':
            header += 'static const char AllocatorPath[]=' + json.dumps(runtime_dir + '/' + allocator.name) + ';\n'
            header += 'static const size_t AllocatorBytes=' + str(allocator_manifest['library']['bytes']) + ';\n'
            header += 'static const unsigned char AllocatorSHA[32]=' + literal(bytes.fromhex(allocator_manifest['library']['sha256'])) + ';\n'
            header += 'static const char AllocatorUUID[]=' + json.dumps(allocator_manifest['library']['uuid']) + ';\n'
        (folder / 'libquarantine27-pins.h').write_text(header)
        sdk_path = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path'])[0].decode().strip()
        probe = folder / 'libquarantine27-loadonly-probe'
        run(role + '-probe-build', ['xcrun', 'clang', '-target', target, '-isysroot', sdk_path, '-std=c11', '-O2',
            '-fptrauth-abi-version=0', '-fno-typed-memory-operations-experimental', '-Wall', '-Wextra', '-Werror',
            '-Wno-deprecated-declarations', '-DVM27_QTN_IOS=' + str(int(role == 'ios')), '-I' + str(folder),
            str(source / 'modern_libquarantine_loadonly_probe.c'), '-Wl,-no_adhoc_codesign', '-o', str(probe)])
        if role == 'ios':
            data = bytearray(probe.read_bytes()); a = next(a for c, a, _ in commands(data) if c == 0x32)
            struct.pack_into('<III', data, a + 8, 2, 0x100100, 0x100100); probe.write_bytes(data)
        probe_cd = sign(role + '-probe', probe, RIGHTS if role == 'ios' else None)
        probe_record = identity(probe); probe_record.update(CDHash=probe_cd, entitlements=RIGHTS if role == 'ios' else {})
        item = {'role': role, 'library': record, 'probe': probe_record, 'positiveImports': desired,
                'nativeDirectory': runtime_dir, 'allSectionPayloadBytesUnchanged': True, 'initializerCount': 0,
                'platformChange': 'MACOS+MACCATALYST to single iOS16.1; no dependency removal' if role == 'ios' else 'original MACOS+MACCATALYST',
                'genuineQtnAPICalls': 0, 'deviceExecuted': False}
        if role == 'ios': item['allocator'] = allocator_manifest['library']
        else:
            for mode in ('--inventory', '--load-only'):
                stdout, _ = run('macos-real' + mode, [str(probe), mode])
                rows = [json.loads(line) for line in stdout.decode().splitlines()]
                assert rows[0]['PID'] == processes[-1]['directChildPID'] == rows[-1]['PID']
                assert rows[-1]['identityFailures'] == 0
                if mode == '--load-only': assert rows[-1]['passed'] and rows[-1]['qtnExportIdentities'] == 9
                item['actualMac' + mode] = rows[-1]
        candidates.append(item)
    result = {'candidates': candidates, 'processes': processes, 'inputSHA256': SHA(original),
              'cacheOwnerSnapshotSHA256': SHA(cache_symbols_path.read_bytes()), 'originalContractSHA256': SHA(contract_path.read_bytes()),
              'genuine27QuarantineNominalTypesImplemented': False, 'qtnAPICalls': 0,
              'quarantineKernelProtocolSupported': False, 'originalDI2Loaded': False,
              'originalDI2UnencryptedRAWOpened': False, 'deviceOperations': False,
              'productionModified': False, 'full27Backend': False}
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'candidate': str(out / 'candidate.json'), 'candidates': [{k: row[k] for k in ('role', 'library', 'probe', 'nativeDirectory')} for row in candidates]}, indent=2))

if __name__ == '__main__': main()
