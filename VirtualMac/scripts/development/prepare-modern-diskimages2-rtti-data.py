#!/usr/bin/env python3
"""Restore five misnamed DI2 data imports and original 1189 vptr auth slots.

The exact original slide-v5 owner/export/addend/PAC inventory is mandatory.
Uses Apple's DYLD_CHAINED_IMPORT_ADDEND (format2), not destructor providers.
Does not load a framework, restore other flat imports, or operate a device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, segments, imports, chain_entries, cstring
SHA = lambda data: hashlib.sha256(data).hexdigest()

def output_imports(data):
    at = next(at for command, at, _ in commands(data) if command == 0x80000034)
    start, size = struct.unpack_from('<II', data, at + 8)
    version, starts, entries, strings, count, fmt, compressed = struct.unpack_from('<7I', data, start)
    assert version == compressed == 0 and fmt == 2
    result = []
    for index in range(count):
        word, addend = struct.unpack_from('<Ii', data, start + entries + index * 8)
        ordinal = word & 255
        if ordinal >= 240:
            ordinal -= 256
        result.append({'name': cstring(data, start + strings + (word >> 9), start + size),
                       'ordinal': ordinal, 'weak': bool(word & 256), 'addend': addend})
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--expected-input-sha256', required=True)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--expected-contract-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.input.read_bytes()
    assert SHA(original) == args.expected_input_sha256
    oracle_bytes = args.contract.read_bytes()
    assert SHA(oracle_bytes) == args.expected_contract_sha256
    oracle = json.loads(oracle_bytes)
    assert oracle['rebuiltSHA256'] == SHA(original) and oracle['originalSlots'] == 1189
    assert oracle['nativeOwnerUUID'] == 'a21743ee6e1c3e7497ea7af793de4bdf'
    slot_bytes = Path(oracle['allOriginalSlotsPath']).read_bytes()
    assert SHA(slot_bytes) == oracle['allOriginalSlotsSHA256']
    slots = json.loads(slot_bytes)
    assert len(slots) == 1189 and len({r['newVA'] for r in slots}) == 1189
    routes = {r['converterSymbol']: r for r in oracle['imports']}
    assert len(routes) == 5
    for row in slots:
        assert row['chainMembershipVerified'] and row['auth'] == 1 and row['key'] == 2
        assert row['diversity'] == '0x0' and row['addressDiversity'] == 0
        assert row['addressPointAddend'] == 16 and row['originalOwner'] == '/usr/lib/libc++abi.dylib'
        assert row['originalOwnerUUID'] == oracle['nativeOwnerUUID']
    before_imports = imports(original)
    assert len(before_imports['imports']) == 818
    chains = {entry['address']: entry for entry in chain_entries(original)}
    data = bytearray(original)
    ncmds, sizeofcmds = struct.unpack_from('<II', data, 16)
    command_end = 32 + sizeofcmds
    first_payload = min(s['fileoff'] for g in segments(original) if g['name'] != '__LINKEDIT'
                        for s in g['sections'] if s['size'] and s['fileoff'])
    assert not any(data[command_end:first_payload])
    linked = [cstring(data, at + struct.unpack_from('<I', data, at + 8)[0])
              for command, at, _ in commands(data) if command in (0xc, 0x80000018, 0x8000001f, 0x80000023)]
    assert '/usr/lib/libc++abi.dylib' not in linked and len(linked) == 30
    path = b'/usr/lib/libc++abi.dylib\0'
    size = (24 + len(path) + 7) & ~7
    assert command_end + size <= first_payload
    # Explicit new strong owner dependency. Version1 preserves old-host
    # compatibility; the original cached data owner UUID is an oracle pin,
    # not a requirement to map the macOS libc++abi onto iPadOS.
    command = struct.pack('<6I', 0xc, size, 24, 2, 0x10000, 0x10000) + path
    command += bytes(size - len(command))
    data[command_end:command_end + size] = command
    struct.pack_into('<II', data, 16, ncmds + 1, sizeofcmds + size)
    owner_ordinal = 31
    pointer_changes = []
    for row in slots:
        entry = chains[int(row['newVA'], 16)]
        assert entry['symbol'] == row['converterSymbol'] and entry['auth'] and entry['bind']
        assert entry['word'] == int(row['newBindWord'], 16)
        # Retain next/bind/auth/ordinal; verify the native vptr DA0 PAC.
        # The pinned reconstruction already has the correct key bits. Its
        # actual defect is the D1 name/+16 lost addend, not a PAC change.
        rewritten = (entry['word'] & (0x7ff << 51)) | (3 << 62) | (2 << 49) | entry['import_index']
        assert rewritten == entry['word']
        struct.pack_into('<Q', data, entry['fileoff'], rewritten)
        pointer_changes.append({'RVA': hex(entry['address'] - 0x100000000),
                                'fileoff': entry['fileoff'], 'before': hex(entry['word']), 'after': hex(rewritten)})
    fixup_at = next(at for command, at, _ in commands(data) if command == 0x80000034)
    old_start, old_size = struct.unpack_from('<II', data, fixup_at + 8)
    old_header = before_imports['header']
    prefix = bytearray(original[old_start:old_start + old_header[2]])
    strings, entries, expected = bytearray(), bytearray(), []
    for row in before_imports['imports']:
        name, ordinal, weak, addend = row['name'], row['ordinal'], row['weak'], 0
        if name in routes:
            assert ordinal == -2 and not weak
            name, ordinal, weak, addend = routes[name]['exactExport'], owner_ordinal, False, 16
        string_offset = len(strings)
        strings += name.encode() + b'\0'
        assert string_offset < (1 << 23)
        entries += struct.pack('<Ii', (ordinal & 255) | (int(weak) << 8) | (string_offset << 9), addend)
        expected.append({'name': name, 'ordinal': ordinal, 'weak': weak, 'addend': addend})
    new_blob = prefix + entries + strings
    struct.pack_into('<7I', new_blob, 0, 0, old_header[1], len(prefix), len(prefix) + len(entries), len(expected), 2, 0)
    new_start = (len(data) + 7) & ~7
    data += bytes(new_start - len(data)) + new_blob
    struct.pack_into('<II', data, fixup_at + 8, new_start, len(new_blob))
    linkedit = next(g for g in segments(data) if g['name'] == '__LINKEDIT')
    file_size = len(data) - linkedit['fileoff']
    struct.pack_into('<Q', data, linkedit['command'] + 32, (file_size + 0x3fff) & ~0x3fff)
    struct.pack_into('<Q', data, linkedit['command'] + 48, file_size)
    assert output_imports(data) == expected
    # No executable/data payload changed beyond the listed vptr fixups.
    for section in [s for g in segments(original) for s in g['sections'] if g['name'] == '__TEXT' and s['size']]:
        begin, length = section['fileoff'], section['size']
        assert data[begin:begin + length] == original[begin:begin + length]
    before_uuid = next(original[at + 8:at + 24] for command, at, _ in commands(original) if command == 0x1b)
    assert before_uuid.hex() == 'a456d4a4d6ab3549965d0400f3552de3'
    assert next(data[at + 8:at + 24] for command, at, _ in commands(data) if command == 0x1b) == before_uuid
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    frozen = out / 'source'; frozen.mkdir()
    for source in (Path(__file__), args.contract, Path(oracle['allOriginalSlotsPath'])):
        (frozen / source.name).write_bytes(source.read_bytes())
    sdk_header = Path('/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.1.sdk/usr/include/mach-o/fixup-chains.h')
    (frozen / sdk_header.name).write_bytes(sdk_header.read_bytes())
    calls = []
    candidates = []
    for role in ('macos', 'ios'):
        image = bytearray(data)
        if role == 'ios':
            platform_at = next(at for command, at, _ in commands(image) if command == 0x32)
            struct.pack_into('<III', image, platform_at + 8, 2, 0x100100, 0x100100)
        target = out / ('DiskImages2.rtti-data.' + role + '.dylib')
        target.write_bytes(image)
        for label, argv in [('sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', str(target)]),
                            ('strict', ['codesign', '--verify', '--strict', str(target)]),
                            ('validate', ['xcrun', 'dyld_info', '-validate_only', '-imports', '-linked_dylibs', str(target)])]:
            child = subprocess.run(argv, capture_output=True)
            (out / (role + '-' + label + '.stdout')).write_bytes(child.stdout)
            (out / (role + '-' + label + '.stderr')).write_bytes(child.stderr)
            calls.append({'argv': argv, 'exit': child.returncode})
            assert child.returncode == 0, child.stderr.decode(errors='replace')
        candidate_bytes = target.read_bytes()
        assert output_imports(candidate_bytes) == expected
        candidates.append({'role': role, 'path': str(target), 'bytes': len(candidate_bytes),
                           'sha256': SHA(candidate_bytes), 'UUID': before_uuid.hex(),
                           'signed': True, 'strictVerified': True, 'dyldValidated': True,
                           'loaded': False, 'platformOnlyChangeFromMacOS': role == 'ios'})
    result = {'inputSHA256': SHA(original), 'oracleSHA256': SHA(oracle_bytes), 'candidates': candidates,
              'importsFormat': 2, 'importsCount': len(expected), 'strongVTableOwnerOrdinal': owner_ordinal,
              'strongVTableOwner': '/usr/lib/libc++abi.dylib', 'correctedDataImports': list(routes.values()),
              'originalPACSlotsValidated': len(pointer_changes),
              'changedOriginalPACSlots': sum(r['before'] != r['after'] for r in pointer_changes),
              'pointerBindingsAudit': pointer_changes,
              'executableSectionBytesUnchanged': True, 'allOtherImportNameOrdinalWeakSemanticsPreserved': True,
              'nlistSyntheticD1EntriesPresent': False, 'originalCachedOwnerUUIDIsOracleOnly': True,
              'completeStrongClosure': False, 'otherModernDI2ImportsAndMetadataStillPending': True,
              'DI2FrameworkAPICalls': 0, 'deviceOperations': False, 'productionModified': False,
              'commands': calls}
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'candidate': str(out / 'candidate.json'), 'candidates': candidates,
                      'originalPACSlotsValidated': len(pointer_changes), 'changedPACSlots': 0}, indent=2))

if __name__ == '__main__':
    main()
