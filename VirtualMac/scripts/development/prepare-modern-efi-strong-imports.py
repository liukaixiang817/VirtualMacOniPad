#!/usr/bin/env python3
"""Prepare a private EFI27 load-only copy with explicit strong providers.

No EFI API is executed. Original instructions, fixup-chain words and PAC bits
stay byte-identical. Six cache-optimized C names use existing public-name
suffixes in the import string pool; __si D1 uses a separately gated provider.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('efi_macho', ROOT / 'scripts/development/prepare-modern-vmm-runtime-imports.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
spec = importlib.util.spec_from_file_location('efi_imports', ROOT / 'scripts/tests/validate-modern-cxa-primary-exception.py')
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)
SOURCE_SHA = '3fbc8ce53db18b9c9c7b2ade2cbe84e22fa17e5fc9e26344936b55b57e5666e8'
SOURCE_BYTES = 168496
LEDGER_SHA = 'b2a5b563c46189ef05ecffbac45e461fd5eef4d47eaad3839d40dd4051c307fa'
RTTI = '__ZN10__cxxabiv120__si_class_type_infoD1Ev'
PROVIDER = '@loader_path/VM27NativeRTTICompat.dylib'
ALIASES = {'___bzero': '_bzero', '__platform_memcmp': '_memcmp',
           '__platform_memmove': '_memmove', '__platform_memset': '_memset',
           '__platform_strlen': '_strlen', '____chkstk_darwin': '___chkstk_darwin'}
sha = lambda b: hashlib.sha256(b).hexdigest()


def main(source_path, output_path):
    source = Path(source_path).resolve(); original = source.read_bytes()
    assert source.is_file() and not source.is_symlink()
    assert len(original) == SOURCE_BYTES and sha(original) == SOURCE_SHA
    assert struct.unpack_from('<3I', original, 4) == (0x100000c, 0x80000002, 6)
    before = V.imports(original)
    assert len(before) == 95 and all(not row['weak'] and row['addend'] == 0 for row in before)
    assert M.libraries(original) == ['/usr/lib/libc++.1.dylib', '/usr/lib/libSystem.B.dylib']
    assert {row['symbol'] for row in before if row['ordinal'] < 1} == {RTTI, *ALIASES}
    assert all(row['ordinal'] == -2 for row in before if row['symbol'] in {RTTI, *ALIASES})
    # Original nlist supplies the requested providers for every other bind.
    ledger_path = ROOT.parent / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/efi-support-contract-v1/import-original-comparison.json'
    ledger_bytes = ledger_path.read_bytes()
    assert sha(ledger_bytes) == LEDGER_SHA
    ledger = json.loads(ledger_bytes)['originalNlist']
    for row in before:
        if row['symbol'] in ALIASES or row['symbol'] == RTTI: continue
        assert row['ordinal'] == ledger[row['symbol']]['ordinal'] and row['weak'] == ledger[row['symbol']]['weak']
    for public in ALIASES.values():
        assert ledger[public] == {'ordinal': 2, 'weak': False}
    fixup_commands = [(at, size) for cmd, at, size in M.commands(original) if cmd == 0x80000034]
    assert len(fixup_commands) == 1
    fixup_start, fixup_size = struct.unpack_from('<II', original, fixup_commands[0][0] + 8)
    version, starts, table, strings, count, form, symbolform = struct.unpack_from('<7I', original, fixup_start)
    assert version == symbolform == 0 and form == 1 and count == 95
    data = bytearray(original); changed_imports = []
    for index, row in enumerate(before):
        name = row['symbol']
        if name not in ALIASES and name != RTTI: continue
        at = fixup_start + table + 4 * index
        word = struct.unpack_from('<I', data, at)[0]
        old_name_offset = word >> 9
        if name == RTTI:
            new_word = (word & ~255) | 3
            new_name, ordinal = name, 3
        else:
            new_name = ALIASES[name]; suffix = name.index(new_name)
            assert name[suffix:] == new_name
            ordinal = 2
            # A substring reference preserves the entire original string pool.
            new_word = ((old_name_offset + suffix) << 9) | (word & 256) | ordinal
        struct.pack_into('<I', data, at, new_word)
        changed_imports.append({'index': index, 'offset': at, 'originalSymbol': name,
                                'symbol': new_name, 'originalOrdinal': row['ordinal'],
                                'ordinal': ordinal, 'weak': False, 'addend': 0})
    assert len(changed_imports) == 7
    section_ranges = []; id_commands = []; kept = []
    for cmd, at, size in M.commands(original):
        if cmd == 0x19:
            count = struct.unpack_from('<I', original, at + 64)[0]
            assert 72 + 80 * count == size
            for i in range(count):
                s = at + 72 + 80 * i
                length = struct.unpack_from('<Q', original, s + 40)[0]
                offset = struct.unpack_from('<I', original, s + 48)[0]
                flags = struct.unpack_from('<I', original, s + 64)[0]
                if length and offset and flags & 255 not in (1, 12, 18):
                    assert offset + length <= len(original)
                    section_ranges.append((offset, length))
        if cmd == 0xd:
            id_commands.append((at, size))
            new_id = bytearray(M.dylib_command('@rpath/EfiSupport27.dylib'))
            struct.pack_into('<I', new_id, 0, 0xd)
            new_id[12:24] = original[at+12:at+24]
            kept.append(bytes(new_id))
        elif cmd != 0x1d:
            kept.append(original[at:at+size])
    assert len(id_commands) == 1 and sum(cmd == 0x1d for cmd, _, _ in M.commands(original)) == 1
    new_commands = b''.join([*kept, M.dylib_command(PROVIDER)])
    first_section = min(offset for offset, _ in section_ranges)
    old_end = 32 + struct.unpack_from('<I', original, 20)[0]
    new_end = 32 + len(new_commands)
    assert new_end + 16 <= first_section and not any(original[old_end:first_section])
    data[32:first_section] = bytes(first_section - 32)
    data[32:new_end] = new_commands
    struct.pack_into('<II', data, 16, len(kept) + 1, len(new_commands))
    after = V.imports(data)
    expected = [dict(row) for row in before]
    for row in expected:
        if row['symbol'] == RTTI: row['ordinal'] = 3
        elif row['symbol'] in ALIASES: row.update(symbol=ALIASES[row['symbol']], ordinal=2)
    assert after == expected and all(row['ordinal'] > 0 and not row['weak'] for row in after)
    assert M.libraries(data) == [*M.libraries(original), PROVIDER]
    assert all(original[offset:offset+length] == data[offset:offset+length] for offset, length in section_ranges)
    assert original[fixup_start:fixup_start+table] == data[fixup_start:fixup_start+table]
    assert original[fixup_start+strings:fixup_start+fixup_size] == data[fixup_start+strings:fixup_start+fixup_size]
    allowed = set(range(16, 24)) | set(range(32, first_section))
    allowed.update(i for row in changed_imports for i in range(row['offset'], row['offset']+4))
    changed = [i for i, (a, b) in enumerate(zip(original, data)) if a != b]
    assert len(data) == len(original) and set(changed) <= allowed
    out = Path(output_path).resolve(); assert not out.exists() and not out.is_symlink(); out.mkdir(mode=0o700)
    candidate = out / 'EfiSupport27.strong.unsigned'; candidate.write_bytes(data)
    check = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(candidate)], capture_output=True, timeout=20)
    (out / 'dyld-validation.stdout').write_bytes(check.stdout); (out / 'dyld-validation.stderr').write_bytes(check.stderr)
    assert check.returncode == 0
    report = dict(sourcePath=str(source), sourceSHA256=SOURCE_SHA, candidatePath=str(candidate),
                  candidateSHA256=sha(data), candidateBytes=len(data), strongImportsBeforeAndAfter=95,
                  originalPositiveProviderRowsPreserved=88, selectedChainedImports=changed_imports,
                  allFileBackedSectionsUnchanged=True, originalFixupChainsAndPACUnchanged=True,
                  originalImportStringPoolUnchanged=True, originalNlistUnchanged=True,
                  addedStrongProvider=PROVIDER, installName='@rpath/EfiSupport27.dylib',
                  actualEFICalls=0, nativeExecution=False, fullEFIABIVerified=False,
                  original27VMMExecuted=False, systemOrProductionModified=False,
                  callerABIEvidenceRequired=True, originalLedgerSHA256=sha(ledger_path.read_bytes()))
    (out / 'binding-review.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    if len(sys.argv) != 3: raise SystemExit('Usage: prepare-modern-efi-strong-imports.py PINNED_EFI_COPY NEW_DIRECTORY')
    main(*sys.argv[1:])
