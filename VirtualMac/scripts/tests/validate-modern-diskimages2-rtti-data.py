#!/usr/bin/env python3
"""Independent byte/chain/owner/addend validation; never dlopen DI2."""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, segments, chain_entries, cstring
SHA = lambda b: hashlib.sha256(b).hexdigest()

def validate(original, modified, oracle, original_slots, platform):
    expected = {int(row['newVA'], 16): row for row in original_slots}
    assert len(expected) == 1189
    originals = list(chain_entries(original))
    before = {entry['address']: entry for entry in originals}
    fixup_command = next(at for c, at, _ in commands(modified) if c == 0x80000034)
    start, length = struct.unpack_from('<II', modified, fixup_command + 8)
    version, starts, imported, symbols, count, fmt, compressed = struct.unpack_from('<7I', modified, start)
    assert version == compressed == 0 and fmt == 2 and count == 818
    imports = []
    for index in range(count):
        bits, addend = struct.unpack_from('<Ii', modified, start + imported + index * 8)
        ordinal = bits & 255
        if ordinal >= 240: ordinal -= 256
        imports.append({'symbol': cstring(modified, start + symbols + (bits >> 9), start + length),
                        'ordinal': ordinal, 'weak': bool(bits & 256), 'addend': addend})
    linked = [cstring(modified, a + struct.unpack_from('<I', modified, a + 8)[0])
              for c, a, _ in commands(modified) if c in (0xc, 0x80000018, 0x8000001f, 0x80000023)]
    assert len(linked) == 31 and linked[30] == '/usr/lib/libc++abi.dylib'
    vtables = {r['converterSymbol']: r['exactExport'] for r in oracle['imports']}
    # Parse fmt2 chain starts independently instead of a fmt1 helper.
    count_segments = struct.unpack_from('<I', modified, start + starts)[0]
    current = {}
    for index, segment in enumerate(segments(modified)):
        relative = struct.unpack_from('<I', modified, start + starts + 4 + index * 4)[0]
        if not relative: continue
        cursor = start + starts + relative
        size, page_size, pointer_format, segment_offset, maxptr, page_count = struct.unpack_from('<IHHQIH', modified, cursor)
        assert pointer_format == 9 and size == 22 + 2 * page_count
        for page in range(page_count):
            first = struct.unpack_from('<H', modified, cursor + 22 + 2 * page)[0]
            if first == 0xffff: continue
            assert not first & 0x8000
            offset = segment['fileoff'] + page * page_size + first
            visits = 0
            while True:
                word = struct.unpack_from('<Q', modified, offset)[0]
                va = segment['address'] + offset - segment['fileoff']
                assert va not in current
                current[va] = {'fileoff': offset, 'word': word}
                if va in expected:
                    source = before[va]
                    imp = imports[word & 0xffff]
                    assert imp == {'symbol': vtables[source['symbol']], 'ordinal': 31, 'weak': False, 'addend': 16}
                    assert word >> 62 == 3 and (word >> 49 & 3) == 2
                    assert not (word >> 32 & 0x1ffff)
                    assert (word >> 51 & 0x7ff) == (source['word'] >> 51 & 0x7ff)
                else:
                    assert word == before[va]['word']
                    if word >> 62 & 1:
                        source = before[va]
                        assert imports[word & 0xffff]['symbol'] == source['symbol']
                next_bytes = (word >> 51 & 0x7ff) * 8
                if not next_bytes: break
                offset += next_bytes; visits += 1
                assert visits < page_size // 8 and offset < segment['fileoff'] + (page + 1) * page_size
    assert current.keys() == before.keys() and count_segments == len(segments(modified))
    # Every old payload byte is unchanged except the exact 1189 vptr words.
    first_payload = min(s['fileoff'] for g in segments(original) if g['name'] != '__LINKEDIT'
                        for s in g['sections'] if s['fileoff'] and s['size'])
    allowed = {p for va in expected for p in range(before[va]['fileoff'], before[va]['fileoff'] + 8)}
    changed_payload = []
    for index in range(first_payload, len(original)):
        if modified[index] != original[index]:
            assert index in allowed, hex(index)
            changed_payload.append(index)
    for c, a, s in commands(original):
        other = next((at for command, at, size in commands(modified) if command == c and at == a), None)
        assert other == a
        if c not in (0x19, 0x80000034, 0x32):
            assert original[a:a + s] == modified[a:a + s]
        if c == 0x19:
            name = original[a + 8:a + 24].split(b'\0')[0]
            if name != b'__LINKEDIT': assert original[a:a + s] == modified[a:a + s]
    uuid = next(modified[a + 8:a + 24].hex() for c, a, _ in commands(modified) if c == 0x1b)
    assert uuid == 'a456d4a4d6ab3549965d0400f3552de3'
    build = next(a for c, a, _ in commands(modified) if c == 0x32)
    assert struct.unpack_from('<I', modified, build + 8)[0] == platform
    return {'chainPointers': len(current), 'RTTIVPtrs': len(expected),
            'changedOldPayloadBytes': len(changed_payload), 'allOtherOldPayloadBytesIdentical': True,
            'genuineUUID': uuid, 'format2StrongVtableAddendVerified': True, 'authDA0Verified': True}

def main():
    candidate_path = Path(sys.argv[1]); destination = Path(sys.argv[2])
    destination.mkdir(parents=True, exist_ok=False)
    candidate = json.loads(candidate_path.read_bytes())
    n = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
    original = (n / 'diskimages2-reconstruct-root-v1/DiskImages2.reconstructed.mac').read_bytes()
    assert SHA(original) == candidate['inputSHA256']
    oracle_path = candidate_path.parent / 'source/contract.json'
    oracle = json.loads(oracle_path.read_bytes()); assert SHA(oracle_path.read_bytes()) == candidate['oracleSHA256']
    original_slots = json.loads((candidate_path.parent / 'source/all-original-slots.json').read_bytes())
    results = []
    negatives = []
    for row in candidate['candidates']:
        data = Path(row['path']).read_bytes(); assert SHA(data) == row['sha256']
        platform = 2 if row['role'] == 'ios' else 1
        verified = validate(original, data, oracle, original_slots, platform)
        results.append(dict(role=row['role'], **verified))
        first = candidate.get('pointerBindingsAudit', candidate.get('pointerChanges'))[0]['fileoff']
        broken = bytearray(data); word = struct.unpack_from('<Q', broken, first)[0]
        struct.pack_into('<Q', broken, first, word & ~(3 << 49))
        try: validate(original, broken, oracle, original_slots, platform)
        except AssertionError: negatives.append(row['role'] + '-wrong-function-key-rejected')
        else: raise AssertionError('IA incorrectly accepted')
        fixup_at = next(a for c, a, _ in commands(data) if c == 0x80000034)
        blob = struct.unpack_from('<I', data, fixup_at + 8)[0]
        imported = struct.unpack_from('<I', data, blob + 8)[0]
        index = word & 0xffff
        broken = bytearray(data); struct.pack_into('<i', broken, blob + imported + index * 8 + 4, 0)
        try: validate(original, broken, oracle, original_slots, platform)
        except AssertionError: negatives.append(row['role'] + '-missing-address-point-addend-rejected')
        else: raise AssertionError('zero addend incorrectly accepted')
    report = {'candidatePath': str(candidate_path), 'candidateSHA256': SHA(candidate_path.read_bytes()),
              'results': results, 'negativeControls': negatives, 'frameworkLoaded': False,
              'actualFrameworkFunctionCalls': 0, 'deviceOperations': False}
    (destination / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
