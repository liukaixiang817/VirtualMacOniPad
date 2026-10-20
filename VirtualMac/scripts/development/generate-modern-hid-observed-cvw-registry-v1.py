#!/usr/bin/env python3
"""Generate exact inert registry bytes from the audited original HID programs."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cvw_registry_source', HERE / 'build-modern-hid-observed-cvw-component-v2.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
p = b.p
DIRECTORY = p.NODE / 'universalhid-cvw-observed-ownership-abi-readonly-v7'


def generate(out):
    registry_path, audit_path = [DIRECTORY / name for name in ('observed-registry.json', 'audit.json')]
    registry, audit = [json.loads(x.read_text()) for x in (registry_path, audit_path)]
    assert audit['registry'] == p.pin(registry_path)
    assert len(registry['programs']) == 37 and len(registry['completedOriginalMetadata']) == 65
    assert registry['completedUHMetadata'] == 64 and registry['completedUHKMetadata'] == 1
    programs = registry['programs']
    keys = {(row['owner'], row['programRVA']): index for index, row in enumerate(programs)}
    assert len(keys) == 37
    lines = ['#pragma once', '#include "modern_swift_hid_observed_cvw_v2_compat.h"',
        '// Exact original bytes. Relative getter fields keep their original high words.',
        'namespace VM27HIDObservedRegistry {',
        'struct ProgramRecord { unsigned owner; size_t rva; const unsigned char *bytes; size_t size; };',
        'struct MetadataRecord { unsigned owner; size_t metadataRVA, vwtRVA, programIndex; VM27HIDObservedCVW::Layout layout; };']
    for index, row in enumerate(programs):
        raw = bytes.fromhex(row['bytesHex'])
        assert len(raw) == row['bytes'] and len(raw) % 8 == 0
        words = struct.unpack('<' + 'Q' * (len(raw) // 8), raw)
        assert words[1] + 24 == len(raw)
        lines.append('alignas(8) constexpr uint64_t Program%d[] = {%s};' %
            (index, ','.join('0x%016xULL' % word for word in words)))
    lines += ['const ProgramRecord Programs[] = {']
    for index, row in enumerate(programs):
        lines.append('{%d,0x%x,(const unsigned char *)Program%d,sizeof(Program%d)},' %
            (row['owner'] == 'UniversalHIDKit', row['programRVA'], index, index))
    lines += ['};', 'constexpr MetadataRecord Metadata[] = {']
    for row in registry['completedOriginalMetadata']:
        program_index = keys[(row['owner'], row['programRVA'])]
        assert programs[program_index]['sha256'] == row['expectedProgramSHA256']
        lines.append('{%d,0x%x,0x%x,%d,{%d,%d,0x%x,%d}},' %
            (row['owner'] == 'UniversalHIDKit', row['metadataRVA'], row['vwtRVA'], program_index,
             row['size'], row['stride'], row['flags'], row['extraInhabitants']))
    lines += ['};', 'constexpr size_t GetterRVA = 0xcea4;',
        'constexpr unsigned char GetterBytes[] = {']
    getter = DIRECTORY / 'original-uh-enum-tag-getter.bin'
    raw = getter.read_bytes()
    assert len(raw) == 28
    lines.append(','.join('0x%02x' % byte for byte in raw) + '};')
    lines += ['constexpr unsigned char UUIDs[2][16] = {',
        '{0x72,0x82,0x4f,0xab,0x0b,0xb7,0x3b,0x56,0xa4,0x0d,0x00,0x08,0x84,0x10,0xf0,0x53},',
        '{0xe6,0x80,0x1a,0x30,0xbc,0xfe,0x35,0xeb,0x9c,0x88,0x20,0x6d,0x35,0xfa,0x13,0x97}};',
        '} // namespace VM27HIDObservedRegistry']
    header = out / 'modern_swift_hid_observed_cvw_registry.h'
    header.write_text('\n'.join(lines) + '\n')
    report = dict(schema='Exact original observed HID ownership registry source v1',
        inputs=list(map(p.pin, (Path(__file__), registry_path, audit_path, getter))), header=p.pin(header),
        originalPrograms=37, completedStaticMetadata=65, completedUHMetadata=64, completedUHKMetadata=1,
        separatelyInitialPODUsesExactCompletedPODGuard=True, runtimeOriginalIdentityPassed=False,
        deviceOperations=0, nativeIOSExecuted=False)
    p.save(out / 'registry.json', report)
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    directory = ap.parse_args().output.resolve()
    assert directory.is_relative_to(p.NODE) and not directory.exists()
    directory.mkdir()
    print(json.dumps(generate(directory)))
