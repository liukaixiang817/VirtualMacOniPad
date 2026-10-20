#!/usr/bin/env python3
"""Check exact original untagged programs and PAC prefixes for the finite gate."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cvw_whitelist', HERE / 'generate-modern-hid-observed-cvw-registry-v1.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
p = g.p
SOURCE = p.NODE / 'universalhid-bitwise-take-real-reexport-data-v1/candidate.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    generated = g.generate(out)
    original = json.loads((g.DIRECTORY / 'observed-registry.json').read_text())
    source = json.loads(SOURCE.read_text())
    raws, chains, pins = {}, {}, generated['inputs'] + [p.pin(Path(__file__)), p.pin(SOURCE)]
    for image in source['images']:
        pin = image['candidate']; path = Path(pin['path'])
        assert pin == p.pin(path)
        raw = path.read_bytes(); owner = image['name']
        raws[owner] = raw; chains[owner] = {x['address'] - 0x100000000: x for x in p.chain_entries(raw)}
        pins.append(pin)
    def read(raw, rva, size):
        for segment in p.segments(raw):
            if segment['address'] <= 0x100000000 + rva and rva + size <= segment['address'] - 0x100000000 + segment['filesize']:
                offset = segment['fileoff'] + rva - (segment['address'] - 0x100000000)
                return raw[offset:offset + size]
        raise AssertionError((rva, size))
    rows = []
    for entry in original['completedOriginalMetadata']:
        owner, rva = entry['owner'], entry['metadataRVA']
        row = dict(entry)
        for label, offset, target, diversity in [('program', -16, entry['programRVA'], 0x8b65),
                                                ('VWT', -8, entry['vwtRVA'], 0x2e3f),
                                                ('descriptor', 8, None, 0xae86)]:
            slot = chains[owner][rva + offset]; word = slot['word']
            actual = word & 0xffffffff
            assert not slot['bind'] and slot['auth'] and (word >> 49 & 3) == 2
            assert word >> 48 & 1 and word >> 32 & 0xffff == diversity
            if target is not None: assert actual == target
            row[label + 'Prefix'] = dict(slot, normalizedTargetRVA=actual, key=2,
                diversity=diversity, addressDiversity=True)
        assert not row['programPrefix']['normalizedTargetRVA'] & 1
        row['metadataKind'] = struct.unpack('<Q', read(raws[owner], rva, 8))[0]
        assert row['metadataKind'] in (0x200, 0x201)
        actual_layout = struct.unpack('<QQII', read(raws[owner], entry['vwtRVA'] + 64, 24))
        assert actual_layout == (entry['size'], entry['stride'], entry['flags'], entry['extraInhabitants'])
        program = next(x for x in original['programs'] if x['owner'] == owner and x['programRVA'] == entry['programRVA'])
        assert read(raws[owner], entry['programRVA'], program['bytes']) == bytes.fromhex(program['bytesHex'])
        rows.append(row)
    assert len(rows) == 65
    getter = (g.DIRECTORY / 'original-uh-enum-tag-getter.bin').read_bytes()
    assert read(raws['UniversalHID'], 0xcea4, 28) == getter
    header = out / 'modern_swift_hid_observed_cvw_prefix_registry.h'
    header.write_text('#pragma once\nnamespace VM27HIDObservedRegistry {\n' +
        'constexpr size_t DescriptorRVAs[] = {' + ','.join(hex(x['descriptorPrefix']['normalizedTargetRVA']) for x in rows) + '};\n' +
        'constexpr uintptr_t MetadataKinds[] = {' + ','.join(hex(x['metadataKind']) for x in rows) + '};\n}\n')
    report = dict(schema='Original 65 static HID CVW untagged/PAC prefix whitelist v1', inputs=pins,
        generatedRegistry=generated, prefixHeader=p.pin(header), rows=rows,
        originalRelativeFNUsesUntaggedMetadataProgram=True, resolvedPODUsesIndependentTaggedOneGuard=True,
        originalGetterWholeBytesPreserved=True, productionRuntimeIdentityPassed=False,
        originalHIDLoaded=False, deviceOperations=0, nativeIOSExecuted=False, full27Backend=False)
    p.save(out / 'audit.json', report)
    p.save(out / 'freeze.json', dict(files=pins + list(map(p.pin, [x for x in out.rglob('*') if x.is_file()]))))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), originalStaticMetadata=len(rows), headers=[generated['header'], p.pin(header)])))


if __name__ == '__main__': main()
