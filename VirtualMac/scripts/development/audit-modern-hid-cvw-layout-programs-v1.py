#!/usr/bin/env python3
"""Read actual HID CVW layout programs, exact pointer/section mappings only.

This is a bounded schema audit of the observed programs, not an interpreter or
runtime provider. It never loads HID/Core or edits either candidate. The parser
rejects unobserved tags instead of guessing a universal bytecode ABI.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cvw_layout_genuine', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
from swift_relative_metadata import RelativeMetadata
spec = importlib.util.spec_from_file_location('cvw_starts', HERE / 'audit-modern-hid-oldhost-contiguousbytes-v1.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
SOURCE = p.NODE / 'universalhid-typedthrow-real-reexport-data-v1/candidate.json'
TAG_NAMES = {0: 'End', 2: 'NativeStrong', 8: 'Bridge', 10: 'ObjC', 14: 'Existential', 20: 'MultiPayloadEnumFN'}


def inverse(a, address):
    g, s = a.section(address, False)
    targets = [b for x in a.old for b in x['sections'] if x['name'] == g['name'] and b['name'] == s['name']]
    assert len(targets) == 1
    delta = address - s['address']
    assert delta < targets[0]['size']
    return targets[0]['address'] + delta


class Programs:
    def __init__(self, original, candidate):
        self.a = RelativeMetadata(original, candidate)
        self.tags, self.nodes, self.fields = collections.Counter(), [], []
        self.starts = f.function_starts(original)
        self.getters = {}

    def number(self, slot, end):
        assert slot + 8 <= end, ('bounded field extent', hex(slot), hex(end))
        return self.a.read(slot, '<Q')[0]

    def relative(self, slot):
        word = self.a.read(slot, '<i')[0]
        target = slot + word
        _, target_section = self.a.section(target)
        assert target_section['name'] == '__text', ('function target kind', hex(target))
        assert target in self.starts, ('actual complete function start required', hex(target))
        self.a.relative(slot, 'layoutMultiPayloadEnumTagFunction')
        row = self.a.rows[-1]
        assert row['beforeRelative32'] == row['newRelative32'], ('candidate relative function is wrong', row)
        assert self.a.read(slot + 4, '<I')[0] == struct.unpack_from('<I', self.a.rebuilt, self.a.offset(row['newSlot'], False) + 4)[0]
        row = dict(row, storedFieldBytes=8, decodedSignedPayloadBytes=4,
                   high32Preserved=True, sourcePointerAuthentication='IA key 0 discriminator 0')
        self.fields.append(row)
        if target not in self.getters:
            end = self.starts[self.starts.index(target) + 1]
            code = self.a.raw[self.a.offset(target):self.a.offset(target) + end - target]
            mapped = self.a.mapped(target)
            current = self.a.rebuilt[self.a.offset(mapped, False):self.a.offset(mapped, False) + len(code)]
            assert code == current and len(code) <= 65536
            self.getters[target] = dict(originalCacheVA=target, candidateVA=mapped, completeFunctionBytes=len(code),
                nextActualFunctionStart=end, codeSHA256=hashlib.sha256(code).hexdigest(),
                instructionsUnchanged=True, actualLCFunctionStarts=True)

    def sequence(self, begin, end, depth=0):
        assert depth < 8 and begin < end and (end - begin) <= 65536
        at, size, events = begin, 0, []
        while at < end:
            slot = at
            tag_word = self.number(at, end)
            at += 8
            tag, skip = tag_word >> 56, tag_word & ((1 << 56) - 1)
            assert tag in TAG_NAMES, ('unobserved bytecode tag rejected', tag, hex(slot))
            self.tags[TAG_NAMES[tag]] += 1
            size += skip
            event = dict(originalCacheVA=slot, candidateVA=self.a.mapped(slot), tag=tag, name=TAG_NAMES[tag], skippedValueBytes=skip)
            events.append(event)
            if tag == 0:
                assert at == end, ('end tag must finish declared region', hex(at), hex(end))
                self.nodes.append(dict(originalCacheBegin=begin, candidateBegin=self.a.mapped(begin), bytes=end - begin,
                                       nestingDepth=depth, valueBytes=size, events=events))
                return size
            if tag in (2, 8, 10):
                size += 8
            elif tag == 14:
                # BytecodeLayouts.cpp existential* advances NumWords_ValueBuffer
                # (three words); the metadata/witness words remain in End.skip.
                size += 24
            elif tag == 20:
                self.relative(at)
                at += 8
                count, reference_bytes, enum_size = [self.number(at + q * 8, end) for q in range(3)]
                at += 24
                assert 0 < count <= 64 and 0 < enum_size <= 65536 and reference_bytes <= 65536
                offsets = [self.number(at + q * 8, end) for q in range(count)]
                at += count * 8
                assert reference_bytes > 0 and at + reference_bytes <= end
                assert offsets == sorted(set(offsets)) and offsets[0] == 0 and offsets[-1] < reference_bytes
                event.update(payloadCases=count, referenceBytes=reference_bytes, enumValueBytes=enum_size, caseOffsets=offsets)
                nested_sizes = []
                for i, off in enumerate(offsets):
                    limit = offsets[i + 1] if i + 1 < count else reference_bytes
                    nested_sizes.append(self.sequence(at + off, at + limit, depth + 1))
                assert all(q <= enum_size for q in nested_sizes), ('nested case exceeds real enum storage', nested_sizes, enum_size)
                event['actualCaseValueBytes'] = nested_sizes
                at += reference_bytes
                size += enum_size
        raise AssertionError('missing end tag')

    def layout(self, original_address):
        flag, length = self.a.read(original_address, '<2Q')
        assert flag in (0, 1 << 63) and length <= 65536
        total = 16 + length + 8
        begin = original_address + 16
        size = self.sequence(begin, original_address + total)
        old_off = self.a.offset(original_address)
        new_address = self.a.mapped(original_address)
        new_off = self.a.offset(new_address, False)
        old_bytes = self.a.raw[old_off:old_off + total]
        new_bytes = self.a.rebuilt[new_off:new_off + total]
        assert len(old_bytes) == total and old_bytes == new_bytes, 'all actual layout bytes must remain exact'
        return dict(originalCacheVA=original_address, candidateVA=new_address, headerFlagWord=flag,
                    declaredBodyBytes=length, finalEndTagBytes=8, completeStorageBytes=total,
                    decodedValueBytes=size, originalAndCandidateBytesEqual=True,
                    bytesSHA256=hashlib.sha256(old_bytes).hexdigest())


def inspect(name, original, candidate):
    parser = Programs(original, candidate)
    rows = list(p.chain_entries(candidate))
    by_address = {r['address']: r for r in rows}
    imports = {r['index']: r for r in p.imports(candidate)['imports']}
    base = p.segments(candidate)[0]['address']
    witnesses = {r['address']: r for r in rows if r['bind'] and imports[r['import_index']]['name'] == '_swift_cvw_initializeBufferWithCopyOfBuffer'}
    metadata, layouts, incomplete = [], {}, []
    for row in rows:
        if row['bind'] or not row['auth'] or (row['word'] >> 32 & 65535) != 0x2e3f:
            continue
        vwt = base + (row['word'] & 0xffffffff)
        if vwt not in witnesses:
            continue
        assert (row['word'] >> 49 & 3) == 2 and (row['word'] >> 48 & 1)
        address = row['address'] + 8
        table = witnesses[vwt]
        size, stride, flags, extra = struct.unpack_from('<QQII', candidate, table['fileoff'] + 64)
        record = dict(candidateVA=address, originalCacheVA=inverse(parser.a, address), candidateVWT=vwt,
                      size=size, stride=stride, flags=flags, extraInhabitants=extra,
                      vwtDAKey=2, vwtDiscriminator=0x2e3f, vwtAddressDiversity=True)
        if flags & 0x400000:
            assert address - 16 not in by_address
            record['requiresRealRuntimeLayoutCompletion'] = True
            incomplete.append(record)
            continue
        layout = by_address[address - 16]
        assert not layout['bind'] and layout['auth'] and (layout['word'] >> 32 & 65535) == 0x8b65
        assert (layout['word'] >> 49 & 3) == 2 and (layout['word'] >> 48 & 1)
        target = base + (layout['word'] & 0xffffffff)
        assert not target & 1, 'observed complete program has no instantiation marker'
        old_target = inverse(parser.a, target)
        if old_target not in layouts:
            layouts[old_target] = parser.layout(old_target)
        assert layouts[old_target]['decodedValueBytes'] == size
        record.update(candidateLayout=target, originalCacheLayout=old_target,
                      layoutDAKey=2, layoutDiscriminator=0x8b65, layoutAddressDiversity=True)
        metadata.append(record)
    assert len(metadata) == (64 if name == 'UniversalHID' else 1)
    assert len(incomplete) == (1 if name == 'UniversalHID' else 0)
    assert len(layouts) == (36 if name == 'UniversalHID' else 1)
    assert len(witnesses) == len(metadata) + len(incomplete)
    assert not parser.a.unresolved
    return parser, dict(name=name, completedMetadata=metadata, incompleteMetadata=incomplete,
        uniqueLayouts=list(layouts.values()), schemaNodes=parser.nodes, actualTagCounts=dict(parser.tags),
        actualRelativeFunctionFields=parser.fields, actualCompleteTagFunctions=list(parser.getters.values()),
        relativeFunctionFieldsNeedingRelocation=0, observedSchemaComplete=True,
        fullGenericRuntimeBytecodeSchemaImplemented=False, existingCandidateBytesChanged=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    for pin in json.loads((SOURCE.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
    source = json.loads(SOURCE.read_bytes())
    results, inputs, mutations = [], [Path(__file__), Path(f.__file__), HERE / 'swift_relative_metadata.py', SOURCE], []
    vendor = p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag'
    inputs += [vendor / 'Swift-BytecodeLayouts.cpp', vendor / 'Swift-BytecodeLayouts.h', vendor / 'LICENSE.txt']
    for image in source['images']:
        path = Path(image['candidate']['path'])
        original_path = p.NODE / 'universalhid-original-contract-v1/raw' / image['name']
        raw, candidate = original_path.read_bytes(), path.read_bytes()
        parser, result = inspect(image['name'], raw, candidate)
        result.update(original=p.pin(original_path), candidate=p.pin(path))
        results.append(result)
        inputs += [path, original_path]
        # Mutate authentic schema payloads independently of the parser's rows.
        original_layout = result['uniqueLayouts'][0]['originalCacheVA']
        off = parser.a.offset(original_layout)
        cases = [('unknown tag', off + 23, 0xff), ('oversized declared body', off + 15, 0xff),
                 ('changed header', off, 0x23)]
        if parser.fields:
            field = parser.fields[0]
            cases += [('wrong relative tag function', parser.a.offset(field['slot']), 0),
                      ('changed high32 relative payload', parser.a.offset(field['slot']) + 4, 0)]
        for label, at, byte in cases:
            changed = bytearray(raw)
            assert changed[at] != byte
            changed[at] = byte
            rejected = False
            try:
                inspect(image['name'], bytes(changed), candidate)
            except (AssertionError, ValueError, struct.error):
                rejected = True
            assert rejected, label
            mutations.append(dict(image=image['name'], mutation=label, changedFileOffset=at, rejected=True))
    report = dict(schema='Actual HID bounded CVW layout schema and relative function audit v1',
        source=p.pin(SOURCE), images=results, rejectedCounterexamples=mutations,
        candidateVAsAreNormalizedAndSeparateFromOriginalCacheVAs=True,
        priorMatrixOriginalVALabelWasCandidateVA=True,
        priorSlowHelpersAreLazyOverrideResolversNotOldVWTDelegates=True,
        layoutProgramsRequiringPatch=0, allObservedRelativeFunctionTargetsAlreadyCorrect=True,
        incompleteDynamicMetadataRequiresOriginalInitLayoutABI=True,
        cvwCompatibilityOverrideHooksNotClosed=True, newStrongImportsRouted=0,
        full27MetadataPreserved=False, full27Backend=False, candidateReadyForNativeLoading=False,
        deviceOperations=0, nativeIOSExecuted=False, originalHIDLoaded=False, originalVZLoaded=False)
    p.save(out / 'audit.json', report)
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in inputs + [out / 'audit.json']],
        deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), uniqueLayouts=sum(len(x['uniqueLayouts']) for x in results),
        completeMetadata=sum(len(x['completedMetadata']) for x in results),
        relativeFields=sum(len(x['actualRelativeFunctionFields']) for x in results),
        negativeCases=len(mutations), originalBytesPatched=0)))


if __name__ == '__main__':
    main()
