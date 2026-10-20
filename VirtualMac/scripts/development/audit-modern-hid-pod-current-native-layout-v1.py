#!/usr/bin/env python3
"""Join actual current metadata rebases and TypeLayouts, without loading HID."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pod_current_layout_plan', HERE / 'plan-modern-hid-pod-native-type-layout-v1.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)
s, p = plan.s, plan.p
HEADERS = p.NODE / 'ipad-current-cache-pod-leaf-headers-v3/headers.json'
METADATA_PLAN = p.NODE / 'ipad-current-hid-pod-native-metadata-plan-v3/request.json'
METADATA = p.NODE / 'ipad-current-hid-pod-native-metadata-readonly-v1'
LAYOUT_PLAN = p.NODE / 'ipad-current-hid-pod-native-type-layout-plan-v1/request.json'
LAYOUT = p.NODE / 'ipad-current-hid-pod-native-type-layout-readonly-v1'
POD = p.NODE / 'universalhid-pod-layout-real-reexport-data-v2/candidate.json'
ABI = p.NODE / 'universalhid-pod-layout-original-abi-readonly-v6/audit.json'
BUILD = p.NODE / 'swift-hid-pod-layout-data-build-v9/candidate.json'
REVIEW = p.NODE / 'hid-pod-leaf-independent-review-v1/review.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def frozen(source):
    files = json.loads((source.parent / 'freeze.json').read_bytes())['files']
    for row in files:
        require(p.pin(Path(row['path'])) == row, 'unchanged frozen input: ' + row['path'])
    return files


def slot(raw, add, discriminator):
    require(raw >> 63 == 1, 'authenticated actual slide3 rebase')
    require((raw >> 49) & 3 == 2, 'actual DA2 key')
    require((raw >> 48) & 1 == 1, 'actual address diversity')
    require((raw >> 32) & 0xffff == discriminator, 'actual type discriminator')
    return dict(raw=hex(raw), actualTarget=add + (raw & 0xffffffff), key=2,
                addressDiversity=True, diversity=discriminator, nextBytes=((raw >> 51) & 0x7ff) * 8)


def type_layout(body, expected):
    require(len(body) == 24, 'exact TypeLayout byte count')
    result = struct.unpack('<QQII', body)
    require(result == expected, 'actual supported native field layout')
    return dict(size=result[0], stride=result[1], flags=result[2], extraInhabitants=result[3])


def mapped(heads, address, length):
    matches = [(row, mapping) for row in heads['headers'] for mapping in row['maps']
               if mapping['address'] <= address and address + length <= mapping['address'] + mapping['size']]
    require(len(matches) == 1, 'unique actual current containing mapping')
    row, mapping = matches[0]
    require(row['name'] == '27-data', 'actual physical .27.dylddata member')
    return mapping['fileOffset'] + address - mapping['address']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'new inert local audit directory')
    out.mkdir()
    inputs = [Path(__file__), Path(plan.__file__), Path(s.__file__), HEADERS,
              METADATA_PLAN, LAYOUT_PLAN, POD, ABI, BUILD, REVIEW]
    freeze_pins = []
    for source in (LAYOUT_PLAN, POD, ABI, BUILD, REVIEW):
        freeze_pins += frozen(source)
    # Validate the real transport, fixed source, requested ranges, decoded bytes,
    # and before/after header guards independently of the archive's pointers.
    s.checked_capture(METADATA, METADATA_PLAN, HEADERS)
    s.checked_capture(LAYOUT, LAYOUT_PLAN, HEADERS)
    heads = json.loads(HEADERS.read_bytes())
    require(heads['mainUUID'] == '1995ea169d0a33a0b78962cf99891168' and len(heads['headers']) == 10, 'current ten-member header set')
    physical = next(x for x in heads['headers'] if x['name'] == '27-data')
    require(physical['UUID'] == '08193a3ab05d3ab2a931a09d2a1dc98a' and
            physical['sha256'] == '8276c3e17b75e5ebd24a7b5f524ebc23df555f10459f6154466e2c80687066a1', 'current .27.dylddata identity')
    slide_path = METADATA / 'native-metadata-mapping-slide-header.bin'
    version, page_size, page_count, padding, add = struct.unpack('<4IQ', slide_path.read_bytes())
    require((version, page_size, page_count, padding, add) == (3, 4096, 9328, 0, 0x180000000), 'actual metadata mapping slide3 header')
    images = s.primary.captured_images()
    requests = json.loads(LAYOUT_PLAN.read_bytes())['ranges']
    records = []
    negatives = []
    for name, owner, symbol, metadata_va, expected in (
        ('foundation-uuid', '/System/Library/Frameworks/Foundation.framework/Foundation', '_$s10Foundation4UUIDVN', 0x1de611370, (16, 16, 0, 0)),
        ('swiftcore-uint64', '/usr/lib/swift/libswiftCore.dylib', '_$ss6UInt64VN', 0x1de5e6b50, (8, 8, 7, 0))):
        image = images[owner]
        header = Path(image['header']['path'])
        trie = Path(image['trie']['path'])
        text = next(x for x in p.segments(header.read_bytes()) if x['name'] == '__TEXT')
        export = image['exports'][symbol]
        require(export['flags'] == 0 and text['address'] + export['offsetOrAbsoluteAddress'] == metadata_va, 'actual stock export selects exact metadata')
        metadata_path = METADATA / (name + '-metadata.bin')
        layout_path = LAYOUT / (name + '-type-layout.bin')
        pointer, kind, descriptor = struct.unpack('<3Q', metadata_path.read_bytes())
        require(kind == 0x200, 'actual struct metadata kind')
        vwt, context = slot(pointer, add, 0x2e3f), slot(descriptor, add, 0xae86)
        require(vwt['nextBytes'] == 16, 'actual VWT-to-descriptor cache chain')
        layout_va = vwt['actualTarget'] + 64
        requested = next(x for x in requests if x['name'] == name + '-type-layout')
        require(requested == dict(name=name + '-type-layout', cache='27-data', offset=mapped(heads, layout_va, 24), length=24), 'actual rebased VWT +64 request')
        record = type_layout(layout_path.read_bytes(), expected)
        records.append(dict(name=name, currentImageUUID=image['UUID'], actualExport=symbol,
            actualMetadataVA=metadata_va, actualMetadata=p.pin(metadata_path), actualVWT=vwt,
            actualDescriptor=context, actualTypeLayoutVA=layout_va, actualTypeLayout=p.pin(layout_path),
            currentTypeLayout=record, requestedRange=requested, actualExportHeader=p.pin(header), actualExportTrie=p.pin(trie)))
        inputs += [header, trie, metadata_path, layout_path]
        for label, bit in (('unauthenticated', 63), ('wrong data key', 49), ('no address diversity', 48), ('wrong VWT discriminator', 32)):
            try:
                slot(pointer ^ (1 << bit), add, 0x2e3f)
            except ValueError:
                negatives.append(dict(name=name + ' ' + label, rejected=True))
            else:
                raise ValueError('accepted corrupt metadata authentication')
        for index, field in enumerate(('size', 'stride', 'flags', 'extra')):
            damaged = list(expected)
            damaged[index] ^= 1
            try:
                type_layout(struct.pack('<QQII', *damaged), expected)
            except ValueError:
                negatives.append(dict(name=name + ' unsupported ' + field, rejected=True))
            else:
                raise ValueError('accepted unsupported native field')
        for body in (layout_path.read_bytes()[:-1], layout_path.read_bytes() + b'\0'):
            try:
                type_layout(body, expected)
            except ValueError:
                negatives.append(dict(name=name + ' wrong TypeLayout length ' + str(len(body)), rejected=True))
            else:
                raise ValueError('accepted non-TypeLayout span')
    fields = records[0]['currentTypeLayout'], records[1]['currentTypeLayout']
    require(fields[0]['flags'] == 0 and fields[1]['flags'] == 7, 'actual old-host POD flags')
    require(fields[0]['size'] + fields[1]['size'] == 24, 'actual ordered UUID UInt64 POD size')
    source = p.ROOT / 'VirtualMac/vz/host/modern_swift_hid_pod_layout_compat.cpp'
    inputs.append(source)
    code = source.read_text()
    require('first.size != 16 || first.stride != 16' in code and 'second.size != 8 || second.stride != 8 || second.flags != 7' in code,
            'unchanged genuine field guard accepts the two actual native layouts')
    report = dict(schema='Actual current iPad UUID UInt64 POD TypeLayout evidence v1',
        originalPODCandidate=p.pin(POD), originalPODBuild=p.pin(BUILD), originalABI=p.pin(ABI), independentLocalReview=p.pin(REVIEW),
        currentHeaders=p.pin(HEADERS), actualMetadataReceipt=p.pin(METADATA / 'receipt.json'), actualTypeLayoutReceipt=p.pin(LAYOUT / 'receipt.json'),
        actualSlideHeader=p.pin(slide_path), actualAuthValueAdd=add, records=records, negativeControls=negatives,
        actualCurrentIOSUUIDAndUInt64TypeLayoutsRead=True, productionFieldGuardMatchesActualCurrentTypeLayouts=True,
        expectedOriginalHIDCompletedPODLayout=dict(size=24, stride=24, flags=7, extraInhabitants=0, fieldOffsets=[0, 16]),
        expectedOriginalHIDCompletedLayoutIsPredictionNotExecution=True, archivePointersUsed=False,
        actualCurrentOldNativeInitializer1180BAndCommonWitness988BRead=True,
        originalHIDInitializerExecuted=False, productionHIDIdentityGatePassed=False,
        twoKernelLeafDefinitionsStillUncaptured=True, fullProviderGraphValidated=False,
        generalCVWInterpreterProvided=False, fullSwift27RuntimeEquivalent=False,
        candidateReadyForNativeLoading=False, originalHIDLoaded=False, nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    for capture in (METADATA, LAYOUT):
        inputs += [capture / name for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]
    inputs += [slide_path, out / 'audit.json']
    unique = {x['path']: x for x in freeze_pins + [p.pin(x) for x in inputs]}
    p.save(out / 'freeze.json', dict(files=list(unique.values()), deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), negativeControls=len(negatives), actualTypeLayouts=[r['currentTypeLayout'] for r in records])))


if __name__ == '__main__':
    main()
