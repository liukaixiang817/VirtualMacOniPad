#!/usr/bin/env python3
"""Derive bounded old-host selector/class requests from actual allocator bytes.

The class slot and slide header are requests, not evidence of their targets.
Only an archived 4096-byte header identical to the actual guarded member is
used to locate the slide header and the page-start entry.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_init_s', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
from current_hid_extra_three_capture_v1 import mapping
from DyldExtractor.dyld.dyld_structs import dyld_cache_header
p = s.p
spec = importlib.util.spec_from_file_location('iokit_init_h', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


def branch(pc, word):
    displacement = (word & 0x3ffffff) << 2
    return pc + displacement - (0x10000000 if displacement & 0x8000000 else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path = p.NODE / 'ipad-current-cache-swift-leaf-headers-v1/headers.json'
    heads = json.loads(heads_path.read_bytes())
    capture = p.NODE / 'ipad-current-swift-iokit-stackprobe-readonly-v1'
    request = p.NODE / 'ipad-current-swift-iokit-stackprobe-plan-v1/request.json'
    receipt = s.checked_capture(capture, request, heads_path)
    assert receipt['readerSHA256'] == p.pin(capture / 'reader-source.py')['sha256'] == '6cb61cbad0775c70b229f6c25fca4305bcb35c640c3f492bac6fc5954193f922'
    allocator_path = capture / 'iokit-event-allocate-complete.bin'
    raw = allocator_path.read_bytes()
    assert len(raw) == 100
    words = struct.unpack('<25I', raw)
    assert words[9:12] == (0xaa0003e2, 0x9025d8e8, 0xf941c100)
    assert words[12] & 0xfc000000 == 0x94000000 and words[24] & 0xfc000000 == 0x14000000
    allocate_island = branch(0x18ec74aa0, words[12])
    initialize_island = branch(0x18ec74ad0, words[24])
    assert (allocate_island, initialize_island) == (0x18ed2efa0, 0x18ed2efe0)
    class_slot = 0x1da790000 + ((words[11] >> 10) & 0xfff) * 8
    assert class_slot == 0x1da790380
    requests = [dict(name=name, **mapping(heads, va, size)) for name, va, size in (
        ('iokit-allocate-selector-island', allocate_island, 16),
        ('iokit-initialize-selector-island', initialize_island, 16),
        ('iokit-event-class-reference', class_slot, 8))]
    archive = p.NODE.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin'
    archived = archive.read_bytes()[27 * 4096:28 * 4096]
    physical = next(row for row in heads['headers'] if row['name'] == '27-data')
    import hashlib
    assert hashlib.sha256(archived).hexdigest() == physical['sha256']
    assert archived[88:104].hex() == physical['UUID'] == '08193a3ab05d3ab2a931a09d2a1dc98a'
    header = dyld_cache_header.from_buffer_copy(archived)
    assert header.mappingWithSlideCount == 6
    slide_maps = []
    for index in range(header.mappingWithSlideCount):
        at = header.mappingWithSlideOffset + index * h.dyld_cache_mapping_and_slide_info.SIZE
        item = h.dyld_cache_mapping_and_slide_info.from_buffer_copy(archived[at:])
        slide_maps.append({key: getattr(item, key) for key, _ in item._fields_})
    matched = [row for row in slide_maps if row['address'] <= class_slot < row['address'] + row['size']]
    assert len(matched) == 1
    slide_map = matched[0]
    assert slide_map['address'] == 7959199744 and slide_map['slideInfoFileOffset'] == 179814400
    # This current cache's previously captured slide3 schemas use 4096-byte
    # pages. The new mapping's actual header must confirm it before decoding.
    page = (class_slot - slide_map['address']) // 4096
    assert page == 276 and class_slot % 4096 == 0x380
    requests += [dict(name='iokit-class-mapping-slide-header', cache='27-data', offset=slide_map['slideInfoFileOffset'], length=24),
                 dict(name='iokit-class-reference-page-start', cache='27-data', offset=slide_map['slideInfoFileOffset'] + 24 + page * 2, length=2)]
    assert len(requests) == 5 and sum(row['length'] for row in requests) == 66
    assert requests[0]['cache'] == requests[1]['cache'] == '05' and requests[2]['cache'] == '27-data'
    out.mkdir()
    p.save(out / 'request.json', dict(ranges=requests))
    p.save(out / 'derivation.json', dict(schema='Actual old IOKit allocator to initializer selectors and class slot request v1',
        actualAllocator=p.pin(allocator_path), actualCaptureReceipt=p.pin(capture / 'receipt.json'),
        actualHeaders=p.pin(heads_path), allocatorVA=0x18ec74a70, allocatorLength=100,
        actualAllocateBranch=dict(pc=0x18ec74aa0, word=words[12], target=allocate_island),
        actualInitializeTailBranch=dict(pc=0x18ec74ad0, word=words[24], target=initialize_island),
        actualClassSlotInstructions=dict(adrpWord=words[10], ldrWord=words[11], slot=class_slot),
        guardedExactHeaderOnlyUsedForSlideLocation=True, archivedClassPointerOrBodyUsed=False,
        requestedSlideMapping=slide_map, expectedPageSizeMustBeConfirmedByActualHeader=4096,
        pageIndex=page, request=p.pin(out / 'request.json'), requestedBytes=66,
        initializerSelectorAndClassTargetProven=False, oldInitializerNewTypeAcceptanceProven=False,
        originalHIDLoaded=False, nativeIOSExecuted=False, deviceOperations=0, full27Backend=False))
    pins = [p.pin(x) for x in (Path(__file__), Path(s.__file__), Path(h.__file__), heads_path, request,
            allocator_path, archive, out / 'request.json', out / 'derivation.json')]
    pins += [p.pin(capture / name) for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]
    p.save(out / 'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(request=p.pin(out / 'request.json'), headers=p.pin(heads_path), ranges=requests)))


if __name__ == '__main__': main()
