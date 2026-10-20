#!/usr/bin/env python3
"""Derive a fixed .09 header identity request from the actual main subcache table."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('current_stock', HERE/'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
from DyldExtractor.dyld.dyld_structs import dyld_cache_header
from current_hid_extra_three_capture_v1 import inventory, join, mapping


def main():
    n = p.NODE
    out = n/'ipad-current-hid-trace-member-header-plan-v1'
    assert not out.exists()
    pins, _ = join(s, {})
    hp = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers = json.loads(hp.read_bytes())
    assert len(headers['headers']) == 13
    archive = n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    archived = archive.read_bytes()
    tail = n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    prefix = archived[:4096]
    actual_main = prefix + tail.read_bytes()
    rows = inventory(prefix, tail.read_bytes(), headers)
    image = [x for x in rows if x['path'] == '/usr/lib/system/libsystem_trace.dylib']
    assert len(image) == 1
    image = image[0]
    h = dyld_cache_header.from_buffer_copy(actual_main)
    assert h.subCacheArrayCount == 44 and h.subCacheArrayOffset == 167024
    records = []
    for index in range(h.subCacheArrayCount):
        at = h.subCacheArrayOffset + 56 * index
        uuid, vmoffset, suffix = struct.unpack_from('<16sQ32s', actual_main, at)
        assert b'\0' in suffix
        suffix = suffix.split(b'\0')[0].decode()
        records.append(dict(index=index, actualMainRecordOffset=at, rawRecord=actual_main[at:at+56].hex(),
                            UUID=uuid.hex(), cacheVMOffset=vmoffset, suffix=suffix))
    record = [r for r in records if r['suffix'] == '.09']
    assert len(record) == 1
    record = record[0]
    assert record['UUID'] == 'a0382d94e343309f9c547d8ac8bb852b'
    raw = archived[9*4096:10*4096]
    header = dyld_cache_header.from_buffer_copy(raw)
    assert bytes(header.uuid).hex() == record['UUID']
    assert hashlib.sha256(raw).hexdigest() == 'd120bffcc61c867c8c6e4f6fa478c0a30f85c9b43744cb37dbabf55f4834c28b'
    maps = [dict(address=address, size=size, fileOffset=offset, maxProt=maxprot, initProt=initprot)
            for address, size, offset, maxprot, initprot in
            (struct.unpack_from('<3Q2I', raw, header.mappingOffset + i*32) for i in range(header.mappingCount))]
    assert len(maps) == 1 and maps[0]['address'] == 0x180000000 + record['cacheVMOffset']
    assert maps[0]['address'] <= image['address'] and image['address']+4096 <= maps[0]['address']+maps[0]['size']
    try:
        mapping(headers, image['address'], 4096)
    except AssertionError:
        pass
    else:
        raise AssertionError('trace header unexpectedly current')
    member = '/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'+record['suffix']
    out.mkdir(mode=0o700)
    (out/'archive-expected-member-header.bin').write_bytes(raw)
    p.save(out/'request.json', dict(schema='Fixed current cache member header identity request v1',
        fixedFiles=[dict(name='main', path=member[:-3], offset=0, length=4096,
                        expectedUUID=headers['mainUUID'], expectedHeaderSHA256=hashlib.sha256(prefix).hexdigest()),
                    dict(name='09', path=member, offset=0, length=4096,
                         expectedUUID=record['UUID'], expectedHeaderSHA256=hashlib.sha256(raw).hexdigest())],
        requestedBytes=8192, currentMemberDataNotRequested=True,
        requireNonSymlinkRegularFileAndMainMemberBeforeAfterGuards=True))
    p.save(out/'derivation.json', dict(schema='Current main subcache identity and archived .09 request derivation v1',
        actualMainRecord=record, actualTraceInventoryRow=image, currentHeaders=p.pin(hp),
        actualMainTail=p.pin(tail), mainPrefix4096EqualsCurrentHeader=True,
        archivedMemberExpectedHeader=p.pin(out/'archive-expected-member-header.bin'),
        archivedMappingForRequestOnly=maps, archivedHeaderSourceByteOffset=9*4096,
        currentMemberHeaderCaptured=False, currentTraceCommandsOrExportsCaptured=False,
        deviceOperations=0, frameworkLoads=0, nativeCPUCalls=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [hp, archive, tail, Path(__file__), out/'archive-expected-member-header.bin',
                                    out/'request.json', out/'derivation.json', out/'source.py']]
    p.save(out/'freeze.json', dict(files=list({x['path']: x for x in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), freeze=p.pin(out/'freeze.json'), member=member,
                          expectedUUID=record['UUID'], expectedHeaderSHA256=hashlib.sha256(raw).hexdigest())))


if __name__ == '__main__':
    main()
