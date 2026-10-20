#!/usr/bin/env python3
"""Read the genuine UHK scroll timestamp constant and exact original functions.

No original framework, HID factory or device operation executes.
"""
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scroll_p', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('scroll_h', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
IOKIT = '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
UH = '/System/Library/PrivateFrameworks/UniversalHID.framework/Versions/A/UniversalHID'
TIME = '_$s12UniversalHID7HIDTimeV11nanosecondsACSd_tcfC'

def main():
    out = p.NODE / 'iokit-processed-scroll-original-contract-readonly-v2'
    assert not out.exists()
    peer = p.NODE / 'uhk-input-semantic-bridge-design-independent-v1'
    records = json.loads((peer / 'dependencies.json').read_bytes())
    for row in json.loads((peer / 'freeze.json').read_bytes())['files']:
        pin = p.pin(Path(row['path']))
        assert (pin['bytes'], pin['sha256']) == (row['bytes'], row['sha256'])
    islands = [r for r in records['islands'] if r['name'] in (TIME, '_IOHIDEventCreateScrollEvent')]
    assert len(islands) == 2 and all(r['strongRegular'] for r in islands)
    out.mkdir()
    reads, functions, images, pins = [], [], {}, [p.pin(Path(__file__))]
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subcaches = cache.addSubCaches(p.CACHE)
        try:
            genuine = p.GenuineCacheExports(cache)
            def read(address, count, label):
                assert 0 < count <= 2 * 1024 * 1024
                offset, context = cache.convertAddr(address)
                data = context.getBytes(offset, count)
                assert len(data) == count
                path = out / (label + '.bin'); assert not path.exists(); path.write_bytes(data)
                record = dict(address=address, bytes=count, physicalUUID=bytes(context.header.uuid).hex(),
                    offset=offset, purpose=label, data=p.pin(path))
                reads.append(record); pins.append(record['data'])
                return data
            def image(path):
                if path in images: return images[path]
                actual = genuine.image(path)
                prefix = read(actual['base'], 32, Path(path).name + '-prefix')
                commands = read(actual['base'], 32 + struct.unpack_from('<I', prefix, 20)[0], Path(path).name + '-commands')
                link = next(row for row in p.segments(commands) if row['name'] == '__LINKEDIT')
                off, count = next(struct.unpack_from('<II', commands, at + 8) for cmd, at, size in p.commands(commands) if cmd == 0x26)
                encoded = read(link['address'] + off - link['fileoff'], count, Path(path).name + '-function-starts')
                starts, cursor, address = [], 0, actual['base']
                while cursor < len(encoded):
                    delta, cursor = h.uleb(encoded, cursor)
                    if not delta: break
                    address += delta; starts.append(address)
                assert starts == sorted(set(starts)) and encoded[cursor:] == b'\0' * (len(encoded) - cursor)
                images[path] = dict(identity=actual, commands=reads[-2]['data'], functionStarts=reads[-1]['data'], starts=starts)
                return images[path]
            def function(path, address, label):
                owner = image(path)
                index = bisect.bisect_left(owner['starts'], address)
                assert index < len(owner['starts']) - 1 and owner['starts'][index] == address
                end = owner['starts'][index + 1]
                assert 0 < end - address <= 65536
                data = read(address, end - address, label)
                result = dict(owner=path, UUID=owner['identity']['UUID'], begin=address, end=end,
                    exactLC26Bounds=True, data=reads[-1]['data'], instructions=h.decode_body(data, address))
                functions.append(result)
                return result
            for row in islands:
                resolved = genuine.resolve(row['owner'], row['name'])
                assert resolved['exportAddress'] == row['address'] == row['slot']['target']
                assert resolved['exportFlags'] == 0
                actual = image(row['owner'])['identity']
                assert actual['UUID'] == row['ownerUUID']
                function(row['owner'], row['address'], 'timestamp-converter' if row['name'] == TIME else 'scroll-factory')
            constant = read(0x29fdba958, 8, 'uhk-scroll-timestamp-scale')
            scale = struct.unpack('<d', constant)[0]
            p.save(out / 'audit.json', dict(schema='Genuine macOS27 processed scroll original scalar ABI v1',
                originalPeerDependencyPin=p.pin(peer / 'dependencies.json'),
                originalPeerWholeScrollFrame=p.pin(peer / 'read-007.bin'),
                cacheUUID=bytes(cache.header.uuid).hex(), actualImages=images,
                originalResolvedIslands=islands, functions=functions, constant=dict(address=0x29fdba958,
                    actualBytes=constant.hex(), double=scale, read=reads[-1]), freshReads=reads,
                nativeOldHostABIProven=False, nativeOldHostFactoryExecuted=False, sourcePortIntegrated=False,
                deviceOperations=0, nativeHVCalls=0, nativeVMCalls=0, originalLoaded=False, full27Backend=False))
        finally:
            for context in subcaches: context.file.close()
    pins += [p.pin(out / 'audit.json'), p.pin(peer / 'dependencies.json'), p.pin(peer / 'read-007.bin'),
        p.pin(peer / 'freeze.json')]
    p.save(out / 'freeze.json', dict(files=list({r['path']:r for r in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), functions=[dict(begin=f['begin'], bytes=f['end']-f['begin']) for f in functions], scale=scale)))

if __name__ == '__main__': main()
