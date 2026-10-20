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
    out = p.NODE / 'iokit-processed-scroll-original-contract-readonly-v8'
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
                text_section = next(r for r in h.sections(commands) if r['name'] == '__text')
                text_end = text_section['address'] + text_section['bytes']
                assert starts[-1] < text_end
                images[path] = dict(identity=actual, commands=reads[-2]['data'], functionStarts=reads[-1]['data'], starts=starts, textEnd=text_end)
                return images[path]
            def function(path, address, label):
                owner = image(path)
                index = bisect.bisect_right(owner['starts'], address) - 1
                assert 0 <= index < len(owner['starts'])
                requested = address
                address = owner['starts'][index]
                end = owner['starts'][index + 1] if index + 1 < len(owner['starts']) else owner['textEnd']
                assert 0 < end - address <= 65536
                data = read(address, end - address, label)
                result = dict(owner=path, UUID=owner['identity']['UUID'], begin=address, end=end,
                    exactLC26Begin=True, endFromNextLC26OrActualTextEnd=True, requestedAddress=requested, data=reads[-1]['data'], instructions=h.decode_body(data, address))
                functions.append(result)
                return result
            for row in islands:
                resolved = genuine.resolve(row['owner'], row['name'])
                assert resolved['exportAddress'] == row['address'] == row['slot']['target']
                assert resolved['exportFlags'] == 0
                actual = image(row['owner'])['identity']
                assert actual['UUID'] == row['ownerUUID']
                function(row['owner'], row['address'], 'timestamp-converter' if row['name'] == TIME else 'scroll-factory')
            direct_edges = []
            seen = {f['begin'] for f in functions}
            for source in list(functions):
                raw = Path(source['data']['path']).read_bytes()
                for at in range(0, len(raw), 4):
                    word = struct.unpack_from('<I', raw, at)[0]
                    if word & 0x7c000000 != 0x14000000: continue
                    delta = (word & 0x3ffffff) << 2
                    if delta & 0x8000000: delta -= 0x10000000
                    target = source['begin'] + at + delta
                    owner = images[source['owner']]
                    if not owner['starts'][0] <= target <= owner['starts'][-1]:
                        direct_edges.append(dict(pc=source['begin']+at, target=target, ownerUnknown=True))
                        continue
                    index = bisect.bisect_right(owner['starts'], target) - 1
                    begin = owner['starts'][index]
                    direct_edges.append(dict(pc=source['begin']+at, target=target, owner=source['owner'], exactLC26Begin=begin))
                    if begin not in seen:
                        assert len(functions) < 12
                        frame = function(source['owner'], target, 'direct-' + hex(begin)[2:])
                        assert frame['end'] - frame['begin'] <= 4096
                        seen.add(begin)
            function(UH, 0x29fd88a5c, 'timestamp-once-initializer')
            function('/System/Library/PrivateFrameworks/UniversalHIDKit.framework/Versions/A/UniversalHIDKit',
                0x29fdba738, 'uhk-scroll-contact-phase-converter')
            second_depth_edges = []
            for source in list(functions)[2:]:
                raw = Path(source['data']['path']).read_bytes()
                for at in range(0, len(raw), 4):
                    word = struct.unpack_from('<I',raw,at)[0]
                    if word & 0x7c000000 != 0x14000000: continue
                    delta=(word & 0x3ffffff) << 2
                    if delta & 0x8000000: delta -= 0x10000000
                    target=source['begin']+at+delta
                    owner=images[source['owner']]
                    if not owner['starts'][0] <= target <= owner['starts'][-1]:
                        second_depth_edges.append(dict(pc=source['begin']+at,target=target,ownerUnknown=True)); continue
                    index=bisect.bisect_right(owner['starts'],target)-1;begin=owner['starts'][index]
                    second_depth_edges.append(dict(pc=source['begin']+at,target=target,owner=source['owner'],exactLC26Begin=begin))
                    if begin not in seen:
                        assert len(functions)<20
                        frame=function(source['owner'],target,'second-direct-'+hex(begin)[2:])
                        assert frame['end']-frame['begin']<=4096
                        seen.add(begin)
            constant = read(0x29fdba958, 8, 'uhk-scroll-timestamp-scale')
            scale = struct.unpack('<d', constant)[0]
            p.save(out / 'audit.json', dict(schema='Genuine macOS27 processed scroll original scalar ABI v1',
                originalPeerDependencyPin=p.pin(peer / 'dependencies.json'),
                originalPeerWholeScrollFrame=p.pin(peer / 'read-007.bin'),
                cacheUUID=bytes(cache.header.uuid).hex(), actualImages={key:dict(
                    identity={k:r["identity"][k] for k in ("path", "UUID", "base")},
                    commands=r["commands"], functionStarts=r["functionStarts"], actualStartCount=len(r["starts"]))
                    for key,r in images.items()},
                originalResolvedIslands=islands, functions=functions, firstDepthActualDirectEdges=direct_edges, secondDepthActualDirectEdges=second_depth_edges,
                recursiveCalleeClosureProven=False, constant=dict(address=0x29fdba958,
                    actualBytes=constant.hex(), double=scale, read=reads[-1]), freshReads=reads,
                nativeOldHostABIProven=False, nativeOldHostFactoryExecuted=False, sourcePortIntegrated=False,
                deviceOperations=0, nativeHVCalls=0, nativeVMCalls=0, originalLoaded=False, full27Backend=False))
        finally:
            for context in subcaches: context.close()
    pins += [p.pin(out / 'audit.json'), p.pin(peer / 'dependencies.json'), p.pin(peer / 'read-007.bin'),
        p.pin(peer / 'freeze.json')]
    p.save(out / 'freeze.json', dict(files=list({r['path']:r for r in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), functions=[dict(begin=f['begin'], bytes=f['end']-f['begin']) for f in functions], scale=scale)))

if __name__ == '__main__': main()
