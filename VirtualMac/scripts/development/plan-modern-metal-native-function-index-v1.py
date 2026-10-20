#!/usr/bin/env python3
"""Request only the current genuine Metal function index from actual load commands."""
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
from current_vz_eight_capture_v2 import join
from current_hid_extra_three_capture_v1 import mapping


def main():
    n = p.NODE
    out = n/'ipad-current-metal-native-function-index-plan-v1'
    assert not out.exists()
    images = {}
    pins = s.join_capture(images, 'system', n/'ipad-current-cache-system-headers-v1/headers.json')
    added, proof = join(s, images)
    pins += added
    image = images[s.primary.canonical_path('/System/Library/Frameworks/Metal.framework/Metal')]
    declared = next(x for x in proof['actualCommandAndExportProofs'] if x['path'] == image['path'])
    hp = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers = json.loads(hp.read_bytes())
    raw = Path(image['header']['path']).read_bytes()
    assert image['UUID'] == '8f062125748839efafda57db8cd80033'
    indices = [dict(commandVA=declared['base']+at, originalDataOffset=off, length=length)
               for cmd, at, size in p.commands(raw) if cmd == 0x26
               for off, length in [struct.unpack_from('<II', raw, at+8)]]
    assert len(indices) == 1 and indices[0]['length'] == 10576
    entry = indices[0]
    link = next(x for x in p.segments(raw) if x['name'] == '__LINKEDIT')
    va = link['address']+entry['originalDataOffset']-link['fileoff']
    mapped = mapping(headers, va, entry['length'])
    assert mapped['cache'] == '44-linkedit'
    definition = image['exports']['_MTLCreateSystemDefaultDevice']
    assert definition['flags'] == 0 and '_MTLCopyAllDevices' not in image['exports']
    assert not [dep for dep in image['dependencies'] if dep['command'] == 0x8000001f]
    row = dict(name='metal-function-starts', **mapped)
    out.mkdir(mode=0o700)
    p.save(out/'request.json', dict(ranges=[row]))
    p.save(out/'derivation.json', dict(schema='Actual current native Metal LC26 index request v1',
        currentHeaders=p.pin(hp), actualMetalCommands=image['header'], actualMetalTrie=image['trie'],
        actualInventoryRow=declared['actualInventoryRow'], actualMetalUUID=image['UUID'],
        LC26=entry, linkeditMapping=link, indexVA=va, request=row,
        actualNativeDefaultDeviceDefinition=definition,
        actualNativeDefaultDeviceAddress=declared['base']+definition['offsetOrAbsoluteAddress'],
        allDevicesActualAbsent=True, noNativeMetalReexports=True,
        exactNativeHelperBoundsNotYetRead=True, deviceOperations=0, nativeCPUCalls=0,
        frameworkLoads=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [hp, Path(__file__), out/'request.json', out/'derivation.json', out/'source.py']]
    p.save(out/'freeze.json', dict(files=list({x['path']: x for x in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), freeze=p.pin(out/'freeze.json'), range=row)))


if __name__ == '__main__':
    main()
