#!/usr/bin/env python3
"""Derive one bounded current IOKit LC26 read from actual complete commands."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_current_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
from current_hid_extra_three_capture_v1 import join, mapping
p = s.p


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    images = {}
    pins, proof = join(s, images)
    key = '/System/Library/Frameworks/IOKit.framework/IOKit'
    image = images[key]
    raw = Path(image['header']['path']).read_bytes()
    records = [struct.unpack_from('<II', raw, at + 8) for cmd, at, size in p.commands(raw) if cmd == 0x26]
    assert records == [(106922264, 4784)]
    link = next(x for x in p.segments(raw) if x['name'] == '__LINKEDIT')
    va = link['address'] + records[0][0] - link['fileoff']
    headers = p.NODE / 'ipad-current-cache-pod-leaf-headers-v3/headers.json'
    row = dict(name='iokit-function-starts', **mapping(json.loads(headers.read_bytes()), va, records[0][1]))
    assert row == dict(name='iokit-function-starts', cache='44-linkedit', offset=106922264, length=4784)
    out.mkdir()
    p.save(out / 'request.json', dict(ranges=[row]))
    p.save(out / 'derivation.json', dict(schema='Actual current IOKit LC26 helper ABI index request v1',
        actualCurrentImage=dict(path=image['path'], UUID=image['UUID'], commands=image['header']),
        currentHeaders=p.pin(headers), actualLC26=records[0], actualLC26VA=va,
        request=p.pin(out / 'request.json'), exactNamedDefinition=image['exports']['__IOHIDEventCreate'],
        originalConstructorBodiesAvailable=True, currentHelperABIProven=False, currentHelperExecuted=False,
        currentInitializerAndObjectLayoutProven=False, deviceOperations=0, full27Backend=False))
    pins += [p.pin(Path(__file__)), p.pin(out / 'request.json'), p.pin(out / 'derivation.json')]
    p.save(out / 'freeze.json', dict(files=list({x['path']:x for x in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out / 'request.json'), ranges=[row], headers=p.pin(headers))))


if __name__ == '__main__':
    main()
