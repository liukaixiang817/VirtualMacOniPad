#!/usr/bin/env python3
"""Bound old-host IOKit helpers by the actual captured LC26 function index."""
import argparse
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_native_s', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
from current_hid_extra_three_capture_v1 import join, mapping
p = s.p


def decode(data, base):
    starts, at, address = [], 0, base
    while at < len(data):
        delta = 0
        for shift in range(0, 70, 7):
            assert at < len(data)
            byte = data[at]; at += 1
            assert shift < 63 or byte <= 1
            delta |= (byte & 127) << shift
            if not byte & 128: break
        else: raise ValueError('LC26 uint64 overflow')
        if not delta:
            assert data[at:] == b'\0' * (len(data) - at)
            break
        address += delta
        assert base < address < base + 2 * 1024 * 1024 and address % 4 == 0
        starts.append(address)
    assert starts and starts == sorted(set(starts))
    return starts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    images = {}
    pins, stock = join(s, images)
    image = images['/System/Library/Frameworks/IOKit.framework/IOKit']
    raw = Path(image['header']['path']).read_bytes()
    text = next(x for x in p.segments(raw) if x['name'] == '__TEXT')
    capture_headers = p.NODE / 'ipad-current-cache-pod-leaf-headers-v3/headers.json'
    headers_path = p.NODE / 'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    headers = json.loads(headers_path.read_bytes())
    captured = p.NODE / 'ipad-current-static-cn-iokit-extra-readonly-v1'
    request = p.NODE / 'ipad-current-static-cn-iokit-extra-plan-v1/request.json'
    receipt = s.checked_capture(captured, request, capture_headers)
    assert receipt['readerSHA256'] == p.pin(captured / 'reader-source.py')['sha256']
    rows = [x for x in receipt['ranges'] if x['name'] == 'iokit-function-starts']
    assert len(rows) == 1
    assert {k:rows[0][k] for k in ('cache','offset','length')} == dict(cache='44-linkedit',offset=106922264,length=4784)
    original_request = p.NODE / 'ipad-current-iokit-native-helper-index-plan-v1/request.json'
    assert rows[0]['name'] == json.loads(original_request.read_bytes())['ranges'][0]['name']
    assert all(rows[0][key] == json.loads(original_request.read_bytes())['ranges'][0][key] for key in ('cache','offset','length'))
    index_file = Path(rows[0]['path'])
    starts = decode(index_file.read_bytes(), text['address'])
    current_request = p.NODE / 'ipad-current-iokit-processed-scroll-native-entries-plan-v2/request.json'
    current_capture = p.NODE / 'ipad-current-iokit-processed-scroll-native-entries-readonly-v1'
    current_receipt = s.checked_capture(current_capture, current_request, headers_path)
    current_derivation = json.loads((p.NODE / 'ipad-current-iokit-processed-scroll-native-entries-plan-v2/derivation.json').read_bytes())
    requests, methods = [], []
    for symbol, name, address in [('_IOHIDEventCreateScrollEvent','iokit-current-scroll-common-complete',0x18ecbfee8),
                                   ('_IOHIDEventGetFloatValue','iokit-current-float-common-complete',0x18ec772c8)]:
        prior = next(row for row in current_derivation['functions'] if row['symbol'] == symbol)
        raw = (current_capture / (prior['request']['name'] + '.bin')).read_bytes()
        at = len(raw) - 4
        word = struct.unpack_from('<I', raw, at)[0]
        assert word & 0xfc000000 == 0x14000000
        delta = (word & 0x3ffffff) << 2
        if delta & 0x8000000: delta -= 0x10000000
        assert prior['start'] + at + delta == address
        index = bisect.bisect_left(starts, address)
        assert index < len(starts) - 1 and starts[index] == address
        end = starts[index + 1]
        assert 0 < end - address <= 65536
        row = dict(name=name, **mapping(headers, address, end - address))
        assert row['cache'] == '05'
        requests.append(row)
        methods.append(dict(symbol=symbol, start=address, end=end, exactActualLC26Boundary=True, request=row))
    negatives = []
    for label, bad in [('truncated ULEB',b'\x80'),('overflow ULEB',b'\xff'*10),
                       ('data after terminator',b'\0\x01'),('unaligned function start',b'\x01\0'),
                       ('empty index',b'\0')]:
        try: decode(bad, text['address'])
        except (AssertionError, ValueError): negatives.append(dict(name=label,rejected=True))
        else: raise AssertionError('accepted malformed LC26: '+label)
    out.mkdir()
    p.save(out / 'request.json', dict(ranges=requests))
    p.save(out / 'derivation.json', dict(schema='Current IOKit processed scroll genuine direct callee request v1',
        currentImage=dict(path=image['path'],UUID=image['UUID'],commands=image['header']),
        actualIndex=p.pin(index_file), actualIndexReadReceipt=p.pin(captured/'receipt.json'),
        currentHeaders=p.pin(headers_path), actualFunctionStarts=len(starts), functions=methods,
        actualCallerDerivation=p.pin(p.NODE / "ipad-current-iokit-processed-scroll-native-entries-plan-v2/derivation.json"),
        actualCallerCaptureReceipt=p.pin(current_capture / "receipt.json"),
        actualCallerBytes=[p.pin(current_capture / (r["request"]["name"] + ".bin")) for r in current_derivation["functions"]],
        LC26NegativeControls=negatives, request=p.pin(out/'request.json'),
        nativeScrollFloatingABIProven=False, nativeScrollOwnedReturnAndReleaseProven=False,
        nativeTimestampClockOriginProven=False, originalUHKSourcePortIntegrated=False,
        reader=p.pin(HERE / 'read-ipad-current-cache-ranges-readonly-v10.py'),
        actualOldIndexCaptureHeaders=p.pin(capture_headers), currentObjectDataLayoutProven=False,
        currentBodyBytesRead=False, deviceOperations=0, nativeHVCalls=0, full27Backend=False))
    pins += [p.pin(current_capture / name) for name in ('receipt.json','manifest.json','reader-source.py','script.sh','stdout','stderr')]
    pins += [p.pin(current_request),p.pin(p.NODE / 'ipad-current-iokit-processed-scroll-native-entries-plan-v2/derivation.json')]
    pins += [p.pin(current_capture / (r['request']['name'] + '.bin')) for r in current_derivation['functions']]
    pins += [p.pin(Path(__file__)),p.pin(index_file),p.pin(original_request),p.pin(request),
        p.pin(out/'request.json'),p.pin(out/'derivation.json')]
    pins.extend(p.pin(captured/name) for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py'))
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),methods=methods,indexStarts=len(starts))))


if __name__ == '__main__': main()
