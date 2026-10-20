#!/usr/bin/env python3
"""Verify actual current scroll bodies and request only their typed jump entries.

No device operation or native factory executes. The two tables are not inferred
from the archived cache: this request is derived from current captured code.
"""
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scroll_current_s', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
p = s.p
spec = importlib.util.spec_from_file_location('scroll_current_h', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
from current_hid_extra_three_capture_v1 import mapping


def main():
    out = p.NODE / 'iokit-processed-scroll-native-contract-readonly-v1'
    assert not out.exists()
    headers_path = p.NODE / 'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    headers = json.loads(headers_path.read_bytes())
    capture = p.NODE / 'ipad-current-iokit-processed-scroll-native-callees-readonly-v1'
    request = p.NODE / 'ipad-current-iokit-processed-scroll-native-callees-plan-v1/request.json'
    receipt = s.checked_capture(capture, request, headers_path)
    assert receipt['requestedBytes'] == 2872 and receipt['requestedRanges'] == 2
    frames = []
    for name, begin, count in [('iokit-current-scroll-common-complete', 0x18ecbfee8, 120),
                               ('iokit-current-float-common-complete', 0x18ec772c8, 2752)]:
        path = capture / (name + '.bin'); raw = path.read_bytes()
        assert len(raw) == count
        frames.append(dict(begin=begin, bytes=count, raw=p.pin(path), instructions=h.decode_body(raw, begin)))
    common, getter = frames
    def word(frame, address):
        return struct.unpack_from('<I', Path(frame['raw']['path']).read_bytes(), address-frame['begin'])[0]
    # Actual old-host data pointer and fixed16.16 conversion; no +96 transplant.
    assert word(common, 0x18ecbff24) == 0xf9403408
    assert word(common, 0x18ecbff28) == 0x1e18c549
    assert word(common, 0x18ecbff38) == 0x1e18c52b
    assert word(common, 0x18ecbff40) == 0x29022d09
    assert word(getter, 0x18ec77450) == 0x51418270
    assert word(getter, 0x18ec77464) == 0xd0000251
    assert word(getter, 0x18ec77468) == 0x91091231
    assert word(getter, 0x18ec77b38) == 0x1e620100
    assert word(getter, 0x18ec77b44) == 0x1e610800
    ranges = [dict(name='iokit-current-scroll-type-jump', **mapping(headers, 0x18ecc112c, 4)),
              dict(name='iokit-current-scroll-field-jumps', **mapping(headers, 0x18ecc1244, 16))]
    assert all(r['cache'] == '05' for r in ranges)
    out.mkdir()
    p.save(out / 'request.json', dict(ranges=ranges))
    p.save(out / 'audit.json', dict(schema='Actual current IOKit processed scroll scalar ABI v1',
        actualCapture=p.pin(capture/'receipt.json'), actualRequest=p.pin(request),
        currentHeaders=p.pin(headers_path), frames=frames,
        scrollDoubleArguments=['d0:x', 'd1:y', 'd2:z'], nativeDataPointerOffset=104,
        nativeFixed16FractionBits=16, nativeEventType=6,
        scrollCommonCallsNativeAllocatorAt=0x18ec740c4,
        fieldTypeShift=16, candidateScrollFieldBase=0x60000,
        signedFixedGetterUsesScaleBits='3ef0000000000000',
        actualTypedJumpEntriesRead=False, nativeFactoryExecuted=False,
        nativeClockOriginValidated=False, originalUHKSourcePortIntegrated=False,
        request=p.pin(out/'request.json'), deviceOperations=0, nativeHVCalls=0,
        nativeVMCalls=0, full27Backend=False))
    pins = [p.pin(Path(__file__)),p.pin(headers_path),p.pin(request)]
    pins += [p.pin(capture / name) for name in ('receipt.json','manifest.json','reader-source.py','script.sh','stdout','stderr')]
    pins += [frame['raw'] for frame in frames]
    pins += [p.pin(out/'audit.json'),p.pin(out/'request.json')]
    p.save(out/'freeze.json', dict(files=list({r['path']:r for r in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),request=p.pin(out/'request.json'),ranges=ranges)))


if __name__ == '__main__': main()
