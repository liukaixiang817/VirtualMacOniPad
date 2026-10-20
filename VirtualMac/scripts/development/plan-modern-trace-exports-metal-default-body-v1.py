#!/usr/bin/env python3
"""Derive exact trace exports and Metal default-device body from actual bounded bytes."""
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('current_stock', HERE/'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
p = s.p
spec = importlib.util.spec_from_file_location('starts', p.NODE/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
from current_hid_extra_three_capture_v1 import commands, mapping


def main():
    n = p.NODE
    out = n/'ipad-current-trace-exports-metal-default-body-plan-v2'
    assert not out.exists()
    hp = n/'ipad-current-cache-trace-header-readonly-v1/headers.json'
    headers = json.loads(hp.read_bytes())
    assert len(headers['headers']) == 14 and p.pin(hp)['sha256'] == 'f457d8f2168723936b1e363967b3d07ed047f89da967cc7d8eed9603ff1bb868'
    combined = n/'ipad-current-trace-metal-bounded-read-plan-v1'
    cap = n/'ipad-current-trace-metal-bounded-readonly-v1'
    receipt = s.checked_capture(cap, combined/'request.json', hp)
    assert receipt['readerSHA256'] == p.pin(cap/'reader-source.py')['sha256'] == 'c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
    assert receipt['requestedRanges'] == 2 and receipt['requestedBytes'] == 14672
    pins = []
    for directory in [combined, n/'ipad-current-hid-trace-command-prefix-plan-v1', n/'ipad-current-metal-native-function-index-plan-v1']:
        for pin in json.loads((directory/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path'])) == pin
            pins.append(pin)
        pins.append(p.pin(directory/'freeze.json'))
    original_trace = json.loads((n/'ipad-current-hid-trace-command-prefix-plan-v1/derivation.json').read_bytes())
    actual_trace = original_trace['actualImage']
    trace_prefix = cap/'system-trace-commands-prefix.bin'
    raw = trace_prefix.read_bytes()
    assert len(raw) == 4096
    length = 32+struct.unpack_from('<I', raw, 20)[0]
    assert 4096 < length <= 128*1024
    trace_row = dict(name='system-trace-commands-tail', **mapping(headers, actual_trace['address']+4096, length-4096))
    assert trace_row['cache'] == '09'
    metal_plan = json.loads((n/'ipad-current-metal-native-function-index-plan-v1/derivation.json').read_bytes())
    cp = Path(metal_plan['actualMetalCommands']['path'])
    assert p.pin(cp) == metal_plan['actualMetalCommands']
    metal = commands(p, cp.read_bytes(), metal_plan['actualInventoryRow'])
    encoded_path = cap/'metal-function-starts.bin'
    encoded = encoded_path.read_bytes()
    captured = next(x for x in receipt['ranges'] if x['name'] == 'metal-function-starts')
    assert {key: captured[key] for key in ('cache', 'offset', 'length')} == mapping(headers, metal_plan['indexVA'], metal_plan['LC26']['length'])
    at, address, starts = 0, metal['text']['address'], []
    while at < len(encoded):
        delta, at = h.uleb(encoded, at)
        if not delta: break
        address += delta; starts.append(address)
    assert starts == sorted(set(starts)) and encoded[at:] == b'\0'*(len(encoded)-at)
    helper = metal_plan['actualNativeDefaultDeviceAddress']
    index = bisect.bisect_left(starts, helper)
    assert index < len(starts)-1 and starts[index] == helper
    begin, end = starts[index:index+2]
    assert 0 < end-begin <= 65536 and end <= metal['text']['address']+metal['text']['size']
    body_row = dict(name='metal-native-default-device-complete', **mapping(headers, begin, end-begin))
    assert body_row['cache'] in ('01','03','05','07','09','11','13','17','21','25')
    ranges = [trace_row, body_row]
    assert sum(x['length'] for x in ranges) <= 4*1024*1024
    out.mkdir(mode=0o700)
    p.save(out/'request.json', dict(ranges=ranges))
    p.save(out/'derivation.json', dict(schema='Actual trace command completion and exact native Metal helper body request v2',
        currentHeaders=p.pin(hp), reader=p.pin(cap/'reader-source.py'), actualCombinedCaptureReceipt=p.pin(cap/'receipt.json'),
        originalPlans=[p.pin(n/name/'derivation.json') for name in
                       ('ipad-current-hid-trace-command-prefix-plan-v1','ipad-current-metal-native-function-index-plan-v1')],
        actualTraceImage=actual_trace, traceActualCommandPrefix=p.pin(trace_prefix), traceCompleteCommandBytes=length,
        traceCommandCompletionRequest=trace_row, traceCompleteCommandsNotYetCaptured=True,
        actualMetalCommands=p.pin(cp), actualMetalFunctionIndex=p.pin(encoded_path),
        actualNativeMetalUUID=metal['UUID'], nativeMetalDefaultDefinition=metal_plan['actualNativeDefaultDeviceDefinition'],
        nativeMetalDefaultBodyBounds=dict(start=begin, end=end, LC26Index=index, exactNamedEntry=True, bytes=end-begin),
        nativeMetalDefaultBodyRequest=body_row, requestedBytes=sum(x['length'] for x in ranges), requestedRanges=2,
        actualTraceDefinitionsNotYetCaptured=True, actualNativeMetalHelperBodyNotYetCaptured=True,
        deviceOperations=0, nativeCPUCalls=0, frameworkLoads=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [hp, Path(__file__), Path(h.__file__), trace_prefix, encoded_path, cp,
                    combined/'request.json', combined/'derivation.json',
                    out/'request.json', out/'derivation.json', out/'source.py']+[cap/name for name in
                    ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]]
    p.save(out/'freeze.json', dict(files=list({x['path']: x for x in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), freeze=p.pin(out/'freeze.json'), ranges=ranges,
                          nativeDefaultStart=begin, nativeDefaultBytes=end-begin)))


if __name__ == '__main__':
    main()
