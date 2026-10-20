#!/usr/bin/env python3
"""Plan exact current native Metal callbacks and stubs without device access.

This follows actual instructions and complete LC_FUNCTION_STARTS, rather than
assuming that a nil device identifies a GPU, selector, entitlement or service
failure. Only currently guarded members are requested.
"""
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('metal_nil_frontier', HERE/'audit-modern-private-declarations-v2.py')
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
p, s, N = d.p, d.f.s, d.N
from current_hid_extra_three_capture_v1 import mapping


def function_starts(raw, base):
    at, current, rows = 0, base, []
    while at < len(raw):
        value = 0
        for shift in range(0, 64, 7):
            assert at < len(raw)
            byte = raw[at]; at += 1
            if shift == 63: assert byte < 2
            value |= (byte & 127) << shift
            if not byte & 128: break
        else: raise AssertionError('function-start ULEB overflow')
        if not value:
            assert not any(raw[at:]); return rows
        current += value
        assert not rows or current > rows[-1]
        rows.append(current)
    raise AssertionError('missing function-start terminator')


def literal_pair(raw, base, offset, register):
    first, second = struct.unpack_from('<2I', raw, offset)
    assert first & 0x9f000000 == 0x90000000 and first & 31 == register
    assert second & 0xff000000 == 0x91000000
    assert second & 31 == (second >> 5) & 31 == register
    immediate = ((first >> 5) & 0x7ffff) << 2 | (first >> 29) & 3
    if immediate & (1 << 20): immediate -= 1 << 21
    address = ((base+offset) & ~4095)+(immediate << 12)
    address += ((second >> 10) & 4095) << (12 if second & (1 << 22) else 0)
    return address


def direct_call(raw, base, offset):
    word = struct.unpack_from('<I', raw, offset)[0]
    assert word & 0xfc000000 == 0x94000000
    immediate = word & 0x3ffffff
    if immediate & 0x2000000: immediate -= 0x4000000
    return base+offset+(immediate << 2)


def main():
    out = N/'ipad-current-metal-native-nil-downstream-plan-v1'; assert not out.exists()
    images, pins = d.current_images()
    hp = N/'ipad-current-cache-trace-header-readonly-v1/headers.json'
    headers = d.strict_json(hp)
    assert len(headers['headers']) == 14
    audit_path = N/'metal-current-default-entry-readonly-v1/audit.json'
    pins += d.original_freeze(audit_path.parent/'freeze.json')
    audit = d.strict_json(audit_path)
    body_path = Path(audit['actualCompleteBody']['path'])
    assert p.pin(body_path) == audit['actualCompleteBody']
    raw = body_path.read_bytes(); bounds = audit['exactBodyBounds']; base = bounds['start']
    assert base == 0x181b1d390 and len(raw) == bounds['bytes'] == 248
    metal_path = '/System/Library/Frameworks/Metal.framework/Metal'
    image = images[s.primary.canonical_path(metal_path)]
    assert image['UUID'] == audit['actualNativeMetalUUID'] == '8f062125748839efafda57db8cd80033'
    cp = Path(image['header']['path']); command_bytes = cp.read_bytes()
    sections = [q for sg in p.segments(command_bytes) for q in sg['sections']]
    text = next(x for x in p.segments(command_bytes) if x['name'] == '__TEXT')
    function_index = N/'ipad-current-trace-metal-bounded-readonly-v1/metal-function-starts.bin'
    function_command = next(at for command, at, size in p.commands(command_bytes) if command == 0x26)
    index_offset, index_length = struct.unpack_from('<II', command_bytes, function_command+8)
    link = next(x for x in p.segments(command_bytes) if x['name'] == '__LINKEDIT')
    index_va = link['address']+index_offset-link['fileoff']
    first_capture = N/'ipad-current-trace-metal-bounded-readonly-v1'
    receipt = s.checked_capture(first_capture, N/'ipad-current-trace-metal-bounded-read-plan-v1/request.json', hp)
    selected = next(x for x in receipt['ranges'] if x['path'] == str(function_index))
    assert mapping(headers, index_va, index_length) == {k:selected[k] for k in ('cache','offset','length')}
    starts = function_starts(function_index.read_bytes(), text['address'])
    assert len(starts) == 8344 and starts[bounds['LC26Index']] == base
    targets = [
        ('metal-native-default-result-block-complete', literal_pair(raw, base, 0x94, 16), 'function', 144),
        ('metal-native-default-byref-copy-complete', literal_pair(raw, base, 0x3c, 16), 'function', 16),
        ('metal-native-default-byref-destroy-complete', literal_pair(raw, base, 0x50, 16), 'function', 12),
        ('metal-native-default-call1-auth-stub', direct_call(raw, base, 0xb4), 'stub', 16),
        ('metal-native-default-once-auth-stub', direct_call(raw, base, 0xf0), 'stub', 16),
        ('metal-native-default-once-global-block', literal_pair(raw, base, 0xe8, 1), 'block-prefix', 32)]
    assert [x[1] for x in targets] == [0x181b1caec,0x181bad774,0x181bad784,0x181c14c30,0x181c14b30,0x1df4f7b48]
    for offset, va in [(0x2c, 0x181c2c4f0), (0x84, 0x181c2aa50)]:
        # ADRP followed by the actual scaled floating-point LDR d0.
        adrp, load = struct.unpack_from('<2I', raw, offset)
        assert adrp & 0x9f000000 == 0x90000000 and load & 0xffc00000 == 0xfd400000
        assert (load >> 5) & 31 == adrp & 31 and load & 31 == 0
        immediate = ((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29) & 3
        if immediate & (1 << 20): immediate -= 1 << 21
        actual = ((base+offset) & ~4095)+(immediate << 12)+((load >> 10) & 4095)*8
        assert actual == va
        targets.append(('metal-native-default-block-word-'+hex(offset)[2:], va, 'literal', 8))
    requests, proof = [], []
    for name, address, kind, expected_length in targets:
        section = next(x for x in sections if x['address'] <= address and address+expected_length <= x['address']+x['size'])
        if kind == 'function':
            index = bisect.bisect_left(starts, address)
            assert starts[index] == address and starts[index+1]-address == expected_length
            assert section['name'] == '__text'
            extent = dict(LC26Index=index, end=starts[index+1], fullFunction=True)
        elif kind == 'stub':
            stride = struct.unpack_from('<I', command_bytes, section['command']+72)[0]
            assert section['name'] == '__auth_stubs' and stride == 16
            assert (address-section['address']) % stride == 0
            extent = dict(sectionStubStride=stride, completeSectionStub=True, actualTargetBindingUnproved=True)
        else:
            extent = dict(prefixOrLiteralOnly=True, decodedPointerIdentityProven=False)
        request = dict(name=name, **mapping(headers, address, expected_length))
        assert request['cache'] in ('01','27-data') and request['offset'] >= 4096
        requests.append(request); proof.append(dict(request=request, VA=address, kind=kind,
            actualSection=section, extent=extent))
    unmapped_call = direct_call(raw, base, 0xc8)
    assert unmapped_call == 0x186cbd270
    actual_table = d.strict_json(N/'ipad-current-cache-hid-extra-inventory-v1/current-images.json')
    assert not [x for x in actual_table if x['address'] <= unmapped_call < x['address']+x['textSize']]
    try: mapping(headers, unmapped_call, 4)
    except AssertionError: not_guarded = True
    else: not_guarded = False
    assert not_guarded
    assert len(requests) == 8 and sum(x['length'] for x in requests) == 252
    reader = HERE/'read-ipad-current-cache-ranges-readonly-v9.py'
    assert p.pin(reader)['sha256'] == 'c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
    out.mkdir(mode=0o700)
    p.save(out/'request.json', dict(ranges=requests))
    p.save(out/'derivation.json', dict(schema='Exact current native Metal nil downstream fixed request v1',
        headers=p.pin(hp), reader=p.pin(reader), originalCurrentNativeBody=p.pin(body_path),
        nativeMetalUUID=image['UUID'], currentNativeCommands=p.pin(cp), actualLC26Index=p.pin(function_index),
        namedBodyBounds=bounds, actualExactRequestDerivations=proof, requestedBytes=252, requestedRanges=8,
        unmappedDirectCall=dict(address=unmapped_call, requested=False, guardedMemberEstablished=False,
            actualImageInventoryOwnerEstablished=False, namedCalleeBindingEstablished=False),
        nativeDefaultNilDoesNotProveNoGPU=True, selectorAvailabilityMeasured=False,
        serviceQueryOrEntitlementFailureProven=False, deviceOperations=0, nativeCPUCalls=0,
        frameworkLoads=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(x) for x in (Path(__file__), hp, cp, body_path, function_index, reader,
        first_capture/'receipt.json', first_capture/'manifest.json', first_capture/'script.sh',
        first_capture/'reader-source.py', out/'request.json', out/'derivation.json', out/'source.py')]
    dedup = {x['path']:x for x in pins}; assert all(dedup[x['path']] == x for x in pins)
    p.save(out/'freeze.json', dict(files=list(dedup.values()), deviceOperations=0, nativeCPUCalls=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), derivation=p.pin(out/'derivation.json'),
        freeze=p.pin(out/'freeze.json'), requestedBytes=252, ranges=8)))


if __name__ == '__main__': main()
