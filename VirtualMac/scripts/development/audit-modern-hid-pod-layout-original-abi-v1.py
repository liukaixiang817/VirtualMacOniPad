#!/usr/bin/env python3
"""Exact original HID POD completion caller and current native initializer ABI."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pod_actual_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
from swift_relative_metadata import RelativeMetadata
spec = importlib.util.spec_from_file_location('pod_actual_starts', HERE / 'audit-modern-hid-oldhost-contiguousbytes-v1.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
spec = importlib.util.spec_from_file_location('pod_actual_disassembly', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    n = p.NODE
    headers = n / 'ipad-current-cache-xpc-leaf-headers-v2/headers.json'
    caps = []
    for role in ('index', 'body'):
        directory = n / ('ipad-current-hid-pod-layout-' + role + '-readonly-v1')
        plan = n / ('ipad-current-hid-pod-layout-' + role + '-plan-v1/request.json')
        s.checked_capture(directory, plan, headers)
        caps.extend(directory / name for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py'))
    old_file = n / 'ipad-current-hid-pod-layout-body-readonly-v1/swiftcore-init-struct-metadata.bin'
    body = old_file.read_bytes()
    actual = 0x180fbafd4
    assert len(body) == 1180
    expected = {0: 0xd503237f, 28: 0xaa0003f3, 36: 0xb40004c2,
                124: 0xf86c786d, 144: 0xb86c7891, 156: 0xb82c788f,
                476: 0xf85f8e70, 492: 0xdac11a30, 520: 0x36400081,
                1144: 0x97fffdb9, 1148: 0xa9045e95, 1152: 0x290a6296,
                1176: 0xd65f0fff}
    for at, word in expected.items():
        assert struct.unpack_from('<I', body, at)[0] == word, (at, hex(word))
    native_starts_blob = n / 'ipad-current-hid-pod-layout-index-readonly-v1/swiftcore-function-starts.bin'
    starts, address, at = [], 0x180bd5000, 0
    blob = native_starts_blob.read_bytes()
    while at < len(blob):
        delta, at = h.uleb(blob, at)
        if not delta:
            break
        address += delta
        starts.append(address)
    assert not any(blob[at:]) and starts[starts.index(actual) + 1] == actual + len(body)
    common = 0x180fbab30
    assert common in starts
    common_end = starts[starts.index(common) + 1]
    head = json.loads(headers.read_bytes())
    maps = [(r['name'], m) for r in head['headers'] for m in r['maps'] if m['address'] <= common and common_end <= m['address'] + m['size']]
    assert len(maps) == 1
    cache, mapping = maps[0]
    p.save(out / 'common-witness-request.json', dict(schema='bounded-current-iPad-POD-common-witness-body-v1',
        ranges=[dict(name='swiftcore-install-common-value-witnesses', cache=cache,
                     offset=mapping['fileOffset'] + common - mapping['address'], length=common_end - common)]))
    raw_file = n / 'universalhid-original-contract-v1/raw/UniversalHID'
    raw = raw_file.read_bytes()
    a = RelativeMetadata(raw, raw)
    callers = f.branches(raw, 0x2a0072260)
    assert len(callers) == 1 and callers[0]['PC'] == 0x29fd4125c and callers[0]['call']
    begin = 0x29fd4120c
    assert f.function_starts(raw)[f.function_starts(raw).index(begin) + 1] == begin + 116
    offset = a.offset(begin)
    code = raw[offset:offset + 116]
    for at, word in {24: 0x528027e0, 32: 0xf100fc3f, 40: 0x79001fff,
                     60: 0x91003be4, 64: 0x91004265, 68: 0xaa1303e0,
                     72: 0x52802001, 76: 0x52800042, 80: 0x940cc401}.items():
        assert struct.unpack_from('<I', code, at)[0] == word, (at, hex(word))
    caller_file = out / 'UH-original-POD-completion-caller.bin'
    caller_file.write_bytes(code)
    metadata_source = p.ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-full-runtime-port-audit-v1/upstream/Metadata.cpp'
    runtime_def = p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-RuntimeFunctions.def'
    witness_audit = n / 'universalhid-cvw-static-original-abi-readonly-v1/audit.json'
    original = json.loads(witness_audit.read_bytes())
    new_entry = next(x for x in original['completeOriginalCVWEntriesAndFirstHelperBodies'] if x['entry'] == 0x194e76384)
    new_impl = next(x for x in original['completeOriginalCVWEntriesAndFirstHelperBodies'] if x['entry'] == 0x194e80f70)
    for row in json.loads((witness_audit.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    symbols_file = n / 'universalhid-original-contract-v1/UniversalHID-symbols.a2s.batch.json'
    symbols = json.loads(symbols_file.read_bytes())['symbols']
    assert symbols['0x2a0070300'][0] == '_$s10Foundation4UUIDVMa'
    assert symbols['0x2c819baa0'][0] == '__got._$ss6UInt64VN'
    report = dict(schema='Genuine HID one POD completion and actual current native ABI v1',
        currentHeaders=p.pin(headers), originalCaller=p.pin(caller_file), originalCallerEntry=begin,
        originalCallerInstructions=h.decode_body(code, begin),
        originalFields=['actual Foundation.UUID metadata accessor response request 0x13f state <= 0x3f', 'actual native UInt64 metadata'],
        originalTags=[0, 0], originalLayoutFlags=0x100, originalFieldCount=2,
        originalOffsetVectorIsMetadataPlus16=True, originalNewCoreEntry=new_entry, originalNewCoreImpl=new_impl,
        actualCurrentNativeInitializer=p.pin(old_file), actualCurrentEntry=actual,
        actualCurrentNextLCFunctionStart=actual + len(body), actualCurrentInstructions=h.decode_body(body, actual),
        actualCurrentCABIArguments=['x0 metadata', 'w1 layoutFlags', 'x2 fields', 'x3 TypeLayout pointer vector', 'x4 offsets'],
        actualCurrentMutableTableFlagBit=8, actualCurrentVWTSlotOffset=-8,
        actualCurrentVWTPointerDAAuthentication=0x2e3f,
        actualCurrentOutputLayoutStores={'sizeAndStride': hex(actual + 1148), 'flagsAndExtra': hex(actual + 1152)},
        actualCurrentPODCommonWitnessCall=hex(actual + 1144), commonWitnessEntry=common,
        commonWitnessNextLC26Start=common_end,
        commonWitnessBodyBytes=common_end - common, commonWitnessBodyPendingSeparateRead=True,
        commonWitnessRequest=p.pin(out / 'common-witness-request.json'), commonWitnessCacheMapping=mapping,
        ordinaryOwnFixtureMetadataIsNotActualHIDMetadata=True,
        currentActualUUIDAndUInt64MetadataSpansCaptured=False,
        currentNativeInitializerWholeBodyABIProven=True,
        originalRuntimeOverrideHooksNotUniversallyBackported=True,
        nativeHIDEntryExecuted=False, strongImportRouteChanged=False, candidateReadyForNativeLoading=False,
        full27Backend=False, deviceOperations=0, nativeIOSExecuted=False)
    p.save(out / 'audit.json', report)
    inputs = [Path(__file__), Path(s.__file__), Path(f.__file__), Path(h.__file__), headers, old_file,
              native_starts_blob, raw_file, caller_file, symbols_file, metadata_source, runtime_def,
              witness_audit, Path(new_entry['code']['path']), Path(new_impl['code']['path'])] + caps
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in inputs + [out / 'audit.json', out / 'common-witness-request.json']],
        deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), commonWitnessRequest=p.pin(out / 'common-witness-request.json'))))


if __name__ == '__main__':
    main()
