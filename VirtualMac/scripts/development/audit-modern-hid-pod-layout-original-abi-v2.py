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


def common_contract(body):
    assert len(body) == 988
    # Actual POD path: no extra inhabitants, size24/alignment8, inline storage.
    # All builtin-specialized keys fail; six native generic POD callbacks are
    # signed at the actual destination slot with their original IA diversifiers.
    words = {0: 0xb9401008, 4: 0x37800368, 8: 0xb9401409,
             16: 0x1a9f07e9, 20: 0xf940000a, 24: 0x92401d0b,
             28: 0xb370bd4b, 32: 0xaa09c169,
             48: 0x5400032d, 64: 0x5400044c, 80: 0x54000660,
             96: 0x54000501, 256: 0x378811a8,
             260: 0x90000010, 264: 0x913c3210,
             268: 0xaa0103f1, 272: 0xf2fb4951,
             276: 0xdac10230, 280: 0x1400008c,
             840: 0xf9000030, 848: 0x90000010, 852: 0x913ee210,
             860: 0xf2e09f11, 864: 0xdac10230, 868: 0xf9000430,
             880: 0x913ef210, 888: 0xf2fc7751, 892: 0xdac10230,
             896: 0xf9000830, 916: 0xf2e91b11, 920: 0xdac10230,
             924: 0xf9001030, 944: 0xf2f0ea31, 948: 0xdac10230,
             952: 0xf9000c30, 972: 0xf2fdfb51, 976: 0xdac10230,
             980: 0xf9001430, 984: 0xd65f03c0}
    for at, expected in words.items():
        assert struct.unpack_from('<I', body, at)[0] == expected, (at, hex(expected))
    return words


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
    common_directory = n / 'ipad-current-hid-pod-common-witness-readonly-v1'
    common_manifest = n / 'universalhid-pod-layout-original-abi-readonly-v3/common-witness-request.json'
    s.checked_capture(common_directory, common_manifest, headers)
    caps.extend(common_directory / name for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py'))
    common_file = common_directory / 'swiftcore-install-common-value-witnesses.bin'
    common_body = common_file.read_bytes()
    assert common_end == common + len(common_body)
    contract = common_contract(common_body)
    rejected = []
    for at in (4, 24, 256, 272, 276, 892, 980):
        mutant = bytearray(common_body)
        struct.pack_into('<I', mutant, at, struct.unpack_from('<I', mutant, at)[0] ^ 0x20)
        try:
            common_contract(mutant)
        except AssertionError:
            rejected.append(dict(offset=at, rejected=True))
        else:
            raise AssertionError(('changed actual ABI instruction accepted', at))
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
    implementation = Path(new_impl['code']['path']).read_bytes()
    # The true initializer sets the resolved-layout pointer tag before DA2 PAC.
    for at, word in {0x4ac: 0xb2400311, 0x4b0: 0xdac10a11,
                     0x4b4: 0xf9000131}.items():
        assert struct.unpack_from('<I', implementation, at)[0] == word
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
        commonWitnessBodyBytes=common_end - common, commonWitnessBodyPendingSeparateRead=False,
        actualCurrentCommonWitnessBody=p.pin(common_file),
        actualCurrentCommonWitnessInstructions=h.decode_body(common_body, common),
        actualCurrentPODSize24Alignment8DispatchKey=hex((24 << 16) | 7),
        actualCurrentNoBuiltinSpecializationForSize24Alignment8=True,
        actualCurrentPODGenericWitnesses={'buffer': hex(0x180fbaf0c), 'destroy': hex(0x180fbafb8),
            'copy': hex(0x180fbafbc), 'assignCopy': hex(0x180fbafbc),
            'take': hex(0x180fbafbc), 'assignTake': hex(0x180fbafbc)},
        actualCurrentPODWitnessPAC={'buffer': 0xda4a, 'destroy': 0x04f8, 'copy': 0xe3ba,
            'assignCopy': 0x8751, 'take': 0x48d8, 'assignTake': 0xefda,
            'key': 'IA', 'addressDiversity': True},
        actualCurrentGenericPODPathPreservesEnumWitnessSlots=True,
        actualCurrentWordContract={str(k): hex(v) for k, v in contract.items()},
        actualCurrentMachineCounterexamples=rejected,
        originalResolvedLayoutPointerTagBeforePAC=1,
        originalResolvedLayoutPointerTagInstruction=hex(0x194e8141c),
        originalResolvedLayoutPointerDAKey=2, originalResolvedLayoutPointerDiversifier=0x8b65,
        documentedUUIDAddressableForDependenciesFlag=0x02000000,
        originalNewLayoutPropagatesDependencyAddressability=True,
        oldHostActualUUIDAddressabilityFlagPendingTypeLayoutRead=True,
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
              witness_audit, Path(new_entry['code']['path']), Path(new_impl['code']['path']),
              common_file, common_manifest,
              p.ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-own-generic-field-native-candidate-v1/upstream/include--swift--ABI--MetadataValues.h'] + caps
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in inputs + [out / 'audit.json', out / 'common-witness-request.json']],
        deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), commonWitnessRequest=p.pin(out / 'common-witness-request.json'))))


if __name__ == '__main__':
    main()
