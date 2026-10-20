#!/usr/bin/env python3
"""Route the sole HID initial POD take import to its true finite implementation."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('take_route_pod', HERE / 'prepare-modern-hid-pod-layout-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
s, p = r.s, r.p
BASE = p.NODE / 'universalhid-pod-layout-real-reexport-data-v2/candidate.json'
BUILD = p.NODE / 'swift-hid-bitwise-take-data-build-v3/candidate.json'
ABI = p.NODE / 'universalhid-bitwise-take-original-readonly-v1/audit.json'
CURRENT = p.NODE / 'universalhid-pod-current-native-layout-readonly-v1/audit.json'
SYMBOL = '_swift_cvw_initWithTake'


def validate_uh(before, after):
    old, actual = p.imports(before)['imports'], p.imports(after)['imports']
    item = next(x for x in old if x['name'] == SYMBOL)
    assert item['index'] == 11 and item['ordinal'] == 8 and not item['weak']
    expected = bytearray(before)
    expected[item['command']] = 20
    assert after == expected and len(actual) == len(old) == 713
    for a, b in zip(old, actual, strict=True):
        assert b == ({**a, 'ordinal': 20} if a['index'] == 11 else a)
    return dict(index=11, symbol=SYMBOL, at=item['command'], oldOrdinal=8, newOrdinal=20, strong=True)


def ar_contract(before, after):
    count, size = struct.unpack_from('<II', before, 16)
    addition = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/BT\0'
    assert len(addition) == 40 and not any(before[32 + size:32 + size + 40])
    expected = bytearray(before)
    struct.pack_into('<II', expected, 16, count + 1, size + 40)
    expected[32 + size:32 + size + 40] = addition
    assert after == expected and p.imports(after)['imports'] == p.imports(before)['imports']
    assert p.dependencies(after)[:-1] == p.dependencies(before)
    assert p.dependencies(after)[-1]['ordinal'] == 8


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    base, build, abi, current = [r.checked(path) for path in (BASE, BUILD, ABI, CURRENT)]
    assert build['ordinaryMacGenuineDefaultTakeCompared'] and build['ordinaryMacRealARCTransfersAndDestroysProven']
    assert build['productionIdentityIsExactOriginalCompletedHIDMetadata'] and not build['productionHIDIdentityGatePassed']
    assert current['actualCurrentIOSUUIDAndUInt64TypeLayoutsRead'] and not current['originalHIDInitializerExecuted']
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    assert ios['unsignedInertData'] and len(ios['currentExactNativeImports']) == 6
    source_bt = ios['provider']
    btpath = out / 'BT.unchanged-unsigned-ios-provider.inert.macho-data'
    btpath.write_bytes(Path(source_bt['path']).read_bytes())
    assert p.pin(btpath)['sha256'] == source_bt['sha256']
    source_ar = base['modifiedArrayReexportProvider']['candidate']
    before_ar = Path(source_ar['path']).read_bytes()
    ar = bytearray(before_ar)
    ordinal = p.append_dependency(ar, '@loader_path/BT')
    assert ordinal == 8
    added = p.dependencies(ar)[-1]
    assert added['size'] == 40
    struct.pack_into('<I', ar, added['at'], 0x8000001f)
    ar_contract(before_ar, bytes(ar))
    arpath = out / 'AR.real-bitwise-take-reexport.inert.macho-data'
    arpath.write_bytes(ar)
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    assert len(images) == 16
    images[s.primary.canonical_path('@loader_path/AR')] = r.image(p.pin(arpath), '@loader_path/AR')
    images[s.primary.canonical_path('@loader_path/BT')] = r.image(p.pin(btpath), '@loader_path/BT')
    results = []
    for name in ('UniversalHID', 'UniversalHIDKit'):
        source = next(x['candidate'] for x in base['images'] if x['name'] == name)
        before = Path(source['path']).read_bytes()
        after = bytearray(before)
        route = None
        if name == 'UniversalHID':
            item = next(x for x in p.imports(before)['imports'] if x['name'] == SYMBOL)
            after[item['command']] = 20
            route = validate_uh(before, bytes(after))
        else:
            assert after == before
        path = out / (name + '27.bitwise-take-real-reexport.mac.inert.macho-data')
        path.write_bytes(after)
        row = dict(name=name, source=source, candidate=p.pin(path), routes=[route] if route else [],
                   allInstructionMetadataWitnessPACBytesPreserved=True, originalAvailabilityGuardPreserved=True)
        results.append(row)
        images[s.primary.canonical_path('@loader_path/' + name + '27.dylib')] = r.image(p.pin(path), '@loader_path/' + name + '27.dylib')
    proof = s.primary.resolve(images, '@loader_path/AR', SYMBOL)
    leaf = proof
    while 'nested' in leaf: leaf = leaf['nested']
    assert proof['status'] == 'actualDirectExport' and leaf['owner'] == '@loader_path/BT'
    results[0]['routes'][0]['actualReexportDefinition'] = proof
    negatives = []
    before = Path(results[0]['source']['path']).read_bytes()
    after = Path(results[0]['candidate']['path']).read_bytes()
    at = results[0]['routes'][0]['at']
    text = next(section for segment in p.segments(before) for section in segment['sections'] if section['name'] == '__text')['fileoff']
    pac = next(row for row in p.chain_entries(before) if row['auth'])['fileoff'] + 4
    metadata = next(section for segment in p.segments(before) for section in segment['sections'] if section['name'].startswith('__swift5'))['fileoff']
    for label, offset in [('wrong ordinal', at), ('weak bit', at + 1), ('name offset', at + 2), ('instruction', text), ('real PAC', pac), ('original metadata', metadata)]:
        bad = bytearray(after)
        bad[offset] ^= 1
        try: validate_uh(before, bytes(bad))
        except (AssertionError, ValueError): negatives.append(dict(name=label, rejected=True))
        else: raise AssertionError('invalid original take route accepted')
    validations = []
    for path in [arpath, btpath] + [Path(row['candidate']['path']) for row in results]:
        result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path), exit=result.returncode))
    report = dict(schema='Genuine HID sole completed POD take private reexport data v1',
        sources=[p.pin(path) for path in (BASE, BUILD, ABI, CURRENT)], images=results,
        modifiedArrayReexportProvider=dict(alias='AR', intendedLoadPath='@loader_path/AR', source=source_ar,
            candidate=p.pin(arpath), addedGenuineReexport=dict(ordinal=8, path='@loader_path/BT', bytes=40),
            allOriginalSectionsImportsAndChainedPointerBytesPreserved=True, preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='BT', intendedLoadPath='@loader_path/BT', source=source_bt, candidate=p.pin(btpath),
            currentPositiveStrongDefinitions=ios['currentExactNativeImports']),
        preservedLeafProviders=base['preservedLeafProviders'] + [base['unchangedRuntimeProvider']],
        originalCallerABI=p.pin(ABI), actualCurrentPODFieldLayout=p.pin(CURRENT), currentStockImages=16,
        routedStrongImports=1, negativeControls=negatives, structuralValidations=validations,
        ordinaryMac3072GenuineDefaultTakeComparisonsPerRole=True, ordinaryMacRealARCTransfersAndDestroysProven=True,
        originalTakeThreeCABIArgumentsPreserved=True, productionIdentityIsExactOriginalCompletedHIDMetadata=True,
        productionHIDIdentityGatePassed=False, originalHIDInitializerMustCompleteBeforeTakeUse=True,
        actualCurrentIOSUUIDAndUInt64TypeLayoutsRead=True, generalNonBitwiseInterpreterProvided=False,
        remainingFiveCVWBindingsClosed=False, fullOriginal27RuntimeOverrideHookIdentity=False,
        fullSwift27RuntimeEquivalent=False, fullSwift27ParserEquivalent=False, allOriginalHIDTypesProvenResolvable=False,
        conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False, allCurrentProvidersDeclared=False,
        currentCompleteProviderDependencyGraphValidated=False, metadataCompatibilityProven=False,
        originalHIDInitializerExecuted=False, originalUHLoaded=False, originalVZLoaded=False,
        nativeIOSExecuted=False, deviceOperations=0, codeSigned=False, candidateReadyForNativeLoading=False, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(__file__), Path(r.__file__), BASE, BUILD, ABI, CURRENT, out / 'candidate.json', arpath, btpath,
             Path(source_ar['path']), Path(source_bt['path'])] + [Path(row[k]['path']) for row in results for k in ('source', 'candidate')]
    p.save(out / 'freeze.json', dict(files=pins + [p.pin(path) for path in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), strongImportsRouted=1, providerStrongImports=6,
        currentActualDefinitions=4, currentKernelReexportsUnverified=2, rejectedControls=len(negatives))))


if __name__ == '__main__':
    main()
