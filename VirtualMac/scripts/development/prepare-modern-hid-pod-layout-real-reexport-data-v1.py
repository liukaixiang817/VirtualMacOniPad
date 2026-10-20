#!/usr/bin/env python3
"""Route one genuine HID POD initializer to a finite native-layout adapter."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pod_route_current', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
BASE = p.NODE / 'universalhid-typedthrow-real-reexport-data-v1/candidate.json'
BUILD = p.NODE / 'swift-hid-pod-layout-data-build-v9/candidate.json'
ABI = p.NODE / 'universalhid-pod-layout-original-abi-readonly-v6/audit.json'
SYMBOL = '_swift_cvw_initStructMetadataWithLayoutString'


def checked(path):
    for row in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    return json.loads(path.read_bytes())


def image(pin, alias):
    raw = Path(pin['path']).read_bytes()
    for command, at, size in p.commands(raw):
        if command == 27:
            uuid = raw[at + 8:at + 24].hex()
        if command == 0x80000033:
            off, length = struct.unpack_from('<II', raw, at + 8)
            tree = s.primary.trie(raw[off:off + length])
    return dict(path=alias, UUID=uuid, exports=tree, dependencies=p.dependencies(raw), image=pin)


def validate_uh(before, after):
    old, actual = p.imports(before)['imports'], p.imports(after)['imports']
    item = next(x for x in old if x['name'] == SYMBOL)
    assert item['index'] == 348 and item['ordinal'] == 8 and not item['weak']
    expected = bytearray(before)
    expected[item['command']] = 20
    assert after == expected
    assert len(actual) == len(old) == 713
    for a, b in zip(old, actual, strict=True):
        assert b == ({**a, 'ordinal': 20} if a['index'] == 348 else a)
    return dict(index=348, symbol=SYMBOL, at=item['command'], oldOrdinal=8, newOrdinal=20, strong=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    base, build, abi = [checked(path) for path in (BASE, BUILD, ABI)]
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    assert ios['unsignedInertData'] and len(ios['currentExactNativeImports']) == 8
    assert build['ordinaryMacNativeCoreCompared'] and build['productionIdentityIsExactOriginalHIDMetadata']
    assert not build['productionHIDIdentityGatePassed'] and not build['candidateReadyForNativeLoading']
    assert build['originalResolvedLayoutStringPointerTagAndDAAuthenticationPreserved']
    assert build['documentedAddressableForDependenciesFlagPropagated']
    assert build['actualCurrentOldNativeCommonWitness988BRead']
    source_tt = ios['provider']
    ttpath = out / 'PL.unchanged-unsigned-ios-provider.inert.macho-data'
    ttpath.write_bytes(Path(source_tt['path']).read_bytes())
    assert p.pin(ttpath)['sha256'] == source_tt['sha256']
    source_ar = base['modifiedArrayReexportProvider']['candidate']
    before_ar = Path(source_ar['path']).read_bytes()
    ar = bytearray(before_ar)
    count, size = struct.unpack_from('<II', ar, 16)
    ordinal = p.append_dependency(ar, '@loader_path/PL')
    assert ordinal == 7
    added = p.dependencies(ar)[-1]
    assert added['size'] == 40 and added['at'] == 32 + size
    struct.pack_into('<I', ar, added['at'], 0x8000001f)
    expected_ar = bytearray(before_ar)
    struct.pack_into('<II', expected_ar, 16, count + 1, size + 40)
    expected_ar[32 + size:32 + size + 40] = ar[32 + size:32 + size + 40]
    assert ar == expected_ar and p.imports(ar)['imports'] == p.imports(before_ar)['imports']
    arpath = out / 'AR.real-pod-layout-reexport.inert.macho-data'
    arpath.write_bytes(ar)
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    assert len(images) == 16
    images[s.primary.canonical_path('@loader_path/AR')] = image(p.pin(arpath), '@loader_path/AR')
    images[s.primary.canonical_path('@loader_path/PL')] = image(p.pin(ttpath), '@loader_path/PL')
    results = []
    for name in ('UniversalHID', 'UniversalHIDKit'):
        source = next(row for row in base['images'] if row['name'] == name)['candidate']
        before = Path(source['path']).read_bytes()
        after = bytearray(before)
        route = None
        if name == 'UniversalHID':
            item = next(x for x in p.imports(before)['imports'] if x['name'] == SYMBOL)
            after[item['command']] = 20
            route = validate_uh(before, bytes(after))
        else:
            assert after == before
        path = out / (name + '27.pod-layout-real-reexport.mac.inert.macho-data')
        path.write_bytes(after)
        row = dict(name=name, source=source, candidate=p.pin(path), routes=[route] if route else [],
                   allInstructionMetadataWitnessPACBytesPreserved=True, originalAvailabilityGuardPreserved=True)
        results.append(row)
        images[s.primary.canonical_path('@loader_path/' + name + '27.dylib')] = image(p.pin(path), '@loader_path/' + name + '27.dylib')
    proof = s.primary.resolve(images, '@loader_path/AR', SYMBOL)
    leaf = proof
    while 'nested' in leaf:
        leaf = leaf['nested']
    assert proof['status'] == 'actualDirectExport' and leaf['owner'] == '@loader_path/PL'
    results[0]['routes'][0]['actualReexportDefinition'] = proof
    negatives = []
    before = Path(results[0]['source']['path']).read_bytes()
    after = Path(results[0]['candidate']['path']).read_bytes()
    at = results[0]['routes'][0]['at']
    text = next(section for segment in p.segments(before) for section in segment['sections'] if section['name'] == '__text')['fileoff']
    pac = next(row for row in p.chain_entries(before) if row['auth'])['fileoff'] + 4
    for label, offset in (('wrong ordinal', at), ('weak bit', at + 1), ('name offset', at + 2), ('instruction', text), ('real PAC', pac)):
        bad = bytearray(after)
        bad[offset] ^= 1
        try:
            validate_uh(before, bytes(bad))
        except (AssertionError, ValueError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise AssertionError('invalid typed-throw route accepted')
    validations = []
    for path in [arpath, ttpath] + [Path(row['candidate']['path']) for row in results]:
        result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path), exit=result.returncode))
    report = dict(schema='Genuine HID finite two-field POD initializer private reexport data v1',
        sources=[p.pin(path) for path in (BASE, BUILD, ABI)], images=results,
        modifiedArrayReexportProvider=dict(alias='AR', intendedLoadPath='@loader_path/AR', source=source_ar,
            candidate=p.pin(arpath), addedGenuineReexport=dict(ordinal=7, path='@loader_path/PL', bytes=40),
            allOriginalSectionsImportsAndChainedPointerBytesPreserved=True,
            preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='PL', intendedLoadPath='@loader_path/PL', source=source_tt, candidate=p.pin(ttpath),
            currentPositiveStrongDefinitions=ios['currentExactNativeImports']),
        preservedLeafProviders=base['preservedLeafProviders'] + [base['unchangedRuntimeProvider']],
        originalCallerABI=p.pin(ABI), currentStockImages=16, routedStrongImports=1,
        negativeControls=negatives, structuralValidations=validations,
        genuinePODComponentComparedToNativeCVWOnMac=True,
        originalPODCallerSixCABIArgumentsPreserved=True, actualCurrentNativeFiveCABIArgumentsProven=True,
        originalResolvedLayoutPointerTagAndAuthenticationPreserved=True,
        documentedDependencyAddressabilityFlagPropagated=True,
        productionHIDIdentityIsExactOriginalEventReportSenderID=True,
        productionHIDIdentityGatePassed=False, actualCurrentIOSUUIDAndUInt64TypeLayoutsRead=False,
        nativePODCommonWitnessSelectionAndCompletenessPublicationRetained=True,
        generalCVWInterpreterProvided=False, fullOriginal27RuntimeOverrideHookIdentity=False,
        fullSwift27RuntimeEquivalent=False,
        fullSwift27ParserEquivalent=False, allOriginalHIDTypesProvenResolvable=False,
        conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False,
        allCurrentProvidersDeclared=False, currentCompleteProviderDependencyGraphValidated=False,
        metadataCompatibilityProven=False, originalUHLoaded=False, originalVZLoaded=False,
        nativeIOSExecuted=False, deviceOperations=0, codeSigned=False,
        candidateReadyForNativeLoading=False, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(__file__), BASE, BUILD, ABI, out / 'candidate.json', arpath, ttpath,
             Path(source_ar['path']), Path(source_tt['path'])]
    files += [Path(row[k]['path']) for row in results for k in ('source', 'candidate')]
    p.save(out / 'freeze.json', dict(files=pins + [p.pin(path) for path in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), strongImportsRouted=1,
        nativeProviderStrongImports=8, actualDefinitions=6, unverifiedKernelReexports=2, rejectedControls=5)))


if __name__ == '__main__':
    main()
