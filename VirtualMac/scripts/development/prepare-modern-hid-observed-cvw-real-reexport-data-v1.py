#!/usr/bin/env python3
"""Route six exact strong CVW imports to the true finite ownership provider."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('observed_cvw_route', HERE / 'prepare-modern-hid-bitwise-take-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
s, p = r.s, r.p
from current_kernel_capture_v1 import join as join_kernel
BASE = p.NODE / 'universalhid-bitwise-take-real-reexport-data-v1/candidate.json'
BUILD = p.NODE / 'hid-observed-cvw-production-data-build-v2/candidate.json'
WHITELIST = p.NODE / 'hid-observed-cvw-production-whitelist-readonly-v1/audit.json'
SYMBOLS = ['_swift_cvw_initializeBufferWithCopyOfBuffer', '_swift_cvw_destroy', '_swift_cvw_initWithCopy',
           '_swift_cvw_assignWithCopy', '_swift_cvw_assignWithTake']
INDICES = {'UniversalHID': [7,8,9,10,12], 'UniversalHIDKit': [5]}


def contract(before, after, name):
    original = p.imports(before)['imports']; actual = p.imports(after)['imports']
    expected = bytearray(before); routes = []
    indices = INDICES[name]
    for index in indices:
        row = original[index]
        assert row['index'] == index and row['name'] in SYMBOLS and row['ordinal'] == 8 and not row['weak']
        if name == 'UniversalHIDKit': assert row['name'] == SYMBOLS[0]
        ordinal = 20 if name == 'UniversalHID' else 1
        expected[row['command']] = ordinal
        routes.append(dict(index=index, symbol=row['name'], at=row['command'], oldOrdinal=8, newOrdinal=ordinal, strong=True))
    assert after == expected and len(actual) == len(original)
    for old, new in zip(original, actual, strict=True):
        assert new == ({**old, 'ordinal': 20 if name == 'UniversalHID' else 1} if old['index'] in indices else old)
    return routes


def ar_contract(before, after):
    count, size = struct.unpack_from('<II', before, 16)
    addition = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/OW\0'
    assert len(addition) == 40 and not any(before[32 + size:32 + size + 40])
    expected = bytearray(before); struct.pack_into('<II', expected, 16, count + 1, size + 40)
    expected[32 + size:32 + size + 40] = addition
    assert after == expected and p.imports(after)['imports'] == p.imports(before)['imports']
    assert p.dependencies(after)[:-1] == p.dependencies(before)
    assert p.dependencies(after)[-1]['ordinal'] == 9


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists(); out.mkdir()
    base, build, whitelist = [r.r.checked(path) for path in (BASE, BUILD, WHITELIST)]
    assert build['allFiveNamedEntriesImplemented'] and build['allPositiveStrongImportsActualCurrentDefined']
    assert not build['productionHIDIdentityGatePassed'] and len(whitelist['rows']) == 65
    ios = next(x for x in build['roles'] if x['role'] == 'ios'); source_ow = ios['provider']
    owpath = out / 'OW.unchanged-unsigned-ios-provider.inert.macho-data'
    owpath.write_bytes(Path(source_ow['path']).read_bytes()); assert p.pin(owpath)['sha256'] == source_ow['sha256']
    source_ar = base['modifiedArrayReexportProvider']['candidate']; before_ar = Path(source_ar['path']).read_bytes()
    ar = bytearray(before_ar); ordinal = p.append_dependency(ar, '@loader_path/OW'); assert ordinal == 9
    added = p.dependencies(ar)[-1]; assert added['size'] == 40
    struct.pack_into('<I', ar, added['at'], 0x8000001f); ar_contract(before_ar, bytes(ar))
    arpath = out / 'AR.real-observed-cvw-reexport.inert.macho-data'; arpath.write_bytes(ar)
    images = s.primary.captured_images(); pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    pins += join_kernel(s, images); assert len(images) == 17
    images[s.primary.canonical_path('@loader_path/AR')] = r.r.image(p.pin(arpath), '@loader_path/AR')
    images[s.primary.canonical_path('@loader_path/OW')] = r.r.image(p.pin(owpath), '@loader_path/OW')
    results, negatives = [], []
    for name in ('UniversalHID', 'UniversalHIDKit'):
        source = next(x['candidate'] for x in base['images'] if x['name'] == name)
        before = Path(source['path']).read_bytes(); after = bytearray(before)
        for index in INDICES[name]:
            after[p.imports(before)['imports'][index]['command']] = 20 if name == 'UniversalHID' else 1
        routes = contract(before, bytes(after), name)
        path = out / (name + '27.observed-cvw-real-reexport.mac.inert.macho-data'); path.write_bytes(after)
        row = dict(name=name, source=source, candidate=p.pin(path), routes=routes,
            allInstructionMetadataWitnessPACBytesPreserved=True, originalAvailabilityGuardPreserved=True)
        results.append(row)
        images[s.primary.canonical_path('@loader_path/' + name + '27.dylib')] = r.r.image(p.pin(path), '@loader_path/' + name + '27.dylib')
        text = next(section for segment in p.segments(before) for section in segment['sections'] if section['name'] == '__text')['fileoff']
        pac = next(x for x in p.chain_entries(before) if x['auth'])['fileoff'] + 4
        metadata = next(section for segment in p.segments(before) for section in segment['sections'] if section['name'].startswith('__swift5'))['fileoff']
        for label, offset in [(f'import{route["index"]} ordinal', route['at']) for route in routes] + [
                ('weak bit', routes[0]['at'] + 1), ('symbol name offset', routes[0]['at'] + 2),
                ('source instruction', text), ('source PAC', pac), ('source metadata', metadata)]:
            changed = bytearray(after); changed[offset] ^= 1
            try: contract(before, bytes(changed), name)
            except (AssertionError, ValueError): negatives.append(dict(owner=name, name=label, rejected=True))
            else: raise AssertionError('mutated CVW route accepted')
    for image in results:
        owner = '@loader_path/' + image['name'] + '27.dylib'
        for route in image['routes']:
            dependency = next(x['path'] for x in p.dependencies(Path(image['candidate']['path']).read_bytes()) if x['ordinal'] == route['newOrdinal'])
            proof = s.primary.resolve(images, dependency, route['symbol']); leaf = proof
            while 'nested' in leaf: leaf = leaf['nested']
            assert proof['status'] == 'actualDirectExport' and leaf['owner'] == '@loader_path/OW'
            route['actualReexportDefinition'] = proof
    # AR header additions must preserve all earlier instructions, sections,
    # imports, chained pointers and providers. Test three actual counterexamples.
    fixups_at = next(struct.unpack_from('<II', before_ar, at + 8)[0]
        for cmd, at, size in p.commands(before_ar) if cmd == 0x80000034)
    for label, offset in [('wrong reexport command', added['at']), ('old AR instruction',
            next(sec['fileoff'] for segment in p.segments(before_ar) for sec in segment['sections'] if sec['name'] == '__text')),
            ('old AR chained fixups', fixups_at)]:
        changed = bytearray(ar); changed[offset] ^= 1
        try: ar_contract(before_ar, bytes(changed))
        except (AssertionError, ValueError): negatives.append(dict(owner='AR', name=label, rejected=True))
        else: raise AssertionError('mutated AR accepted')
    validations = []
    for path in [arpath, owpath] + [Path(x['candidate']['path']) for x in results]:
        result = subprocess.run(['xcrun','dyld_info','-validate_only',str(path)], capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path),exit=0))
    report = dict(schema='Genuine HID finite observed ownership six-strong private reexport data v1',
        sources=list(map(p.pin, (Path(__file__), BASE, BUILD, WHITELIST))), images=results,
        modifiedArrayReexportProvider=dict(alias='AR', intendedLoadPath='@loader_path/AR',source=source_ar,candidate=p.pin(arpath),
            addedGenuineReexport=dict(ordinal=9,path='@loader_path/OW',bytes=40),
            allOriginalSectionsImportsAndChainedPointerBytesPreserved=True, preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='OW',intendedLoadPath='@loader_path/OW',source=source_ow,candidate=p.pin(owpath),
            currentPositiveStrongDefinitions=ios['currentExactNativeImports']),
        preservedLeafProviders=base['preservedLeafProviders'] + [base['unchangedRuntimeProvider']],
        currentStockImages=17,routedStrongImports=6,negativeControls=negatives,structuralValidations=validations,
        allFiveNamedEntriesImplementedForExactOriginalWhitelist=True, originalStaticMetadataSchemas=65,
        completedInitialPODSupportedThroughIndependentGate=True,originalGetterWhole28BytesPreserved=True,
        originalRelativeFunctionProgramLowTagsPreserved=True, allOriginalInstructionsAndMetadataPreserved=True,
        candidateReadyForNativeLoading=False,productionHIDIdentityGatePassed=False,productionOriginalHIDEntryExecuted=False,
        originalEnumCallbackRuntimeCallabilityProven=False, fullSwiftBytecodeInterpreterImplemented=False,
        fullOriginal27RuntimeOverrideHookIdentity=False, fullSwift27RuntimeEquivalent=False, fullSwift27ParserEquivalent=False,
        allOriginalHIDTypesProvenResolvable=False,conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,
        allCurrentProvidersDeclared=False,currentCompleteProviderDependencyGraphValidated=False,metadataCompatibilityProven=False,
        originalHIDInitializerExecuted=False,originalUHLoaded=False,originalVZLoaded=False,nativeIOSExecuted=False,
        deviceOperations=0,codeSigned=False,full27Backend=False)
    p.save(out / 'candidate.json',report)
    paths = [Path(__file__),Path(r.__file__),BASE,BUILD,WHITELIST,Path(source_ar['path']),Path(source_ow['path']),
        arpath,owpath,out/'candidate.json'] + [Path(x[k]['path']) for x in results for k in ('source','candidate')]
    p.save(out/'freeze.json',dict(files=pins + list(map(p.pin,paths)),deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),strongImportsRouted=6,providerStrongImports=16,rejectedControls=len(negatives))))


if __name__ == '__main__': main()
