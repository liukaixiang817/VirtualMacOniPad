#!/usr/bin/env python3
"""Route four exact signed lookup entries through a real, guarded old-host provider."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hid_lookup_current', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
AV = p.NODE / 'universalhid-availability-real-reexport-data-v1/candidate.json'
STATE = p.NODE / 'vz-state2-oldhost-entry-data-v1/candidate.json'
ABI = p.NODE / 'universalhid-lookup-oldhost-entry-abi-v2/audit.json'
NAMES = ('_swift_getTypeByMangledNameInContext2', '_swift_getTypeByMangledNameInContextInMetadataState2')
LOOKUP = '@loader_path/VM27SwiftLookup.dylib'


def checked(path):
    for pin in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
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


def hid_contract(old, new, ordinal, indices):
    original = p.imports(old)['imports']
    actual = p.imports(new)['imports']
    expected = bytearray(old)
    routes = []
    for symbol, index in zip(NAMES, indices):
        item = next(x for x in original if x['name'] == symbol)
        assert item['index'] == index and item['ordinal'] == 8 and not item['weak']
        at = item['command']
        expected[at] = ordinal
        routes.append(dict(index=index, symbol=symbol, at=at, oldOrdinal=8, newOrdinal=ordinal, strong=True))
    assert new == expected
    for a, b in zip(original, actual, strict=True):
        assert b == ({**a, 'ordinal': ordinal} if a['index'] in indices else a)
    return routes


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    av, state, abi = [checked(x) for x in (AV, STATE, ABI)]
    assert abi['externalSwiftCCAndPACEntryABICompatible'] and abi['callerSignedContextsAndGenericArgumentsAllNull']
    assert not abi['fullSwift27ParserEquivalent'] and not abi['allOriginalHIDTypesProvenResolvable']
    source = state['unchangedRuntimeProvider']['candidate']
    assert abi['wholeActualOldHostProvider'] == source
    providerpath = out / 'VM27SwiftLookup.unchanged-ios-provider.inert.macho-data'
    providerpath.write_bytes(Path(source['path']).read_bytes())
    assert p.pin(providerpath)['sha256'] == source['sha256']
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v2/headers.json'))
    assert len(images) == 16
    provider = image(p.pin(providerpath), LOOKUP)
    assert set(provider['exports']) == set(NAMES)
    dependencies = {x['ordinal']: x['path'] for x in provider['dependencies']}
    provider_imports = []
    for item in p.imports(Path(source['path']).read_bytes())['imports']:
        assert item['ordinal'] > 0 and not item['weak']
        proof = s.primary.resolve(images, dependencies[item['ordinal']], item['name'])
        assert proof['status'] == 'actualDirectExport'
        provider_imports.append(dict(item, dependency=dependencies[item['ordinal']], definition=proof))
    assert len(provider_imports) == 11
    images[s.primary.canonical_path(LOOKUP)] = provider
    arsource = av['modifiedArrayReexportProvider']['candidate']
    before_ar = Path(arsource['path']).read_bytes()
    ar = bytearray(before_ar)
    count, size = struct.unpack_from('<II', ar, 16)
    ordinal = p.append_dependency(ar, LOOKUP)
    assert ordinal == 5
    added = p.dependencies(ar)[-1]
    assert added['size'] == 64 and added['at'] == 32 + size
    struct.pack_into('<I', ar, added['at'], 0x8000001f)
    expected = bytearray(before_ar)
    struct.pack_into('<II', expected, 16, count + 1, size + 64)
    expected[32 + size:32 + size + 64] = ar[32 + size:32 + size + 64]
    assert ar == expected and p.imports(ar)['imports'] == p.imports(before_ar)['imports']
    arpath = out / 'AR.real-lookup-reexport.inert.macho-data'
    arpath.write_bytes(ar)
    images[s.primary.canonical_path('@loader_path/AR')] = image(p.pin(arpath), '@loader_path/AR')
    results = []
    originals = []
    for name, owner_ordinal, indices in (('UniversalHID', 20, (367, 368)), ('UniversalHIDKit', 1, (136, 137))):
        original = next(x for x in av['images'] if x['name'] == name)['candidate']
        before = Path(original['path']).read_bytes()
        data = bytearray(before)
        for symbol in NAMES:
            item = next(x for x in p.imports(before)['imports'] if x['name'] == symbol)
            data[item['command']] = owner_ordinal
        routes = hid_contract(before, bytes(data), owner_ordinal, indices)
        path = out / (name + '27.lookup-oldhost-entry.mac.inert.macho-data')
        path.write_bytes(data)
        images[s.primary.canonical_path('@loader_path/' + name + '27.dylib')] = image(p.pin(path), '@loader_path/' + name + '27.dylib')
        results.append(dict(name=name, source=original, candidate=p.pin(path), routes=routes,
            allInstructionMetadataWitnessPACBytesPreserved=True))
        originals.append((name, before, bytes(data), owner_ordinal, indices))
    for row in results:
        owners = {x['ordinal']: x['path'] for x in p.dependencies(Path(row['candidate']['path']).read_bytes())}
        for route in row['routes']:
            proof = s.primary.resolve(images, owners[route['newOrdinal']], route['symbol'])
            leaf = proof
            while 'nested' in leaf:
                leaf = leaf['nested']
            assert proof['status'] == 'actualDirectExport' and leaf['owner'] == LOOKUP
            route['actualReexportDefinition'] = proof
    negatives = []
    for name, before, after, ordinal, indices in originals:
        at = next(x for x in p.imports(before)['imports'] if x['index'] == indices[0])['command']
        text = next(x for g in p.segments(before) for x in g['sections'] if x['name'] == '__text')['fileoff']
        pac = next(x for x in p.chain_entries(before) if x['auth'])['fileoff'] + 4
        for label, offset in (('wrong entry ordinal', at), ('weak lookup', at + 1), ('genuine instruction', text), ('genuine PAC', pac)):
            damaged = bytearray(after)
            damaged[offset] ^= 1
            try:
                hid_contract(before, bytes(damaged), ordinal, indices)
            except (AssertionError, ValueError):
                negatives.append(dict(name=name + ': ' + label, rejected=True))
            else:
                raise AssertionError('invalid lookup candidate accepted')
    validations = []
    for path in [arpath, providerpath] + [Path(row['candidate']['path']) for row in results]:
        result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path), exit=result.returncode))
    report = dict(schema='Four genuine HID old-host authenticated lookup entry strong routes v1',
        sources=[p.pin(x) for x in (AV, STATE, ABI)], images=results,
        modifiedArrayReexportProvider=dict(alias='AR', intendedLoadPath='@loader_path/AR', source=arsource,
            candidate=p.pin(arpath), addedGenuineReexport=dict(ordinal=5, path=LOOKUP, bytes=64),
            allOriginalSectionsImportsAndChainedPointersPreserved=True, preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='VM27SwiftLookup', intendedLoadPath=LOOKUP, source=source,
            candidate=p.pin(providerpath), currentPositiveStrongDefinitions=provider_imports),
        preservedLeafProviders=[av['unchangedRuntimeProvider'], av['preservedCoroProvider']],
        originalCallerABI=p.pin(ABI), currentStockImages=16, allElevenLookupProviderStrongDefinitionsResolved=True,
        routedStrongImports=4, negativeControls=negatives, structuralValidations=validations,
        compatibilityScope='finite old-host SwiftCC/PAC entry delegation with nullable metadata and complete state value retained',
        callerSignedContextsAndGenericArgumentsAllNull=True, fullSwift27ParserEquivalent=False,
        allOriginalHIDTypesProvenResolvable=False, conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False,
        allCurrentProvidersDeclared=False, currentCompleteProviderDependencyGraphValidated=False, metadataCompatibilityProven=False,
        originalUHLoaded=False, originalVZLoaded=False, nativeIOSExecuted=False, deviceOperations=0,
        codeSigned=False, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(__file__), AV, STATE, ABI, out / 'candidate.json', arpath, providerpath]
    files += [Path(x[k]['path']) for x in results for k in ('source', 'candidate')]
    files += [Path(arsource['path']), Path(source['path'])]
    pins += [p.pin(x) for x in files]
    p.save(out / 'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), strongImportsRouted=4, nativeProviderDefinitions=11, rejectedControls=8)))


if __name__ == '__main__':
    main()
