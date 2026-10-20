#!/usr/bin/env python3
"""Audit the declared inert HID/VZ subset against sixteen current stock tries.

This is exact definition evidence. Missing providers, process-global lookup,
Swift 27 parser equivalence and native loading remain separate unproved facts.
"""
import argparse
import collections
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from exact_private_bundle_rpath_v1 import resolve as bundle_resolve
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('current_frontier_stock_v2', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
NODE = p.NODE
ARRAY = NODE / 'universalhid-real-array-reexports-data-v1/candidate.json'
CP = NODE / 'vz-cxx-six-strong-data-v2/candidate.json'
AB = NODE / 'vz-arraybuffer-consume-strong-data-v1/candidate.json'
STATE = NODE / 'vz-state2-oldhost-entry-data-v1/candidate.json'
LOOKUP = NODE / 'universalhid-lookup-oldhost-entry-data-v1/candidate.json'
TYPED = NODE / 'universalhid-typedthrow-real-reexport-data-v1/candidate.json'
CG = NODE / 'cgaffine-genuine-equal-private-v6/candidate.json'


def image(pin, alias):
    assert p.pin(Path(pin['path'])) == pin
    body = Path(pin['path']).read_bytes()
    uuid = exports = None
    rpaths = []
    for command, at, size in p.commands(body):
        if command == 27:
            uuid = body[at + 8:at + 24].hex()
        if command == 0x80000033:
            off, length = struct.unpack_from('<II', body, at + 8)
            exports = s.primary.trie(body[off:off + length])
        if command == 0x8000001c:
            offset = struct.unpack_from('<I', body, at + 8)[0]
            assert 12 <= offset < size and b'\0' in body[at + offset:at + size]
            rpaths.append(body[at + offset:at + size].split(b'\0')[0].decode())
    assert uuid and exports is not None
    return dict(path=alias, UUID=uuid, image=pin, exports=exports,
                dependencies=p.dependencies(body), rpaths=rpaths,
                declaredFlatPrivateBundle=True, inertApplicationPrivate=True)


def resolve(images, path, symbol, requester=None):
    return bundle_resolve(s.primary, images, path, symbol, requester)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(NODE) and not out.exists()
    out.mkdir()
    for source in (ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED):
        for row in json.loads((source.parent / 'freeze.json').read_text())['files']:
            assert p.pin(Path(row['path'])) == row
    array, cp, ab, state, cg, lookup, typed = [json.loads(x.read_bytes()) for x in (ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED)]
    assert state['sourceCandidate'] == p.pin(AB)
    assert not state['fullSwift27ParserEquivalent']
    assert not state['allOriginalVZTypesProvenResolvable']
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, NODE / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, NODE / ('ipad-current-cache-' + group + '-headers-v2/headers.json'))
    assert len(images) == 16
    runtime = s.runtime_import_contract(images)
    declarations = []
    for row in typed['images']:
        if row['name'] != 'Virtualization':
            declarations.append((row['name'], '@loader_path/' + row['name'] + '27.dylib', row['candidate']))
    declarations.append(('Virtualization', '@loader_path/Virtualization27.dylib', state['frontendCandidate']))
    for provider in array['unchangedRuntimeProviders']:
        pin = typed['modifiedArrayReexportProvider']['candidate'] if provider['alias'] == 'AR' else provider['candidate']
        declarations.append((provider['alias'], provider['intendedLoadPath'], pin))
    declarations += [(r.get('alias', Path(r['candidate']['path']).name), r['intendedLoadPath'], r['candidate']) for r in cp['unchangedRuntimeProviders']]
    for name, candidate in (('AB', ab), ('TT', typed)):
        provider = candidate['unchangedRuntimeProvider']
        declarations.append((name, provider['intendedLoadPath'], provider['candidate']))
    declarations += [(provider['alias'], provider.get('intendedLoadPath', '@loader_path/' + provider['alias']), provider['candidate']) for provider in typed['preservedLeafProviders']]
    declarations.append(('CGe', '@loader_path/CGe', cg['iosProvider']))
    private = []
    for name, alias, pin in declarations:
        key = s.primary.canonical_path(alias)
        assert key not in images
        row = image(pin, alias)
        images[key] = row
        private.append((name, row))
    results = []
    for name, row in private:
        body = Path(row['image']['path']).read_bytes()
        status = 'parsedExactActiveImportTable'
        dependencies = {r['ordinal']: r['path'] for r in row['dependencies']}
        if row['image'] == runtime['runtimeProvider']:
            imports = [dict(index=x['index'], name=x['symbol'], ordinal=x['ordinal'], weak=x['weak'], addend=x['addend']) for x in runtime['imports']]
        else:
            try:
                imports = p.vz_reader.parse(body)['imports'] if name == 'Virtualization' else p.imports(body)['imports']
            except (ValueError, AssertionError):
                imports = []
                status = 'unsupportedImportSchemaNotProven'
        rows = []
        for item in imports:
            if item['weak']:
                continue
            ordinal = item['ordinal']
            owner = dependencies.get(ordinal)
            if ordinal <= 0:
                assert row['image'] == runtime['runtimeProvider']
                proof = runtime['imports'][item['index']]['definition']
                assert proof['status'] == 'specialWeakLookupProvenanceUnproved'
            else:
                assert owner is not None
                proof = resolve(images, owner, item['name'], row)
            rows.append(dict(index=item['index'], symbol=item['name'], ordinal=ordinal,
                             addend=item.get('addend', 0), dependency=owner, proof=proof))
        results.append(dict(name=name, path=row['path'], image=row['image'], importAuditStatus=status,
                            strongImports=len(rows), counts=dict(collections.Counter(r['proof']['status'] for r in rows)), imports=rows))
    reserve = resolve(images, '@loader_path/UniversalHID27.dylib', '_$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5')
    assert reserve['status'] == 'actualDirectExport'
    stateproof = resolve(images, '@loader_path/VM27SwiftLookup.dylib', '_swift_getTypeByMangledNameInContextInMetadataState2')
    assert stateproof['status'] == 'actualDirectExport'
    assert resolve(images, '@loader_path/VM27SwiftLookup.dylib', '__VM27_absent__')['status'] == 'actualExportAbsent'
    assert resolve(images, '@loader_path/VM27_unknown_provider', '_swift_getWitnessTable')['status'] == 'uncapturedOwner'
    frontend = next(x for x in results if x['name'] == 'Virtualization')
    stateimport = next(x for x in frontend['imports'] if x['index'] == 705)
    assert stateimport['ordinal'] == 58 and stateimport['proof']['status'] == 'actualDirectExport'
    runtime_result = next(x for x in results if x['image'] == runtime['runtimeProvider'])
    assert runtime_result['strongImports'] == 14
    assert runtime_result['counts'] == dict(actualDirectExport=13, specialWeakLookupProvenanceUnproved=1)
    lookup_result = next(x for x in results if x['name'] == 'VM27SwiftLookup')
    assert lookup_result['strongImports'] == 11 and lookup_result['counts'] == dict(actualDirectExport=11)
    typed_result = next(x for x in results if x['name'] == 'TT')
    assert typed_result['strongImports'] == 3 and typed_result['counts'] == dict(actualDirectExport=3)
    uh = next(x for x in results if x['name'] == 'UniversalHID')
    typed_import = next(x for x in uh['imports'] if x['index'] == 393)
    assert typed_import['ordinal'] == 20 and typed_import['proof']['status'] == 'actualDirectExport'
    assert len(private) == 13
    cpimage = images['@loader_path/CP']
    assert cpimage['rpaths'] == ['@loader_path']
    cp_named = []
    for symbol, entry in cpimage['exports'].items():
        if not entry['flags'] & 8:
            continue
        proof = resolve(images, '@loader_path/CP', symbol)
        assert proof['status'] == 'actualDirectExport'
        leaf = proof
        while 'nested' in leaf:
            leaf = leaf['nested']
        assert leaf['owner'] == '@loader_path/ModernCPURuntimeCompat.dylib'
        cp_named.append(dict(symbol=symbol, definition=proof))
    assert len(cp_named) == 7
    assert all(next(x for x in frontend['imports'] if x['index'] == index)['proof']['status'] == 'actualDirectExport' for index in (23, 24, 401, 425, 426, 427))
    rpath_negatives = []
    symbol = cp_named[0]['symbol']
    for label, rpaths, placement in (('missing actual rpath', [], True),
        ('wrong executable rpath', ['@executable_path'], True),
        ('unknown inherited rpath precedes provider path', ['@rpath/unknown', '@loader_path'], True),
        ('undeclared requesting placement', ['@loader_path'], False)):
        damaged = copy.deepcopy(images)
        damaged['@loader_path/CP']['rpaths'] = rpaths
        damaged['@loader_path/CP']['declaredFlatPrivateBundle'] = placement
        assert resolve(damaged, '@loader_path/CP', symbol)['status'] == 'uncapturedOwner'
        rpath_negatives.append(dict(name=label, rejected=True))
    damaged = copy.deepcopy(images)
    del damaged['@loader_path/ModernCPURuntimeCompat.dylib']
    assert resolve(damaged, '@loader_path/CP', symbol)['status'] == 'uncapturedOwner'
    rpath_negatives.append(dict(name='actual declared runtime absent', rejected=True))
    assert resolve(images, '@rpath/ModernCPURuntimeCompat.dylib', symbol)['status'] == 'uncapturedOwner'
    rpath_negatives.append(dict(name='rpath without requesting image', rejected=True))
    assert resolve(images, '@rpath/../ModernCPURuntimeCompat.dylib', symbol, cpimage)['status'] == 'uncapturedOwner'
    rpath_negatives.append(dict(name='unknown parent path expansion', rejected=True))
    assert resolve(images, '@loader_path/CP', '__VM27_undeclared_CP_symbol__')['status'] == 'actualExportAbsent'
    rpath_negatives.append(dict(name='missing definition does not become available', rejected=True))
    report = dict(schema='Latest exact declared genuine HID/VZ strong export frontier v5',
                  currentCacheUUID='1995ea169d0a33a0b78962cf99891168',
                  sources=[p.pin(x) for x in (ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED)],
                  currentStockImages=16, declaredPrivateImages=len(private), auditedImages=results,
                  privateDefinitions=[{k: v for k, v in row.items() if k != 'exports'} | dict(exportCount=len(row['exports'])) for name, row in private],
                  cxxRuntimeImportContract=runtime, finiteOldHostState2Entry=dict(definition=stateproof,
                      fullSwift27ParserEquivalent=False, allOriginalVZTypesProvenResolvable=False),
                  finiteHIDLookupEntry=dict(source=p.pin(LOOKUP), fullSwift27ParserEquivalent=False, allOriginalHIDTypesProvenResolvable=False),
                  finiteOldHostCoroAllocator=dict(typedAllocatorTelemetryPreserved=False, allCoroutineLifecycleValidated=False),
                  actualSystemAvailability=dict(hostVersionSpoofed=False), privateARSignatureValidityEstablished=False,
                  finitePrivateBundleRPathDefinitions=dict(actualCPLCRPath='@loader_path',
                      sevenNamedReexports=cp_named, negativeControls=rpath_negatives,
                      definitionEvidenceOnly=True, fullRuntimeSpecialOrdinalNamespaceProven=False),
                  finiteOldHostTypedThrow=dict(source=p.pin(TYPED), ordinaryMacThreeBranchesCompared=True,
                      productionNativeCallbackSlotWritten=False, providerPrivateTypedCallbackSlot=True,
                      processGlobalTypedHookIdentityPreserved=False, originalUHErrorWitnessCompatibilityProven=False,
                      allOriginalHIDErrorTypesBoxableOnOldHost=False),
                  definitionEvidenceOnly=True, allCurrentProvidersDeclared=False,
                  currentCompleteProviderDependencyGraphValidated=False, processGlobalLookupProven=False,
                  conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False,
                  metadataCompatibilityProven=False, originalVZLoaded=False, originalVMMExecuted=False,
                  nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    pins += [p.pin(path) for path in (Path(__file__), HERE / 'audit-modern-current-stock-extra-exports-v2.py',
             HERE / 'audit-modern-universalhid-current-stock-exports-v1.py', ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED, out / 'audit.json')]
    pins += [row['image'] for name, row in private]
    pins.append(p.pin(HERE / 'exact_private_bundle_rpath_v1.py'))
    p.save(out / 'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), images=[dict(name=r['name'], status=r['importAuditStatus'], counts=r['counts']) for r in results])))


if __name__ == '__main__':
    main()
