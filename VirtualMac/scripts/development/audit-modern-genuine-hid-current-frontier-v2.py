#!/usr/bin/env python3
"""Audit the declared inert HID/VZ subset against fourteen current stock tries.

This is exact definition evidence. Missing providers, process-global lookup,
Swift 27 parser equivalence and native loading remain separate unproved facts.
"""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
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
CG = NODE / 'cgaffine-genuine-equal-private-v6/candidate.json'


def image(pin, alias):
    assert p.pin(Path(pin['path'])) == pin
    body = Path(pin['path']).read_bytes()
    uuid = exports = None
    for command, at, size in p.commands(body):
        if command == 27:
            uuid = body[at + 8:at + 24].hex()
        if command == 0x80000033:
            off, length = struct.unpack_from('<II', body, at + 8)
            exports = s.primary.trie(body[off:off + length])
    assert uuid and exports is not None
    return dict(path=alias, UUID=uuid, image=pin, exports=exports,
                dependencies=p.dependencies(body), inertApplicationPrivate=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(NODE) and not out.exists()
    out.mkdir()
    for source in (ARRAY, CP, AB, STATE, CG):
        for row in json.loads((source.parent / 'freeze.json').read_text())['files']:
            assert p.pin(Path(row['path'])) == row
    array, cp, ab, state, cg = [json.loads(x.read_bytes()) for x in (ARRAY, CP, AB, STATE, CG)]
    assert state['sourceCandidate'] == p.pin(AB)
    assert not state['fullSwift27ParserEquivalent']
    assert not state['allOriginalVZTypesProvenResolvable']
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, NODE / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    assert len(images) == 14
    runtime = s.runtime_import_contract(images)
    declarations = []
    for row in array['images']:
        if row['name'] != 'Virtualization':
            declarations.append((row['name'], '@loader_path/' + row['name'] + '27.dylib', row['candidate']))
    declarations.append(('Virtualization', '@loader_path/Virtualization27.dylib', state['frontendCandidate']))
    declarations += [(r['alias'], r['intendedLoadPath'], r['candidate']) for r in array['unchangedRuntimeProviders']]
    declarations += [(r.get('alias', Path(r['candidate']['path']).name), r['intendedLoadPath'], r['candidate']) for r in cp['unchangedRuntimeProviders']]
    for name, candidate in (('AB', ab), ('VM27SwiftLookup', state)):
        provider = candidate['unchangedRuntimeProvider']
        declarations.append((name, provider['intendedLoadPath'], provider['candidate']))
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
                proof = s.primary.resolve(images, owner, item['name'])
            rows.append(dict(index=item['index'], symbol=item['name'], ordinal=ordinal,
                             addend=item.get('addend', 0), dependency=owner, proof=proof))
        results.append(dict(name=name, path=row['path'], image=row['image'], importAuditStatus=status,
                            strongImports=len(rows), counts=dict(collections.Counter(r['proof']['status'] for r in rows)), imports=rows))
    reserve = s.primary.resolve(images, '@loader_path/UniversalHID27.dylib', '_$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5')
    assert reserve['status'] == 'actualDirectExport'
    stateproof = s.primary.resolve(images, '@loader_path/VM27SwiftLookup.dylib', '_swift_getTypeByMangledNameInContextInMetadataState2')
    assert stateproof['status'] == 'actualDirectExport'
    assert s.primary.resolve(images, '@loader_path/VM27SwiftLookup.dylib', '__VM27_absent__')['status'] == 'actualExportAbsent'
    assert s.primary.resolve(images, '@loader_path/VM27_unknown_provider', '_swift_getWitnessTable')['status'] == 'uncapturedOwner'
    frontend = next(x for x in results if x['name'] == 'Virtualization')
    stateimport = next(x for x in frontend['imports'] if x['index'] == 705)
    assert stateimport['ordinal'] == 58 and stateimport['proof']['status'] == 'actualDirectExport'
    runtime_result = next(x for x in results if x['image'] == runtime['runtimeProvider'])
    assert runtime_result['strongImports'] == 14
    assert runtime_result['counts'] == dict(actualDirectExport=13, specialWeakLookupProvenanceUnproved=1)
    report = dict(schema='Latest exact declared genuine HID/VZ strong export frontier v2',
                  currentCacheUUID='1995ea169d0a33a0b78962cf99891168',
                  sources=[p.pin(x) for x in (ARRAY, CP, AB, STATE, CG)],
                  currentStockImages=14, declaredPrivateImages=len(private), auditedImages=results,
                  privateDefinitions=[{k: v for k, v in row.items() if k != 'exports'} | dict(exportCount=len(row['exports'])) for name, row in private],
                  cxxRuntimeImportContract=runtime, finiteOldHostState2Entry=dict(definition=stateproof,
                      fullSwift27ParserEquivalent=False, allOriginalVZTypesProvenResolvable=False),
                  definitionEvidenceOnly=True, allCurrentProvidersDeclared=False,
                  currentCompleteProviderDependencyGraphValidated=False, processGlobalLookupProven=False,
                  conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False,
                  metadataCompatibilityProven=False, originalVZLoaded=False, originalVMMExecuted=False,
                  nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    pins += [p.pin(path) for path in (Path(__file__), HERE / 'audit-modern-current-stock-extra-exports-v2.py',
             HERE / 'audit-modern-universalhid-current-stock-exports-v1.py', ARRAY, CP, AB, STATE, CG, out / 'audit.json')]
    pins += [row['image'] for name, row in private]
    p.save(out / 'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), images=[dict(name=r['name'], status=r['importAuditStatus'], counts=r['counts']) for r in results])))


if __name__ == '__main__':
    main()
