#!/usr/bin/env python3
"""One final exact frontier for ten newly captured current stock tables.

All 51 private placements remain explicit. The only changed private bytes are
the two scoped Metal branches. Strong definitions are separate from execution,
complete metadata, special lookup namespaces and a working VM backend.
"""
import collections
import copy
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('final_frontier_prior', HERE / 'audit-modern-genuine-hid-current-frontier-v19.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
from current_remaining_six_capture_v1 import join as join_six
from current_remaining_three_capture_v1 import join as join_three
from current_system_sandbox_capture_v1 import join as join_sandbox
p, s, n = f.p, f.s, f.NODE


def main():
    out = n / 'universalhid-current-exact-frontier-audit-v25'
    assert not out.exists()
    prior = n / 'universalhid-current-exact-frontier-audit-v24/audit.json'
    port = n / 'vz-metal-singleton-selection-data-v3/candidate.json'
    six_audit = n / 'current-remaining-six-native-definitions-readonly-v2/audit.json'
    peer = n / 'vz-metal-singleton-selection-independent-review-v1/review.json'
    pins = []
    for source in (prior, port, six_audit, peer):
        for row in json.loads((source.parent / 'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path'])) == row
            pins.append(row)
        pins.append(p.pin(source.parent / 'freeze.json'))
    previous, branch = json.loads(prior.read_bytes()), json.loads(port.read_bytes())
    assert previous['currentStockImages'] == 36 and previous['declaredPrivateImages'] == 51
    assert branch['changedWholeFileBytes'] == 7 and branch['totalOriginalImports'] == 1056
    assert branch['originalStrongImports'] == 1011
    independent = json.loads(peer.read_bytes())
    assert not independent['findings'] and independent['limitedTwoBranchInertPortPassed']
    assert independent['actualWholeFileChanges'] == 7 and independent['changedInstructions'] == 2
    images = s.primary.captured_images()
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, n / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, n / ('ipad-current-cache-' + group + '-headers-v2/headers.json'))
    pins += f.join_kernel(s, images)
    for fn in (f.join_hid_extra, f.join_swift_two, f.join_eight, f.join_three,
               f.join_trace, f.join_unwind, f.join_compiler, f.join_crypto):
        added, _ = fn(s, images)
        pins += added
    assert len(images) == 36
    added, six = join_six(s, images)
    pins += added
    added, three = join_three(s, images)
    pins += added
    added, sandbox = join_sandbox(s, images)
    pins += added
    assert len(images) == 46
    private, placements, code_changes = [], {}, []
    for old in previous['privateDefinitions']:
        pin = old['image']
        if pin == branch['sourceFrontendImage']:
            assert old['path'] == '@loader_path/Virtualization27.dylib'
            pin = branch['frontendCandidate']
            code_changes.append(dict(name='Virtualization', previous=old['image'], current=pin,
                source=p.pin(port), changedWholeFileBytes=7, changedInstructions=2,
                originalImportsAndAllOtherWholeFileBytesPreserved=True,
                onlyPinnedZeroOrOneNativeDeviceArrayDomain=True, originalCallerExecuted=False))
        declared = dict(old)
        declared.update(f.image(pin, old['path']))
        assert declared['UUID'] == old['UUID'] and declared['dependencies'] == old['dependencies'] and declared['rpaths'] == old['rpaths']
        key = s.primary.canonical_path(old['path'])
        assert key not in images
        images[key] = declared
        private.append(declared)
        placements[old['image']['path']] = declared
        pins.append(pin)
    assert len(code_changes) == 1 and len(private) == 51
    results, transitions = [], []
    for old in previous['auditedImages']:
        declared = placements[old['image']['path']]
        schema = f.import_records(Path(declared['image']['path']).read_bytes(), p.commands)
        ordinary = [row for row in schema['imports'] if not row['weak']]
        assert len(ordinary) == old['strongImports']
        indexes = {row['index']: row for row in ordinary}
        rows = []
        for before in old['imports']:
            record = indexes[before['index']]
            assert (record['name'], record['ordinal'], record['addend']) == (before['symbol'], before['ordinal'], before['addend'])
            if record['ordinal'] <= 0:
                proof = before['proof']
            else:
                dependency = next(row for row in declared['dependencies'] if row['ordinal'] == record['ordinal'])
                assert dependency['path'] == before['dependency']
                proof = f.resolve(images, dependency['path'], record['name'], declared)
            rows.append(dict(before, proof=proof))
            if proof['status'] != before['proof']['status']:
                assert before['proof']['status'] in ('uncapturedOwner', 'ownerHasNoDefinitionReexportsUnverified')
                assert proof['status'] == 'actualDirectExport'
                transitions.append(dict(owner=old['name'], index=before['index'], symbol=record['name'],
                    dependency=before['dependency'], previousStatus=before['proof']['status'],
                    currentStatus=proof['status'], currentProof=proof))
        results.append(dict(old, image=declared['image'], imports=rows,
            activeImportRecordSchema={k: v for k, v in schema.items() if k != 'imports'},
            counts=dict(collections.Counter(row['proof']['status'] for row in rows))))
    assert sum(row['strongImports'] for row in results) == 3647
    frontend = next(row for row in results if row['name'] == 'Virtualization')
    assert frontend['image'] == branch['frontendCandidate']
    assert frontend['strongImports'] == 1011
    sandbox_routes = []
    for item in frontend['imports']:
        if item['index'] not in (675, 676, 677, 678, 679, 835, 836):
            continue
        proof = item['proof']
        assert proof['status'] == 'actualDirectExport'
        assert proof['reexportDependency']['command'] == 0x8000001f
        assert proof['nested']['owner'] == sandbox['actualPath']
        sandbox_routes.append(dict(index=item['index'], symbol=item['symbol'], proof=proof))
    assert len(sandbox_routes) == 7
    accelerate_routes, negatives = [], []
    accelerate = '/System/Library/Frameworks/Accelerate.framework/Accelerate'
    for item in frontend['imports']:
        if item['dependency'] != accelerate:
            continue
        proof = item['proof']
        assert proof['status'] == 'actualDirectExport'
        assert proof['reexportDependency']['ordinal'] == 1 and proof['reexportDependency']['command'] == 0x8000001f
        assert proof['nested']['owner'] == '/System/Library/Frameworks/Accelerate.framework/Frameworks/vImage.framework/vImage'
        accelerate_routes.append(dict(index=item['index'], symbol=item['symbol'], proof=proof))
    assert len(accelerate_routes) == 3
    symbol = accelerate_routes[0]['symbol']
    for label, operation in (
        ('real reexport replaced by ordinary dependency', lambda graph: graph[accelerate]['dependencies'][0].update(command=12)),
        ('exact vImage dependency changed to unknown leaf', lambda graph: graph[accelerate]['dependencies'][0].update(path='/unknown/vImage')),
        ('actual vImage removed', lambda graph: graph.pop('/System/Library/Frameworks/Accelerate.framework/Frameworks/vImage.framework/vImage'))):
        damaged = copy.deepcopy(images)
        operation(damaged)
        assert f.resolve(damaged, accelerate, symbol)['status'] != 'actualDirectExport'
        negatives.append(dict(name=label, rejected=True))
    report = copy.deepcopy(previous)
    report.update(schema='Latest exact declared genuine HID/VZ strong export frontier v25',
        sources=previous['sources'] + [p.pin(source) for source in (prior, port, six_audit)],
        currentStockImages=46, declaredPrivateImages=51, auditedImages=results,
        privateDefinitions=[{k: v for k, v in row.items() if k != 'exports'} for row in private],
        actualSixCurrentStockCapture=six, actualLastThreeCurrentStockCapture=three,
        actualSystemSandboxCapture=sandbox, actualSystemSandboxSevenFrontendDefinitions=sandbox_routes,
        actualAccelerateVImageThreeFrontendDefinitions=accelerate_routes,
        exactNativeReexportNegativeControls=negatives,
        totalStrongImports=3647,
        totalStrongDefinitionCounts=dict(sum((collections.Counter(row['counts']) for row in results), collections.Counter())),
        exactPreviousFrontierComparison=dict(source=p.pin(prior), unchangedPrivateCandidateBytes=False,
            exactLocalCandidateChanges=code_changes, newPrivateProviders=[],
            allOtherPrivateCandidateWholeBytesUnchanged=True,
            allActiveImportRecordsAndDependencyOrdinalsUnchanged=True,
            strongDefinitionTransitions=transitions,
            counts=dict(collections.Counter(item['currentStatus'] for item in transitions)),
            allExplicitActualMissingDefinitions=[dict(owner=result['name'], index=item['index'], symbol=item['symbol'],
                dependency=item['dependency'], proof=item['proof']) for result in results for item in result['imports']
                if item['proof']['status'] == 'actualExportAbsent']),
        finiteMetalSingletonSelectionCodePort=dict(source=p.pin(port), frontend=branch['frontendCandidate'],
            independentFinitePeer=p.pin(peer), independentLimitedPortPassed=True,
            changedWholeFileBytes=7, changedInstructions=2, actualPinnedZeroOrOneDomainOnly=True,
            allOriginalPACAndOwnershipInstructionsPreserved=True, nativeObjectIdentityPreserved=True,
            propertiesInvented=False, systemMethodsAdded=False, originalVZCallerExecuted=False,
            exceptionTableBytesPreserved=True, completeExceptionSemanticsNewlyValidated=False,
            codeCandidateReadyForDeviceExecution=False),
        allCurrentProvidersDeclared=False, currentCompleteProviderDependencyGraphValidated=False,
        processGlobalLookupProven=False, originalVZLoaded=False, originalVMMExecuted=False,
        nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    report['finiteExistingPrivateDeclarationSubset']['exactOriginal38CandidatesWholeBytesPreserved'] = False
    report['finiteExistingPrivateDeclarationSubset']['allExceptScopedVZTwoBranchesWholeBytesPreserved'] = True
    report['finiteNativeMetalArray']['currentFrontendCodeOnlyPort'] = p.pin(port)
    out.mkdir()
    p.save(out / 'audit.json', report)
    for row in three['images']:
        p.save(out / (Path(row['actualPath']).name + '-exports.json'), images[s.primary.canonical_path(row['actualPath'])]['exports'])
    p.save(out / 'libsystem_sandbox.dylib-exports.json', images[sandbox['actualPath']]['exports'])
    pins += [p.pin(path) for path in (Path(__file__), HERE / 'current_remaining_six_capture_v1.py',
        HERE / 'current_remaining_three_capture_v1.py', HERE / 'current_system_sandbox_capture_v1.py',
        prior, port, six_audit, peer, n / 'current-remaining-six-native-definitions-readonly-v1/audit.json')]
    pins += [p.pin(path) for path in out.iterdir() if path.is_file()]
    unique = {row['path']: row for row in pins}
    assert all(unique[row['path']] == row for row in pins)
    p.save(out / 'freeze.json', dict(files=list(unique.values()), deviceOperations=0, nativeCPUCalls=0))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), freeze=p.pin(out / 'freeze.json'),
        stockImages=46, privateImages=51, strongImports=3647,
        counts=report['totalStrongDefinitionCounts'], frontendCounts=frontend['counts'],
        newStrongDefinitions=len(transitions), counterexamples=len(six['negativeControls']) +
            len(three['negativeControls']) + len(sandbox['negativeControls']) + len(negatives))))


if __name__ == '__main__':
    main()
