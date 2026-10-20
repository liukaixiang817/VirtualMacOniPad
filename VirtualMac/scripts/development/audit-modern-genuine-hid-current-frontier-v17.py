#!/usr/bin/env python3
"""Audit the declared inert HID/VZ subset against thirty-four current stock tries.

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
from current_kernel_capture_v1 import join as join_kernel
from current_hid_extra_three_capture_v1 import join as join_hid_extra
from current_swift_two_capture_v1 import join as join_swift_two
from current_vz_eight_capture_v2 import join as join_eight
from current_hid_system_three_capture_v1 import join as join_three
from current_hid_trace_capture_v1 import join as join_trace
from current_metal_unwind_capture_v1 import join as join_unwind
from macho_chained_import_records_v1 import read as import_records
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
POD = NODE / 'universalhid-pod-layout-real-reexport-data-v2/candidate.json'
TAKE = NODE / 'universalhid-bitwise-take-real-reexport-data-v1/candidate.json'
OWNERSHIP = NODE / 'universalhid-observed-cvw-real-reexport-data-v2/candidate.json'
DECLARATIONS = NODE / 'current-private-declarations-readonly-v3/audit.json'
CURRENT = NODE / 'universalhid-pod-current-native-layout-readonly-v1/audit.json'
CG = NODE / 'cgaffine-genuine-equal-private-v6/candidate.json'
KEY = NODE / 'universalhid-request-key-real-reexport-data-v2/candidate.json'
DE = NODE / 'universalhid-double-events-real-reexport-data-v2/candidate.json'
PREVIOUS = NODE / 'universalhid-current-exact-frontier-audit-v18/audit.json'
SCOPED_DECLARATIONS = NODE / 'current-private-scoped-declarations-readonly-v2/audit.json'
EIGHT = NODE / 'current-vz-eight-native-exports-audit-v3/audit.json'
MALLOC = NODE / 'iokit-current-malloc-definition-readonly-v1/audit.json'
METAL = NODE / 'vz-metal-array-real-reexport-data-v4/candidate.json'
METAL_CLOSURE = NODE / 'metal-current-strong-definitions-readonly-v1/audit.json'


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
    for source in (ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED, POD, TAKE, CURRENT, OWNERSHIP, DECLARATIONS, KEY, DE, PREVIOUS, EIGHT, MALLOC, METAL, METAL_CLOSURE, SCOPED_DECLARATIONS):
        for row in json.loads((source.parent / 'freeze.json').read_text())['files']:
            assert p.pin(Path(row['path'])) == row
    array, cp, ab, state, cg, lookup, typed = [json.loads(x.read_bytes()) for x in (ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED)]
    pod = json.loads(POD.read_bytes())
    take = json.loads(TAKE.read_bytes())
    ownership = json.loads(OWNERSHIP.read_bytes())
    key_route = json.loads(KEY.read_bytes())
    assert key_route['routedStrongImports'] == 1 and not key_route['remainingTwoEventConstructorsImplemented']
    de_route=json.loads(DE.read_bytes())
    assert de_route['routedStrongImports']==2 and not de_route['nativeIOSExecuted']
    actual_declarations = json.loads(DECLARATIONS.read_bytes())
    scoped_declarations = json.loads(SCOPED_DECLARATIONS.read_bytes())
    assert scoped_declarations['newPrivateDeclarationCount'] == 13
    assert not scoped_declarations['currentCompleteProviderDependencyGraphValidated']
    current = json.loads(CURRENT.read_bytes())
    assert current['actualCurrentIOSUUIDAndUInt64TypeLayoutsRead'] and not current['originalHIDInitializerExecuted']
    assert state['sourceCandidate'] == p.pin(AB)
    assert not state['fullSwift27ParserEquivalent']
    assert not state['allOriginalVZTypesProvenResolvable']
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, NODE / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, NODE / ('ipad-current-cache-' + group + '-headers-v2/headers.json'))
    pins += join_kernel(s, images)
    hid_extra_pins, hid_extra = join_hid_extra(s, images)
    pins += hid_extra_pins
    swift_two_pins, swift_two = join_swift_two(s, images)
    pins += swift_two_pins
    assert len(images) == 22
    eight_pins, eight = join_eight(s, images)
    pins += eight_pins
    assert len(images) == 29 and eight['newlyDeclaredNativeImages'] == 7
    three_pins, three = join_three(s, images); pins += three_pins
    trace_pins, trace = join_trace(s, images); pins += trace_pins
    unwind_pins, unwind = join_unwind(s, images); pins += unwind_pins
    assert len(images) == 34
    metal = json.loads(METAL.read_bytes())
    metal_closure = json.loads(METAL_CLOSURE.read_bytes())
    assert metal['completeMDCurrentStrongDefinitionsValidated'] and not metal['candidateReadyForNativeLoading']
    assert metal['sourceFrontend'] == state['frontendCandidate']
    runtime = s.runtime_import_contract(images)
    declarations = []
    for row in de_route['images']:
        if row['name'] != 'Virtualization':
            declarations.append((row['name'], '@loader_path/' + row['name'] + '27.dylib', row['candidate']))
    declarations.append(('Virtualization', '@loader_path/Virtualization27.dylib', metal['frontendCandidate']))
    for provider in array['unchangedRuntimeProviders']:
        pin = de_route['modifiedArrayReexportProvider']['candidate'] if provider['alias'] == 'AR' else provider['candidate']
        declarations.append((provider['alias'], provider['intendedLoadPath'], pin))
    declarations += [(r.get('alias', Path(r['candidate']['path']).name), r['intendedLoadPath'], r['candidate']) for r in cp['unchangedRuntimeProviders']]
    for name, candidate in (('AB', ab), ('TT', typed), ('PL', pod), ('BT', take), ('OW', ownership), ('IK', key_route), ('DE', de_route)):
        provider = candidate['unchangedRuntimeProvider']
        declarations.append((name, provider['intendedLoadPath'], provider['candidate']))
    declarations += [(provider['alias'], provider.get('intendedLoadPath', '@loader_path/' + provider['alias']), provider['candidate']) for provider in typed['preservedLeafProviders']]
    declarations.append(('CGe', '@loader_path/CGe', cg['iosProvider']))
    md_provider = metal['unchangedRuntimeProvider']
    declarations.append(('MD', md_provider['intendedLoadPath'], md_provider['candidate']))
    private = []
    for name, alias, pin in declarations:
        key = s.primary.canonical_path(alias)
        assert key not in images
        row = image(pin, alias)
        images[key] = row
        private.append((name, row))
    new_declarations, identical_declarations = [], []
    for provider in actual_declarations['providers']:
        alias, pin = provider['intendedLoadPath'], provider['candidate']
        key = s.primary.canonical_path(alias)
        if key in images:
            assert images[key]['image']['sha256'] == pin['sha256']
            assert images[key]['image']['bytes'] == pin['bytes']
            identical_declarations.append(dict(path=alias, current=images[key]['image'], sameWholeBytes=pin))
            continue
        row = image(pin, alias)
        row.update(historicalPartialBundleDeclarationOnly=True, functionSemanticsNewlyAudited=False,
                   originalMetadataSemanticsNewlyAudited=False)
        images[key] = row
        private.append((provider['name'], row))
        new_declarations.append(dict(path=alias, image=pin, exportCount=len(row['exports'])))
    scoped_private = []
    for provider in scoped_declarations['providers']:
        alias, pin = provider['intendedLoadPath'], provider['candidate']
        key = s.primary.canonical_path(alias)
        assert key not in images
        row = image(pin, alias)
        assert row['UUID'] == provider['UUID'] and row['dependencies'] == provider['dependencies']
        row.update(finiteExistingPrivateDeclarationOnly=True, finiteScope=provider['finiteScope'],
                   functionSemanticsNewlyAudited=False, originalCallerRuntimeBindingValidated=False)
        images[key] = row
        private.append((provider['name'], row))
        scoped_private.append(dict(name=provider['name'], path=alias, image=pin,
            finiteOwnAPIVersionOnlyRepair=provider['finiteOwnAPIVersionOnlyRepair'],
            existingCandidateWholeBytesPreserved=provider['existingCandidateWholeBytesPreserved']))
    assert len(scoped_private) == 13
    results = []
    for name, row in private:
        body = Path(row['image']['path']).read_bytes()
        schema = import_records(body, p.commands)
        status = 'parsedExactActiveChainedImportRecordsFormat' + str(schema['importsFormat'])
        dependencies = {r['ordinal']: r['path'] for r in row['dependencies']}
        if row['image'] == runtime['runtimeProvider']:
            imports = [dict(index=x['index'], name=x['symbol'], ordinal=x['ordinal'], weak=x['weak'], addend=x['addend']) for x in runtime['imports']]
            assert [(x['index'],x['name'],x['ordinal'],x['weak'],x['addend']) for x in imports] == [
                (x['index'],x['name'],x['ordinal'],x['weak'],x['addend']) for x in schema['imports']]
        else:
            imports = schema['imports']
            if name == 'Virtualization':
                old = p.vz_reader.parse(body)['imports']
                assert [(x['index'],x['name'],x['ordinal'],x['weak'],x.get('addend',0)) for x in old] == [
                    (x['index'],x['name'],x['ordinal'],x['weak'],x['addend']) for x in imports]
            elif schema['importsFormat'] == 1:
                assert imports == [dict(x,addend=0) for x in p.imports(body)['imports']]
        rows = []
        for item in imports:
            if item['weak']:
                continue
            ordinal = item['ordinal']
            owner = dependencies.get(ordinal)
            if ordinal <= 0:
                if row['image'] == runtime['runtimeProvider']:
                    proof = runtime['imports'][item['index']]['definition']
                    assert proof['status'] == 'specialWeakLookupProvenanceUnproved'
                else:
                    proof = dict(status='specialGlobalLookupProvenanceUnproved',specialOrdinal=ordinal,
                        symbol=item['name'],weakImportBit=item['weak'],addend=item.get('addend',0),
                        recordSchemaProven=True,processGlobalBindingProven=False)
            else:
                assert owner is not None
                proof = resolve(images, owner, item['name'], row)
            rows.append(dict(index=item['index'], symbol=item['name'], ordinal=ordinal,
                             addend=item.get('addend', 0), dependency=owner, proof=proof))
        results.append(dict(name=name, path=row['path'], image=row['image'], importAuditStatus=status,
                            activeImportRecordSchema={k:v for k,v in schema.items() if k != 'imports'},
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
    pod_import = next(x for x in uh['imports'] if x['index'] == 348)
    assert pod_import['ordinal'] == 20 and pod_import['proof']['status'] == 'actualDirectExport'
    pod_result = next(x for x in results if x['name'] == 'PL')
    assert pod_result['strongImports'] == 8 and pod_result['counts'] == dict(actualDirectExport=8)
    assert all(x['proof']['status'] == 'actualDirectExport' for x in pod_result['imports'])
    take_import = next(x for x in uh['imports'] if x['index'] == 11)
    assert take_import['ordinal'] == 20 and take_import['proof']['status'] == 'actualDirectExport'
    take_result = next(x for x in results if x['name'] == 'BT')
    assert take_result['strongImports'] == 6 and take_result['counts'] == dict(actualDirectExport=6)
    kernel_reexports = []
    for symbol in ('_vm_read_overwrite', '_mach_task_self_'):
        proof = resolve(images, '/usr/lib/libSystem.B.dylib', symbol)
        assert proof['status'] == 'actualDirectExport' and proof['reexportDependency'] == dict(
            ordinal=26, command=0x8000001f, path='/usr/lib/system/libsystem_kernel.dylib', at=3312, size=64)
        assert proof['nested']['owner'] == '/usr/lib/system/libsystem_kernel.dylib'
        kernel_reexports.append(dict(symbol=symbol, proof=proof))
    ownership_result = next(x for x in results if x['name'] == 'OW')
    assert ownership_result['strongImports'] == 16 and ownership_result['counts'] == dict(actualDirectExport=16)
    ownership_routes = []
    for name, indices in [('UniversalHID', (7,8,9,10,12)), ('UniversalHIDKit', (5,))]:
        result = next(x for x in results if x['name'] == name)
        for index in indices:
            row = next(x for x in result['imports'] if x['index'] == index)
            proof = row['proof']; leaf = proof
            while 'nested' in leaf: leaf = leaf['nested']
            assert row['ordinal'] == (20 if name == 'UniversalHID' else 1)
            assert proof['status'] == 'actualDirectExport' and leaf['owner'] == '@loader_path/OW'
            ownership_routes.append(dict(owner=name,index=index,symbol=row['symbol'],proof=proof))
    assert len(ownership_routes) == 6
    assert len(private) == 51 and len(new_declarations) == 19 and len(identical_declarations) == 2
    newly_declared_frontend_definitions = []
    for dependency,expected_count in [('@loader_path/DiskImages227.dylib',49),
                                     ('@loader_path/DiskImageKit27.dylib',13),
                                     ('@loader_path/VM27VZCVW.dylib',6)]:
        imports = [x for x in frontend['imports'] if x['dependency'] == dependency]
        assert len(imports) == expected_count and all(x['proof']['status']=='actualDirectExport' for x in imports)
        newly_declared_frontend_definitions += [dict(index=x['index'],symbol=x['symbol'],dependency=dependency,proof=x['proof']) for x in imports]
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
    previous = json.loads(PREVIOUS.read_bytes())
    transitions, candidate_changes, newly_added_private = [], [], []
    for result in results:
        old = [x for x in previous['auditedImages'] if x['name'] == result['name']]
        if not old:
            declaration = next(x for x in scoped_declarations['providers'] if x['name'] == result['name'])
            assert result['image'] == declaration['candidate']
            prior_audit = next(x for x in scoped_declarations['declaredProviderImports'] if x['name'] == result['name'])
            assert result['strongImports'] == prior_audit['strongImports'] and result['counts'] == prior_audit['counts']
            assert result['imports'] == prior_audit['imports']
            newly_added_private.append(dict(name=result['name'], image=result['image'],
                strongImports=result['strongImports'], counts=result['counts']))
            continue
        assert len(old) == 1 and old[0]['strongImports'] == result['strongImports']
        before_image = old[0]['image']
        assert all(before_image[key] == result['image'][key] for key in ('sha256','bytes'))
        by_index = {x['index']:x for x in old[0]['imports']}
        for item in result['imports']:
            before = by_index[item['index']]
            assert all(item[key] == before[key] for key in ('index','symbol','addend'))
            assert item['ordinal'] == before['ordinal']
            assert item['dependency'] == before['dependency']
            if item['proof']['status'] != before['proof']['status']:
                transitions.append(dict(owner=result['name'],index=item['index'],symbol=item['symbol'],
                    previousDependency=before['dependency'],dependency=item['dependency'],
                    previousStatus=before['proof']['status'],currentStatus=item['proof']['status'],
                    currentProof=item['proof']))
    assert not candidate_changes and len(newly_added_private) == 13
    assert len(transitions) == 27
    assert all(x['owner'] == 'Virtualization' and x['previousStatus'] == 'uncapturedOwner' and
               x['currentStatus'] == 'actualDirectExport' for x in transitions)
    assert {(x['index'],x['symbol'],x['dependency']) for x in transitions} == {
        (x['index'],x['symbol'],x['dependency']) for x in scoped_declarations['exactNewStrongDefinitionTransitions']}
    assert frontend['counts'] == dict(actualDirectExport=965, ownerHasNoDefinitionReexportsUnverified=24, uncapturedOwner=22)
    assert sum(x['strongImports'] for x in newly_added_private) == 219
    assert sum(x['counts'].get('actualDirectExport',0) for x in newly_added_private) == 215
    md_result = next(x for x in results if x['name'] == 'MD')
    assert md_result['counts'] == dict(actualDirectExport=12)
    assert uh['counts'] == dict(actualDirectExport=712, actualExportAbsent=1)
    missing = [dict(owner=result['name'],index=item['index'],symbol=item['symbol'],dependency=item['dependency'],proof=item['proof'])
               for result in results for item in result['imports'] if item['proof']['status']=='actualExportAbsent']
    report = dict(schema='Latest exact declared genuine HID/VZ strong export frontier v19',
                  currentCacheUUID='1995ea169d0a33a0b78962cf99891168',
                  sources=[p.pin(x) for x in (ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED, POD, TAKE, CURRENT, OWNERSHIP, DECLARATIONS, KEY, DE, PREVIOUS, EIGHT, MALLOC, METAL, METAL_CLOSURE, SCOPED_DECLARATIONS)],
                  currentStockImages=34,
                  actualThreeSystemLeafCapture=three, actualTraceCapture=trace, actualUnwindCapture=unwind,
                  priorSevenCurrentStockDefinitions=eight,
                  priorTwoCurrentSwiftStockDefinitions=swift_two,
                  priorThreeCurrentStockDefinitions=hid_extra,
                  exactPreviousFrontierComparison=dict(source=p.pin(PREVIOUS), unchangedPrivateCandidateBytes=True,
                      exactLocalCandidateChanges=candidate_changes, newPrivateProviders=newly_added_private,
                      allOtherPrivateCandidateWholeBytesUnchanged=True,
                      strongDefinitionTransitions=transitions, counts=dict(collections.Counter(x['currentStatus'] for x in transitions)),
                      allExplicitActualMissingDefinitions=missing), declaredPrivateImages=len(private), auditedImages=results,
                  privateDefinitions=[{k: v for k, v in row.items() if k != 'exports'} | dict(exportCount=len(row['exports'])) for name, row in private],
                  actualPinnedHistoricalPrivateSubset=dict(source=p.pin(DECLARATIONS),newDeclarations=new_declarations,
                      identicalCurrentDeclarations=identical_declarations, DI2DIKitVZCVWFrontendNamedDefinitions=newly_declared_frontend_definitions,
                      sourceManifestHistoricalPartialStrongClosure=True, sourceManifestHasSixHistoricalUnprovedFlatDiagnostics=True,
                      newlyDeclaredFunctionSemanticsProven=False,newlyDeclaredOriginalMetadataSemanticsProven=False,
                      completeCurrentDependencyGraphClaimed=False),
                  finiteExistingPrivateDeclarationSubset=dict(source=p.pin(SCOPED_DECLARATIONS),
                      newPrivateImages=scoped_private, frontendNewNamedDefinitions=27,
                      newProviderStrongImports=219, newProviderCurrentPositiveDefinitions=215,
                      newProviderUnprovedSystemReexports=4, exactOriginal38CandidatesWholeBytesPreserved=True,
                      threePrivateLeafOwnAPIVersionsRepairedWithoutCodeChanges=True,
                      originalEFIDynamicLoaderSearchContextValidated=False,
                      fullEFISecureBootPolicyValidated=False, guestNetworkingProvided=False,
                      candidateReadyForNativeLoading=False),
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
                  finiteOldHostHIDPODInitializer=dict(source=p.pin(POD), actualCurrentFieldAudit=p.pin(CURRENT),
                      exactOriginalEventReportSenderIDOnly=True, nativeFiveCABIToOriginalSixCABIProven=True,
                      taggedResolvedLayoutPointerDA8b65Preserved=True, documentedDependencyAddressabilityFlagPropagated=True,
                      ordinaryMacNativeCVWCompared=True, actualCurrentIOSUUIDAndUInt64TypeLayoutsRead=True,
                      twoKernelLeafReexportsActualCurrentDefinitions=kernel_reexports, generalCVWInterpreterProvided=False,
                      fullOriginal27RuntimeOverrideHookIdentity=False, candidateReadyForNativeLoading=False),
                  finiteOldHostHIDPODTake=dict(source=p.pin(TAKE), originalSolePODVWTBinding=True,
                      originalThreeCABIAndIA0Address48d8Preserved=True, ordinaryMacRealARCTransferCompared=True,
                      currentAllSixStrongDefinitionsResolved=True, productionHIDIdentityGatePassed=False,
                      originalHIDInitializerExecuted=False, generalNonBitwiseInterpreterProvided=False,
                      originalProcessGlobalRuntimeOverrideHookIdentity=False, originalTakeBuildRemainingFiveBindingsUnclosed=True,
                      currentFiveNamedEntryFiniteRouteProvided=True,
                      candidateReadyForNativeLoading=False),
                  finiteIOKitRequestTerminateCFString=dict(source=p.pin(KEY),symbol='_kIOHIDServiceRequestTerminateKey',
                      genuineCFStringTypeValueAndLifetimePreserved=True,positiveCurrentCFStrongDefinition=True,
                      routeActualOriginalOrdinal1ToAR20=True,ARTrueReexportOrdinal10ToIK=True,
                      originalKeyValueBridgeCallersExecuted=False,twoEventConstructorsStillAbsent=False,
                      productionHIDIdentityGatePassed=False,candidateReadyForNativeLoading=False),
                  finiteNativeIOKitDoubleEvents=dict(source=p.pin(DE),
                      twoOriginalStrongBindingsRoutedViaAR20=True,ARTrueReexportOrdinal11ToDE=True,
                      tenPositiveStrongDefinitionsFromCurrentTwentyTwoTables=True,
                      productionActualIOKitUUIDRequired='87ae25ce3bef39d9baa90d8cc15a34a0',
                      productionClass112AndData104Required=True,MacProfileClass104AndData96Separate=True,
                      ordinaryMacGenuineConstructorsEntirePacketsAndOwnershipCompared=True,
                      actualCurrentMallocNamedDefinitionSupplement=p.pin(MALLOC),
                      actualCurrentMallocNamedDefinitionEqualsCapturedPACGOT=True,
                      currentIOKitKernelNewTypeConsumerValidated=False,originalFullIOKitSemanticsPreserved=False,
                      originalHIDCtorCallersExecuted=False,nativeIOSExecuted=False,candidateReadyForNativeLoading=False),
                  finiteObservedHIDOwnership=dict(source=p.pin(OWNERSHIP), sixStrongRoutes=ownership_routes,
                      allSixteenPositiveStrongDefinitionsCurrent=True, completedStaticMetadataWhitelist=65,
                      originalProgramsWhitelisted=37, completedInitialPODUsesIndependentGuard=True,
                      originalStaticRelativeFNProgramUntaggedPointersPreserved=True, originalGetterWhole28BytesPreserved=True,
                      ordinaryMacGenuineCoreFiveOperationsCompared=True, ordinaryMacRealARCAndBoxOwnershipCompared=True,
                      productionHIDIdentityGatePassed=False, originalEnumGetterRuntimeCallabilityProven=False,
                      originalGlobalRuntimeOverrideHookIdentity=False, fullSwiftBytecodeInterpreterImplemented=False,
                      candidateReadyForNativeLoading=False),
                  finiteNativeMetalArray=dict(source=p.pin(METAL), currentStrongDefinitionSupplement=p.pin(METAL_CLOSURE),
                      twelveCurrentStrongDefinitions=True, trueNativeMetalReexport=True, originalVZMetalOrdinal=26,
                      threeStrongDefinitionsRouted=True, newlyClosedMissingStrongDefinitions=1,
                      sameNativeDefaultObjectInPlusOneOwnedArray=True, actualIPadGPUObjectOrSelectorsValidated=False,
                      originalMacEntireMultiGPUCatalogEquivalent=False, originalVZCallerExecuted=False, candidateReadyForNativeLoading=False),
                  definitionEvidenceOnly=True, allCurrentProvidersDeclared=False,
                  currentCompleteProviderDependencyGraphValidated=False, processGlobalLookupProven=False,
                  conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False,
                  metadataCompatibilityProven=False, originalVZLoaded=False, originalVMMExecuted=False,
                  nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    pins += [p.pin(path) for path in (Path(__file__), HERE / 'audit-modern-current-stock-extra-exports-v2.py',
             HERE / 'audit-modern-universalhid-current-stock-exports-v1.py', ARRAY, CP, AB, STATE, CG, LOOKUP, TYPED, POD, TAKE, CURRENT, OWNERSHIP, DECLARATIONS, HERE / 'macho_chained_import_records_v1.py', HERE / 'current_kernel_capture_v1.py', HERE / 'current_hid_extra_three_capture_v1.py', HERE / 'current_swift_two_capture_v1.py', HERE/'current_vz_eight_capture_v2.py', KEY, DE, EIGHT, MALLOC, METAL, METAL_CLOSURE, PREVIOUS, SCOPED_DECLARATIONS, HERE/'current_hid_system_three_capture_v1.py', HERE/'current_hid_trace_capture_v1.py', HERE/'current_metal_unwind_capture_v1.py', out / 'audit.json')]
    pins += [row['image'] for name, row in private]
    pins.append(p.pin(HERE / 'exact_private_bundle_rpath_v1.py'))
    p.save(out / 'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), images=[dict(name=r['name'], status=r['importAuditStatus'], counts=r['counts']) for r in results])))


if __name__ == '__main__':
    main()
