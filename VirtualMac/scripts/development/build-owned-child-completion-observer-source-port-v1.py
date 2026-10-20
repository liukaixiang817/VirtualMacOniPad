#!/usr/bin/env python3
"""Root-only HOST build of two bounded, typed completion observers in the MG leaf.

No signing, runtime packaging, network or device actions. Reuse the original MG
object, replace only the V2 disk object with V3, and route two original Child
libSystem imports to two new MG exports. Code/PAC slots and all 57 loads remain
whole. CPU65 and all other runtime providers are not rebuilt or modified.
"""
import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
B = R / 'VirtualMac/scripts/development'
BASE = N / 'independent27-signed-runtime-disk-io-qualification-product-v83-attempt1/candidate.json'
BASE_SHA = '10d87945a795f5b9d959749610edffe5c31f16a955cca0009fe4d6061dbb5452'
CHILD_SHA = 'a81986fef61181b07902d3b996338a3e56808ae5890f4ecc1a938d6e0af085ca'
LEAF_SHA = '08a1c1d2662ca212efccbd80a2c8eff9356b44891f91462196bdcc2c4dc9e3dd'
PATCHER = B / 'build-owned-child-disk-io-observer-source-port-v1.py'
PATCHER_SHA = '91d3dc8a978d497d259f8baec29fb049f47ab8125c7f6db5ffe6a7abd0a225f8'
READER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
NATIVE = N / 'current-native-header-export-index-v3/index.json'
M = N / 'owned-child-gestalt-helper-v2-attempt1'
OLD_OBJECT = M / 'child-gestalt-v2.ios.o'
OLD_OBJECT_SHA = '560469172317c28cd1e66d8a15773a4a382c4e7fbd4363f91e2c6fe7c27015bd'
ABI = N / 'owned-child-completion-observer-abi-source-plan-v1.json'
KEY = 'VM27OwnedChildGestaltCompat.dylib'
SELECTED = {322: ('_dispatch_sync_f', '_VM27OwnedChildCompletionDispatchSyncV1'),
            356: ('_kdebug_trace', '_VM27OwnedChildCompletionKdebugTraceV1')}
EXISTING = {347: '_VM27OwnedChildDiskFsyncV1', 401: '_VM27OwnedChildDiskPreadV1',
            402: '_VM27OwnedChildDiskPreadvV1', 417: '_VM27OwnedChildDiskPwriteV1',
            418: '_VM27OwnedChildDiskPwritevV1'}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    out = ap.parse_args().output.resolve()
    import hashlib
    def pin(path):
        path = pathlib.Path(path).resolve()
        raw = path.read_bytes()
        return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    def need(value, reason):
        if not value:
            raise ValueError(reason)
    def dump(path, value):
        path.write_text(json.dumps(value, indent=2) + '\n')
    need(out.parent == N and not out.exists(), 'fresh HOST output')
    for path, expected in [(BASE, BASE_SHA), (PATCHER, PATCHER_SHA), (OLD_OBJECT, OLD_OBJECT_SHA),
        (READER, '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b'),
        (M/'commands.json', 'ba4355ba40a504e0d2dcadd74f1366c6c9a4741c8e37ff390ce2092b9cb86885'),
        (M/'libMobileGestalt.tbd', 'fac8969acf491025ae94792a404898005ab31508e7b59993180df8e4f98650ca'),
        (NATIVE, '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019')]:
        need(pin(path)['sha256'] == expected, 'exact frozen input ' + str(path))
    patcher = load(PATCHER, 'completion_original_import_patcher')
    reader = load(READER, 'completion_exact_macho')
    baseline = json.loads(BASE.read_bytes())
    folder = pathlib.Path(baseline['runtimeRoot']) / 'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS'
    child, old_leaf = folder/'com.apple.Virtualization.VirtualMachine', folder/KEY
    need(pin(child)['sha256'] == CHILD_SHA and pin(old_leaf)['sha256'] == LEAF_SHA,
         'actual Runtime83 Child and V2 MG leaf')
    abi = json.loads(ABI.read_bytes())
    need(abi['actualChildMain'] == pin(child) and abi['nativeIndex'] == pin(NATIVE) and
         abi['dispatchSyncReturnRVA'] == 0x36fbb4 and abi['dispatchCallbackRVA'] == 0x370990 and
         abi['kdebugReturnSites'] == [0x1f87d4, 0x2702f8, 0x26ccdc] and
         abi['kdebugPrototype'] == 'int kdebug_trace(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t)',
         'exact real Child sites and primary kdebug ABI plan')
    for row in abi['actualChildCallWords']:
        need(child.read_bytes()[row['fileoff']:row['fileoff']+4].hex() == row['hex'],
             'actual unchanged original BL word ' + hex(row['fileoff']))
    source, header, extra = [S/name for name in (
        'vm27_owned_child_disk_io_observer_v3.c', 'vm27_owned_child_disk_io_observer_v3.h',
        'vm27_owned_child_completion_observer_v1.inc')]
    source_pins = [pin(p) for p in (source, header, extra)]
    need(abi['sourceFiles'] == source_pins and
         pin(abi['dispatchSDKQueueHeader']['path']) == abi['dispatchSDKQueueHeader'] and
         pin(abi['dispatchSDKBaseHeader']['path']) == abi['dispatchSDKBaseHeader'],
         'exact reviewed observer sources and SDK dispatch ABI headers')
    old_commands = json.loads((M/'commands.json').read_bytes())
    compile_template = next(c for c in old_commands if c['label'] == 'compile' and c['exit'] == 0)['argv']
    link_template = next(c for c in old_commands if c['label'] == 'link' and c['exit'] == 0)['argv']
    need([v for v in link_template if v.endswith('.o')] == [str(OLD_OBJECT)],
         'one exact unchanged original MG object')
    out.mkdir(mode=0o700)
    commands = []
    def run(label, argv):
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        dump(out/'commands.json', commands)
        need(result.returncode == 0, label+': '+result.stderr.decode(errors='replace'))
    obj, provider = out/'owned-disk-completion-observer.ios.o', out/KEY
    argv = list(compile_template)
    argv[argv.index(str(S/'vm27_owned_child_gestalt_v2.c'))] = str(source)
    argv[argv.index(str(OLD_OBJECT))] = str(obj)
    run('compile-disk-v3-completion-only', argv)
    argv = list(link_template)
    argv[argv.index(str(M/KEY))] = str(provider)
    argv.insert(argv.index(str(OLD_OBJECT))+1, str(obj))
    run('link-existing-MG-plus-completion', argv)
    helper, old_helper = reader.MachO(provider.read_bytes()), reader.MachO(old_leaf.read_bytes())
    old_exports = {'_VM27OwnedChildMGGetSInt32AnswerV1'} | set(EXISTING.values())
    need(set(old_helper.exports) == old_exports and
         set(helper.exports) == old_exports | {after for _, after in SELECTED.values()} and
         all(row['flags'] == 0 for row in helper.exports.values()), 'eight exact strong helper exports')
    index = json.loads(NATIVE.read_bytes())
    routes = []
    for imp in helper.imports:
        need(imp['ordinal'] > 0 and not imp['weak'] and imp['addend'] == 0, 'strong native helper import')
        required = helper.loads[imp['ordinal']-1]
        found = patcher.native_routes(index, required['path'], imp['name'])
        unique = {json.dumps(row, sort_keys=True): row for row in found}
        need(len(unique) == 1, 'one actual strong native definition: '+imp['name'])
        routes.append(dict(actualImport=imp, requiredLoad=required,
                           resolvedDefinition=next(iter(unique.values()))))
    need({'_dispatch_sync_f', '_kdebug_trace'} <= {row['name'] for row in helper.imports},
         'both wrappers delegate genuine native imports')
    # Reuse the exact previously reviewed import-only patch implementation.
    # Its two-level and nlist guards apply to these two original libSystem rows.
    patcher.SELECTED = SELECTED
    changed, before, layout = patcher.patch(child.read_bytes(), reader)
    patched = out/'ChildMain.unsigned'
    patched.write_bytes(changed)
    after = reader.MachO(changed)
    need(after.uuid == before.uuid and after.exports == before.exports and
         [{k:r[k] for k in ('ordinal','cmd','size','path')} for r in after.loads] ==
         [{k:r[k] for k in ('ordinal','cmd','size','path')} for r in before.loads] and
         len(after.imports) == len(before.imports) == 1207, 'whole UUID/exports/57 loads/1207 imports')
    for old, new in zip(before.imports, after.imports, strict=True):
        expected = patcher.semantic(old)
        if old['index'] in SELECTED:
            expected.update(name=SELECTED[old['index']][1], ordinal=57)
        need(patcher.semantic(new) == expected, 'only two selected import names/ordinals change')
    for i, name in EXISTING.items():
        need(before.imports[i]['name'] == name and before.imports[i]['ordinal'] == 57 and
             patcher.semantic(after.imports[i]) == patcher.semantic(before.imports[i]),
             'existing five disk observer rows remain whole')
    expected_binds = [{**row, 'name':SELECTED[row['index']][1]} if row['index'] in SELECTED else row
                      for row in before.binds]
    need(after.binds == expected_binds, 'all chained slot positions/PAC/diversities/addends whole')
    for path in (provider, patched):
        run('validate-'+path.name, ['xcrun', 'dyld_info', '-validate_only', str(path)])
    run('observer-object-disassembly', ['xcrun', 'llvm-objdump', '-d', '-r', str(obj)])
    need(pin(OLD_OBJECT)['sha256'] == OLD_OBJECT_SHA and
         [pin(p) for p in (source, header, extra)] == source_pins, 'whole original MG and stable source inputs')
    contract = dict(existingProviderOrdinal=57, providerKey=KEY,
        selectedActualImportIndices=sorted(SELECTED), actualImportsChanged=2, actualImportsUnchanged=1205,
        actualRequiredLoads=57, addedRequiredLoads=0, existingFiveObserverImportRoutesWhole=True,
        originalChildCodeAndPACSlotsWhole=True, all29CPUObjectsWholeRuntime83=True,
        originalMGObjectWhole=pin(OLD_OBJECT), originalMGExportPreserved=True,
        exactCallerPathAndUUIDAndUID501Required=True,
        dispatchSyncReturnRVA=0x36fbb4, dispatchCallbackRVA=0x370990,
        guestStatusTraceReturnRVA=0x1f87d4, guestStatusTraceDebugID=0x0620000c,
        splitUsedTraceReturnRVA=0x2702f8, packedUsedTraceReturnRVA=0x26ccdc,
        usedTraceDebugID=0x06200004, firstDetailedPairsPerKind=8, completionKinds=4,
        completionSummariesAtInheritedDiskWatchSeconds=[5,30,60], newWatchThreads=0,
        nativeCallExactlyOnceSourceContract=True, nativeArgsAndCallbackUnchangedSourceContract=True,
        nativeResultAndErrnoPreservedSourceContract=True, noQueueOrContextOrGuestMemoryAccess=True,
        noCallbackSubstitution=True, noRetryOrReplacementQueue=True,
        inheritedVerifiedStderrWriterAndGlobalLogBound=224, diskFirstDetailedCallsReducedTo=8,
        noConclusionFromMissingRecords=True, countsCoverAllDisksAtExactCallsites=True,
        exactABIAndSites=pin(ABI), sourceFiles=source_pins,
        actualObjectDisassembly=pin(out/'observer-object-disassembly.stdout'))
    graph = out/'graph.json'
    dump(graph, dict(schema='Actual existing MG plus typed completion observer closure v1',
        baselineRuntimeCandidate=pin(BASE), originalChildMain=pin(child), originalProvider=pin(old_leaf),
        oldObject=pin(OLD_OBJECT), newObserverObject=pin(obj), newProvider=pin(provider),
        actualProviderNativeRows=routes, actualProviderStrongImports=len(routes),
        allProviderNativeStrongImportsClosed=True, parentAndAllOtherProvidersWhole=True,
        all29CPUObjectsWholeRuntime83=True, requiredLoadListWhole=True, runtimeFilePathsUnchanged=True,
        selectedImports=[dict(before=before.imports[i],after=after.imports[i]) for i in sorted(SELECTED)],
        allOriginalChildPostheaderPrefixBytesWhole=True, layout=layout, deviceOperations=0))
    candidate = dict(schema='Actual Child-only original disk completion observer source port v1',
        builder=pin(__file__), baselineRuntimeCandidate=pin(BASE), providerKey=KEY,
        originalChildMain=pin(child), patchedChildMain=pin(patched), originalProvider=pin(old_leaf),
        newProvider=pin(provider), originalMGObject=pin(OLD_OBJECT), actualIOSObject=pin(obj),
        adapterContract=contract, graph=pin(graph), actualProviderStrongImports=len(routes),
        childOnly=True, existingLeafOnly=True, actualChildImportsChanged=2, actualChildImportsUnchanged=1205,
        existingFiveObserverImportRoutesWhole=True, codeSignatureRemovedForActualSigning=True,
        localCodeSigned=False, deviceOperations=0, trustCacheOperations=0, codeSigningOperations=0)
    dump(out/'candidate.json', candidate)
    pins = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    pins += [pin(p) for p in (__file__,BASE,PATCHER,READER,NATIVE,ABI,M/'commands.json',
             M/'libMobileGestalt.tbd',OLD_OBJECT,child,old_leaf)] + source_pins
    pins += [abi['dispatchSDKQueueHeader'], abi['dispatchSDKBaseHeader']]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
                                deviceOperations=0, codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),graph=pin(graph),freeze=pin(out/'freeze.json'),
                          provider=pin(provider),child=pin(patched),importsChanged=2,exports=8,addedRuntimePaths=0)))


if __name__ == '__main__':
    main()
