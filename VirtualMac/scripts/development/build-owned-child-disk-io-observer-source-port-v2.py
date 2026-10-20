#!/usr/bin/env python3
"""Root-only HOST build: replace the V1 disk observer in the existing Child MG leaf with V2.

No signing, runtime packaging, network or device actions. All original Child
machine code/PAC slots and required loads remain whole; all 1207 imports, load commands and the complete signed Child input remain unchanged. CPU65 is not rebuilt or modified.
"""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
BASE = N / 'independent27-signed-runtime-disk-io-observation-product-v82-attempt1/candidate.json'
BASE_SHA = 'e92c77fcef212a27b7d88f4db65604be9d9ad4aa89a175ba758a63a7bdeff08d'
CHILD_SHA = 'f2ac34288837d74fc2927b857d2c4da12425ff7f20484d9d28b893d60a185c27'
LEAF_SHA = 'fdb34ee6b4876c57c19cd93174dead9e46f1d15758ae9a259f36606ec7a481f1'
M = N / 'owned-child-gestalt-helper-v2-attempt1'
OLD_OBJECT = M / 'child-gestalt-v2.ios.o'
OLD_OBJECT_SHA = '560469172317c28cd1e66d8a15773a4a382c4e7fbd4363f91e2c6fe7c27015bd'
READER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
NATIVE = N / 'current-native-header-export-index-v3/index.json'
KEY = 'VM27OwnedChildGestaltCompat.dylib'
SELECTED = {347: ('_fsync', '_VM27OwnedChildDiskFsyncV1'),
            401: ('_pread', '_VM27OwnedChildDiskPreadV1'),
            402: ('_preadv', '_VM27OwnedChildDiskPreadvV1'),
            417: ('_pwrite', '_VM27OwnedChildDiskPwriteV1'),
            418: ('_pwritev', '_VM27OwnedChildDiskPwritevV1')}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def align(value, size=8):
    return (value + size - 1) & ~(size - 1)


def semantic(row):
    return {key: row[key] for key in ('index', 'ordinal', 'weak', 'name', 'addend')}


def native_routes(index, path, name, seen=()):
    need((path, name) not in seen, 'acyclic native reexport/alias lookup')
    if path not in index['images']:
        return []
    image = index['images'][path]
    definition = image['definitions'].get(name)
    if definition:
        if definition['flags'] & 8:
            target = next(row['path'] for row in image['dependencies'] if row['ordinal'] == definition['ordinal'])
            return native_routes(index, target, definition.get('alias') or definition.get('importedName') or name,
                                 seen + ((path, name),))
        return [dict(path=path, UUID=image['UUID'], symbol=name, definition=definition)]
    return [row for dependency in image['dependencies'] if dependency['command'] == 0x8000001f
            for row in native_routes(index, dependency['path'], name, seen + ((path, name),))]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh HOST output')
    for path, expected in [(BASE, BASE_SHA), (OLD_OBJECT, OLD_OBJECT_SHA),
        (READER, '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b'),
        (M/'commands.json', 'ba4355ba40a504e0d2dcadd74f1366c6c9a4741c8e37ff390ce2092b9cb86885'),
        (M/'libMobileGestalt.tbd', 'fac8969acf491025ae94792a404898005ab31508e7b59993180df8e4f98650ca'),
        (NATIVE, '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019')]:
        need(pin(path)['sha256'] == expected, 'exact frozen input ' + str(path))
    reader = module(READER, 'disk_observer_exact_macho')
    baseline = json.loads(BASE.read_bytes())
    root = pathlib.Path(baseline['runtimeRoot'])
    folder = root/'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS'
    child, original_leaf = folder/'com.apple.Virtualization.VirtualMachine', folder/KEY
    need(pin(child)['sha256'] == CHILD_SHA and pin(original_leaf)['sha256'] == LEAF_SHA, 'actual Runtime82 Child and MG leaf')
    source, header = S/'vm27_owned_child_disk_io_observer_v2.c', S/'vm27_owned_child_disk_io_observer_v2.h'
    source_pin, header_pin = pin(source), pin(header)
    proof_root = N/'independent27-app99-current-guest-readonly-v11-attempt1'
    receipt_path, configuration_path = proof_root/'receipt.json', proof_root/'configuration.json'
    need(pin(receipt_path)['sha256'] == '82de27bc8f5e0f98e490fc7d700d5c90546267a54a7f829cc0a9e12d22bea98d' and
         pin(configuration_path)['sha256'] == 'a13433a56b794296f6a63771d83e8374a00821f9763911bb6afc5526ea22505d',
         'exact Root read-only descriptor identity proof')
    receipt, configuration = json.loads(receipt_path.read_bytes()), json.loads(configuration_path.read_bytes())
    need(receipt['transportExit'] == receipt['deviceWrites'] == receipt['processSignals'] == 0 and
         configuration['metadata']['Disk.img'] == '16777223:45558518:501:501:600:1:274877906944' and
         configuration['priorLogMetadata'].startswith('16777223:48200252:501:501:600:1:'),
         'actual same-device owned Disk/log identity and successful read-only receipt')
    for key in ('request','stdout','stderr'):
        need(pin(receipt[key]['path']) == receipt[key], 'actual read-only proof '+key)
    proof = dict(receipt=pin(receipt_path), configuration=pin(configuration_path))
    old_commands = json.loads((M/'commands.json').read_bytes())
    compile_template = next(c for c in old_commands if c['label'] == 'compile' and c['exit'] == 0)['argv']
    link_template = next(c for c in old_commands if c['label'] == 'link' and c['exit'] == 0)['argv']
    need([v for v in link_template if v.endswith('.o')] == [str(OLD_OBJECT)], 'one exact original MG object list')
    out.mkdir(mode=0o700)
    commands = []

    def run(label, argv):
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        dump(out/'commands.json', commands)
        need(result.returncode == 0, label+': '+result.stderr.decode(errors='replace'))

    obj, provider = out/'owned-disk-observer.ios.o', out/KEY
    argv = list(compile_template)
    argv[argv.index(str(S/'vm27_owned_child_gestalt_v2.c'))] = str(source)
    argv[argv.index(str(OLD_OBJECT))] = str(obj)
    run('compile-observer-only', argv)
    argv = list(link_template)
    argv[argv.index(str(M/KEY))] = str(provider)
    argv.insert(argv.index(str(OLD_OBJECT))+1, str(obj))
    run('link-existing-MG-plus-observer-v2', argv)
    helper, previous_helper = reader.MachO(provider.read_bytes()), reader.MachO(original_leaf.read_bytes())
    expected_exports = {'_VM27OwnedChildMGGetSInt32AnswerV1'} | {after for before, after in SELECTED.values()}
    need(set(previous_helper.exports) == set(helper.exports) == expected_exports and
         all(row['flags'] == 0 for row in helper.exports.values()),
         'same six exact strong exports: original MG plus five V1-named observer entry points')
    index = json.loads(NATIVE.read_bytes())
    routes = []
    for imp in helper.imports:
        need(imp['ordinal'] > 0 and not imp['weak'] and imp['addend'] == 0, 'strong native helper import')
        load = helper.loads[imp['ordinal']-1]
        found = native_routes(index, load['path'], imp['name'])
        unique = {json.dumps(row, sort_keys=True): row for row in found}
        need(len(unique) == 1, 'one actual strong native definition: '+imp['name'])
        routes.append(dict(actualImport=imp, requiredLoad=load, resolvedDefinition=next(iter(unique.values()))))
    before = reader.MachO(child.read_bytes())
    need(len(before.imports) == 1207 and len(before.loads) == 57 and
         before.loads[56]['path'] == '@loader_path/'+KEY, 'actual already-routed Child1207/57')
    for index_value, (native_name, existing_observer_name) in SELECTED.items():
        imp = before.imports[index_value]
        need(imp['name'] == existing_observer_name and imp['ordinal'] == 57 and
             not imp['weak'] and imp['addend'] == 0, 'existing five typed observer routes remain whole')
    patched, after = child, before  # SAME current signed Child; there is no import/code/signature edit.
    layout = dict(childByteChanges=0, importChanges=0, requiredLoadChanges=0, originalSignatureRetained=True)
    for path in (provider, patched):
        run('validate-'+path.name, ['xcrun', 'dyld_info', '-validate_only', str(path)])
    run('observer-object-disassembly', ['xcrun', 'llvm-objdump', '-d', '-r', str(obj)])
    need(pin(OLD_OBJECT)['sha256'] == OLD_OBJECT_SHA and pin(source) == source_pin and pin(header) == header_pin,
         'whole original MG object and stable observer sources through actual build')
    contract = dict(existingProviderOrdinal=57, providerKey=KEY, selectedActualImportIndices=sorted(SELECTED),
        actualImportsChanged=0, actualImportsUnchanged=1207, actualRequiredLoads=57, addedRequiredLoads=0,
        originalChildCodeAndPACSlotsWhole=True, all29CPUObjectsWholeRuntime82=True,
        originalMGObjectWhole=pin(OLD_OBJECT), originalMGExportPreserved=True,
        ownedDiskPath='/private/var/mobile/Media/VirtualMac/Tahoe3.bundle/Disk.img',
        descriptorAdmission='stripped export return-address dladdr main path/UUID and UID501; fixed Root-proven fstat FD identity',
        fixedDiskIdentityReadOnlyProof=proof, optionalPathStatNeverSuppressesFDIdentity=True,
        firstWrapperEntryDiagnostics=8, logWritesRequireExactInheritedStderrIdentity=True,
        nativeCallExactlyOnceSourceContract=True, nativeResultAndErrnoPreservedSourceContract=True,
        noBufferOrIOVectorMemoryAccess=True, noFcntlAdaptation=True, noRetryOrReplacementQueue=True,
        trackingSlots=64, firstDetailedCalls=32, exceptionalCompletionLimit=32,
        maximumLogAttempts=224, watchdogIterations=180, outstandingThresholdSeconds=[5,30,60],
        source=source_pin, header=header_pin, actualObjectDisassembly=pin(out/'observer-object-disassembly.stdout'))
    graph = out/'graph.json'
    dump(graph, dict(schema='Actual existing-MG disk observer V2 closure; whole already-routed Child',
        baselineRuntimeCandidate=pin(BASE), originalChildMain=pin(child), originalProvider=pin(original_leaf),
        oldObject=pin(OLD_OBJECT), newObserverObject=pin(obj), fixedDiskIdentityReadOnlyProof=proof, newProvider=pin(provider),
        actualProviderNativeRows=routes, actualProviderStrongImports=len(routes),
        allProviderNativeStrongImportsClosed=True, parentAndAllOtherProvidersWhole=True,
        all29CPUObjectsWholeRuntime82=True, requiredLoadListWhole=True, runtimeFilePathsUnchanged=True,
        selectedImports=[dict(before=before.imports[i], after=after.imports[i]) for i in sorted(SELECTED)],
        allOriginalChildPostheaderPrefixBytesWhole=True, layout=layout, deviceOperations=0))
    candidate = dict(schema='Actual Child-only original disk I/O observer V2 helper replacement',
        builder=pin(__file__), baselineRuntimeCandidate=pin(BASE), providerKey=KEY,
        originalChildMain=pin(child), patchedChildMain=pin(patched), originalProvider=pin(original_leaf),
        newProvider=pin(provider), originalMGObject=pin(OLD_OBJECT), actualIOSObject=pin(obj),
        adapterContract=contract, graph=pin(graph), actualProviderStrongImports=len(routes),
        childOnly=True, existingLeafOnly=True, actualChildImportsChanged=0, actualChildImportsUnchanged=1207,
        actualChildWholeBytesUnchanged=True, existingFiveObserverImportRoutesWhole=True,
        codeSignatureRemovedForActualSigning=False, localCodeSigned=False, deviceOperations=0,
        trustCacheOperations=0, codeSigningOperations=0)
    dump(out/'candidate.json', candidate)
    pins = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    pins += [pin(__file__), pin(BASE), pin(READER), pin(NATIVE), pin(M/'commands.json'),
             pin(M/'libMobileGestalt.tbd'), pin(OLD_OBJECT), pin(child), pin(original_leaf), source_pin, header_pin,
             pin(receipt_path), pin(configuration_path), receipt['request'], receipt['stdout'], receipt['stderr']]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()), deviceOperations=0, codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), graph=pin(graph), freeze=pin(out/'freeze.json'),
                          provider=pin(provider), child=pin(patched), importsChanged=0, exports=6, addedRuntimePaths=0)))


if __name__ == '__main__':
    main()
