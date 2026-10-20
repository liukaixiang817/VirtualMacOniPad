#!/usr/bin/env python3
"""Root-only HOST build: append five disk observers to the existing Child MG leaf.

No signing, runtime packaging, network or device actions. All original Child
machine code/PAC slots and required loads remain whole; only five import names
and their two-level ordinals change. CPU65 is not rebuilt or modified.
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
BASE = N / 'independent27-signed-runtime-guest-context-product-v81-attempt1/candidate.json'
BASE_SHA = 'fe6f7f6a3bbdf80bc7dab80e10a59235b2f5a57ffaeeeff81a0df0d2ebbaf8c4'
CHILD_SHA = 'a2278ab56cffec0442be82b5e278c6dfe744b38cf19a5db8330182fa94e92966'
LEAF_SHA = 'add7154f875f8924e962dfe0356932422c9e6698baf68f968dbabadc07adb21e'
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


def patch(data, reader):
    old = reader.MachO(data)
    need(len(old.imports) == 1207 and len(old.loads) == 57 and
         old.loads[56]['path'] == '@loader_path/' + KEY, 'actual Child1207 imports and existing MG ordinal57')
    for index, (before, after) in SELECTED.items():
        row = old.imports[index]
        need(row['name'] == before and row['ordinal'] == 15 and not row['weak'] and row['addend'] == 0,
             'exact original strong libSystem import ' + before)
    signature = [c for c in old.commands if c['cmd'] == 0x1d]
    need(len(signature) == 1, 'one old Child signature command')
    start, size = struct.unpack_from('<II', signature[0]['raw'], 8)
    need(start + size == len(data), 'terminal exact old Child signature')
    commands = [bytearray(c['raw']) for c in old.commands if c['cmd'] != 0x1d]
    chain = next(c for c in old.commands if c['cmd'] == 0x80000034)
    at, size = struct.unpack_from('<II', chain['raw'], 8)
    fixups = bytearray(data[at:at + size])
    version, starts, imports, symbols, count, form, compression = struct.unpack_from('<7I', fixups)
    need(version == compression == 0 and count == 1207 and form == 2, 'actual chained imports2 and no compression')
    work = bytearray(data[:start])
    for index, (before_name, after_name) in SELECTED.items():
        name_offset = len(fixups) - symbols
        fixups += after_name.encode() + b'\0'
        before, addend = struct.unpack_from('<Ii', fixups, imports + index * 8)
        need(addend == 0 and before & 255 == 15 and not before & 256, 'unchanged native import ABI flags/addend')
        struct.pack_into('<Ii', fixups, imports + index * 8, 57 | (name_offset << 9), 0)
    new_chain = len(work)
    work += fixups
    sym = next(c for c in old.commands if c['cmd'] == 2)
    so, count, strings_at, strings_size = struct.unpack_from('<4I', sym['raw'], 8)
    nlist = bytearray(data[so:so + count * 16])
    strings = bytearray(data[strings_at:strings_at + strings_size])
    changes = {before: after for before, after in SELECTED.values()}
    hits = {before: [] for before in changes}
    for index in range(count):
        no, typ, section, desc, value = struct.unpack_from('<IBBHQ', nlist, index * 16)
        end = strings.find(b'\0', no)
        need(0 <= no < len(strings) and end >= no, 'bounded original nlist symbol string')
        name = strings[no:end].decode()
        if name in changes and typ & 0x0e == 0:
            need(desc >> 8 == 15, 'exact selected nlist original ordinal15')
            hits[name].append(index)
            new_name = len(strings)
            strings += changes[name].encode() + b'\0'
            struct.pack_into('<IBBHQ', nlist, index * 16, new_name, typ, section, (57 << 8) | (desc & 255), value)
    need(all(len(rows) == 1 for rows in hits.values()), 'one undefined nlist per selected original symbol')
    work += b'\0' * (align(len(work)) - len(work))
    new_so = len(work)
    work += nlist
    new_strings = len(work)
    work += strings
    for command in commands:
        kind = struct.unpack_from('<I', command)[0]
        if kind == 0x80000034:
            struct.pack_into('<II', command, 8, new_chain, len(fixups))
        elif kind == 2:
            struct.pack_into('<4I', command, 8, new_so, count, new_strings, len(strings))
        elif kind == 0x19 and command[8:24].rstrip(b'\0') == b'__LINKEDIT':
            off = struct.unpack_from('<Q', command, 40)[0]
            extent = len(work) - off
            struct.pack_into('<Q', command, 32, align(extent, 16384))
            struct.pack_into('<Q', command, 48, extent)
    header = b''.join(commands)
    first = min(section['fileoff'] for section in old.sections if section['fileoff'] > 0)
    need(32 + len(header) <= first and not any(data[32 + old.sizeofcmds:first]), 'old zero header capacity only')
    work[32:first] = header + b'\0' * (first - 32 - len(header))
    struct.pack_into('<II', work, 16, len(commands), len(header))
    need(bytes(work[first:start]) == data[first:start], 'all original code/PAC/old-linkedit bytes whole')
    return bytes(work), old, dict(oldSignatureOffset=start, oldSignatureBytes=len(data) - start,
        firstSectionOffset=first, newFixupsOffset=new_chain, newFixupsBytes=len(fixups),
        newNlistOffset=new_so, newStringsOffset=new_strings, selectedNlistIndices=hits,
        addedRequiredLoads=0, allOriginalPostheaderPrefixBytesWhole=True)


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
    need(pin(child)['sha256'] == CHILD_SHA and pin(original_leaf)['sha256'] == LEAF_SHA, 'actual Runtime81 Child and MG leaf')
    source, header = S/'vm27_owned_child_disk_io_observer_v1.c', S/'vm27_owned_child_disk_io_observer_v1.h'
    source_pin, header_pin = pin(source), pin(header)
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
    run('link-existing-MG-plus-observer', argv)
    helper, previous_helper = reader.MachO(provider.read_bytes()), reader.MachO(original_leaf.read_bytes())
    expected_exports = set(previous_helper.exports) | {after for before, after in SELECTED.values()}
    need(set(previous_helper.exports) == {'_VM27OwnedChildMGGetSInt32AnswerV1'} and
         set(helper.exports) == expected_exports and all(row['flags'] == 0 for row in helper.exports.values()),
         'six exact strong exports: original MG plus five typed observers')
    index = json.loads(NATIVE.read_bytes())
    routes = []
    for imp in helper.imports:
        need(imp['ordinal'] > 0 and not imp['weak'] and imp['addend'] == 0, 'strong native helper import')
        load = helper.loads[imp['ordinal']-1]
        found = native_routes(index, load['path'], imp['name'])
        unique = {json.dumps(row, sort_keys=True): row for row in found}
        need(len(unique) == 1, 'one actual strong native definition: '+imp['name'])
        routes.append(dict(actualImport=imp, requiredLoad=load, resolvedDefinition=next(iter(unique.values()))))
    changed, before, layout = patch(child.read_bytes(), reader)
    patched = out/'ChildMain.unsigned'
    patched.write_bytes(changed)
    after = reader.MachO(changed)
    need(after.uuid == before.uuid and after.exports == before.exports and
         [{k:r[k] for k in ('ordinal','cmd','size','path')} for r in after.loads] ==
         [{k:r[k] for k in ('ordinal','cmd','size','path')} for r in before.loads] and
         len(after.imports) == len(before.imports) == 1207, 'same Child UUID/exports/57 loads/1207 imports')
    for old, new in zip(before.imports, after.imports, strict=True):
        expected = semantic(old)
        if old['index'] in SELECTED:
            expected.update(name=SELECTED[old['index']][1], ordinal=57)
        need(semantic(new) == expected, 'only five selected import names/ordinals change')
    expected_binds = [{**row, 'name':SELECTED[row['index']][1]} if row['index'] in SELECTED else row for row in before.binds]
    need(after.binds == expected_binds, 'original chained slot positions/PAC/addends unchanged')
    for path in (provider, patched):
        run('validate-'+path.name, ['xcrun', 'dyld_info', '-validate_only', str(path)])
    run('observer-object-disassembly', ['xcrun', 'llvm-objdump', '-d', '-r', str(obj)])
    need(pin(OLD_OBJECT)['sha256'] == OLD_OBJECT_SHA and pin(source) == source_pin and pin(header) == header_pin,
         'whole original MG object and stable observer sources through actual build')
    contract = dict(existingProviderOrdinal=57, providerKey=KEY, selectedActualImportIndices=sorted(SELECTED),
        actualImportsChanged=5, actualImportsUnchanged=1202, actualRequiredLoads=57, addedRequiredLoads=0,
        originalChildCodeAndPACSlotsWhole=True, all29CPUObjectsWholeRuntime81=True,
        originalMGObjectWhole=pin(OLD_OBJECT), originalMGExportPreserved=True,
        ownedDiskPath='/private/var/mobile/Media/VirtualMac/Tahoe3.bundle/Disk.img',
        descriptorAdmission='exact Child path/UUID and UID501; lstat regular owned path joins fstat device/inode/size',
        nativeCallExactlyOnceSourceContract=True, nativeResultAndErrnoPreservedSourceContract=True,
        noBufferOrIOVectorMemoryAccess=True, noFcntlAdaptation=True, noRetryOrReplacementQueue=True,
        trackingSlots=64, firstDetailedCalls=32, exceptionalCompletionLimit=32,
        maximumLogAttempts=224, watchdogIterations=180, outstandingThresholdSeconds=[5,30,60],
        source=source_pin, header=header_pin, actualObjectDisassembly=pin(out/'observer-object-disassembly.stdout'))
    graph = out/'graph.json'
    dump(graph, dict(schema='Actual existing-MG leaf plus five owned disk observers closure v1',
        baselineRuntimeCandidate=pin(BASE), originalChildMain=pin(child), originalProvider=pin(original_leaf),
        oldObject=pin(OLD_OBJECT), newObserverObject=pin(obj), newProvider=pin(provider),
        actualProviderNativeRows=routes, actualProviderStrongImports=len(routes),
        allProviderNativeStrongImportsClosed=True, parentAndAllOtherProvidersWhole=True,
        all29CPUObjectsWholeRuntime81=True, requiredLoadListWhole=True, runtimeFilePathsUnchanged=True,
        selectedImports=[dict(before=before.imports[i], after=after.imports[i]) for i in sorted(SELECTED)],
        allOriginalChildPostheaderPrefixBytesWhole=True, layout=layout, deviceOperations=0))
    candidate = dict(schema='Actual Child-only original disk I/O observer source port v1',
        builder=pin(__file__), baselineRuntimeCandidate=pin(BASE), providerKey=KEY,
        originalChildMain=pin(child), patchedChildMain=pin(patched), originalProvider=pin(original_leaf),
        newProvider=pin(provider), originalMGObject=pin(OLD_OBJECT), actualIOSObject=pin(obj),
        adapterContract=contract, graph=pin(graph), actualProviderStrongImports=len(routes),
        childOnly=True, existingLeafOnly=True, actualChildImportsChanged=5, actualChildImportsUnchanged=1202,
        codeSignatureRemovedForActualSigning=True, localCodeSigned=False, deviceOperations=0,
        trustCacheOperations=0, codeSigningOperations=0)
    dump(out/'candidate.json', candidate)
    pins = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    pins += [pin(__file__), pin(BASE), pin(READER), pin(NATIVE), pin(M/'commands.json'),
             pin(M/'libMobileGestalt.tbd'), pin(OLD_OBJECT), pin(child), pin(original_leaf), source_pin, header_pin]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()), deviceOperations=0, codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), graph=pin(graph), freeze=pin(out/'freeze.json'),
                          provider=pin(provider), child=pin(patched), importsChanged=5, exports=6, addedRuntimePaths=0)))


if __name__ == '__main__':
    main()
