#!/usr/bin/env python3
"""Prepare Stage13's explicit owned platform launch from genuine Stage10.

The existing premain library is replaced; original child import428 selects
its explicitly named preparation API through existing required ordinal55.
Sandbox profile application remains explicitly deferred. No native success
is fabricated, and no compiler/adapter, new image or load command is added.
This HOST builder does not sign, execute iOS code or contact a device.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CHILD = 'com.apple.Virtualization.VirtualMachine'
PREMAIN = 'VM27OwnedAppChildPreMainV3.dylib'
OWN_API = '_VM27OwnedPlatformLaunchPrepareV1'
CONTENTS = 'VMM.bundle/Contents/XPCServices/' + CHILD + '.xpc/Contents'


def pin(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def verify_freeze(path):
    value = json.loads(Path(path).read_bytes())
    rows = value.get('files', value.get('pins'))
    need(isinstance(rows, list), 'real source/output freeze required')
    for row in rows:
        need(pin(row['path']) == {key: row[key] for key in ('path', 'bytes', 'sha256')}, 'frozen actual bytes: ' + row['path'])


def own_load_paths(raw, module, available):
    image = module.MachO(raw)
    commands, changes = [], []
    for command in image.commands:
        value = command['raw']
        if command['cmd'] in (12, 0x80000018, 0x8000001f, 0x80000023):
            name_at = struct.unpack_from('<I', value, 8)[0]
            name = value[name_at:].split(b'\0', 1)[0].decode()
            if name.startswith('@rpath/'):
                key = name[7:]
                need(key in available, 'true existing provider dependency')
                new = '@loader_path/' + key
                payload = new.encode() + b'\0'
                length = (name_at + len(payload) + 7) & ~7
                need(not any(value[name_at + len(name.encode()) + 1:]), 'true old string zero padding')
                amended = bytearray(value[:name_at] + payload + bytes(length - name_at - len(payload)))
                struct.pack_into('<I', amended, 4, length)
                value = bytes(amended)
                changes.append(dict(oldPath=name, newPath=new))
        commands.append(value)
    body = b''.join(commands)
    old_end, new_end = 32 + image.sizeofcmds, 32 + len(body)
    first = min(section['fileoff'] for section in image.sections if section['size'] and section['fileoff'] and section['flags'] & 255 not in (1, 12, 18))
    need(new_end <= first and (new_end <= old_end or not any(raw[old_end:new_end])), 'actual new provider header capacity')
    amended = bytearray(raw)
    amended[32:max(old_end, new_end)] = body + bytes(max(old_end, new_end) - new_end)
    struct.pack_into('<II', amended, 16, len(commands), len(body))
    actual = bytes(amended)
    after = module.MachO(actual)
    need(after.uuid == image.uuid and after.sections == image.sections and after.segments == image.segments and
         after.exports == image.exports and after.imports == image.imports and after.binds == image.binds, 'provider code/sections/PAC/exports/imports preserved')
    allowed = set(range(16, 24)) | set(range(32, max(old_end, new_end)))
    need(all(index in allowed for index, (before, later) in enumerate(zip(raw, actual)) if before != later), 'provider dependency-header-only change')
    return actual, after, changes


def child_binding(raw, module):
    old = module.MachO(raw)
    selected = old.imports[428]
    need(old.uuid == '4a6a588d1afd30f5a64d6304eb79be0b' and selected['name'] == '_sandbox_init_with_parameters' and
         selected['ordinal'] == 15 and not selected['weak'] and selected['addend'] == 0, 'true Stage10 original import428')
    dep = next(row for row in old.loads if row['ordinal'] == 55)
    need(dep['cmd'] == 12 and dep['path'] == '@loader_path/' + PREMAIN, 'existing required premain55')
    command = next(row for row in old.commands if row['cmd'] == 0x80000034)
    offset, length = struct.unpack_from('<II', raw, command['at'] + 8)
    before = raw[offset:offset + length]
    version, starts, imports, symbols, count, form, symbols_form = struct.unpack_from('<7I', before)
    need(version == 0 and form == 2 and symbols_form == 0 and count == len(old.imports), 'actual original form2')
    payload = bytearray(before)
    name_offset = len(payload) - symbols
    need(0 <= name_offset < 1 << 23, 'real appended name offset')
    at = imports + 428 * 8
    original_word = struct.unpack_from('<I', payload, at)[0]
    struct.pack_into('<I', payload, at, (name_offset << 9) | (original_word & 0x100) | 55)
    payload.extend(OWN_API.encode() + b'\0')
    need(all(index in range(at, at + 4) for index, (a, b) in enumerate(zip(before, payload)) if a != b), 'single copied import word only')
    amended = bytearray(raw)
    new_offset = (len(amended) + 15) & ~15
    amended.extend(bytes(new_offset - len(amended)))
    amended.extend(payload)
    struct.pack_into('<II', amended, command['at'] + 8, new_offset, len(payload))
    link = next(row for row in old.commands if row['cmd'] == 0x19 and row['raw'][8:24].rstrip(b'\0') == b'__LINKEDIT')
    fileoff = struct.unpack_from('<Q', raw, link['at'] + 40)[0]
    struct.pack_into('<Q', amended, link['at'] + 32, (len(amended) - fileoff + 16383) & ~16383)
    struct.pack_into('<Q', amended, link['at'] + 48, len(amended) - fileoff)
    actual = bytes(amended)
    new = module.MachO(actual)
    need(new.uuid == old.uuid and new.exports == old.exports and new.sections == old.sections and new.loads == old.loads and
         new.ncmds == old.ncmds and new.sizeofcmds == old.sizeofcmds, 'all original header/load geometry except LINKEDIT extent preserved')
    for a, b in zip(old.imports, new.imports):
        expected = dict(a, at=b['at'])
        if a['index'] == 428:
            expected.update(name=OWN_API, ordinal=55)
        need(expected == b, 'sole selected import semantics')
    need(new.binds == [dict(row, name=OWN_API if row['index'] == 428 else row['name']) for row in old.binds], 'original pointer words/PAC retained')
    for section in old.sections:
        if section['size'] and section['fileoff'] and section['flags'] & 255 not in (1, 12, 18):
            at, length = section['fileoff'], section['size']
            need(actual[at:at + length] == raw[at:at + length], 'all original VMM sections/code/flags/NULL/fatal branch unchanged')
    allowed = set(range(command['at'] + 8, command['at'] + 16)) | set(range(link['at'] + 32, link['at'] + 40)) | set(range(link['at'] + 48, link['at'] + 56))
    need(all(index in allowed for index, (a, b) in enumerate(zip(raw, actual)) if a != b), 'original-file-only LINKEDIT metadata changes')
    need(actual[offset:offset + len(before)] == before, 'old fixup payload and nlist/stringtable preserved')
    need(struct.unpack_from('<I', actual, new.file(new.base + 0x2e9d4c))[0] == 0x9404a45a, 'original VM bootstrap BL unchanged')
    return actual, new, dict(original=selected, actual=new.imports[428], existingRequiredLoad55=dep,
        oldFixupDataOffset=offset, newFixupDataOffset=new_offset, newFixupDataBytes=len(payload),
        addedLoadCommands=0, addedImages=0, originalMainCodeFlags3NULLAndFatalBranchWholeUnchanged=True,
        allOriginalVMMSectionsAndAuthenticatedPointerWordsWholeUnchanged=True, nativeSandboxInitSuccessFabricated=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider-candidate', type=Path, required=True)
    parser.add_argument('--provider-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == NODE and not out.exists(), 'fresh actual Stage13 output')
    out.mkdir(mode=0o700)
    inputs, steps = [], []
    try:
        stage_path = NODE / 'independent27-owned-bundle-stage-v10-attempt1/candidate.json'
        graph_path = NODE / 'independent27-owned-bundle-definition-graph-v6-attempt1/verification.json'
        need(pin(stage_path)['sha256'] == 'f16868649796d871855bf32fab0461c4149f3022ecbd8093ee122d07184baf35' and
             pin(graph_path)['sha256'] == 'e9d7458fab3439fe83b7e0f258991894a0846f920ffb8a9ec082820b62c9f3b7', 'true immutable Stage10/graph')
        provider_path = args.provider_candidate.resolve()
        need(pin(provider_path)['sha256'] == args.provider_sha256, 'exact reviewed new platform launch provider')
        for path in [stage_path.parent / 'freeze.json', graph_path.parent / 'freeze.json', provider_path.parent / 'freeze.json']:
            verify_freeze(path)
            inputs.append(pin(path))
        stage, baseline, provider = [json.loads(path.read_bytes()) for path in [stage_path, graph_path, provider_path]]
        need(not any(any(step.get('path') == PREMAIN for step in row['resolution'].get('route', []))
                     for row in baseline['actualStrongImportRows']),
             'no inherited stale premain export route; only new selected428 targets it')
        source = provider['childOnlyPreMain']
        need(pin(source['path']) == source, 'actual new premain bytes')
        contract = provider['ownPlatformPrepContract']
        need(contract['sandboxProfileApplied'] is False and contract['nativeSandboxApplyUnavailable'] == 45,
             'explicit owned platform launch and actual unavailable native sandbox, not native success')
        reader = NODE / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
        native_path = NODE / 'current-native-header-export-index-v3/index.json'
        need(pin(reader)['sha256'] == '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b' and
             pin(native_path)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019', 'actual bounded reader/native67')
        inputs += [pin(__file__), pin(stage_path), pin(graph_path), pin(provider_path), source, pin(reader), pin(native_path)]
        spec = importlib.util.spec_from_file_location('owned_platform_stage_macho', reader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        old_rows = {row['key']: row for row in stage['stagedImages']}
        premain_raw, premain_image, load_changes = own_load_paths(Path(source['path']).read_bytes(), module, old_rows)
        need(OWN_API in premain_image.exports and premain_image.exports[OWN_API]['flags'] == 0, 'actual explicitly named owned API direct definition')
        old_premain = module.MachO(Path(old_rows[PREMAIN]['staged']['path']).read_bytes())
        need(all(premain_image.exports.get(name) is not None for name in old_premain.exports), 'all previous premain public API retained')
        child_raw, child_image, recipe = child_binding(Path(old_rows[CHILD]['staged']['path']).read_bytes(), module)
        flat = out / 'flat'
        flat.mkdir(mode=0o700)
        rows, unchanged = [], []
        parsed = {PREMAIN: premain_image, CHILD: child_image}
        for key, old in sorted(old_rows.items()):
            need(pin(old['staged']['path']) == old['staged'], 'inherited real Stage10 image')
            selected_source = source if key == PREMAIN else old['staged']
            raw = premain_raw if key == PREMAIN else child_raw if key == CHILD else Path(selected_source['path']).read_bytes()
            target = flat / key
            target.write_bytes(raw)
            target.chmod(0o600)
            rows.append(dict(key=key, source=selected_source, staged=pin(target), UUID=parsed[key].uuid if key in parsed else old['UUID'],
                loadPathChanges=load_changes if key == PREMAIN else [], codeSignatureStaleUntilFinalSigning=True))
            if key not in (PREMAIN, CHILD):
                need(raw == Path(old['staged']['path']).read_bytes(), 'other71 original wholebytes preserved')
                unchanged.append(key)
            else:
                image = parsed[key]
                builds = [struct.unpack_from('<II', raw, command['at'] + 8) for command in image.commands if command['cmd'] == 0x32]
                need(builds == [(2, 0x100100)], 'true modified iOS16.1 ABI')
                argv = ['xcrun', 'dyld_info', '-validate_only', str(target)]
                result = subprocess.run(argv, capture_output=True, timeout=30)
                (out / (key + '.validate.stdout')).write_bytes(result.stdout)
                (out / (key + '.validate.stderr')).write_bytes(result.stderr)
                steps.append(dict(arguments=argv, exit=result.returncode))
                need(result.returncode == 0, 'actual modified Mach-O validation')
        need(len(rows) == 73 and len(unchanged) == 71, 'true original73 graph, no compiler or adapter additions')
        native = json.loads(native_path.read_bytes())['images']
        row_by_key = {row['key']: row for row in rows}
        def target(path):
            if path in native:
                return 'native', path
            if path.startswith('@loader_path/') and path[13:] in row_by_key:
                return 'own', path[13:]
            return 'missing', path
        def image(key):
            if key not in parsed:
                parsed[key] = module.MachO(Path(row_by_key[key]['staged']['path']).read_bytes())
            return parsed[key]
        def deps(kind, key):
            return native[key]['dependencies'] if kind == 'native' else [dict(ordinal=row['ordinal'], command=row['cmd'], path=row['path']) for row in image(key).loads]
        def definition(kind, key, name, seen=()):
            need(kind != 'missing' and (kind, key, name) not in seen, 'actual present definition without reexport cycle')
            seen += ((kind, key, name),)
            value = native[key] if kind == 'native' else image(key)
            exports = value['definitions'] if kind == 'native' else value.exports
            entry = exports.get(name)
            step = dict(kind=kind, path=key, symbol=name)
            if entry:
                step['actualExport'] = entry
                if entry['flags'] & 8:
                    dep = next(row for row in deps(kind, key) if row['ordinal'] == entry['ordinal'])
                    rest = definition(*target(dep['path']), entry.get('alias', entry.get('importedName', '')) or name, seen)
                    rest['route'] = [step] + rest['route']
                    return rest
                step['UUID'] = value['UUID'] if kind == 'native' else value.uuid
                return dict(resolved=True, route=[step])
            for dep in deps(kind, key):
                if dep['command'] == 0x8000001f and target(dep['path'])[0] != 'missing':
                    try:
                        rest = definition(*target(dep['path']), name, seen)
                    except KeyError:
                        continue
                    rest['route'] = [step] + rest['route']
                    return rest
            raise KeyError((kind, key, name))
        increment = []
        for key, imports in [(CHILD, [child_image.imports[428]]), (PREMAIN, premain_image.imports)]:
            for imp in imports:
                need(imp['ordinal'] > 0 and not imp['weak'], 'actual new/selected strong two-level import')
                dep = next(row for row in deps('own', key) if row['ordinal'] == imp['ordinal'])
                increment.append(dict(importer=key, actualImport=imp, resolution=definition(*target(dep['path']), imp['name'])))
        strong = []
        for old in baseline['actualStrongImportRows']:
            if old['importer'] == PREMAIN:
                continue
            row = copy.deepcopy(old)
            if row['importer'] == CHILD:
                actual = child_image.imports[row['actualImport']['index']]
                expected = dict(row['actualImport'], at=actual['at'])
                if actual['index'] == 428:
                    expected.update(name=OWN_API, ordinal=55)
                    row = increment[0]
                else:
                    row['actualImport'] = actual
                need(actual == expected, 'true inherited child actual record')
            strong.append(row)
        strong += increment[1:]
        weak = copy.deepcopy(baseline['actualNativeWeakDefinitionRows'])
        need(not any(row['importer'] == PREMAIN for row in weak), 'unchanged original weak-lookup proof excludes replaced premain')
        for row in weak:
            if row['importer'] == CHILD:
                actual = child_image.imports[row['actualImport']['index']]
                need(dict(row['actualImport'], at=actual['at']) == actual, 'original child weak-lookup unchanged')
                row['actualImport'] = actual
        loads = [copy.deepcopy(row) for row in baseline['actualLoadRows'] if row['importer'] != PREMAIN]
        for row in loads:
            if row['importer'] == CHILD:
                row['strongImportCount'] = sum(not imp['weak'] and imp['ordinal'] == row['ordinal'] for imp in child_image.imports)
        for dep in deps('own', PREMAIN):
            kind, key = target(dep['path'])
            need(kind != 'missing', 'new actual premain dependency present')
            loads.append(dict(importer=PREMAIN, **dep, targetKind=kind, target=key, required=True,
                strongImportCount=sum(not imp['weak'] and imp['ordinal'] == dep['ordinal'] for imp in premain_image.imports)))
        need(not any(row['required'] and row['targetKind'] == 'missing' for row in loads), 'all actual required first loads available')
        total = len(strong) + len(weak)
        need(len({(row['importer'], row['actualImport']['index']) for row in strong + weak}) == total, 'exact joined import uniqueness')
        profile_source = NODE / 'mac27-vmm-sandbox-import-dir-compile-only-host-v1-attempt1/Resources/com.apple.Virtualization.VirtualMachine.sb'
        need(pin(profile_source)['sha256'] == '59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504' and pin(profile_source)['bytes'] == 32301, 'genuine same27 Main resource')
        profile = out / 'resources/child-flat' / CONTENTS / 'Resources' / (CHILD + '.sb')
        profile.parent.mkdir(parents=True)
        profile.write_bytes(profile_source.read_bytes())
        profile.chmod(0o600)
        resource = dict(id='child-sandbox-profile', kind='resource', role='sandbox-profile', local=pin(profile), source=pin(profile_source),
            relativePath='Resources/' + CHILD + '.sb', relativePathBase='original child XPC Contents', childFlatRelativePath=CONTENTS + '/Resources/' + CHILD + '.sb',
            runtimeRelativePath='child-flat/' + CONTENTS + '/Resources/' + CHILD + '.sb', mode=0o600, hostMachO=False, addsTrustCacheHash=False)
        inputs.append(pin(profile_source))
        save(out / 'original-child-owned-platform-launch-import-recipe.json', recipe)
        save(out / 'incremental-platform-launch-definition-rows.json', increment)
        stage.pop('actualOther71ImagesByteIdentical', None)
        stage.update(schema='HOST Stage13 explicit owned platform launch; native sandbox profile honestly deferred', builder=pin(__file__),
            baseStage=pin(stage_path), prior=pin(stage_path), stagedImages=rows, actualOnlyReplacedImages=[CHILD, PREMAIN],
            actualUnchangedOtherImages=71, actualOther71ImagesByteIdentical=True, ownPlatformLaunchProviderCandidate=pin(provider_path),
            ownPlatformPrepContract=contract, genuineSandboxResources=[resource], actualAddedImages=[], actualAddedChildLoadCommands=0,
            originalChildOwnedPlatformLaunchRecipe=pin(out / 'original-child-owned-platform-launch-import-recipe.json'),
            actualIncrementalResolvedImportRows=len(increment), actualJoinedStrongImportRowsIncludingExistingWeakDefinitions=total,
            finalStrongDefinitionGraphClosed=True, definitionGraphOutputPath=str(out / 'verification.json'),
            sandboxProfileApplied=False, nativeSandboxApplyUnavailable=45, nativeSandboxInitSuccessFabricated=False,
            originalMainCodeAndFlags3AndNULLAndFatalBranchWholeUnchanged=True, originalAllVMMSectionsAndPACWholeUnchanged=True,
            codeSigned=False, actualCodeSigned=False, readyForDeviceExecution=False, loaderExecuted=False, deviceOperations=0,
            trustCacheOperations=0, guestBoot=False, readiness='HOST candidate requires independent source/product peer and actual owned initialization proof')
        save(out / 'candidate.json', stage)
        proof = copy.deepcopy(baseline)
        proof.update(schema='Actual Stage13 joined graph: Stage10 inheritance and explicit platform preparation increment v1',
            actualLoadRows=loads, actualStrongImportRows=strong, actualNativeWeakDefinitionRows=weak, actualStrongImports=total,
            actualRequiredNativeLibCxxLoadRows=[row for row in loads if row['required'] and row['targetKind'] == 'native' and row['target'] == '/usr/lib/libc++.1.dylib'],
            sources=[pin(out / 'candidate.json'), pin(native_path), pin(reader), pin(__file__), pin(graph_path)] + [row['staged'] for row in rows],
            inheritedExactPreviousVerification=pin(graph_path), incrementallyResolvedActualStrongRows=len(increment),
            unresolvedStrongImportRows=[], requiredSelectedLoadGaps=[], remainingActualStrongSymbols=0,
            finalStrongDefinitionGraphClosed=True, sandboxProfileApplied=False, nativeSandboxInitSuccessFabricated=False,
            deviceOperations=0, loaderExecuted=False, guestBoot=False)
        save(out / 'verification.json', proof)
        save(out / 'actual-validation-steps.json', steps)
        files = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
        files += inputs + [row['staged'] for row in old_rows.values()] + [row['local'] for row in stage['firmwareResources']]
        save(out / 'freeze.json', dict(schema='HOST Stage13 explicit owned preparation original-code composition freeze v1',
            files=list({row['path']: row for row in files}.values()), sandboxProfileApplied=False, deviceOperations=0, codeSigned=False))
        print(json.dumps(dict(candidate=pin(out / 'candidate.json'), verification=pin(out / 'verification.json'), freeze=pin(out / 'freeze.json'),
            images=73, changedImages=2, increment=len(increment), joinedStrong=total, sandboxProfileApplied=False)))
    except Exception as error:
        save(out / 'failure.json', dict(error=repr(error), inputs=inputs, steps=steps, deviceOperations=0, codeSigned=False))
        raise


if __name__ == '__main__':
    main()
