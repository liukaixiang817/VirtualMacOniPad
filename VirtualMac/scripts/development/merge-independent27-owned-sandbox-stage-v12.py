#!/usr/bin/env python3
"""Prepare HELD Stage11: genuine compiler, owned flags3 adapter and resources.

Only one original child chained import and its required load are changed.
Previous strong definitions are inherited from immutable Stage10 bytes;
new definitions are resolved against actual native67 and own exports.
This builder neither signs nor executes images and never contacts a device.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CHILD = 'com.apple.Virtualization.VirtualMachine'
ADAPTER = 'VM27SandboxInitOwnedCompilerV1.dylib'
NEW_SYMBOL = '_VM27SandboxInitWithOwnedCompilerV1'
OLD_SYMBOL = '_sandbox_init_with_parameters'
CHILD_CONTENTS = 'VMM.bundle/Contents/XPCServices/' + CHILD + '.xpc/Contents'
TARGET_ROOT = '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def frozen(directory, candidate_name, expected, inputs):
    path = NODE / directory / candidate_name
    need(pin(path)['sha256'] == expected, 'exact reviewed input: ' + directory)
    freeze = path.parent / 'freeze.json'
    record = json.loads(freeze.read_bytes())
    for row in record.get('files', record.get('pins', [])):
        need(pin(row['path']) == {key: row[key] for key in ('path', 'bytes', 'sha256')},
             'frozen bytes changed: ' + row['path'])
    inputs.extend([pin(path), pin(freeze)])
    return path, json.loads(path.read_bytes())


def change_child(raw, module):
    original = module.MachO(raw)
    need(original.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'true original child UUID')
    selected = original.imports[428]
    need(selected['index'] == 428 and selected['name'] == OLD_SYMBOL and selected['ordinal'] == 15
         and not selected['weak'] and selected['addend'] == 0, 'exact original single import428')
    need(not any(command['cmd'] == 0x1d for command in original.commands), 'Stage10 child has no signature to preserve or remove')
    required_path = '@loader_path/' + ADAPTER
    need(not any(row['path'] == required_path for row in original.loads), 'new required load absent from original')
    payload = required_path.encode() + b'\0'
    size = (24 + len(payload) + 7) & ~7
    command = struct.pack('<6I', 12, size, 24, 0, 0, 0) + payload + bytes(size - 24 - len(payload))
    old_end = 32 + original.sizeofcmds
    new_end = old_end + size
    first_section = min(section['fileoff'] for section in original.sections
                        if section['size'] and section['fileoff'] > 0 and section['flags'] & 255 not in (1, 12, 18))
    need(new_end <= first_section and not any(raw[old_end:new_end]), 'only actual zero header capacity used')
    fixup_commands = [row for row in original.commands if row['cmd'] == 0x80000034]
    need(len(fixup_commands) == 1, 'one true chained fixups command')
    fixup = fixup_commands[0]
    old_offset, old_size = struct.unpack_from('<II', raw, fixup['at'] + 8)
    original_table = raw[old_offset:old_offset + old_size]
    version, starts, imports, symbols, count, form, symbols_form = struct.unpack_from('<7I', original_table)
    need(version == 0 and form == 2 and symbols_form == 0 and count == len(original.imports), 'true original form2 import table')
    new_ordinal = len(original.loads) + 1
    need(0 < new_ordinal < 128, 'true signed8 positive load ordinal')
    table = bytearray(original_table)
    new_name_offset = len(table) - symbols
    need(0 <= new_name_offset < 1 << 23, 'real appended symbol name23 bound')
    word_at = imports + 428 * 8
    old_word = struct.unpack_from('<I', table, word_at)[0]
    new_word = (new_name_offset << 9) | (old_word & 0x100) | new_ordinal
    struct.pack_into('<I', table, word_at, new_word)
    table.extend(NEW_SYMBOL.encode() + b'\0')
    table_allowed = set(range(word_at, word_at + 4))
    need(all(position in table_allowed for position, (before, after) in enumerate(zip(original_table, table))
             if before != after), 'only selected import word changed in copied original fixup payload')
    amended = bytearray(raw)
    amended[old_end:new_end] = command
    struct.pack_into('<II', amended, 16, original.ncmds + 1, original.sizeofcmds + size)
    appended_at = (len(amended) + 15) & ~15
    amended.extend(bytes(appended_at - len(amended)))
    amended.extend(table)
    struct.pack_into('<II', amended, fixup['at'] + 8, appended_at, len(table))
    linkedit = next(row for row in original.commands if row['cmd'] == 0x19
                    and raw[row['at'] + 8:row['at'] + 24].rstrip(b'\0') == b'__LINKEDIT')
    fileoff = struct.unpack_from('<Q', raw, linkedit['at'] + 40)[0]
    struct.pack_into('<Q', amended, linkedit['at'] + 32, (len(amended) - fileoff + 16383) & ~16383)
    struct.pack_into('<Q', amended, linkedit['at'] + 48, len(amended) - fileoff)
    actual = bytes(amended)
    changed = module.MachO(actual)
    need(changed.uuid == original.uuid and changed.sections == original.sections and changed.exports == original.exports,
         'true original UUID/exports/all section geometry unchanged')
    need(len(changed.imports) == len(original.imports) and len(changed.loads) == len(original.loads) + 1,
         'one required load, original import count')
    for before, after in zip(original.imports, changed.imports):
        expected = dict(before, at=after['at'])
        if before['index'] == 428:
            expected.update(name=NEW_SYMBOL, ordinal=new_ordinal)
        need(expected == after, 'only actual428 semantic import change')
    expected_binds = [dict(row, name=NEW_SYMBOL if row['index'] == 428 else row['name']) for row in original.binds]
    need(changed.binds == expected_binds, 'all original bind words/PAC/slots exactly unchanged')
    need(changed.loads[:-1] == original.loads and changed.loads[-1]['path'] == required_path
         and changed.loads[-1]['ordinal'] == new_ordinal and changed.loads[-1]['cmd'] == 12,
         'old actual loads exactly preserved and one required own load appended')
    for before, after in zip(original.segments, changed.segments):
        if before['name'] == '__LINKEDIT':
            expected = dict(before, size=(len(actual) - before['fileoff'] + 16383) & ~16383,
                            filesize=len(actual) - before['fileoff'])
            need(after == expected, 'LINKEDIT only exact filesize and rounded virtual size extend')
        else:
            need(before == after, 'all original non-LINKEDIT segments unchanged')
    sections = []
    for section in original.sections:
        if section['size'] and section['fileoff'] and section['flags'] & 255 not in (1, 12, 18):
            at, length = section['fileoff'], section['size']
            need(actual[at:at + length] == raw[at:at + length], 'all genuine backed code/data sections wholebytes')
            sections.append(dict(segment=section['segment'], name=section['name'], fileoff=at, bytes=length,
                                 sha256=hashlib.sha256(raw[at:at + length]).hexdigest()))
    allowed = set(range(16, 24)) | set(range(old_end, new_end)) | set(range(fixup['at'] + 8, fixup['at'] + 16))
    allowed |= set(range(linkedit['at'] + 32, linkedit['at'] + 40)) | set(range(linkedit['at'] + 48, linkedit['at'] + 56))
    need(all(position in allowed for position, (before, after) in enumerate(zip(raw, actual)) if before != after),
         'strict original-file byte whitelist: header only; original LINKEDIT payload all untouched')
    need(actual[old_offset:old_offset + old_size] == original_table, 'previous fixup payload retained wholebytes')
    need(struct.unpack_from('<I', actual, changed.file(changed.base + 0x2e9d4c))[0] == 0x9404a45a,
         'actual original VM setup BL unchanged')
    return actual, changed, dict(selectedOriginalImport=selected, selectedActualImport=changed.imports[428],
        newRequiredLoad=changed.loads[-1], originalHeaderEnd=old_end, newHeaderEnd=new_end,
        firstOriginalSection=first_section, actualRequiredZeroPaddingBytes=size,
        oldFixupDataOffset=old_offset, oldFixupDataBytes=old_size, newFixupDataOffset=appended_at,
        newFixupDataBytes=len(table), allOriginalNListAndStringTableWholeUnchanged=True,
        allOriginalBackedSectionsWholeUnchanged=sections, originalMainFlags3NULLAndFatalBranchWholeUnchanged=True,
        allOriginalAuthenticatedFixupWordsWholeUnchanged=True, originalCodeInstructionsChanged=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == NODE and not out.exists(), 'fresh direct diagnostic output')
    out.mkdir(mode=0o700)
    inputs, steps = [], []
    try:
        stage_path, stage = frozen('independent27-owned-bundle-stage-v10-attempt1', 'candidate.json',
            'f16868649796d871855bf32fab0461c4149f3022ecbd8093ee122d07184baf35', inputs)
        graph_path, baseline = frozen('independent27-owned-bundle-definition-graph-v6-attempt1', 'verification.json',
            'e9d7458fab3439fe83b7e0f258991894a0846f920ffb8a9ec082820b62c9f3b7', inputs)
        compiler_path, compiler = frozen('genuine-sandbox-compiler-ios-unsigned-local-v1-attempt1', 'candidate.json',
            'a75ebd2678202da139b8bef15bfb387b99e363e4e335c07255d5fd80fa66701c', inputs)
        adapter_path, adapter = frozen('sandbox-init-owned-compiler-adapter-local-v2-attempt1', 'candidate.json',
            'c69fd00fff9b683ad9a892e09771400a30ffe6aa7ccd275b1ce16a82f6ad134d', inputs)
        peers = [('genuine-sandbox-compiler-ios-independent-review-v1-attempt1/review.json', '32f1cab591e40c0af445b5a04e8705dd6a12425fa6b556ed7aea94aada0e1877'),
                 ('sandbox-init-owned-compiler-adapter-independent-review-v2-attempt1/review.json', '18a86e947e84d66da174ff190543e7ee13af24331cd5e025f12fb9f9f824b89a')]
        for relative, expected in peers:
            path = NODE / relative
            need(pin(path)['sha256'] == expected and json.loads(path.read_bytes())['findings'] == [], 'real prior independent finite peer')
            inputs.append(pin(path))
        need(stage['actualImages'] == baseline['actualImages'] == 73 and baseline['actualStrongImports'] == 5445
             and baseline['finalStrongDefinitionGraphClosed'] and baseline['unresolvedStrongImportRows'] == []
             and baseline['requiredSelectedLoadGaps'] == [], 'actual finalized inherited Stage10 graph')
        reader = NODE / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
        native_path = NODE / 'current-native-header-export-index-v3/index.json'
        need(pin(reader)['sha256'] == '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b', 'exact bounded real reader')
        need(pin(native_path)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019', 'actual current native67 index')
        inputs.extend([pin(__file__), pin(reader), pin(native_path)])
        spec = importlib.util.spec_from_file_location('owned_sandbox_stage_reader', reader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        native = json.loads(native_path.read_bytes())['images']
        sources = {row['key']: row['staged'] for row in stage['stagedImages']}
        new_sources = {row['key']: row['binary'] for row in compiler['actualIOSImages'] if row['newOwnImage']}
        need(set(new_sources) == {'VM27GenuineSandboxCompiler27.dylib', 'VM27GenuineMatch27.dylib',
                                  'VM27SandboxCompilerImportsCompatV1.dylib'}, 'exact three new reviewed compiler images')
        new_sources[ADAPTER] = adapter['binary']
        need(not set(new_sources) & set(sources), 'four genuinely new stage keys')
        before_child = Path(sources[CHILD]['path']).read_bytes()
        child_bytes, child_image, recipe = change_child(before_child, module)
        flat = out / 'flat'
        flat.mkdir(mode=0o700)
        rows, unchanged = [], []
        old_by_key = {row['key']: row for row in stage['stagedImages']}
        all_sources = {**sources, **new_sources}
        parsed = {CHILD: child_image}
        for key, source in sorted(all_sources.items()):
            need(pin(source['path']) == source, 'exact selected actual file')
            target = flat / key
            data = child_bytes if key == CHILD else Path(source['path']).read_bytes()
            target.write_bytes(data)
            target.chmod(0o600)
            if key in new_sources:
                parsed[key] = module.MachO(data)
                versions = [struct.unpack_from('<II', data, command['at'] + 8) for command in parsed[key].commands if command['cmd'] == 0x32]
                need(versions == [(2, 0x100100)] and not any(command['cmd'] == 0x1d for command in parsed[key].commands),
                     'new true iOS16.1 image and unsigned product')
            image_uuid = parsed[key].uuid if key in parsed else old_by_key[key]['UUID']
            rows.append(dict(key=key, source=source, staged=pin(target), UUID=image_uuid,
                             loadPathChanges=[] if key != CHILD else [recipe['newRequiredLoad']],
                             codeSignatureStaleUntilFinalSigning=key not in new_sources,
                             newOwnedSandboxImage=key in new_sources))
            if key in sources and key != CHILD:
                need(data == Path(source['path']).read_bytes(), 'all other72 old images exact wholebytes')
                unchanged.append(key)
            if key == CHILD or key in new_sources:
                argv = ['xcrun', 'dyld_info', '-validate_only', str(target)]
                env = {name: value for name, value in os.environ.items() if not name.startswith('DYLD_')}
                result = subprocess.run(argv, capture_output=True, env=env, timeout=30)
                label = key + '.validate'
                (out / (label + '.stdout')).write_bytes(result.stdout)
                (out / (label + '.stderr')).write_bytes(result.stderr)
                steps.append(dict(image=key, arguments=argv, exit=result.returncode,
                                  stdout=pin(out / (label + '.stdout')), stderr=pin(out / (label + '.stderr'))))
                need(result.returncode == 0, 'actual changed/new Mach-O validate')
        need(len(rows) == 77 and len(unchanged) == 72, 'exact77 images and72 unchanged old images')

        resources = []
        import_root = NODE / 'mac27-vmm-sandbox-import-dir-compile-only-host-v1-attempt1'
        resource_specs = [('child-sandbox-profile', 'com.apple.Virtualization.VirtualMachine.sb', import_root / 'Resources/com.apple.Virtualization.VirtualMachine.sb', 32301, '59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504'),
                          ('child-sandbox-system-import', 'SandboxProfiles27/system.sb', import_root / 'ImportProfiles/system.sb', 12041, '180a0356611b5de7a7db84b800ed47a1d2f15ec884d0fb960445366ededac7c8'),
                          ('child-sandbox-dyld-import', 'SandboxProfiles27/dyld-support.sb', import_root / 'ImportProfiles/dyld-support.sb', 3152, 'bdfc2354c683c8fb95a39e63fbc8610e9739b0256c89ab880564edefbe73a5ce')]
        for resource_id, name, source, length, sha in resource_specs:
            need(pin(source)['bytes'] == length and pin(source)['sha256'] == sha, 'actual genuine same-version resource')
            relative = CHILD_CONTENTS + '/Resources/' + name
            target = out / 'resources/child-flat' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o600)
            resources.append(dict(id=resource_id, kind='resource', role='sandbox-profile',
                source=pin(source), local=pin(target), relativePath='Resources/' + name,
                relativePathBase='original child XPC Contents', childFlatRelativePath=relative,
                runtimeRelativePath='child-flat/' + relative, devicePath=TARGET_ROOT + '/child-flat/' + relative,
                mode=0o600, hostMachO=False, addsTrustCacheHash=False, exactGenuineWholeBytes=True))
            inputs.append(pin(source))

        rows_by_key = {row['key']: row for row in rows}
        def own_image(key):
            if key not in parsed:
                parsed[key] = module.MachO(Path(rows_by_key[key]['staged']['path']).read_bytes())
            return parsed[key]

        def target(path):
            if path in native:
                return 'native', path
            if path.startswith('@loader_path/') and path[13:] in rows_by_key:
                return 'own', path[13:]
            return 'missing', path

        def deps(kind, key):
            return native[key]['dependencies'] if kind == 'native' else [dict(ordinal=row['ordinal'], command=row['cmd'], path=row['path']) for row in own_image(key).loads]

        def definition(kind, key, symbol, seen=()):
            need(kind != 'missing', 'selected true dependency absent: ' + key)
            identity = kind, key, symbol
            need(identity not in seen, 'real reexport cycle')
            seen += (identity,)
            image = native[key] if kind == 'native' else own_image(key)
            exports = image['definitions'] if kind == 'native' else image.exports
            entry = exports.get(symbol)
            hop = dict(kind=kind, path=key, symbol=symbol)
            if entry:
                hop['actualExport'] = entry
                if entry['flags'] & 8:
                    dep = next(row for row in deps(kind, key) if row['ordinal'] == entry['ordinal'])
                    result = definition(*target(dep['path']), entry.get('alias', entry.get('importedName', '')) or symbol, seen)
                    result['route'] = [hop] + result['route']
                    return result
                hop['UUID'] = image['UUID'] if kind == 'native' else image.uuid
                return dict(resolved=True, route=[hop])
            for dep in deps(kind, key):
                if dep['command'] == 0x8000001f and target(dep['path'])[0] != 'missing':
                    try:
                        result = definition(*target(dep['path']), symbol, seen)
                    except KeyError:
                        continue
                    result['route'] = [hop] + result['route']
                    return result
            raise KeyError((kind, key, symbol))

        def resolve(key, imp):
            need(imp['ordinal'] > 0 and not imp['weak'], 'new actual strong two-level positive imports only')
            dep = next(row for row in deps('own', key) if row['ordinal'] == imp['ordinal'])
            return dict(importer=key, actualImport=imp, resolution=definition(*target(dep['path']), imp['name']))

        increment = [resolve(CHILD, child_image.imports[428])]
        new_loads = []
        for key in sorted(new_sources):
            image = own_image(key)
            need(all(not imp['weak'] and imp['ordinal'] > 0 for imp in image.imports), 'all four new images have actual strong positive imports')
            increment.extend(resolve(key, imp) for imp in image.imports)
            for dep in deps('own', key):
                kind, selected_target = target(dep['path'])
                need(kind != 'missing' and dep['command'] == 12, 'new genuine required load available')
                new_loads.append(dict(importer=key, **dep, targetKind=kind, target=selected_target, required=True,
                                     strongImportCount=sum(not imp['weak'] and imp['ordinal'] == dep['ordinal'] for imp in image.imports)))
        need(len(increment) == 229, 'one selected child plus228 actual new import resolutions')
        actual_strong_rows = []
        for old in baseline['actualStrongImportRows']:
            row = copy.deepcopy(old)
            if row['importer'] == CHILD:
                actual_imp = child_image.imports[row['actualImport']['index']]
                expected = dict(row['actualImport'], at=actual_imp['at'])
                if actual_imp['index'] == 428:
                    expected.update(name=NEW_SYMBOL, ordinal=57)
                    row = increment[0]
                else:
                    row['actualImport'] = actual_imp
                need(expected == actual_imp, 'inherited child row exactly joins current relocated actual import')
            actual_strong_rows.append(row)
        actual_strong_rows += increment[1:]
        weak_rows = copy.deepcopy(baseline['actualNativeWeakDefinitionRows'])
        for row in weak_rows:
            if row['importer'] == CHILD:
                actual_imp = child_image.imports[row['actualImport']['index']]
                need(dict(row['actualImport'], at=actual_imp['at']) == actual_imp, 'existing child native weak-lookup semantic bytes same')
                row['actualImport'] = actual_imp
        load_rows = copy.deepcopy(baseline['actualLoadRows'])
        for row in load_rows:
            if row['importer'] == CHILD:
                row['strongImportCount'] = sum(not imp['weak'] and imp['ordinal'] == row['ordinal'] for imp in child_image.imports)
        dep = deps('own', CHILD)[-1]
        kind, selected_target = target(dep['path'])
        new_loads.append(dict(importer=CHILD, **dep, targetKind=kind, target=selected_target, required=True, strongImportCount=1))
        load_rows += new_loads
        need(len(load_rows) == 448 and len(actual_strong_rows) == 5660 and len(weak_rows) == 13,
             'actual joined448 loads/5660 normal strong/13 existing weak-lookup definitions')
        need(len({(row['importer'], row['actualImport']['index']) for row in actual_strong_rows + weak_rows}) == 5673,
             'no duplicate or missing joined import rows')
        for row in actual_strong_rows + weak_rows:
            if row['importer'] in new_sources or row['importer'] == CHILD:
                need(own_image(row['importer']).imports[row['actualImport']['index']] == row['actualImport'], 'current changed/new actual import row joins raw bytes')
        need(all(row['resolution']['resolved'] for row in actual_strong_rows), 'true finalized increment and inherited strong definition rows')
        need(not any(row['required'] and row['targetKind'] == 'missing' for row in load_rows), 'actual required selected loads available')

        save(out / 'original-child-single-import-recipe.json', recipe)
        save(out / 'incremental-229-definition-rows.json', increment)
        save(out / 'actual-validation-steps.json', steps)
        for obsolete in ['actualOther71ImagesByteIdentical', 'actualOther72ImagesByteIdentical']:
            stage.pop(obsolete, None)
        stage.update(schema='HELD independent27 genuine sandbox compiler and original flags3 Stage11',
            builder=pin(__file__), reader=pin(reader), baseStage=pin(stage_path), prior=pin(stage_path),
            stagedImages=rows, actualImages=77, actualOnlyReplacedImages=[CHILD], actualUnchangedOtherImages=72,
            actualOther72ImagesByteIdentical=True, actualAddedImages=sorted(new_sources),
            genuineSandboxCompilerCandidate=pin(compiler_path), ownedSandboxAdapterCandidate=pin(adapter_path),
            genuineSandboxResources=resources, originalChildSandboxImportRecipe=pin(out / 'original-child-single-import-recipe.json'),
            explicitRequiredDynamicChildImages=['VM27GenuineSandboxCompiler27.dylib', 'VM27GenuineMatch27.dylib', 'VM27SandboxCompilerImportsCompatV1.dylib'],
            fixedOwnedCompilerDlopenPath=TARGET_ROOT + '/child-flat/VM27GenuineSandboxCompiler27.dylib',
            dynamicCompilerImagesMustBeIncludedInChildManifest=True, dynamicCompilerImagesAddedToParent=False,
            actualIncrementalResolvedImportRows=229, actualJoinedStrongImportRowsIncludingExistingWeakDefinitions=5673,
            finalStrongDefinitionGraphClosed=True, definitionGraphOutputPath=str(out / 'verification.json'),
            originalMainCodeAndFlags3AndNULLAndFatalBranchWholeUnchanged=True, originalAllVMMSectionsAndPACWholeUnchanged=True,
            originalVMMMainAndFirmwareDataBytesUnchanged=True, finalSignedProductManifestGenerated=False,
            codeSigned=False, actualCodeSigned=False, readyForDeviceExecution=False,
            readiness='HELD pending real bounded native apply and oracle evidence plus independent Stage peer',
            nativeApplyAndKernelPolicyCompatibilityVerified=False, nativeCompiledBytecodeCompatibilityVerified=False,
            HELDUntilActualNativeApplyAndOracle=True, actualNativeSandboxApplyExecuted=False,
            loaderExecuted=False, deviceOperations=0, trustCacheOperations=0, nativeCPUOperations=0, guestBoot=False)
        save(out / 'candidate.json', stage)
        proof = copy.deepcopy(baseline)
        proof.update(schema='Actual joined Stage11 graph: immutable Stage10 inheritance and229 incremental resolutions v1',
            actualImages=77, actualLoadRows=load_rows, actualStrongImportRows=actual_strong_rows,
            actualNativeWeakDefinitionRows=weak_rows, actualStrongImports=5673,
            actualRequiredNativeLibCxxLoadRows=[row for row in load_rows if row['required'] and row['targetKind'] == 'native' and row['target'] == '/usr/lib/libc++.1.dylib'],
            unresolvedStrongImportRows=[], remainingActualStrongSymbols=0, requiredSelectedLoadGaps=[],
            inheritedActualStrongDefinitionRows=5444, incrementallyResolvedActualStrongRows=229,
            inheritedExactPreviousVerification=pin(graph_path), actualCurrentChildImportRecordsRelocatedAndJoined=True,
            allSelectedFirstLoadImagePathsAvailable=True, finalStrongDefinitionGraphClosed=True,
            sources=[pin(out / 'candidate.json'), pin(native_path), pin(reader), pin(__file__), pin(graph_path)] + [row['staged'] for row in rows],
            StageIntegrationHeld=True, actualSandboxApplyExecuted=False, loaderExecuted=False, deviceOperations=0, guestBoot=False)
        save(out / 'verification.json', proof)
        files = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
        files += inputs + list(all_sources.values()) + [row['local'] for row in stage['firmwareResources']]
        save(out / 'freeze.json', dict(schema='HELD Stage11 genuine sandbox compiler and adapter whole-byte freeze v1',
            files=list({row['path']: row for row in files}.values()), deviceOperations=0, codeSigned=False,
            nativeApplyCompatibilityVerified=False, readiness='HELD'))
        print(json.dumps(dict(candidate=pin(out / 'candidate.json'), verification=pin(out / 'verification.json'),
                              freeze=pin(out / 'freeze.json'), images=77, actualIncrement=229, joinedStrong=5673, readiness='HELD')))
    except Exception as error:
        save(out / 'failure.json', dict(error=repr(error), inputs=inputs, steps=steps,
            deviceOperations=0, codeSigned=False, nativeSandboxApplyCalls=0))
        raise


if __name__ == '__main__':
    main()
