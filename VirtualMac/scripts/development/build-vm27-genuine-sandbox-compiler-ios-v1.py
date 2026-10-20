"""HOST-only metadata/import routing of actual reconstructed Mac27 code."""
from pathlib import Path
import collections
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST = NODE / 'mac27-reconstructed-sandbox-compile-only-host-v3-attempt1'
BRIDGE = NODE / 'sandbox-compiler-imports-compat-unsigned-local-v4-attempt2'
STAGE = NODE / 'independent27-owned-bundle-stage-v10-attempt1/candidate.json'
READER = NODE / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
OUT = NODE / 'genuine-sandbox-compiler-ios-unsigned-local-v1-attempt1'
COMPILER_NAME = 'VM27GenuineSandboxCompiler27.dylib'
MATCH_NAME = 'VM27GenuineMatch27.dylib'
BRIDGE_NAME = 'VM27SandboxCompilerImportsCompatV1.dylib'
ALLOCATOR_NAME = 'VM27AllocatorProvider.dylib'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    OUT.mkdir(exist_ok=False)
    flat = OUT / 'flat'
    flat.mkdir()
    spec = importlib.util.spec_from_file_location('independent_macho', READER)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    steps = []
    inputs = []

    def run(label, argv):
        argv = list(map(str, argv))
        env = {k: v for k, v in os.environ.items() if not k.startswith('DYLD_')}
        process = subprocess.run(argv, capture_output=True, timeout=45, env=env)
        (OUT / (label + '.stdout')).write_bytes(process.stdout)
        (OUT / (label + '.stderr')).write_bytes(process.stderr)
        steps.append(dict(label=label, arguments=argv, exit=process.returncode,
                          stdout=pin(OUT / (label + '.stdout')),
                          stderr=pin(OUT / (label + '.stderr'))))
        (OUT / 'steps-in-progress.json').write_text(json.dumps(steps, indent=2) + '\n')
        if process.returncode:
            raise ValueError(label + ' failed')
        return process.stdout

    native_index = NODE / 'current-native-header-export-index-v3/index.json'
    images = json.loads(native_index.read_bytes())['images']

    def native_routes(path, symbol, seen=()):
        if (path, symbol) in seen or path not in images:
            return []
        image = images[path]
        definition = image['definitions'].get(symbol)
        found = []
        seen += ((path, symbol),)
        if definition:
            if definition['flags'] & 8:
                dependency = next(row for row in image['dependencies'] if row['ordinal'] == definition['ordinal'])
                for child in native_routes(dependency['path'], definition.get('alias') or symbol, seen):
                    found.append({**child, 'route': [path] + child['route']})
            else:
                found.append(dict(route=[path], provider=path, UUID=image['UUID'],
                                  resolvedSymbol=symbol, actualExport=definition))
        for dependency in image['dependencies']:
            if dependency['command'] == 0x8000001f:
                for child in native_routes(dependency['path'], symbol, seen):
                    found.append({**child, 'route': [path] + child['route']})
        return found

    def nlist(image):
        command = next(row for row in image.commands if row['cmd'] == 2)
        symoff, symcount, stroff, strsize = struct.unpack_from('<4I', image.data, command['at'] + 8)
        strings = image.data[stroff:stroff+strsize]
        rows = []
        for index in range(symcount):
            offset = symoff + 16*index
            string, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', image.data, offset)
            name = strings[string:strings.index(0, string)].decode()
            rows.append(dict(index=index, offset=offset, name=name, kind=kind,
                             section=section, descriptor=descriptor, value=value))
        return rows

    def new_string_command(raw, path):
        assert struct.unpack_from('<I', raw, 8)[0] == 24
        text = path.encode() + b'\0'
        size = (24 + len(text) + 7) & ~7
        updated = bytearray(raw[:24] + text + bytes(size-24-len(text)))
        struct.pack_into('<I', updated, 4, size)
        return bytes(updated)

    try:
        assert pin(READER)['sha256'] == '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b'
        assert pin(native_index)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
        assert pin(HOST / 'report.json')['sha256'] == '229d0276bd1539b6a62f574d151caf67a784c44b80b258fd527ea01763522b97'
        peer_path = NODE / 'mac27-reconstructed-compiler-test-v3-independent-review-v1-attempt1/review.json'
        assert pin(peer_path)['sha256'] == 'b9f18640c80c3ad684c500be989da817ec2da65822ce07f4c5ff804a0256ca45'
        assert pin(BRIDGE / 'candidate.json')['sha256'] == 'a769b7ce17b83cb8aea245606dfbecf93c2678a7b065bb599d102079f3fbd9cc'
        for directory in [HOST, BRIDGE]:
            for row in json.loads((directory / 'freeze.json').read_bytes())['files']:
                assert pin(row['path']) == row, ('changed frozen source', row['path'])
        host = json.loads((HOST / 'report.json').read_bytes())
        bridge_candidate = json.loads((BRIDGE / 'candidate.json').read_bytes())
        stage = json.loads(STAGE.read_bytes())
        allocator_row = next(row for row in stage['stagedImages'] if row['key'] == ALLOCATOR_NAME)
        assert pin(allocator_row['staged']['path']) == allocator_row['staged']
        bridge_path = Path(bridge_candidate['binary']['path'])
        bridge = reader.MachO(bridge_path.read_bytes())
        assert len(bridge.exports) == 10 and len(bridge.imports) == 13
        assert bridge.loads[0]['path'] == '@loader_path/' + ALLOCATOR_NAME
        assert bridge.loads[1]['path'] == '/usr/lib/libSystem.B.dylib'
        bridge_id = next(row['raw'] for row in bridge.commands if row['cmd'] == 0xd)
        bridge_load = bytearray(bridge_id)
        struct.pack_into('<I', bridge_load, 0, 0xc)
        bridge_load = bytes(bridge_load)
        assert len(bridge_load) == 80
        inputs = [pin(Path(__file__).resolve()), pin(READER), pin(native_index),
            pin(HOST / 'report.json'), pin(HOST / 'freeze.json'), pin(peer_path),
            pin(BRIDGE / 'candidate.json'), pin(BRIDGE / 'freeze.json'),
            pin(STAGE), pin(allocator_row['staged']['path']), pin(bridge_path)]
        original_nlists = []
        transformations = []
        actual_binding_rows = []
        match_image = reader.MachO((HOST / 'flat/libMatch.1.dylib').read_bytes())
        for original_name, new_name, expect_count in [('libsandbox.1.dylib', COMPILER_NAME, 163),
                                                     ('libMatch.1.dylib', MATCH_NAME, 19)]:
            source_path = HOST / 'flat' / original_name
            actual_host_input = next(row['signed'] for row in host['inputs'] if Path(row['signed']['path']).name == original_name)
            assert pin(source_path) == actual_host_input
            inputs.append(pin(source_path))
            original = source_path.read_bytes()
            source = reader.MachO(original)
            assert len(source.imports) == expect_count
            assert all(row['ordinal'] == -2 and not row['weak'] for row in source.imports)
            assert struct.unpack_from('<I', original, 24)[0] & 0x80, 'original MH_TWOLEVEL required'
            commands = []
            removed = []
            signatures = []
            command_changes = []
            build_count = 0
            for command in source.commands:
                raw = command['raw']
                if command['cmd'] == 0x1d:
                    offset, count = struct.unpack_from('<II', raw, 8)
                    assert offset+count == len(original)
                    signatures.append(dict(offset=offset, bytes=count,
                        originalBlobSHA256=hashlib.sha256(original[offset:offset+count]).hexdigest()))
                    removed.append(dict(command='LC_CODE_SIGNATURE', originalRawHex=raw.hex(), reason='stale HOST signature removed; payload zeroed, file and segments retained'))
                    continue
                if command['cmd'] == 0x32:
                    platform, minimum, sdk = struct.unpack_from('<III', raw, 8)
                    if platform == 6:
                        removed.append(dict(command='LC_BUILD_VERSION', originalPlatform=6,
                            originalRawHex=raw.hex(), reason='Mac Catalyst metadata is not an iOS device target'))
                        continue
                    assert platform == 1
                    updated = bytearray(raw)
                    struct.pack_into('<II', updated, 8, 2, 0x100100)
                    raw = bytes(updated)
                    build_count += 1
                    command_changes.append(dict(command='LC_BUILD_VERSION', originalPlatform=platform,
                        newPlatform=2, originalMinimum=minimum, newMinimum=0x100100, originalSDKPreserved=sdk))
                elif command['cmd'] == 0xd:
                    raw = new_string_command(raw, '@loader_path/' + new_name)
                    command_changes.append(dict(command='LC_ID_DYLIB', newPath='@loader_path/' + new_name))
                elif command['cmd'] == 0xc:
                    load = next(row for row in source.loads if row['at'] == command['at'])
                    if load['path'] == '@loader_path/libMatch.1.dylib':
                        raw = new_string_command(raw, '@loader_path/' + MATCH_NAME)
                        command_changes.append(dict(command='LC_LOAD_DYLIB', originalPath=load['path'], newPath='@loader_path/' + MATCH_NAME))
                    else:
                        assert load['path'] == '/usr/lib/libSystem.B.dylib'
                commands.append(raw)
            assert build_count == 1 and len(signatures) == 1
            commands.append(bridge_load)
            first = min(section['fileoff'] for section in source.sections if section['fileoff'] and section['size'])
            old_end = 32 + source.sizeofcmds
            new_end = 32 + sum(map(len, commands))
            assert not any(original[old_end:first]), 'real original header padding must be zero'
            assert new_end <= first, ('header capacity blocker', original_name, new_end, first)
            updated = bytearray(original)
            updated[32:first] = b''.join(commands) + bytes(first-new_end)
            struct.pack_into('<II', updated, 16, len(commands), new_end-32)
            intermediate = reader.MachO(updated)
            loads = {row['path']: row['ordinal'] for row in intermediate.loads}
            bridge_ordinal = loads['@loader_path/' + BRIDGE_NAME]
            native_ordinal = loads['/usr/lib/libSystem.B.dylib']
            match_ordinal = loads.get('@loader_path/' + MATCH_NAME)

            def route(symbol):
                if symbol in bridge.exports:
                    return bridge_ordinal, 'exact compat definition or genuine allocator reexport'
                if match_ordinal and symbol in match_image.exports:
                    return match_ordinal, 'genuine local Match definition'
                routes = native_routes('/usr/lib/libSystem.B.dylib', symbol)
                assert routes, ('strong native symbol not captured', original_name, symbol)
                return native_ordinal, 'captured current native LibSystem reexport'

            fixup_command = next(row for row in source.commands if row['cmd'] == 0x80000034)
            fixup_offset, fixup_size = struct.unpack_from('<II', fixup_command['raw'], 8)
            header = struct.unpack_from('<7I', original, fixup_offset)
            assert header[0] == 0 and header[5:] == (1, 0)
            imports_start = fixup_offset + header[2]
            imports_end = imports_start + 4*header[4]
            allowed = [(0, first), (imports_start, imports_end)]
            binding_changes = []
            for row in source.imports:
                ordinal, kind = route(row['name'])
                assert 0 < ordinal < 128
                old_word = struct.unpack_from('<I', original, row['at'])[0]
                assert old_word & 0xff == 0xfe and not old_word & 0x100
                new_word = (old_word & ~0xff) | ordinal
                struct.pack_into('<I', updated, row['at'], new_word)
                result = dict(image=new_name, index=row['index'], symbol=row['name'],
                    originalOrdinal=-2, newOrdinal=ordinal, kind=kind, importEntryFileOffset=row['at'],
                    originalWord=old_word, newWord=new_word, weakImport=False)
                binding_changes.append(result)
                actual_binding_rows.append(result)
            nlist_changes = []
            original_undefined = [row for row in nlist(source) if row['kind'] & 14 == 0]
            for row in original_undefined:
                ordinal, kind = route(row['name'])
                assert row['value'] == 0
                descriptor = (row['descriptor'] & 0x00bf) | (ordinal << 8)
                if descriptor != row['descriptor']:
                    struct.pack_into('<H', updated, row['offset']+6, descriptor)
                    allowed.append((row['offset']+6, row['offset']+8))
                    nlist_changes.append(dict(symbol=row['name'], descriptorFileOffset=row['offset']+6,
                        originalDescriptor=row['descriptor'], newDescriptor=descriptor,
                        originalGenuineWeakRefStrengthened=bool(row['descriptor'] & 0x40), kind=kind))
            for signature in signatures:
                start = signature['offset']
                stop = start + signature['bytes']
                updated[start:stop] = bytes(signature['bytes'])
                allowed.append((start, stop))
            changed = [offset for offset, (a, b) in enumerate(zip(original, updated)) if a != b]
            assert len(original) == len(updated)
            assert all(any(start <= offset < stop for start, stop in allowed) for offset in changed), 'unexpected code/body modification'
            final = reader.MachO(updated)
            assert final.uuid == source.uuid and final.segments == source.segments and final.sections == source.sections
            assert final.exports == source.exports and final.binds == source.binds
            assert all(row['ordinal'] > 0 and not row['weak'] for row in final.imports)
            assert not any(row['cmd'] == 0x1d for row in final.commands)
            for command in [row for row in source.commands if row['cmd'] in [0x19, 0x1b, 0x2a, 0x26, 0x29, 0x80000033]]:
                assert any(command['raw'] == row['raw'] for row in final.commands), ('protected metadata command changed', command['cmd'])
            assert original[fixup_offset:imports_start] == updated[fixup_offset:imports_start]
            assert original[imports_end:fixup_offset+fixup_size] == updated[imports_end:fixup_offset+fixup_size]
            section_checks = []
            for section in source.sections:
                if section['fileoff'] and section['size'] and section['flags'] & 0xff not in [1, 12, 18]:
                    start = section['fileoff']; end = start+section['size']
                    assert original[start:end] == updated[start:end], ('section bytes changed', section)
                    section_checks.append(dict(segment=section['segment'], section=section['name'],
                        fileOffset=start, bytes=section['size'], sha256=hashlib.sha256(original[start:end]).hexdigest()))
            output = flat / new_name
            output.write_bytes(updated)
            run(new_name + '-validate', ['xcrun', 'dyld_info', '-validate_only', output])
            run(new_name + '-imports-exports', ['xcrun', 'dyld_info', '-imports', '-exports', '-dependents', output])
            rebuilt_names = {row['name'] for row in source.imports}
            original_names = {row['name'] for row in original_undefined}
            added = sorted(rebuilt_names-original_names)
            removed_names = sorted(original_names-rebuilt_names)
            original_nlists.append(dict(image=new_name, originalUndefinedNListCount=len(original_undefined),
                actualReconstructedImportCount=len(source.imports), actualAddedImportNames=added,
                originalNListNamesAbsentFromReconstructedImports=removed_names,
                removedOriginalNamesCurrentNativeRoutes=[dict(symbol=name, nativeRoutes=native_routes('/usr/lib/libSystem.B.dylib', name)) for name in removed_names],
                reconstructedAddedNamesActualNativeRoutes=[dict(symbol=name, nativeRoutes=native_routes('/usr/lib/libSystem.B.dylib', name)) for name in added],
                explanation='Dyld reconstruction binds actual optimized stub targets, deduplicates alias targets and includes true helper imports. Runtime closure is checked on actual reconstructed chained imports, not inferred from original nlist counts. The original symbol names are retained as metadata with explicit positive ordinals.'))
            transformations.append(dict(key=new_name, source=pin(source_path), unsigned=pin(output),
                UUID=final.uuid, actualOriginalHeaderEnd=old_end, actualNewHeaderEnd=new_end,
                firstOriginalSection=first, actualOriginalPaddingBytes=first-old_end,
                actualOriginalPaddingWholeZero=True, actualRemainingPaddingBytes=first-new_end,
                actualMetadataChanges=command_changes, removedMetadataCommands=removed,
                staleHostSignaturesRemoved=signatures, removedSignaturePayloadWholeZero=True,
                actualImportFormat=1, actualImports=len(final.imports), actualActualBindSlots=len(final.binds),
                actualTwoLevelBindingChanges=binding_changes, actualUndefinedNListDescriptorChanges=nlist_changes,
                actualPreservedSections=section_checks, actualWhitelistedDifferenceBytes=len(changed),
                wholeFileLengthUnchanged=True, codeAndAllSectionBytesUnchanged=True,
                poolAndChainedSlotsPACCodedWordsUnchanged=True, fixupStartsAndSymbolPoolWholeUnchanged=True,
                segmentsAndExportsAndUUIDWholeUnchanged=True,
                sourceVersionFunctionStartsAndDataInCodeCommandsWholePreserved=True))

        shutil.copyfile(bridge_path, flat / BRIDGE_NAME)
        shutil.copyfile(allocator_row['staged']['path'], flat / ALLOCATOR_NAME)
        assert (flat / BRIDGE_NAME).read_bytes() == bridge_path.read_bytes()
        assert (flat / ALLOCATOR_NAME).read_bytes() == Path(allocator_row['staged']['path']).read_bytes()
        owned = {path.name: reader.MachO(path.read_bytes()) for path in sorted(flat.iterdir())}
        assert set(owned) == {COMPILER_NAME, MATCH_NAME, BRIDGE_NAME, ALLOCATOR_NAME}

        def resolve_load(load_path, symbol, seen):
            if load_path.startswith('@loader_path/'):
                name = load_path.split('/')[-1]
                assert name in owned and load_path == '@loader_path/' + name
                return resolve_owned(name, symbol, seen)
            assert load_path == '/usr/lib/libSystem.B.dylib'
            routes = native_routes(load_path, symbol)
            assert routes, ('native route missing', load_path, symbol)
            return [dict(kind='actual-current-native', provider=row['provider'],
                         path=row['route'], actualNative=row) for row in routes]

        def resolve_owned(name, symbol, seen=()):
            assert (name, symbol) not in seen, ('owned reexport cycle', name, symbol)
            image = owned[name]
            assert symbol in image.exports, ('strong owned definition absent', name, symbol)
            definition = image.exports[symbol]
            if definition['flags'] & 8:
                load = next(row for row in image.loads if row['ordinal'] == definition['ordinal'])
                alias = definition.get('importedName') or symbol
                results = resolve_load(load['path'], alias, seen + ((name, symbol),))
                return [{**row, 'path': [name] + row['path'],
                         'actualOwnedReexport': dict(image=name, symbol=symbol, definition=definition)} for row in results]
            return [dict(kind='actual-owned-definition', provider=name, path=[name],
                         actualOwned=dict(image=name, UUID=image.uuid, symbol=symbol, definition=definition))]

        graph = []
        for name, image in owned.items():
            for row in image.imports:
                assert row['ordinal'] > 0 and not row['weak']
                load = next(load for load in image.loads if load['ordinal'] == row['ordinal'])
                resolved = resolve_load(load['path'], row['name'], ())
                assert resolved
                graph.append(dict(image=name, index=row['index'], symbol=row['name'],
                    ordinal=row['ordinal'], providerLoad=load['path'], weakImport=False,
                    actualDefinitionRoutes=resolved))
        assert len(graph) == 205
        genuine_graph = [row for row in graph if row['image'] in [COMPILER_NAME, MATCH_NAME]]
        assert len(genuine_graph) == 182
        route_counts = collections.Counter()
        for row in genuine_graph:
            providers = {route['provider'] for route in row['actualDefinitionRoutes']}
            assert len(providers) == 1
            provider = providers.pop()
            if provider == MATCH_NAME:
                route_counts['genuine-Match'] += 1
            elif provider == BRIDGE_NAME:
                route_counts['new-explicit-compat-definition'] += 1
            elif provider == ALLOCATOR_NAME:
                route_counts['true-existing-allocator-reexport'] += 1
            else:
                assert provider in images
                route_counts['true-current-native'] += 1
        assert route_counts == {'genuine-Match': 6, 'new-explicit-compat-definition': 7,
                                'true-existing-allocator-reexport': 4, 'true-current-native': 165}
        platforms = []
        for name, image in owned.items():
            versions = []
            for command in image.commands:
                if command['cmd'] == 0x32:
                    platform, minimum, sdk = struct.unpack_from('<III', command['raw'], 8)
                    assert platform == 2 and minimum <= 0x100100
                    versions.append(dict(platform=platform, minimum=minimum, sdk=sdk))
            assert versions
            assert struct.unpack_from('<I', image.data, 4)[0] == 0x100000c
            assert struct.unpack_from('<I', image.data, 8)[0] & 0xffffff == 2
            platforms.append(dict(image=name, actualBuildVersions=versions))
        for name in [BRIDGE_NAME, ALLOCATOR_NAME]:
            run(name + '-validate', ['xcrun', 'dyld_info', '-validate_only', flat / name])
            run(name + '-imports-exports', ['xcrun', 'dyld_info', '-imports', '-exports', '-dependents', flat / name])
        save('actual-182-genuine-import-routes.json', genuine_graph)
        save('actual-all-205-recursive-import-routes.json', graph)
        save('original-nlist-vs-actual-reconstructed-imports.json', original_nlists)
        save('exact-metadata-only-transformations.json', transformations)
        relevant_native_images = set()
        for row in graph:
            for route in row['actualDefinitionRoutes']:
                native = route.get('actualNative')
                if native:
                    relevant_native_images.update(native['route'])
        actual_native_ranges = []
        for path in sorted(relevant_native_images):
            image = images[path]
            for row in image.get('actualCommandSourceRanges', []):
                actual_native_ranges.append(row['rangePin'])
            actual_native_ranges.append(image['actualCompleteExportSource']['rangePin'])
        for row in actual_native_ranges:
            assert pin(row['path']) == row, ('captured native source changed', row['path'])
        inputs += actual_native_ranges
        for row in inputs:
            assert pin(row['path']) == row, ('input changed', row['path'])
        candidate = dict(schema='Actual genuine reconstructed Mac27 sandbox compiler iOS metadata and explicit strong routes v1',
            builder=pin(Path(__file__).resolve()), reader=pin(READER), inputs=inputs,
            actualIOSImages=[dict(key=name, binary=pin(flat / name), UUID=image.uuid,
                loads=image.loads, actualImports=len(image.imports), actualExports=image.exports,
                newOwnImage=name != ALLOCATOR_NAME,
                codeSignatureCommands=sum(row['cmd'] == 0x1d for row in image.commands)) for name, image in owned.items()],
            actualNewIOSImageKeys=[COMPILER_NAME, MATCH_NAME, BRIDGE_NAME],
            actualWholeUnchangedBorrowedAllocator=dict(stageImageKey=allocator_row['key'],
                source=allocator_row['staged'], ownCopy=pin(flat / ALLOCATOR_NAME),
                UUID=allocator_row['UUID'], codeSignatureStaleUntilFinalSigning=allocator_row['codeSignatureStaleUntilFinalSigning']),
            actualReconstructedRuntimeImports=dict(compiler=163, Match=19, total=182,
                directRouteCounts=dict(route_counts),
                allActualPositiveOrdinals=True, allActualWeakImportBitsFalse=True,
                exactRoutes=pin(OUT / 'actual-182-genuine-import-routes.json')),
            actualAllFourImageStrongGraph=dict(imports=205, allClosed=True,
                exactRoutes=pin(OUT / 'actual-all-205-recursive-import-routes.json')),
            actualOriginalNListDifference=pin(OUT / 'original-nlist-vs-actual-reconstructed-imports.json'),
            actualMetadataOnlyTransformations=pin(OUT / 'exact-metadata-only-transformations.json'),
            actualPlatforms=platforms, genuineUUIDsPreserved=True,
            allGenuineCodeAndPoolAndPACCodedSlotsWholeUnchanged=True,
            allGenuineSegmentsAndExportsWholeUnchanged=True,
            originalSourceVersionFunctionStartsDataInCodeMetadataWholePreserved=True,
            realHeaderZeroPaddingVerified=True, staleHostCodeSignaturesRemovedAndPayloadZeroed=True,
            oldGenuineNListWeakRefsStrengthenedOnlyAfterRealNativeDefinitionProof=True,
            noNewWeakMaskAndNoFlatNamespaceRemaining=True,
            trueAllocatorThreeSymbolReexportsOnly=True,
            codeInstructionsPatched=False, poolOrChainSlotsPatched=False,
            actualIOSArm64e161MachOValidatePassed=True, steps=steps,
            sandboxApplyCalls=0, deviceOperations=0, actualIPadCompilerRun=False,
            actualIPadNativeRecoveryRoleObserved=False, actualIPadCompiledBytecodeVerified=False,
            genuineOpaqueCompilerObjectTransferOnIPadVerified=False,
            allKernelPolicyOperationsCompatible=False,
            realReconstructedHOSTCompilePassed=True,
            originalReconstructedHOSTCompileReport=pin(HOST / 'report.json'),
            originalReconstructedHOSTIndependentPeer=pin(peer_path),
            exactReexportsProviderCandidate=pin(BRIDGE / 'candidate.json'),
            stageMerged=False, newCodeSigningPerformed=False, newTrustCacheAdded=False,
            originalVMMMainOrCPUProviderModified=False,
            readiness='HOST metadata/strong-symbol candidate only; independent review and bounded real iPad compile are still required.',
            findings=[])
        save('candidate.json', candidate)
        save('freeze.json', dict(schema='Genuine compiler iOS metadata source and unsigned new product freeze v1',
            files=inputs + [pin(path) for path in sorted(OUT.rglob('*')) if path.is_file()],
            deviceOperations=0, sandboxApplyCalls=0))
        print(json.dumps(dict(candidate=pin(OUT / 'candidate.json'), freeze=pin(OUT / 'freeze.json'))))
    except Exception as error:
        save('failure.json', dict(error=str(error), steps=steps, inputs=inputs,
                                  deviceOperations=0, sandboxApplyCalls=0))
        raise


if __name__ == '__main__':
    main()
