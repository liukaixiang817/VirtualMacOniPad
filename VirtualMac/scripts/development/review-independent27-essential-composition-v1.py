#!/usr/bin/env python3
"""Independent exact composition and definition-route review; no execution."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def pins(value):
    if isinstance(value, dict):
        if {'path', 'bytes', 'sha256'} <= value.keys():
            yield {key: value[key] for key in ('path', 'bytes', 'sha256')}
        else:
            for child in value.values():
                yield from pins(child)
    elif isinstance(value, list):
        for child in value:
            yield from pins(child)


def verify_freeze(path):
    rows = list(pins(json.loads(path.read_bytes())))
    assert rows
    for row in rows:
        actual = pin(row['path'])
        assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'], row['path']
    return len(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    assert out.is_relative_to(N) and not out.exists()
    out.mkdir()
    stage_path = N / 'independent27-essential-dtr-stage-v3-attempt1/candidate.json'
    graph_path = N / 'independent27-essential-definition-graph-v2-attempt1/verification.json'
    assert pin(stage_path)['sha256'] == '3fa967eaff477b81774e48d72736f7bad31eccf141f921176f5db63cfa184701'
    assert pin(graph_path)['sha256'] == 'a4461001020904c0f77ca39038161b6bbcec3a8065cd51f58e7a4ce72811f09c'
    stage, graph = json.loads(stage_path.read_bytes()), json.loads(graph_path.read_bytes())
    base_path = N / 'independent27-flat-graph-stage-v1-attempt3/candidate.json'
    base = json.loads(base_path.read_bytes())
    gpu_path = Path(stage['gpuRecipe']['path'])
    dtr_path = Path(stage['dtrRecipe']['path'])
    gpu, dtr = json.loads(gpu_path.read_bytes()), json.loads(dtr_path.read_bytes())
    platform_path = next(Path(row['path']) for row in stage['inputCandidates']
                         if 'ios-load-platform' in row['path'])
    platform = json.loads(platform_path.read_bytes())
    for row in stage['inputCandidates'] + [stage['gpuRecipe'], stage['dtrRecipe'], stage['baseStage']]:
        assert pin(row['path']) == row
    reviewed = [N / 'independent27-staged-graph-independent-review-v1-attempt3/freeze.json',
                N / 'independent27-ios-platform-source-independent-review-v1/freeze.json',
                N / 'cpu-dtr-v21-independent-source-review-v1-attempt4/freeze.json',
                stage_path.parent / 'freeze.json', graph_path.parent / 'freeze.json',
                Path(stage['baseStage']['path']).parent / 'freeze.json']
    verified = {str(path): verify_freeze(path) for path in reviewed}
    reader = Path(stage['reader']['path'])
    assert pin(reader) == stage['reader']
    spec = importlib.util.spec_from_file_location('essential_peer_macho', reader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base_rows = {row['key']: row['staged'] for row in base['stagedImages']}
    own = {}
    for row in stage['stagedImages']:
        assert pin(row['staged']['path']) == row['staged']
        own[row['key']] = module.MachO(Path(row['staged']['path']).read_bytes())
    assert len(own) == len(stage['stagedImages']) == 73
    vmm_key = 'com.apple.Virtualization.VirtualMachine'
    original_bytes = Path(base_rows[vmm_key]['path']).read_bytes()
    assert gpu['authoringBase'] == dtr['sourceVMM'] == base_rows[vmm_key]
    expected = bytearray(original_bytes)
    changed_ranges = []
    for write in gpu['byteWrites']:
        at = write['fileOffset']
        old, new = bytes.fromhex(write['oldHex']), bytes.fromhex(write['newHex'])
        assert len(old) == len(new) and expected[at:at + len(old)] == old
        assert not any(at < end and begin < at + len(old) for begin, end in changed_ranges)
        changed_ranges.append((at, at + len(old)))
        expected[at:at + len(old)] = new
    gpu_image = module.MachO(bytes(expected))
    # Reconstruct the new command and fixup table from raw format2 words,
    # independently of the author's port() or merge scripts.
    end = 32 + gpu_image.sizeofcmds
    load_name = b'@loader_path/VM27IOSurfaceGuestUnavailableV1.dylib\0'
    load_size = (24 + len(load_name) + 7) & ~7
    load = struct.pack('<6I', 12, load_size, 24, 1, 65536, 65536)
    load += load_name + bytes(load_size - 24 - len(load_name))
    assert not any(expected[end:end + load_size]) and end + load_size <= 8528
    expected[end:end + load_size] = load
    struct.pack_into('<II', expected, 16, gpu_image.ncmds + 1, gpu_image.sizeofcmds + load_size)
    fix_command = next(command for command in gpu_image.commands if command['cmd'] == 0x80000034)
    old_fix_at, old_fix_size = struct.unpack_from('<II', fix_command['raw'], 8)
    blob = bytearray(expected[old_fix_at:old_fix_at + old_fix_size])
    version, starts, imports, symbols, count, form, compression = struct.unpack_from('<7I', blob)
    assert (version, form, compression) == (0, 2, 0)
    assert gpu_image.imports[830]['name'] == '_IOSurfaceAcceleratorParavirtProcessGuestData'
    record = imports + 830 * 8
    old_word, old_addend = struct.unpack_from('<Ii', blob, record)
    assert old_word & 0x1ff == 32 and old_addend == 0
    new_ordinal = len(gpu_image.loads) + 1
    assert new_ordinal == 56
    own_name = b'_VM27IOSurfaceGuestTransformUnavailableV1\0'
    struct.pack_into('<I', blob, record, new_ordinal | ((len(blob) - symbols) << 9))
    blob += own_name
    new_fix_at = (len(expected) + 7) & ~7
    expected += bytes(new_fix_at - len(expected)) + blob
    struct.pack_into('<II', expected, fix_command['at'] + 8, new_fix_at, len(blob))
    linkedit = next(command for command in gpu_image.commands
                    if command['cmd'] == 0x19 and command['raw'][8:24].split(b'\0')[0] == b'__LINKEDIT')
    linkedit_offset = struct.unpack_from('<Q', linkedit['raw'], 40)[0]
    struct.pack_into('<Q', expected, linkedit['at'] + 32, (len(expected) - linkedit_offset + 16383) & ~16383)
    struct.pack_into('<Q', expected, linkedit['at'] + 48, len(expected) - linkedit_offset)
    platform_rows = {row['key']: row for row in platform['actualPorts']}
    port = platform_rows[vmm_key]
    before_platform = Path(port['source']['path']).read_bytes()
    after_platform = Path(port['ported']['path']).read_bytes()
    for at in port['changedByteOffsets']:
        assert expected[at] == before_platform[at]
        assert not any(begin <= at < stop for begin, stop in changed_ranges)
        expected[at] = after_platform[at]
    for patch in dtr['codePatches']:
        image = module.MachO(bytes(expected))
        at = image.file(image.base + patch['startRVA'])
        old, new = bytes.fromhex(patch['beforeHex']), bytes.fromhex(patch['afterHex'])
        assert len(old) == len(new) and expected[at:at + len(old)] == old
        assert not any(at < stop and begin < at + len(old) for begin, stop in changed_ranges)
        changed_ranges.append((at, at + len(old)))
        expected[at:at + len(old)] = new
    actual_vmm = own[vmm_key]
    assert bytes(expected) == actual_vmm.data, 'Whole composed VMM differs from independent reconstruction'
    original_vmm = module.MachO(original_bytes)
    assert original_vmm.uuid == actual_vmm.uuid and original_vmm.exports == actual_vmm.exports
    changes = {row['originalIndex']: (row['newName'], row['newOrdinal']) for row in gpu['imports']}
    changes[830] = ('_VM27IOSurfaceGuestTransformUnavailableV1', 56)
    assert len(original_vmm.imports) == len(actual_vmm.imports)
    actual_changes = []
    for before, after in zip(original_vmm.imports, actual_vmm.imports):
        expected_import = {key: value for key, value in before.items() if key != 'at'}
        if before['index'] in changes:
            expected_import['name'], expected_import['ordinal'] = changes[before['index']]
        assert {key: value for key, value in after.items() if key != 'at'} == expected_import
        if (before['name'], before['ordinal']) != (after['name'], after['ordinal']):
            actual_changes.append(dict(index=before['index'], oldName=before['name'],
                                       oldOrdinal=before['ordinal'], newName=after['name'], newOrdinal=after['ordinal']))
    assert {row['index'] for row in actual_changes} == {463, 597, 830, 840, 1134}
    assert len(original_vmm.binds) == len(actual_vmm.binds)
    for before, after in zip(original_vmm.binds, actual_vmm.binds):
        expected_bind = dict(before)
        if before['index'] in changes:
            expected_bind['name'] = changes[before['index']][0]
        assert expected_bind == after
    for key, image in own.items():
        if key == vmm_key:
            continue
        if key in platform_rows:
            expected_pin = platform_rows[key]['ported']
        elif key == 'VM27HVVMProduction.dylib':
            expected_pin = dtr['replacementProvider']
        elif key == 'VM27DisplayUnavailableV1.dylib':
            expected_pin = gpu['requiredProvider']
        elif key == 'VM27IOSurfaceGuestUnavailableV1.dylib':
            accel = json.loads(next(Path(row['path']).read_bytes() for row in stage['inputCandidates']
                                   if 'iosurface-guest-transform-unavailable' in row['path']))
            expected_pin = accel['provider']
        else:
            expected_pin = base_rows[key]
        assert image.data == Path(expected_pin['path']).read_bytes(), key
        version_command = next(command for command in image.commands if command['cmd'] == 0x32)
        platform_value, minimum = struct.unpack_from('<II', version_command['raw'], 8)
        assert platform_value == 2 and minimum <= 0x100100
    index_path = N / 'current-native-header-export-index-v3/index.json'
    assert pin(index_path)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    native = json.loads(index_path.read_bytes())['images']

    def target(path):
        if path in native:
            return 'native', path
        if path.startswith('@loader_path/') and path.split('/', 1)[1] in own:
            return 'own', path.split('/', 1)[1]
        return 'missing', path

    def deps(kind, key):
        return native[key]['dependencies'] if kind == 'native' else [
            dict(ordinal=row['ordinal'], command=row['cmd'], path=row['path']) for row in own[key].loads]

    def definition(kind, key, symbol):
        return (native[key]['definitions'] if kind == 'native' else own[key].exports).get(symbol)

    def proof(result, initial):
        assert result['resolved']
        route = result['route']
        assert route and (route[0]['kind'], route[0]['path']) == initial
        for i, step in enumerate(route):
            kind, key, symbol = step['kind'], step['path'], step['symbol']
            row = definition(kind, key, symbol)
            assert row == step.get('actualExport')
            if i + 1 == len(route):
                assert row and not row['flags'] & 8
                assert step['UUID'] == (native[key]['UUID'] if kind == 'native' else own[key].uuid)
            else:
                following = route[i + 1]
                if row and row['flags'] & 8:
                    dep = next(d for d in deps(kind, key) if d['ordinal'] == row['ordinal'])
                    assert target(dep['path']) == (following['kind'], following['path'])
                    assert following['symbol'] == (row.get('alias', row.get('importedName', '')) or symbol)
                else:
                    assert following['symbol'] == symbol
                    assert any(d['command'] == 0x8000001f and target(d['path']) == (following['kind'], following['path'])
                               for d in deps(kind, key) if d['path'] in native or d['path'].startswith('@loader_path/'))
        return len(route)

    verified_imports = set()
    steps = 0
    for row in graph['actualStrongImportRows']:
        image, imp = own[row['importer']], row['actualImport']
        assert image.imports[imp['index']] == imp and not imp['weak']
        ident = row['importer'], imp['index']
        assert ident not in verified_imports
        verified_imports.add(ident)
        initial = target(next(d['path'] for d in image.loads if d['ordinal'] == imp['ordinal'])) if imp['ordinal'] > 0 else ('own', row['importer'])
        assert imp['ordinal'] >= 0
        steps += proof(row['resolution'], initial)
    for row in graph['actualNativeWeakDefinitionRows']:
        imp = row['actualImport']
        assert own[row['importer']].imports[imp['index']] == imp
        assert imp['ordinal'] == -3 and not imp['weak'] and imp['addend'] == 0
        assert (row['importer'], imp['index']) not in verified_imports
        verified_imports.add((row['importer'], imp['index']))
        steps += proof(row['actualDefinition'], ('native', '/usr/lib/libc++.1.dylib'))
        assert row['actualDefinition']['route'][-1]['actualExport']['flags'] & 4
    actual_strong = {(key, row['index']) for key, image in own.items() for row in image.imports if not row['weak']}
    assert actual_strong == verified_imports and len(actual_strong) == graph['actualStrongImports'] == 5382
    assert len(graph['actualNativeWeakDefinitionRows']) == 13
    assert graph['unresolvedStrongImportRows'] == graph['requiredSelectedLoadGaps'] == []
    for row in graph['actualLoadRows']:
        dep = next(d for d in own[row['importer']].loads if d['ordinal'] == row['ordinal'])
        assert dep['path'] == row['path'] and dep['cmd'] == row['command']
        assert target(row['path']) == (row['targetKind'], row['target'])
        assert not row['required'] or row['targetKind'] != 'missing'
    premain = 'VM27OwnedAppChildPreMainV3.dylib'
    incoming = [(key, d['cmd']) for key, image in own.items() for d in image.loads
                if d['path'] == '@loader_path/' + premain]
    assert incoming == [(vmm_key, 12)]
    pending = ['VZ27.dylib', 'UniversalHIDKit27.dylib', 'VM27HVVMProduction.dylib', 'VM27OwnedAppStartupV3.dylib']
    reachable = set()
    while pending:
        key = pending.pop()
        if key in reachable:
            continue
        reachable.add(key)
        pending += [d['path'].split('/', 1)[1] for d in own[key].loads if d['path'].startswith('@loader_path/')]
    assert premain not in reachable and vmm_key not in reachable
    assert own['VM27HVVMProduction.dylib'].data == Path(dtr['replacementProvider']['path']).read_bytes()
    assert not any('StartupV9' in key or 'OriginalV9Transport' in key or 'ModernCPURuntimeCompat' in key for key in own)
    review = dict(schema='Actual 73-image essential composition independent review v1',
                  stage=pin(stage_path), definitionGraph=pin(graph_path),
                  verifiedFreezePinCounts=verified, finiteLocalScopePassed=True, findings=[],
                  actualWholeVMMIndependentlyReconstructed=True,
                  noGPU_DTR_Platform_ImportPatchOverlap=True,
                  originalGPUCodeWords=2, originalDTRBodies=4, actualSelectedImportChanges=actual_changes,
                  actualChainedImportFormat=2, actualNewRequiredLoadOrdinal=56,
                  actualAllOriginalAuthenticatedBindWordsUnchanged=True,
                  allOtherImagesExactReviewedProviderOrPlatformParents=True,
                  actualImages=73, actualStrongImports=5382, actualDefinitionRouteSteps=steps,
                  unresolvedStrongDefinitions=0, missingRequiredSelectedLoads=0,
                  actualWeakLookupDefinitions=13, weakCoalescingExecuted=False,
                  childPreMainIncomingOnlyFromActualChild=True, childPreMainNotInParentDSOClosure=True,
                  parentRootClosure=sorted(reachable), oneCPURegistryProvider=True,
                  sourcePins=[pin(path) for path in (Path(__file__), reader, index_path, base_path, gpu_path, dtr_path, platform_path)],
                  finalSignedProductManifestGenerated=False, actualLoaderExecuted=False,
                  deviceOperations=0, nativeOperations=0, guestBoot=False,
                  boundary='Finite byte composition and actual captured definition routes only. '
                           'Existing separately reviewed GPU, own unsupported display/IOSurface, DTR and platform contracts are inherited. '
                           'Runtime load order, final signature, original VMM mandatory remaining context paths and actual guest display remain unproved.')
    save(out / 'review.json', review)
    save(out / 'freeze.json', dict(files=[pin(out / 'review.json'), pin(stage_path), pin(graph_path)]
                                  + review['sourcePins'] + [pin(path) for path in reviewed]))
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'),
                          actualImages=73, actualStrongImports=5382, findings=[])))


if __name__ == '__main__':
    main()
