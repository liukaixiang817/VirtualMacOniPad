#!/usr/bin/env python3
"""Route two genuine coroutine imports via an actual AR reexport; inert only."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('coro_route_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
ARRAY = p.NODE / 'universalhid-real-array-reexports-data-v1/candidate.json'
BUILD = p.NODE / 'swift-coro-frame-data-build-v2/candidate.json'
ABI = p.NODE / 'swift-coro-allocation-original-abi-v4/audit.json'


def checked(source):
    for row in json.loads((source.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    return json.loads(source.read_bytes())


def row_image(path, alias):
    raw = Path(path['path']).read_bytes()
    for command, at, size in p.commands(raw):
        if command == 0x80000033:
            off, length = struct.unpack_from('<II', raw, at + 8)
            tree = s.primary.trie(raw[off:off + length])
        if command == 27:
            uuid = raw[at + 8:at + 24].hex()
    return dict(path=alias, UUID=uuid, exports=tree, dependencies=p.dependencies(raw), image=path)


def validate(before, after, ordinal, name):
    old = p.imports(before)['imports']
    new = p.imports(after)['imports']
    selected = [x for x in old if x['name'] == '_swift_coroFrameAlloc']
    assert len(selected) == 1
    item = selected[0]
    assert item['ordinal'] == 8 and not item['weak']
    offset = item['command']
    assert after[:offset] == before[:offset] and after[offset + 1:] == before[offset + 1:]
    assert after[offset] == ordinal
    for a, b in zip(old, new, strict=True):
        assert b == ({**a, 'ordinal': ordinal} if a['index'] == item['index'] else a)
    return dict(name=name, index=item['index'], symbol=item['name'], at=offset,
                oldOrdinal=8, newOrdinal=ordinal, strong=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    array, build, abi = [checked(x) for x in (ARRAY, BUILD, ABI)]
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    assert ios['unsignedInertData'] and len(ios['currentNativeImports']) == 1
    source_ar = next(x for x in array['unchangedRuntimeProviders'] if x['alias'] == 'AR')['candidate']
    old_ar = Path(source_ar['path']).read_bytes()
    ar = bytearray(old_ar)
    count, old_size = struct.unpack_from('<II', ar, 16)
    ordinal = p.append_dependency(ar, '@loader_path/CR')
    assert ordinal == 3
    added = p.dependencies(ar)[-1]
    assert added['size'] == 40 and added['at'] == 32 + old_size
    struct.pack_into('<I', ar, added['at'], 0x8000001f)
    expected_ar = bytearray(old_ar)
    struct.pack_into('<II', expected_ar, 16, count + 1, old_size + 40)
    expected_ar[32 + old_size:32 + old_size + 40] = ar[32 + old_size:32 + old_size + 40]
    assert ar == expected_ar
    assert p.imports(ar)['imports'] == p.imports(old_ar)['imports']
    arpath = out / 'AR.real-coro-reexport.inert.macho-data'
    arpath.write_bytes(ar)
    crpath = out / 'CR.unchanged-unsigned-ios-provider.inert.macho-data'
    crpath.write_bytes(Path(ios['provider']['path']).read_bytes())
    assert p.pin(crpath)['sha256'] == ios['provider']['sha256']
    images = s.primary.captured_images()
    s.join_capture(images, 'system', p.NODE / 'ipad-current-cache-system-headers-v1/headers.json')
    images[s.primary.canonical_path('@loader_path/AR')] = row_image(p.pin(arpath), '@loader_path/AR')
    images[s.primary.canonical_path('@loader_path/CR')] = row_image(p.pin(crpath), '@loader_path/CR')
    arimports = p.imports(ar)['imports']
    ardeps = {x['ordinal']: x['path'] for x in p.dependencies(ar)}
    for item in arimports:
        assert not item['weak'] and item['ordinal'] > 0
        assert s.primary.resolve(images, ardeps[item['ordinal']], item['name'])['status'] == 'actualDirectExport'
    results = []
    for name, target_ordinal in (('UniversalHID', 20), ('UniversalHIDKit', 1)):
        source = next(x for x in array['images'] if x['name'] == name)['candidate']
        before = Path(source['path']).read_bytes()
        data = bytearray(before)
        item = next(x for x in p.imports(data)['imports'] if x['name'] == '_swift_coroFrameAlloc')
        at = item['command']
        word = struct.unpack_from('<I', data, at)[0]
        struct.pack_into('<I', data, at, (word & ~255) | target_ordinal)
        route = validate(before, bytes(data), target_ordinal, name)
        path = out / (name + '27.coro-real-reexport.mac.inert.macho-data')
        path.write_bytes(data)
        alias = '@loader_path/' + name + '27.dylib'
        images[s.primary.canonical_path(alias)] = row_image(p.pin(path), alias)
        results.append(dict(name=name, source=source, candidate=p.pin(path), route=route,
                            allInstructionMetadataWitnessPACBytesPreserved=True))
    for row in results:
        owner = p.dependencies(Path(row['candidate']['path']).read_bytes())[row['route']['newOrdinal'] - 1]['path']
        proof = s.primary.resolve(images, owner, '_swift_coroFrameAlloc')
        leaf = proof
        while 'nested' in leaf:
            leaf = leaf['nested']
        assert proof['status'] == 'actualDirectExport' and leaf['owner'] == '@loader_path/CR'
        row['exactReexportDefinition'] = proof
    validations = []
    for path in [arpath, crpath] + [Path(x['candidate']['path']) for x in results]:
        result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path), exit=result.returncode))
    report = dict(schema='Finite genuine old-host coroutine strong reexport inert data v1',
        sources=[p.pin(x) for x in (ARRAY, BUILD, ABI)], images=results,
        modifiedArrayReexportProvider=dict(alias='AR', intendedLoadPath='@loader_path/AR', source=source_ar,
            candidate=p.pin(arpath), addedGenuineReexport=dict(ordinal=3, path='@loader_path/CR', bytes=40),
            allOriginalSectionsImportsAndChainedPointerBytesPreserved=True,
            preexistingAdhocSignatureBytesPreserved=True, preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='CR', intendedLoadPath='@loader_path/CR', source=ios['provider'], candidate=p.pin(crpath)),
        originalCallerABI=p.pin(ABI), allSeventeenPositiveProviderStrongDefinitionsResolved=True,
        routedStrongImports=2, structuralValidations=validations, genuineOldHostAllocationAdapted=True,
        typedAllocatorTelemetryPreserved=False, allCoroutineLifecycleValidated=False,
        fullSwift27RuntimeEquivalent=False, conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False,
        allCurrentProvidersDeclared=False, currentCompleteProviderDependencyGraphValidated=False,
        metadataCompatibilityProven=False, originalUHLoaded=False, originalVZLoaded=False,
        nativeIOSExecuted=False, deviceOperations=0, codeSigned=False, full27Backend=False)
    p.save(out / 'candidate.json', report)
    files = [Path(__file__), ARRAY, BUILD, ABI, out / 'candidate.json', arpath, crpath]
    files += [Path(x[k]['path']) for x in results for k in ('source', 'candidate')]
    files += [Path(source_ar['path']), Path(ios['provider']['path'])]
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), strongImportsRouted=2, structuralValidations=4)))


if __name__ == '__main__':
    main()
