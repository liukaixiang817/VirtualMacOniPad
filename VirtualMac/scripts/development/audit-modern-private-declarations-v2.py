#!/usr/bin/env python3
"""Declare exact existing private leaves without executing or altering images.

The declarations are a finite proposed flat application bundle. A named
definition does not prove the loader search context, original caller semantics,
process-global bindings, disabled networking or any native VM execution.
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
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from macho_chained_import_records_v1 import read
spec = importlib.util.spec_from_file_location('private_frontier', HERE/'audit-modern-genuine-hid-current-frontier-v16.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
p, N = f.p, f.NODE
PREVIOUS = N/'universalhid-current-exact-frontier-audit-v18/audit.json'
VERSIONS = N/'private-three-own-api-version-data-v2/candidate.json'


def strict_json(path):
    def unique(pairs):
        answer = {}
        for key, value in pairs:
            assert key not in answer
            answer[key] = value
        return answer
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def checked_pin(row):
    pin = p.pin(Path(row['path']))
    assert all(pin[key] == row[key] for key in ('path', 'bytes', 'sha256'))
    return pin


def original_freeze(path):
    body = strict_json(path)
    rows = body if isinstance(body, list) else body['files']
    pins = [p.pin(path)]
    for row in rows:
        target = Path(row['path'])
        if not target.is_absolute():
            target = path.parent/target
        actual = p.pin(target)
        assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
        if Path(row['path']).is_absolute():
            assert actual['path'] == row['path']
        pins.append(actual)
    return pins


def identities(raw):
    ids, builds = [], []
    for command, at, size in p.commands(raw):
        if command == 13:
            offset, timestamp, current, compatibility = struct.unpack_from('<4I', raw, at+8)
            assert 24 <= offset < size
            end = raw.index(0, at+offset, at+size)
            ids.append(dict(path=raw[at+offset:end].decode(), timestamp=timestamp,
                            current=current, compatibility=compatibility))
        if command == 0x32:
            builds.append(dict(platform=struct.unpack_from('<I', raw, at+8)[0],
                               minOS=struct.unpack_from('<I', raw, at+12)[0],
                               SDK=struct.unpack_from('<I', raw, at+16)[0]))
    assert len(ids) == len(builds) == 1 and builds[0]['platform'] == 2
    return dict(ID=ids[0], build=builds[0])


def current_images():
    images = f.s.primary.captured_images(); pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        pins += f.s.join_capture(images, group, N/('ipad-current-cache-'+group+'-headers-v'+str(version)+'/headers.json'))
    pins += f.join_kernel(f.s, images)
    for join in (f.join_hid_extra, f.join_swift_two, f.join_eight, f.join_three, f.join_trace, f.join_unwind):
        added, _ = join(f.s, images); pins += added
    assert len(images) == 34
    return images, pins


def declarations():
    entries, pins = [], original_freeze(VERSIONS.parent/'freeze.json')
    versions = strict_json(VERSIONS)
    assert versions['onlySixWholeFileBytesChangedAcrossThreeProviders'] and versions['signingCalls'] == 0
    modified = {x['intendedLoadPath']:x for x in versions['providers']}
    def manifest(relative, freeze=None):
        path = N/relative
        pins.append(p.pin(path))
        if freeze:
            pins.extend(original_freeze(path.parent/freeze))
        return path, strict_json(path)
    def add(name, alias, row, source, sha, scope, origin=None):
        pin = checked_pin(row); assert pin['sha256'] == sha
        if origin:
            original = checked_pin(origin)
            assert all(pin[k] == original[k] for k in ('bytes', 'sha256'))
            pins.append(original)
        original_pin = pin
        version = modified.get(alias)
        if version:
            assert version['original'] == pin and version['sourceCandidate'] == p.pin(source)
            candidate = checked_pin(version['candidate'])
            before, after = Path(pin['path']).read_bytes(), Path(candidate['path']).read_bytes()
            identity = identities(before)['ID']
            assert identity['current'] == identity['compatibility'] == 0
            at = next(at for command, at, size in p.commands(before) if command == 13)
            expected = bytearray(before); struct.pack_into('<2I', expected, at+16, 65536, 65536)
            assert after == bytes(expected)
            pins.append(pin); pin = candidate
        image = f.image(pin, alias)
        raw = Path(pin['path']).read_bytes()
        identity = identities(raw)
        schema = read(raw, p.commands)
        dependencies = {r['ordinal']:r['path'] for r in image['dependencies']}
        assert all(r['ordinal'] <= 0 or r['ordinal'] in dependencies for r in schema['imports'])
        if schema['importsFormat'] == 1:
            assert schema['imports'] == [dict(row, addend=0) for row in p.imports(raw)['imports']]
        entries.append(dict(name=name, intendedLoadPath=alias, candidate=pin, source=p.pin(source),
                            UUID=image['UUID'], identity=identity, exportCount=len(image['exports']),
                            dependencies=image['dependencies'], activeImportSchema=schema,
                            finiteScope=scope, originalCandidate=original_pin,
                            existingCandidateWholeBytesPreserved=version is None,
                            finiteOwnAPIVersionOnlyRepair=p.pin(VERSIONS) if version else None,
                            sourceFunctionSemanticsNewlyAudited=False,
                            originalCallerRuntimeBindingValidated=False,
                            currentFullLoadClosureProven=False, definitionEvidenceOnly=True))
        pins.append(pin)
    source, body = manifest('efi-owned-nvram-v1/build-v5/candidate.json', 'freeze-manifest.json')
    ios = next(x for x in body['candidates'] if x['role'] == 'ios')
    efi = [ios['efi'], ios['rtti']] + ios['modules']
    expected = {
        'EfiSupport27.dylib':'faecd5502e07d043d4f71a62f6e0a8bf43cc9d0f4e987f11bbf5d07ebb52f227',
        'VM27NativeRTTICompat.dylib':'1c0306585978aa103821182fbf439bc32803114ea53df547f64de900a48d25e7',
        'libPcdDxe.dylib':'ab9637de7332db754f3700fcde142459e8430893e40debd7194b4fe9c4b88165',
        'libVariableRuntimeDxe.dylib':'84961be6243008ade2e8eedf28d522c91fd3c336a31454016207311665723f0f',
        'libFaultTolerantWriteDxe.dylib':'d2c4241517252d0c0dcd14dd9afc6c0c7829ce82ca8a7a7dca97fc9310d658e1'}
    assert {Path(x['path']).name for x in efi} == set(expected)
    for row in efi:
        name = Path(row['path']).name
        add(name.removesuffix('.dylib'), '@loader_path/'+name, row, source, expected[name],
            'Genuine EFI and three dynamic DXE modules; original VZ dynamic-loader search context and Secure Boot policy remain unproved.')
    source, body = manifest('vz-scoped-display-routes-build-v1/candidate.json', 'freeze.json')
    row = next(x for x in body['files'] if x['name'] == 'VM27ScopedDisplayRoutes.dylib')
    add('VM27ScopedDisplayRoutes', '@loader_path/VM27ScopedDisplayRoutes.dylib', row, source,
        'fd2cad7ebd658e5d4b6433b0d9e7a71d45b2a1b3cfc41fb6ff527d1752185a88',
        'Two scoped display getters; full SkyLight and original caller execution remain unproved.')
    source, body = manifest('vz-ipa-original-route-v1/build-v1/candidate.json', 'freeze.json')
    row = next(x for x in body['aliases'] if x['name'] == 'VT')
    add('VT', '@loader_path/VT', row['copy'], source,
        '0e4654ed43bfeb38d4df18a60186079105a8c8fc69c6191978158263f5baf300',
        'Existing own-process title state with a real CFString key; system LaunchServices equivalence remains unproved.', row['original'])
    row = next(x for x in body['aliases'] if x['name'] == 'VM27IPALimit.dylib')
    add('VM27IPALimit', '@loader_path/VM27IPALimit.dylib', row['copy'], source,
        'f1d29e35c023b6c8606a641b66f1fb2b3540fff91e23d3e7fe8af7025705ad54',
        'Existing native opaque-config IPA entry; original VZ caller and VM creation remain unproved.', row['original'])
    source, body = manifest('vz-maxcpu-original-route-v1/build-v4/candidate.json')
    for key in ('builder', 'reader', 'source'):
        pins.append(checked_pin(body[key]))
    add('VL', '@loader_path/VL', body['providerAlias'], source,
        '71a792922c322806cc62b2f9cf3ab6fe143b33e7da383675cef649b7a8652310',
        'Existing framework-limit leaf; original VZ CPU creation remains unproved.', body['provider'])
    source, body = manifest('vz-six-import-consumer-contract-v1/scoped-strcmp-build-v1/candidate.json', 'inputs.json')
    row = next(x for x in body['products'] if x['role'] == 'ios')['provider']
    assert body['onlyExport'] == '__platform_strcmp' and body['callsOnlyHostPublicStrcmp']
    add('VM27ScopedStringCompare', '@loader_path/VM27ScopedStringCompare.dylib', row, source,
        '7cd8b9ebe52c50192ace1d2b266d6f98ea9f25eef785e16aefa59605defc7b40',
        'Typed ordinary strcmp dispatch entry; original six consumer gates remain unproved.')
    source, body = manifest('softlinking-app-private-local-v1/build-v4/candidate.json', 'freeze.json')
    assert body['onlyAbsolutePathInputsValidated'] and not body['loaderCallerRelativeSemanticsValidated']
    role = next(x for x in body['roles'] if x['role'] == 'ios')
    row = next(x for x in role['files'] if x['label'] == 'provider')
    for pin in body['source']:
        pins.append(checked_pin(pin))
    add('VM27ScopedSoftLinking', '@loader_path/VM27ScopedSoftLinking.dylib', row, source,
        'c77b9f6136c7d7473d6e117595d9f06656d81717d8c053309e53d71611d335a8',
        'Pinned v4 absolute-path loader; original relative caller-PC behavior and global OSLog identity remain unproved.')
    source, body = manifest('allocator-full-five-v1/build-result.json')
    pins.extend(original_freeze(source.parent/'manifest.json'))
    row = body['files']['ios']['provider']
    add('VM27AllocatorProvider', '@loader_path/VM27AllocatorProvider.dylib', row, source,
        'd037098b9c45882d54fba0cafb12d7e7c1d1d94fe46831389e1a370879e72503',
        'Existing five typed allocation entries; allocation correctness does not prove original telemetry semantics.')
    source, body = manifest('vmnet-unavailable-contract-v1/candidate.json', 'freeze.json')
    assert body['requiredNetworkConfiguration'] == 'network=disabled, NIC count0'
    add('VM27VMNetUnavailable', '@loader_path/VM27VMNetUnavailable.dylib', body['candidate'], source,
        '165729cabbf26bf59e8aabad601516cb1bbe8fa47adf2eb53ad211c0686609c1',
        'Explicit network=disabled, NIC count0 unsupported contract; guest networking and SSH forwarding are not provided.')
    assert len(entries) == 13 and len({x['intendedLoadPath'] for x in entries}) == 13
    return entries, pins


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve(); assert out.is_relative_to(N) and not out.exists(); out.mkdir()
    entries, pins = declarations()
    pins += original_freeze(PREVIOUS.parent/'freeze.json')
    previous = strict_json(PREVIOUS)
    images, current_pins = current_images(); pins += current_pins
    names = {x['path']:x['name'] for x in previous['auditedImages']}
    for row in previous['privateDefinitions']:
        image = f.image(row['image'], row['path'])
        assert row['UUID'] == image['UUID'] and row['dependencies'] == image['dependencies']
        key = f.s.primary.canonical_path(row['path']); assert key not in images; images[key] = image
    for row in entries:
        key = f.s.primary.canonical_path(row['intendedLoadPath']); assert key not in images
        images[key] = f.image(row['candidate'], row['intendedLoadPath'])
    assert len(images) == 85
    results, negatives = [], []
    for row in entries:
        raw = Path(row['candidate']['path']).read_bytes(); image = images[row['intendedLoadPath']]
        deps = {r['ordinal']:r['path'] for r in image['dependencies']}; checked = []
        for item in row['activeImportSchema']['imports']:
            if item['weak']: continue
            owner = deps.get(item['ordinal'])
            proof = (f.resolve(images, owner, item['name'], image) if item['ordinal'] > 0 else
                     dict(status='specialGlobalLookupProvenanceUnproved', specialOrdinal=item['ordinal'],
                          processGlobalBindingProven=False))
            checked.append(dict(index=item['index'], symbol=item['name'], ordinal=item['ordinal'],
                                addend=item['addend'], dependency=owner, proof=proof))
        results.append(dict(name=row['name'], path=row['intendedLoadPath'], strongImports=len(checked),
                            counts=dict(collections.Counter(x['proof']['status'] for x in checked)), imports=checked))
        offset = row['activeImportSchema']['activeFixupsOffset']
        for label, at, value in [('wrong header version', offset, 1), ('compressed strings', offset+24, 1),
                ('invalid import format', offset+20, 4), ('overlapping strings', offset+12, 0),
                ('unbounded import count', offset+16, 1048577)]:
            changed = bytearray(raw); struct.pack_into('<I', changed, at, value)
            try: read(bytes(changed), p.commands)
            except (ValueError, struct.error): negatives.append(dict(owner=row['name'], name=label, rejected=True))
            else: raise AssertionError('accepted damaged import schema '+row['name']+' '+label)
    vz = next(x for x in previous['auditedImages'] if x['name'] == 'Virtualization')
    requester = images[vz['path']]; transitions = []
    for item in vz['imports']:
        if item['dependency'] not in {x['intendedLoadPath'] for x in entries}: continue
        assert item['proof']['status'] == 'uncapturedOwner'
        proof = f.resolve(images, item['dependency'], item['symbol'], requester)
        assert proof['status'] == 'actualDirectExport'
        image = images[item['dependency']]
        dependency = next(x for x in requester['dependencies'] if x['ordinal'] == item['ordinal'])
        required = struct.unpack_from('<I', Path(requester['image']['path']).read_bytes(), dependency['at']+20)[0]
        actual = identities(Path(image['image']['path']).read_bytes())['ID']
        assert actual['current'] >= required
        transitions.append(dict(index=item['index'], symbol=item['symbol'], ordinal=item['ordinal'],
                                dependency=item['dependency'], previousStatus='uncapturedOwner', proof=proof,
                                requestedCompatibility=required, actualProviderID=actual))
        absent = copy.deepcopy(images); del absent[item['dependency']]
        assert f.resolve(absent, item['dependency'], item['symbol'], requester)['status'] == 'uncapturedOwner'
        negatives.append(dict(owner='Virtualization', name='remove exact declared owner import'+str(item['index']), rejected=True))
    assert len(transitions) == 27 and len({x['dependency'] for x in transitions}) == 9
    assert len(negatives) == 92
    report = dict(schema='Existing exact EFI and scoped private provider declaration subset v2',
        previousFrontier=p.pin(PREVIOUS), currentStockImages=34, providers=entries,
        newPrivateDeclarationCount=13, exactNewStrongDefinitionTransitions=transitions,
        frontendNewDefinitions=27, frontendDistinctOwners=9, declaredProviderImports=results,
        negativeControls=negatives, prior38PrivateCandidateWholeBytesUnchanged=True,
        exactlyThreeExistingLeafVersionFieldsRepaired=p.pin(VERSIONS),
        selectedSoftLinkingV4IsExplicitNewDeclaration=True, candidateFilesCopiedOrModified=False,
        originalVZDynamicEFILoaderSearchContextValidated=False, EFICompleteSecureBootPolicyValidated=False,
        sourceFunctionSemanticsNewlyAudited=False, allCurrentProvidersDeclared=False,
        currentCompleteProviderDependencyGraphValidated=False, definitionEvidenceOnly=True,
        guestNetworkingProvided=False, nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out/'audit.json', report)
    pins += [p.pin(x) for x in (Path(__file__), HERE/'macho_chained_import_records_v1.py', HERE/'audit-modern-genuine-hid-current-frontier-v16.py', PREVIOUS, VERSIONS, out/'audit.json')]
    dedup = {x['path']:x for x in pins}; assert all(dedup[x['path']] == x for x in pins)
    p.save(out/'freeze.json', dict(files=list(dedup.values()), deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'), freeze=p.pin(out/'freeze.json'), privateProviders=13,
                          frontendNewDefinitions=27, negativeControls=len(negatives), imports=[dict(name=x['name'], counts=x['counts']) for x in results])))


if __name__ == '__main__': main()
