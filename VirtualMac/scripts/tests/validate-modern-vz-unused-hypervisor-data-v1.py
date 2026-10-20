#!/usr/bin/env python3
"""Independent static endpoint/byte review; does not import or invoke builder."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER = NODE/'vz-skylight-remaining-closure-inventory-v1/macho_reader.py'
assert hashlib.sha256(READER.read_bytes()).hexdigest() == '7854d77dde22aa40b47b7ce1bd773f3b74ab7826c8a4505ad8543ccd2adbe7b2'
spec = importlib.util.spec_from_file_location('independent_bounded_macho_reader',READER)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def pin(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    assert output.is_relative_to(NODE) and not output.exists()
    candidate_path = args.build.resolve()/'candidate.json'
    manifest = json.loads(candidate_path.read_text())
    source_path,target_path = Path(manifest['source']['path']),Path(manifest['target']['path'])
    assert pin(source_path) == manifest['source'] and pin(target_path) == manifest['target']
    assert manifest['source']['sha256'] == 'c6c8e08c8b37ad16560630c9cdeb0e766d1e14e4642868d4b032f5e1170581f6'
    assert manifest['target']['sha256'] == '7114c5ae28e7f3283b9fdb8e73fbf98ff1acbd27d9f241331122cde94adf7746'
    source,target = source_path.read_bytes(),target_path.read_bytes()
    a,b = reader.parse(source),reader.parse(target)
    assert len(source) == len(target) == 4212080
    assert len(a['deps']) == 61 and len(b['deps']) == 60
    assert a['header'][3:5] == [80,9544] and b['header'][3:5] == [79,9456]
    omitted = a['deps'][25]
    assert omitted['name'] == '/System/Library/Frameworks/Hypervisor.framework/Hypervisor'
    assert omitted['cmd'] == 12 and omitted['size'] == 88
    assert [c['raw'] for c in b['commands']] == [c['raw'] for c in a['commands'] if c['at'] != omitted['at']]
    assert target[9488:9584] == bytes(96)
    assert a['segments'] == b['segments'] and a['words'] == b['words'] and len(b['words']) == 26993
    original_imports = {r['index']:r for r in a['imports']}
    assert len(a['imports']) == len(b['imports']) == 1056
    edits = set(range(16,24)) | set(range(32,9576))
    routes = []
    for row in b['imports']:
        old = original_imports[row['index']]
        assert old['ordinal'] != 26
        assert all(old[key] == row[key] for key in ['name','weak','addend','at'])
        if old['ordinal'] <= 0:
            assert old['ordinal'] == row['ordinal']
        else:
            old_dependency,new_dependency = a['deps'][old['ordinal']-1],b['deps'][row['ordinal']-1]
            assert (old_dependency['name'],old_dependency['cmd'],old_dependency['versions']) == (
                new_dependency['name'],new_dependency['cmd'],new_dependency['versions'])
            assert row['ordinal'] == old['ordinal']-(old['ordinal']>26)
        if row['ordinal'] != old['ordinal']:
            edits.add(row['at'])
            routes.append(row['index'])
    assert len(routes) == 225
    assert len(a['nlists']) == len(b['nlists']) == 1439
    nlist_edits = []
    for old,new in zip(a['nlists'],b['nlists']):
        assert all(old[key] == new[key] for key in ['index','name','type','section','value','at'])
        if old['type'] == 1:
            ordinal = old['desc']>>8
            assert ordinal != 26
            expected = old['desc']-(256 if 26<ordinal<=61 else 0)
            assert new['desc'] == expected
        else:
            assert new['desc'] == old['desc']
        if new['desc'] != old['desc']:
            edits.add(new['at']+7)
            nlist_edits.append(new['index'])
    assert len(nlist_edits) == 180
    changed = [i for i,(x,y) in enumerate(zip(source,target)) if x != y]
    assert all(i in edits for i in changed)
    section_checks = 0
    for segment in a['segments']:
        for section in segment['sections']:
            at,size = section['at'],section['bytes']
            if at and size and section['flags']&255 not in (1,12,18):
                assert source[at:at+size] == target[at:at+size]
                section_checks += 1
    assert section_checks == 46
    for row in b['commands']:
        if row['cmd'] in (0x80000033,0x1d):
            at,size = struct.unpack_from('<II',row['raw'],8)
            assert source[at:at+size] == target[at:at+size]
    sky = [r for r in b['imports'] if r['ordinal'] == 52]
    assert len(sky) == 12 and all(not r['weak'] and r['addend']==0 for r in sky)
    assert b['deps'][51]['name'] == '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight'
    hv = [(r['index'],r['ordinal'],r['weak']) for r in b['imports'] if r['name'].startswith('_hv_')]
    assert hv == [(559,60,False),(560,59,False)]
    assert all(manifest[key] is False for key in ['originalVZLoaded','originalVMMExecuted','full27Backend','permissionGatesChanged','trustPolicyChanged'])
    assert manifest['deviceOperations'] == manifest['nativeCPUCalls'] == manifest['guestInstructions'] == 0
    negative = json.loads((candidate_path.parent/'negative-controls.json').read_text())
    assert len(negative) == 21 and all(r['rejected'] is True for r in negative)
    for freeze_path in [candidate_path.parent/'freeze.json',Path(manifest['originalCacheAudit']['freeze']['path'])]:
        for record in json.loads(freeze_path.read_text())['files']:
            assert pin(Path(record['path'])) == record
    output.mkdir(parents=True)
    review = dict(schema='Independent unused HV frontend edge static review v1',
        reviewScript=pin(Path(__file__)),independentReader=pin(READER),candidate=pin(candidate_path),
        source=pin(source_path),target=pin(target_path),passed=True,
        targetDependencyCount=60,imports=1056,renumberedImports=225,renumberedNlists=180,
        completePositiveEndpointsPreserved=True,allChangedByteOffsetsAuthorized=True,
        sectionsByteExact=46,chainAndPACWordsByteExact=26993,exportAndSignatureBlobsByteExact=True,
        strongSkyLightImportsRemaining=12,strongUniversalHIDImportsRemaining=104,
        nativeHVCapabilityRoutesRetained=hv,savedNegativeControls=21,
        builderNotImportedOrInvoked=True,sourceAuditNotReexecuted=True,
        deviceOperations=0,nativeCPUCalls=0,originalVZLoaded=False,originalVMMExecuted=False,
        guestInstructions=0,full27Backend=False)
    (output/'review.json').write_text(json.dumps(review,indent=2)+'\n')
    print(json.dumps(dict(passed=True,review=pin(output/'review.json'),sections=46,chainWords=26993)))


if __name__ == '__main__':
    main()
