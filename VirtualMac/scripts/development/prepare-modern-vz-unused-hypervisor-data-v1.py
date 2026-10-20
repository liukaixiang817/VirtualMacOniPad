#!/usr/bin/env python3
"""Remove VZ's unused Hypervisor load edge in new inert data, preserving routes.

Does not load, execute, sign or deploy any image. This prunes only the current
VZ frontend's redundant load edge after its two HV capability imports were
separately routed. It does not remove the CPU/VMM Hypervisor implementation.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE = NODE / 'vz-ipa-original-route-v1/build-v1/VZ27.ipa-native-route.inert.macho-data'
SOURCE_SHA = 'c6c8e08c8b37ad16560630c9cdeb0e766d1e14e4642868d4b032f5e1170581f6'
READER = NODE / 'vz-typed-routes-independent-review-v1/review.py'
READER_SHA = 'a9dc92b4bb4d732b02df7b6ac9b91ce3c0a5dacd43f675d6fefcff261fb6aae4'
AUDIT = NODE / 'vz-unused-hypervisor-original-cache-audit-v2/audit.json'
AUDIT_SHA = '955b83b78ae95a5995b0f3219fccf7b76000ff8732884e7bb4dae437eae3396f'
HV_PATH = '/System/Library/Frameworks/Hypervisor.framework/Hypervisor'
REMOVED = 26

assert hashlib.sha256(READER.read_bytes()).hexdigest() == READER_SHA
spec = importlib.util.spec_from_file_location('bounded_vz_data_reader', READER)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def pin(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def uleb(data, at, end):
    value = 0
    for shift in range(0, 64, 7):
        assert at < end
        byte = data[at]
        at += 1
        if shift == 63:
            assert byte < 2
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, at
    raise AssertionError('ULEB overflow')


def exports(data, image):
    commands = [r for r in image['commands'] if r['cmd'] == 0x80000033]
    assert len(commands) == 1
    start, size = struct.unpack_from('<II', commands[0]['raw'], 8)
    assert size and start+size <= len(data)
    found, visited = [], set()

    def node(offset, prefix):
        assert 0 <= offset < size and offset not in visited and len(prefix) <= 4096
        visited.add(offset)
        length, at = uleb(data, start+offset, start+size)
        end = at+length
        assert end < start+size
        if length:
            flags, at = uleb(data, at, end)
            assert not flags & ~31 and flags & 3 != 3
            assert not flags & 8, 'reexport ordinals require separate explicit remapping'
            address, at = uleb(data, at, end)
            if flags & 16:
                _, at = uleb(data, at, end)
            assert at == end
            found.append(dict(name=prefix, flags=flags, address=address))
        children = data[end]
        at = end+1
        links = []
        for _ in range(children):
            edge, at = reader.checked_string(data, at, start+size)
            assert edge
            child, at = uleb(data, at, start+size)
            links.append((child, prefix+edge))
        for child, name in links:
            node(child, name)
    node(0, '')
    assert len({r['name'] for r in found}) == len(found)
    return found


def ordinal_of_symbol(row):
    # N_STAB desc is not a library ordinal; only external N_UNDF/N_PBUD
    # records carry GET_LIBRARY_ORDINAL in the high byte of n_desc.
    if row['type'] & 0xe0 or not row['type'] & 1 or row['type'] & 0xe not in (0, 12):
        return None
    return row['desc'] >> 8


def unused_edge_guard(image):
    removed = image['deps'][REMOVED-1]
    assert removed['cmd'] == 12 and removed['name'] == HV_PATH and removed['size'] == 88
    assert not any(r['ordinal'] == REMOVED for r in image['imports'])
    assert not any(ordinal_of_symbol(r) == REMOVED for r in image['nlists'])
    assert not any(c['cmd'] in (0x22,0x80000022,0x16,0x17,0x10,0x80000023) for c in image['commands'])


def preconditions(data):
    assert len(data) == 4212080 and hashlib.sha256(data).hexdigest() == SOURCE_SHA
    image = reader.parse(data)
    assert image['header'][3:5] == [80, 9544]
    assert image['header'][5] & 0x80 and not image['header'][5] & 0x100  # TWOLEVEL, no FORCE_FLAT.
    assert len(image['deps']) == 61 and len(image['imports']) == 1056
    unused_edge_guard(image)
    assert all(r['ordinal'] <= 61 for r in image['imports'])
    assert all(ordinal_of_symbol(r) is None or ordinal_of_symbol(r) <= 61 or
               ordinal_of_symbol(r) in (254,255) for r in image['nlists'])
    # No legacy bind/lazy/weak streams or old ordinal-bearing hints are present.
    assert not any(c['cmd'] in (0x22,0x80000022,0x16,0x17,0x10,0x80000023) for c in image['commands'])
    symbols = [r for r in image['imports'] if r['name'].startswith('_hv_')]
    assert [(r['index'],r['name'],r['ordinal'],r['weak'],r['addend']) for r in symbols] == [
        (559,'_hv_vm_config_get_max_ipa_size',61,False,0),
        (560,'_hv_vm_get_max_vcpu_count',60,False,0)]
    assert image['deps'][60]['name'] == '@loader_path/VM27IPALimit.dylib'
    assert image['deps'][59]['name'] == '@loader_path/VL'
    trie = exports(data, image)
    assert trie and not any(r['name'].startswith(('_hv_', '_OBJC_CLASS_$_OS_hv')) for r in trie)
    # The only flat-namespace symbol is inactive unknown index40, already
    # evidenced by the complete chained words. No global HV lookup is needed.
    flat = [r for r in image['imports'] if r['ordinal'] < 0]
    assert len(flat) == 1 and flat[0]['index'] == 40 and flat[0]['name'] == '?' and flat[0]['weak']
    assert not any(r['bind'] and r['index'] == 40 for r in image['words'])
    return image, trie


def audit_proof():
    assert pin(AUDIT)['sha256'] == AUDIT_SHA
    freeze = AUDIT.with_name('freeze.json')
    records = reader.json_read(freeze)['files']
    for record in records:
        assert pin(Path(record['path'])) == record
    audit = reader.json_read(AUDIT)
    assert audit['cacheUUID'] == 'c284a291b68b3d0da1a03f866f87efdc'
    assert audit['originalHypervisorUUID'] == '1b4f3a6a055836c6850d886311584afc'
    assert audit['originalVZUUID'] == '418efc4809d93606918eb6f95baeffdc'
    assert audit['eagerInitializerSections'] == []
    assert all(audit[key] == 0 for key in ('routinesCommands','reexportCommands',
        'nonlazyObjCSections','ownClassLoadMethods','categories','originalVZCStringHVClassAndDynamicPathMatches'))
    assert len(audit['originalHypervisorClasses']) == 5
    assert not any(m['classMethod'] for m in audit['originalHypervisorMethods'])
    assert audit['originalVZClassRefTargetsOutsideHypervisor'] is True
    assert audit['originalVZClassReferences'] and audit['boundedCacheReadCount'] == 369
    assert audit['originalVZSlideChainSlotsChecked'] == 17399
    assert audit['originalVZSlideTargetsInHypervisor'] == []
    assert audit['originalVZDirectBandBLTargetsInHypervisor'] == []
    return dict(audit=pin(AUDIT), freeze=pin(freeze), verifiedFrozenFiles=len(records),
        originalHypervisorClasses=audit['originalHypervisorClasses'],
        ownClassesOmittedFromFrontendOnly=True, exactCacheReadCount=369,
        originalVZSlideSlotsChecked=17399,originalVZSlideTargetsInHypervisor=0,
        initializerAndDynamicReferenceChecksAreStaticOnly=True)


def derive(data):
    image, _ = preconditions(data)
    removed = image['deps'][REMOVED-1]
    commands = [c['raw'] for c in image['commands'] if c['at'] != removed['at']]
    block = b''.join(commands)
    assert len(block) == 9456
    out = bytearray(data)
    out[32:9576] = block+bytes(removed['size'])
    struct.pack_into('<II', out, 16, 79, 9456)
    for row in image['imports']:
        if row['ordinal'] > REMOVED:
            out[row['at']] = row['ordinal']-1
    for row in image['nlists']:
        ordinal = ordinal_of_symbol(row)
        if ordinal is not None and REMOVED < ordinal <= 61:
            struct.pack_into('<H', out, row['at']+6, row['desc']-0x100)
    return bytes(out)


def verify(source, target):
    before, original_exports = preconditions(source)
    after = reader.parse(target)
    assert len(target) == len(source) and after['header'][3:5] == [79,9456]
    assert before['header'][:3]+before['header'][5:] == after['header'][:3]+after['header'][5:]
    assert len(after['deps']) == 60
    kept = [c for c in before['commands'] if c.get('ordinal') != REMOVED]
    assert [c['raw'] for c in after['commands']] == [c['raw'] for c in kept]
    assert target[9488:9584] == bytes(96)  # 88 removed + existing 8 padding.
    assert before['segments'] == after['segments']
    assert before['words'] == after['words'] and len(after['words']) == 26993
    assert exports(target, after) == original_exports
    assert len(before['imports']) == len(after['imports']) == 1056
    changed_imports, changed_nlists = [], []
    allowed = set(range(16,24)) | set(range(32,9576))
    for original, actual in zip(before['imports'], after['imports']):
        expected = dict(original)
        if original['ordinal'] > REMOVED:
            expected['ordinal'] -= 1
            allowed.add(original['at'])
            changed_imports.append(dict(index=actual['index'],name=actual['name'],
                beforeOrdinal=original['ordinal'],afterOrdinal=actual['ordinal']))
        assert actual == expected
        if original['ordinal'] > 0:
            old = before['deps'][original['ordinal']-1]
            new = after['deps'][actual['ordinal']-1]
            assert (old['name'],old['cmd'],old['versions']) == (new['name'],new['cmd'],new['versions'])
    assert len(before['nlists']) == len(after['nlists'])
    for original, actual in zip(before['nlists'], after['nlists']):
        expected = dict(original)
        ordinal = ordinal_of_symbol(original)
        if ordinal is not None and REMOVED < ordinal <= 61:
            expected['desc'] -= 256
            allowed.add(original['at']+7)
            changed_nlists.append(dict(index=actual['index'],name=actual['name'],
                beforeOrdinal=ordinal,afterOrdinal=actual['desc']>>8))
            old, new = before['deps'][ordinal-1], after['deps'][(actual['desc']>>8)-1]
            assert (old['name'],old['cmd'],old['versions']) == (new['name'],new['cmd'],new['versions'])
        assert actual == expected
    assert len(changed_imports) == 225 and len(changed_nlists) == 180
    assert all(index in allowed for index,(x,y) in enumerate(zip(source,target)) if x != y)
    sections = []
    for segment in before['segments']:
        for section in segment['sections']:
            at, size = section['at'], section['bytes']
            if at and size and section['flags'] & 255 not in (1,12,18):
                assert source[at:at+size] == target[at:at+size]
                sections.append(dict(segment=segment['name'],section=section['name'],
                    bytes=size,sha256=hashlib.sha256(target[at:at+size]).hexdigest()))
    sig = next(c for c in after['commands'] if c['cmd'] == 0x1d)
    off, count = struct.unpack_from('<II',sig['raw'],8)
    assert source[off:off+count] == target[off:off+count]
    assert all(not r['weak'] for r in after['imports'] if r['index'] in range(304,318))
    return dict(removedDependency=HV_PATH,removedOrdinal=REMOVED,removedCommandBytes=88,
        dependencyCountBefore=61,dependencyCountAfter=60,importCount=1056,
        importsRenumbered=changed_imports,nlistsRenumbered=changed_nlists,
        everyPositiveImportStillTargetsIdenticalPathCommandAndVersions=True,
        everyUndefinedNlistStillTargetsIdenticalPathCommandAndVersions=True,
        exportTrieUnchanged=True,reexportRows=0,chainAndPACWordsUnchanged=26993,
        fileBackedSectionsUnchanged=sections,allInstructionAndRelativeMetadataBytesUnchanged=True,
        originalSignatureBlobUnchanged=True,signatureStale=True,
        originalHVCapabilityStrongRoutesPreservedAtNewOrdinals=[59,60],
        remainingSkyLightStrongImports=12,remainingUniversalHIDStrongImports=104,
        oldWeakUnknownIndex40StillInactive=True,nativeCPUExecutionGateUnchanged=True,
        full27Backend=False)


def negative_controls(source, target):
    image = reader.parse(target)
    results = []
    def bad(name, data):
        try:
            verify(source,data)
        except (AssertionError,ValueError,IndexError,struct.error):
            results.append(dict(name=name,rejected=True))
            return
        raise AssertionError('accepted damaged data: '+name)
    rows = image['imports']
    chain = next(w for w in image['words'] if w['auth'] and w['bind'])
    nl = next(r for r in image['nlists'] if ordinal_of_symbol(r) == 60)
    for name, at, mask in [('capability import stale ordinal',rows[559]['at'],1),
        ('unrelated stock ordinal',rows[318]['at'],1),('weakening capability',rows[559]['at']+1,1),
        ('capability addend',rows[559]['at']+4,1),('undefined nlist stale ordinal',nl['at']+7,1),
        ('PAC auth bit',chain['at']+7,128),('instruction',9584,1),
        ('new header padding',9488,1),('header count',16,1),('header byte size',20,1),
        ('SkyLight path',image['deps'][51]['at']+24,1),
        ('UniversalHIDKit path',image['deps'][2]['at']+24,1),
        ('stock compatibility',image['deps'][0]['at']+20,1),
        ('ordinary metadata',next(s for g in image['segments'] for s in g['sections'] if s['name']=='__objc_classlist')['at'],1)]:
        data = bytearray(target)
        data[at] ^= mask
        bad(name,bytes(data))
    data = bytearray(target)
    struct.pack_into('<I',data,image['deps'][51]['at'],0x80000018)
    bad('weaken SkyLight load',bytes(data))
    data = bytearray(source)
    data[reader.parse(source)['imports'][559]['at']] = REMOVED
    bad('restore a used Hypervisor import before pruning',bytes(data))
    bad('trailing bytes',target+b'\0')
    # Exercise the actual unused-edge guard independently of the whole-file
    # source hash. These cases must fail because the edge is used or special.
    for name, change in [
        ('semantic guard: used chained import',lambda image: image['imports'][559].update(ordinal=REMOVED)),
        ('semantic guard: used undefined nlist',lambda image: next(r for r in image['nlists'] if ordinal_of_symbol(r)==61).update(desc=REMOVED<<8)),
        ('semantic guard: reexport load edge',lambda image: image['deps'][REMOVED-1].update(cmd=0x8000001f)),
        ('semantic guard: legacy bind stream',lambda image: image['commands'].append(dict(cmd=0x80000022)))]:
        fixture = copy.deepcopy(reader.parse(source))
        change(fixture)
        try:
            unused_edge_guard(fixture)
        except AssertionError:
            results.append(dict(name=name,rejected=True))
        else:
            raise AssertionError('accepted used dependency: '+name)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    output = args.out.resolve()
    assert output.is_relative_to(NODE)
    proof = audit_proof()
    source = SOURCE.read_bytes()
    destination = output/'VZ27.no-unused-hypervisor.inert.macho-data'
    if args.check:
        candidate = reader.json_read(output/'candidate.json')
        target = destination.read_bytes()
        assert candidate['source'] == pin(SOURCE) and candidate['builder'] == pin(Path(__file__))
        assert candidate['target'] == pin(destination) and candidate['reader'] == pin(READER)
        assert candidate['originalCacheAudit'] == proof
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600 and destination.stat().st_nlink == 1
        assert candidate['verification'] == verify(source,target)
        assert reader.json_read(output/'negative-controls.json') == negative_controls(source,target)
        print(json.dumps(dict(checkPassed=True,target=pin(destination))))
        return
    assert not output.exists()
    target = derive(source)
    verification = verify(source,target)
    negatives = negative_controls(source,target)
    output.mkdir(parents=True)
    destination.write_bytes(target)
    destination.chmod(0o600)
    tools = []
    for label, argv in [('metadata',['xcrun','dyld_info','-platform','-dependents','-imports','-validate_only',str(destination)])]:
        result = subprocess.run(argv,capture_output=True,timeout=30)
        (output/(label+'.stdout')).write_bytes(result.stdout)
        (output/(label+'.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        tools.append(dict(label=label,argv=argv,exit=result.returncode))
    candidate = dict(schema='Original27 VZ unused Hypervisor dependency pruning inert v1',
        source=pin(SOURCE),builder=pin(Path(__file__)),reader=pin(READER),target=pin(destination),
        originalCacheAudit=proof,verification=verification,staticTools=tools,
        negativeControlCount=len(negatives),deploymentReady=False,originalVZLoaded=False,
        originalVMMExecuted=False,guestInstructions=0,nativeCPUCalls=0,deviceOperations=0,
        signingCalls=0,trustPolicyChanged=False,permissionGatesChanged=False,full27Backend=False)
    save(output/'candidate.json',candidate)
    save(output/'negative-controls.json',negatives)
    files=[pin(p) for p in sorted(output.iterdir()) if p.is_file()]
    files.extend(pin(p) for p in [Path(__file__),READER,SOURCE,AUDIT,AUDIT.with_name('freeze.json')])
    save(output/'freeze.json',dict(files=files))
    print(json.dumps(dict(target=pin(destination),dependencies=60,imports=1056,
        renumberedImports=225,renumberedNlists=180,negativeControls=len(negatives),full27Backend=False)))


if __name__ == '__main__':
    main()
