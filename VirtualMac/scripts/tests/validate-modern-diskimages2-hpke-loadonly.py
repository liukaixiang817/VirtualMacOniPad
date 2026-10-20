#!/usr/bin/env python3
"""Independent byte/ordinal/section/signature freeze; no dlopen or device calls."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SHA = lambda b: hashlib.sha256(b).hexdigest()
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}

def parse(data):
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    count, length = struct.unpack_from('<II', data, 16); at = 32
    result = dict(commands=[], sections=[], dependencies=[], UUID=None, initializers=[])
    for _ in range(count):
        c, size = struct.unpack_from('<II', data, at)
        assert size >= 8 and not size % 8 and at + size <= 32 + length
        result['commands'].append((c, at, size))
        if c == 0x1b:
            assert size == 24 and result['UUID'] is None; result['UUID'] = data[at + 8:at + 24].hex()
        if c == 0x19:
            n = struct.unpack_from('<I', data, at + 64)[0]; assert size == 72 + n * 80
            for i in range(n):
                p = at + 72 + i * 80
                name = data[p:p + 16].rstrip(b'\0').decode(); segment = data[p + 16:p + 32].rstrip(b'\0').decode()
                address, size_, offset, align, reloff, nreloc, flags = struct.unpack_from('<QQ5I', data, p + 32)
                result['sections'].append(dict(name=name, segment=segment, address=address, bytes=size_, offset=offset,
                                               align=align, reloff=reloff, nreloc=nreloc, flags=flags))
                if name in ('__mod_init_func', '__init_offsets'): result['initializers'].append(name)
        if c in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            off = struct.unpack_from('<I', data, at + 8)[0]; assert 24 <= off < size
            result['dependencies'].append(dict(command=c, path=data[at + off:at + size].split(b'\0', 1)[0].decode()))
        if c in (0x11, 0x1a): result['initializers'].append(hex(c))
        at += size
    assert at == 32 + length
    fixups = [(a, s) for c, a, s in result['commands'] if c == 0x80000034]
    if fixups:
        assert len(fixups) == 1
        base, total = struct.unpack_from('<II', data, fixups[0][0] + 8)
        version, starts, entries, symbols, imports, fmt, compressed = struct.unpack_from('<7I', data, base)
        assert version == compressed == 0 and fmt in (1, 2) and base + total <= len(data)
        rows = []
        for i in range(imports):
            cell = base + entries + i * (4 if fmt == 1 else 8)
            word = struct.unpack_from('<I', data, cell)[0]
            ordinal = word & 255
            if ordinal >= 240: ordinal -= 256
            p = base + symbols + (word >> 9); end = data.index(0, p, base + total)
            rows.append(dict(name=data[p:end].decode(), ordinal=ordinal, weak=bool(word & 256),
                             addend=0 if fmt == 1 else struct.unpack_from('<i', data, cell + 4)[0], cell=cell))
        result.update(imports=rows, importsFormat=fmt)
    return result

def flatten(path):
    if '/Versions/' in path:
        a, b = path.split('/Versions/'); return a + '/' + b.split('/', 1)[1]
    return path

def validate_image(data, original, manifest, expected):
    actual, before = parse(data), parse(original)
    assert actual['UUID'] == before['UUID'] == manifest['genuineDI2UUID'] == 'a456d4a4d6ab3549965d0400f3552de3'
    assert actual['importsFormat'] == 2 and len(actual['imports']) == 818
    rows = [{k:r[k] for k in ('name','ordinal','weak','addend')} for r in actual['imports']]
    assert rows == [{k:r[k] for k in ('name','ordinal','weak','addend')} for r in expected]
    assert sum(not r['weak'] for r in rows) == 770 and sum(r['weak'] for r in rows) == 48
    assert all(r['ordinal'] > 0 for r in rows)
    rtti = [r for r in rows if r['addend']]
    assert len(rtti) == 5 and all(r['addend'] == 16 and r['ordinal'] == 31 and not r['weak'] and r['name'].startswith('__ZTVN10__cxxabiv1') for r in rtti)
    assert actual['sections'] == before['sections']
    for s in actual['sections']:
        if s['bytes'] and s['offset']:
            a,b=s['offset'],s['offset']+s['bytes']; assert data[a:b] == original[a:b]
    assert not actual['initializers']
    assert len(actual['dependencies']) == 32 and len(before['dependencies']) == 31
    assert actual['dependencies'][:31] == [dict(command=r['command'],path=flatten(r['path'])) for r in before['dependencies']]
    assert actual['dependencies'][31] == dict(command=0xc,path='@loader_path/VM27DI2Compat.dylib')
    assert not manifest['frameworkLoaded'] and not manifest['RAWReadWriteVerified'] and not manifest['full27Backend']
    return actual

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate-json', type=Path, required=True); p.add_argument('--expected-candidate-sha256', required=True)
    p.add_argument('--output', type=Path, required=True); args = p.parse_args()
    mbytes = args.candidate_json.read_bytes(); assert SHA(mbytes) == args.expected_candidate_sha256
    manifest = json.loads(mbytes); folder = args.candidate_json.parent
    original_path = N/'di2-rtti-data-build-v2/DiskImages2.rtti-data.ios.dylib'; original = original_path.read_bytes()
    assert SHA(original) == manifest['inputSHA256'] == 'f393dd2ec3c3933bfb06d1d744da05f94c52cd1bfa56c746872040e88eaf8714'
    routes_path = folder/'binding-routes.json'; routes = json.loads(routes_path.read_text())
    plan = json.loads((N/'diskimages2-reconstruct-root-v1/positive-routing-plan.json').read_text())['plans']
    assert len(routes) == len(plan) == 818
    for route, row in zip(routes, plan):
        if route['ordinal'] == 32: assert route['exactPrivateOwner'] and not route['weak']
        elif route['ordinal'] != 31:
            assert route['name'] == row['symbol'] and route['ordinal'] == row['proposedOrdinal']
            assert route['weak'] == (row['proposedWeak'] if row['policy']=='restore-exact-original-nlist-contract' else False)
    files=manifest['files']; assert len(files)==13 and len({r['name'] for r in files})==13
    new_di2=next(r for r in files if r['name']=='DiskImages227.dylib'); data=Path(new_di2['path']).read_bytes()
    actual=validate_image(data,original,manifest,routes)
    umbrella=next(r for r in files if r['name']=='VM27DI2Compat.dylib'); um=Path(umbrella['path']).read_bytes(); up=parse(um)
    reexports=[r['path'] for r in up['dependencies'] if r['command']==0x8000001f]
    assert reexports==manifest['compatibilityReexports'] and len(reexports)==7
    assert reexports[-2:] == ['@loader_path/VM27SwiftLookup.dylib','@rpath/VM27HPKECompat.dylib']
    assert not up['initializers'] and not any(s['name'].startswith(('__objc','__swift')) for s in up['sections'])
    out=args.output.resolve(); out.mkdir(parents=True,exist_ok=False); processes=[]; consumer=[]
    for row in files:
        path=Path(row['path']); b=path.read_bytes(); assert len(b)==row['bytes'] and SHA(b)==row['sha256']
        assert parse(b)['UUID']==row['UUID']
        rights={}; cd=None
        for label,argv in [('strict',['codesign','--verify','--strict',str(path)]),('dyld',['xcrun','dyld_info','-validate_only',str(path)]),
                           ('signature',['codesign','-d','--verbose=4',str(path)]),('rights',['codesign','-d','--entitlements',':-',str(path)])]:
            child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            stdout,stderr=child.communicate(timeout=40); assert child.returncode==0,stderr.decode(errors='replace')
            processes.append(dict(label=label,file=path.name,PID=child.pid,wait=child.returncode,reaped=True))
            if label=='rights': rights=plistlib.loads(stdout) if stdout else {}
            if label=='signature': cd=re.search(rb'CDHash=([0-9a-f]{40})',stderr)[1].decode()
        assert cd==row['CDHash']
        assert rights==(RIGHTS if path.name=='diskimages227-loadonly-probe' else {})
        consumer.append(dict(path=str(path),name=path.name,bytes=len(b),sha256=SHA(b),cdhash=cd,entitlements=rights,code=True))
    assert sum(r['ordinal']==32 for r in routes)==59
    old_libs=[r for r in files if r.get('unchangedFromFrozenProvider')]; assert len(old_libs)==10
    # The nine inputs are independently pinned to the earlier native-tested
    # files; declaration-only claims of "unchanged" are insufficient.
    expected_shas={'VM27CxxABICompat.dylib':'cb5e52b6dc494d2423dac460f99d7b6ec79aa60299378dedd075a514f6822d8f',
      'VM27PrimaryExceptionCompat.dylib':'378d38389334f506d5fbf17dc234bdcc0732bc62d780844994f4f8faef950e58',
      'VM27CxxProvider.dylib':'510239083d0098f2ede68f3fbb67d0c44e6dc25b40248e88c01de68596c2bac6',
      'ModernCPURuntimeCompat.dylib':'9847c7a79a5dcb29624f8e845c91ab01bc468d4cfab8275502142073500ee963',
      'VM27DiskAllocatorProvider.dylib':'5c5f4a403525b04b980ef7e572f759afed58624c003d2afb1872fab8d861ec8b',
      'VM27DiskImageConstants.dylib':'c4c15117398f6c08cab3759d76ee1113707123fb9b853aad85f36197df4365c6',
      'VM27DI2SecurityUnavailable.dylib':'178037bf4c2af9c8f87046e8ccdfe5bc0976cbad62edcbedc896f8e526914499',
      'Libquarantine27.dylib':'41d6e97349c5627c820b070987d60ae335331e710cb90bb1993604da8deeb3d7',
      'VM27SwiftLookup.dylib':'d9b1f6d932a035a68de125c0523b902c5248680899b83576c77fdc3f12180914',
      'VM27HPKECompat.dylib':'143ba9ede2847b00a75c7deb2ac17b20b8ed98c2e65a95067127d99badaa55b7'}
    assert {r['name']:r['sha256'] for r in old_libs}==expected_shas
    # Exactly the fourteen missing CryptoKit HPKE imports change relative to
    # the previously frozen strong candidate; no P256/native contracts change.
    prior_manifest=json.loads((N/'diskimages2-strong-loadonly-build-v3/candidate.json').read_bytes())
    prior_file=next(r for r in prior_manifest['files'] if r['name']=='DiskImages227.dylib')
    prior_bytes=Path(prior_file['path']).read_bytes(); assert SHA(prior_bytes)==prior_file['sha256']
    prior=parse(prior_bytes)['imports']; changed=[]
    names={r['originalSymbol'] for r in json.loads((N/'hpke-compat-build-v6/aliases.json').read_bytes())['aliases'] if not r['originalSymbol'].endswith('Mc')}
    assert len(names)==14
    for old,now in zip(prior,actual['imports']):
        assert old['name']==now['name'] and old['weak']==now['weak'] and old['addend']==now['addend']
        if old['ordinal']!=now['ordinal']:
            assert now['name'] in names and old['ordinal']==20 and now['ordinal']==32 and now['weak'] is False
            changed.append(now['name'])
    assert set(changed)==names and len(changed)==14
    for item in files:
        parsed=parse(Path(item['path']).read_bytes())
        assert not parsed['initializers']
        assert not any(section['bytes'] and section['name'] in ('__objc_nlclslist','__objc_nlcatlist') for section in parsed['sections'])
    negatives=[]
    def rejected(label,modified):
        try: validate_image(modified,original,manifest,routes)
        except (AssertionError,ValueError,IndexError,struct.error): negatives.append(label)
        else: raise AssertionError('negative accepted: '+label)
    first=next(r for r in actual['imports'] if r['ordinal']==32); changed=bytearray(data)
    value=struct.unpack_from('<I',changed,first['cell'])[0]; struct.pack_into('<I',changed,first['cell'],value|256); rejected('private-import-weakened',changed)
    changed=bytearray(data); struct.pack_into('<I',changed,first['cell'],(value&~255)|254); rejected('private-import-flat',changed)
    rtt=next(r for r in actual['imports'] if r['addend']==16); changed=bytearray(data); struct.pack_into('<i',changed,rtt['cell']+4,0); rejected('vtable-addend-lost',changed)
    changed=bytearray(data); section=next(r for r in actual['sections'] if r['name']=='__text'); changed[section['offset']]^=1; rejected('genuine-code-byte-mutated',changed)
    changed=bytearray(data); uuid=next(a for c,a,_ in actual['commands'] if c==0x1b); changed[uuid+8]^=1; rejected('wrong-original-UUID',changed)
    changed=bytearray(data); dep=next(a for c,a,_ in actual['commands'] if c==0xc); struct.pack_into('<I',changed,dep,0x80000018); rejected('original-strong-dependency-weakened',changed)
    cp=dict(scope='private-genuine27-DI2-HPKE-load-only',deviceDirectory=manifest['nativeDirectory'],executable='diskimages227-loadonly-probe',
            arguments=['--load-only'],files=consumer,candidateManifestSHA256=SHA(mbytes),DI2APICalls=0,diskVMGPUCalls=0,
            failureMustRecordActualWaitAndDlerror=True,externalChildAbsenceRequired=True,full27Backend=False)
    (out/'consumer-plan.json').write_text(json.dumps(cp,indent=2)+'\n')
    paths=[N/'diskimages2-strong-loadonly-build-v3/candidate.json',Path(prior_file['path']),N/'hpke-compat-build-v6/aliases.json',N/'hpke-original-sdk-fixture-build-v5/consumer-plan.json',args.candidate_json,routes_path,folder/'ios/diskimages227-pins.h',Path(__file__),original_path]
    paths += [Path(r['path']) for r in files]+list((folder/'source').glob('*'))
    # Helper used by the build is frozen outside the immutable candidate dir.
    helper=ROOT/'VirtualMac/scripts/development/prepare-modern-diskimages2-rtti-data.py'
    source=out/'source'; source.mkdir(); (source/helper.name).write_bytes(helper.read_bytes())
    paths.append(source/helper.name)
    frozen=[dict(path=str(path),bytes=path.stat().st_size,sha256=SHA(path.read_bytes())) for path in sorted(set(paths))]
    (out/'freeze.json').write_text(json.dumps(dict(files=frozen,candidateSHA256=SHA(mbytes)),indent=2)+'\n')
    result=dict(passed=True,imports=818,strongImports=770,restoredOriginalWeakImports=48,exactPrivateImports=59,
                allPayloadAndRTTIPACBytesUnchanged=True,originalDependenciesPreserved=31,extraStrongCompatibilityDependency=1,
                originalUUID=actual['UUID'],tenProviderBytesUnchanged=True, privateHPKE14RouteProvenStatic=True,negativeControlsRejected=negatives,
                actualSignatureRightsAndDyldVerified=13,consumerPlan=str(out/'consumer-plan.json'),freeze=str(out/'freeze.json'),
                originalDI2Loaded=False,DI2APICalls=0,RAWReadWriteVerified=False,deviceOperations=False,processes=processes)
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps({k:v for k,v in result.items() if k!='processes'},indent=2))

if __name__=='__main__': main()
