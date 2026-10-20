#!/usr/bin/env python3
"""Independent byte/route review for the genuine27 HID inert candidates."""
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
READERS = ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
sys.path.insert(0,str(READERS))
from compiler_image import commands,segments,imports,chain_entries,export_trie
VZ_READER = NODE/'vz-typed-routes-independent-review-v1/review.py'
spec = importlib.util.spec_from_file_location('independent_vz_reader',VZ_READER)
vr = importlib.util.module_from_spec(spec);spec.loader.exec_module(vr)
CONTRACT_SHA = '98a3853f3a3355b151c3f07863f63944a4dae66c661451f84c495fda29f15803'
VZ_SHA = '7114c5ae28e7f3283b9fdb8e73fbf98ff1acbd27d9f241331122cde94adf7746'


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def deps(buf):
    result=[]
    for cmd,at,size in commands(buf):
        if cmd not in(12,13,0x80000018,0x8000001f,0x80000023):continue
        no,t,c,v=struct.unpack_from('<4I',buf,at+8)
        name=buf[at+no:at+size].split(b'\0')[0].decode()
        result.append(dict(cmd=cmd,name=name,versions=(t,c,v),at=at,size=size))
    return result


def validate_provider(buf,source,facts,plan):
    imp=imports(buf)['imports'];before=imports(source)['imports']
    assert len(imp)==len(before)==plan['positiveOrdinalImports']
    paths=[d for d in deps(buf)if d['cmd']!=13]
    original=[d for d in deps(source)if d['cmd']!=13]
    extra=1 if facts['name']=='UniversalHIDKit'else 0
    assert len(paths)==len(original)+extra
    for i,(old,new)in enumerate(zip(original,paths)):
        expected='@loader_path/UniversalHID27.dylib'if facts['name']=='UniversalHIDKit'and i==0 else old['name']
        assert (new['cmd'],new['name'],new['versions'])==(old['cmd'],expected,old['versions'])
    assert [d['name']for d in deps(buf)if d['cmd']==13]==['@loader_path/'+facts['name']+'27.dylib']
    if extra:
        assert paths[-1]['cmd']==12 and paths[-1]['name']=='/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight'
    for row,old,route in zip(imp,before,plan['routes']):
        assert row['index']==old['index']==route['index']
        assert row['name']==old['name']==route['name'] and row['name']!='?'
        assert not row['weak'] and row['ordinal']==route['ordinal'] and 0<row['ordinal']<=len(paths)
        proof=route['genuineProof']
        assert proof['exportedSymbol']==row['name'] and proof['route'][-1]['symbol']==row['name']
        assert proof['route'][-1]['kind']=='direct original export'
        assert proof['route'][0]['path']==route['path']
        assert proof['exportAddress']>0x100000000 and len(proof['exportUUID'])==32
    assert list(chain_entries(buf))==list(chain_entries(source))
    oldcmd=[bytes(source[at:at+size])for cmd,at,size in commands(source)if cmd not in(12,13,0x80000018)]
    newcmd=[bytes(buf[at:at+size])for cmd,at,size in commands(buf)if cmd not in(12,13,0x80000018)]
    assert oldcmd==newcmd
    whitelist=set(range(32+struct.unpack_from('<I',source,20)[0]))
    for row in before: whitelist.add(row['command'])
    assert len(source)==len(buf)
    assert all(at in whitelist for at,(old,new)in enumerate(zip(source,buf))if old!=new)
    for g in segments(source):
        for s in g['sections']:
            if s['fileoff'] and s['size'] and s['flags']&255 not in(1,12):
                assert source[s['fileoff']:s['fileoff']+s['size']]==buf[s['fileoff']:s['fileoff']+s['size']]
    triecmd=next(at for cmd,at,_ in commands(buf)if cmd==0x80000033)
    start,size=struct.unpack_from('<II',buf,triecmd+8)
    trie={e['symbol']:e for e in export_trie(buf[start:start+size])}
    assert all(e['genuineExport']['name']in trie for e in facts['exactVZStrongRequirements'])
    return dict(imports=len(imp),chains=len(list(chain_entries(buf))),genuineVZExports=len(facts['exactVZStrongRequirements']),
                dependencies=len(paths),addedSkyLightDependency=bool(extra))


def validate_vz(buf,source):
    assert hashlib.sha256(source).hexdigest()==VZ_SHA
    old,new=vr.parse(source),vr.parse(buf)
    assert old['imports']==new['imports']and old['words']==new['words']
    whitelist=set()
    for i,name in((2,'UniversalHIDKit'),(6,'UniversalHID')):
        d=old['deps'][i];n=new['deps'][i]
        assert n['name']=='@loader_path/'+name+'27.dylib'and n['cmd']==d['cmd']==0x80000018
        whitelist.update(range(d['at']+24,d['at']+d['size']))
    assert len(buf)==len(source)and all(at in whitelist for at,(a,b)in enumerate(zip(source,buf))if a!=b)
    assert len(new['imports'])==1056 and len(new['words'])==26993
    return dict(imports=1056,originalPointerWords=26993,changedDependencyPaths=2)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    root=args.candidate.resolve();out=args.output.resolve()
    assert root.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    report=json.loads((root/'candidate.json').read_text());freeze=json.loads((root/'freeze.json').read_text())
    for row in freeze['files']:assert pin(Path(row['path']))==row
    original=Path(report['originalContract']['path']);assert pin(original)['sha256']==CONTRACT_SHA
    contract=json.loads(original.read_text())
    assert all(report[k]is False for k in('fullSwiftMetadataRelocationProven','stockTransitiveClosureProven','nativeExecuted','codeSigned','full27Backend'))
    facts={p['name']:p for p in contract['providers']};plans={p['name']:p for p in report['providers']}
    source={n:Path(p['source']['path']).read_bytes()for n,p in plans.items()}
    provider={n:Path(p['candidate']['path']).read_bytes()for n,p in plans.items()}
    checks={n:validate_provider(provider[n],source[n],facts[n],plans[n])for n in plans}
    vzsource=Path(report['frontendSource']['path']).read_bytes();vz=Path(report['frontendCandidate']['path']).read_bytes();vzcheck=validate_vz(vz,vzsource)
    negatives=[]
    def reject(label,name,at,xor):
        changed=bytearray(provider[name]);changed[at]^=xor
        try:validate_provider(bytes(changed),source[name],facts[name],plans[name])
        except(AssertionError,ValueError,IndexError,UnicodeDecodeError):negatives.append(label)
        else:raise AssertionError('negative accepted: '+label)
    for name in plans:
        first=imports(provider[name])['imports'][0]
        reject(name+' wrong ordinal',name,first['command'],1)
        reject(name+' weak import',name,first['command']+1,1)
        auth=next(r for r in chain_entries(provider[name])if r['auth'])
        reject(name+' changed PAC key',name,auth['fileoff']+6,2)
        text=next(s for g in segments(provider[name])for s in g['sections']if s['name']=='__text')
        reject(name+' rewritten instruction',name,text['fileoff'],1)
        swift=next(s for g in segments(provider[name])for s in g['sections']if s['name']=='__swift5_fieldmd')
        reject(name+' rewritten Swift metadata',name,swift['fileoff'],1)
    skylight=[d for d in deps(provider['UniversalHIDKit'])if d['cmd']!=13][-1]
    reject('weak SkyLight dependency','UniversalHIDKit',skylight['at'],20)
    changed=bytearray(vz);d=vr.parse(vz)['deps'][2];changed[d['at']+24]^=1
    try:validate_vz(bytes(changed),vzsource)
    except(AssertionError,ValueError,UnicodeDecodeError):negatives.append('wrong frontend provider path')
    else:raise AssertionError('bad frontend path accepted')
    assert len(negatives)==12
    out.mkdir()
    result=dict(schema='Independent genuine27 HID inert-data byte review v1',candidate=pin(root/'candidate.json'),
                providers=checks,frontend=vzcheck,negativeControlsRejected=negatives,
                staticReviewPassed=True,genuineVZStrongExports=104,providerPositiveStrongImports=723,
                allSourceSectionBytesAndOriginalPACPreserved=True,
                unresolvedSwiftEdges={n:p['unresolvedSwiftRelativeEdges']for n,p in plans.items()},
                fullSwiftRelocationProven=False,stockTransitiveClosureProven=False,nativeExecuted=False,deviceOperations=0,full27Backend=False)
    (out/'review.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),negativeControls=len(negatives),staticReviewPassed=True)))


if __name__=='__main__':main()
