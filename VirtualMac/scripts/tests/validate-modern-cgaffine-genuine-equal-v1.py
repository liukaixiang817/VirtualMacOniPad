#!/usr/bin/env python3
"""Independent exact-code, original-caller and one-ordinal CG equality review."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands,segments,imports,chain_entries,export_trie
NATIVE='_$sSo17CGAffineTransformV12CoreGraphicsE2eeoiySbAB_ABtFZ'
CODE_SHA='bf03599fae73d60a0fcb17074bbd89cab20b87b225c9a7adf0c9ede5ffb8780b'


def pin(path):
    data=path.read_bytes();return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def deps(data):
    found=[]
    for cmd,at,size in commands(data):
        if cmd in(12,13,0x80000018,0x8000001f,0x80000023):
            no=struct.unpack_from('<I',data,at+8)[0];found.append(dict(cmd=cmd,at=at,size=size,path=data[at+no:at+size].split(b'\0')[0].decode()))
    return found


def provider(data):
    text=next(s for g in segments(data)for s in g['sections']if s['name']=='__text')
    assert text['size']==108 and hashlib.sha256(data[text['fileoff']:text['fileoff']+108]).hexdigest()==CODE_SHA
    ids=[d['path']for d in deps(data)if d['cmd']==13];assert ids==['@loader_path/CGe']
    assert [(d['cmd'],d['path'])for d in deps(data)if d['cmd']!=13]==[(12,'/usr/lib/libSystem.B.dylib')]
    assert not any(cmd==0x1d for cmd,_,_ in commands(data))
    at=next(at for cmd,at,_ in commands(data)if cmd==0x80000033);off,size=struct.unpack_from('<II',data,at+8)
    actual=export_trie(data[off:off+size]);assert len(actual)==1 and actual[0]['symbol']==NATIVE
    assert actual[0]['address']==text['address'] and actual[0]['flags']==0
    return text


def route(data,source):
    old=imports(source)['imports'];new=imports(data)['imports'];assert len(old)==len(new)==252
    changed=[]
    for a,b in zip(old,new):
        assert all(a[k]==b[k]for k in('name','weak','index'))
        if a['ordinal']!=b['ordinal']:
            assert a['name']==NATIVE and a['ordinal']==6 and b['ordinal']==24 and not b['weak'];changed.append(a['index'])
    assert changed==[64]
    assert list(chain_entries(source))==list(chain_entries(data))
    olddeps=[d for d in deps(source)if d['cmd']!=13];newdeps=[d for d in deps(data)if d['cmd']!=13]
    assert len(olddeps)==23 and len(newdeps)==24
    assert [(d['cmd'],d['path'])for d in olddeps]==[(d['cmd'],d['path'])for d in newdeps[:-1]]
    assert (newdeps[-1]['cmd'],newdeps[-1]['path'])==(12,'@loader_path/CGe')
    before=[bytes(source[at:at+size])for cmd,at,size in commands(source)if cmd!=0x2a]
    after=[bytes(data[at:at+size])for cmd,at,size in commands(data)]
    assert after[:-1]==before
    whitelist=set(range(32+struct.unpack_from('<I',data,20)[0]))
    whitelist.add(old[64]['command'])
    assert len(source)==len(data)and all(at in whitelist for at,(a,b)in enumerate(zip(source,data))if a!=b)
    for g in segments(source):
        for s in g['sections']:
            if s['fileoff']and s['size']and s['flags']&255 not in(1,12):
                assert source[s['fileoff']:s['fileoff']+s['size']]==data[s['fileoff']:s['fileoff']+s['size']]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    root=args.candidate.resolve();out=args.output.resolve();assert root.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    for row in json.loads((root/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    report=json.loads((root/'candidate.json').read_text());dso=Path(report['iosProvider']['path']).read_bytes()
    source=Path(report['originalSource']['path']).read_bytes();routed=Path(report['routedCandidate']['path']).read_bytes()
    text=provider(dso);route(routed,source)
    ir=Path(report['swiftCallerIR']['path']).read_text()
    assert 'call swiftcc i1 @"'+NATIVE[1:]+'"(ptr noalias captures(none) dereferenceable(48)'in ir
    assert report['originalFunctionSHA256']==CODE_SHA and report['pureOwnedMacChecks']==16
    negative=[]
    def reject(label,kind,at,xor):
        data=bytearray(dso if kind=='provider'else routed);data[at]^=xor
        try:
            if kind=='provider':provider(bytes(data))
            else:route(bytes(data),source)
        except(AssertionError,ValueError,UnicodeDecodeError):negative.append(label)
        else:raise AssertionError('negative accepted '+label)
    reject('changed IEEE FCMP code','provider',text['fileoff']+8,1)
    reject('changed genuine false-result code','provider',text['fileoff']+100,1)
    reject('wrong provider install name','provider',next(d['at']+24 for d in deps(dso)if d['cmd']==13),1)
    row=imports(routed)['imports'][64]
    reject('wrong operator owner ordinal','route',row['command'],1)
    reject('weak operator import','route',row['command']+1,1)
    reject('weak private CGe load','route',deps(routed)[-1]['at'],20)
    auth=next(r for r in chain_entries(routed)if r['auth'])
    reject('changed original UHK PAC key','route',auth['fileoff']+6,2)
    assert len(negative)==7
    out.mkdir();result=dict(schema='Independent genuine transform equality code and UHK route review v1',
        candidate=pin(root/'candidate.json'),copiedExactGenuineBytes=108,pureOwnedMacChecks=16,
        originalSwiftCallerVerified=True,changedStrongImportIndex=64,newStrongOrdinal=24,
        negativeControlsRejected=negative,staticReviewPassed=True,nativeHIDLoaded=False,
        completeMetadataSchema=False,completeTransitiveClosure=False,deviceOperations=0,full27Backend=False)
    (out/'review.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(review=pin(out/'review.json'),negativeControls=len(negative))))


if __name__=='__main__':main()
