#!/usr/bin/env python3
"""New app-private strcmp import route; retain all six original consumer gates."""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
from vz_import_addend_image import commands,segments,imports,chain_entries,cstring
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')


def dependencies(b):
    result=[]
    for c,a,z in commands(b):
        if c in (12,0x80000018,0x8000001f,0x80000023):
            result.append(dict(ordinal=len(result)+1,kind=c,path=cstring(b,a+struct.unpack_from('<I',b,a+8)[0],a+z),metadata=list(struct.unpack_from('<3I',b,a+12))))
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data-candidate',required=True,type=pathlib.Path);ap.add_argument('--expected-data-sha256',required=True)
    ap.add_argument('--provider-candidate',required=True,type=pathlib.Path);ap.add_argument('--expected-provider-sha256',required=True)
    ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    assert pin(args.data_candidate)['sha256']==args.expected_data_sha256
    assert pin(args.provider_candidate)['sha256']==args.expected_provider_sha256
    dc=json.loads(args.data_candidate.read_text());pc=json.loads(args.provider_candidate.read_text())
    assert dc['originalConsumerValidationPending']==[14,15,20,22,40,490] and dc['loaded'] is False and dc['full27'] is False
    assert pc['nativeSummary']['ownedPairs']==924 and pc['nativeSummary']['passed'] is True and pc['full27'] is False
    original=pathlib.Path(dc['binary']['path']);assert pin(original)==dc['binary'];old=original.read_bytes();b=bytearray(old)
    before=list(chain_entries(old));assert len(before)==26993
    oldimports=imports(old);assert oldimports['header'][5]==2;rows=oldimports['imports'];assert len(rows)==1056
    assert rows[490]['name']=='__platform_strcmp' and rows[490]['ordinal']==-2 and rows[490]['weak'] and rows[490]['addend']==0
    deps=dependencies(old);assert len(deps)==54
    private_path='@loader_path/VM27ScopedStringCompare.dylib';name=private_path.encode()+b'\0';needed=(24+len(name)+7)&~7
    first=min(q['fileoff'] for g in segments(old) for q in g['sections'] if q['fileoff'] and q['size'] and q['flags']&255 not in (1,12,18))
    count,size=struct.unpack_from('<II',old,16);packed=bytearray();compacted=[];removed=0;ordinal=0
    for c,a,z in commands(old):
        if c==0x1d:assert z==16;removed+=1;continue
        record=bytearray(old[a:a+z])
        if c in (12,0x80000018,0x8000001f,0x80000023):
            ordinal+=1;offset=struct.unpack_from('<I',record,8)[0];path=cstring(record,offset,z)
            minimum=(offset+len(path.encode())+1+7)&~7
            # Only eliminate unused NUL padding of existing private dependency LCs.
            if path.startswith('@loader_path/') and minimum<z:
                assert not any(record[minimum:]);struct.pack_into('<I',record,4,minimum);record=record[:minimum]
                compacted.append(dict(ordinal=ordinal,path=path,beforeBytes=z,afterBytes=minimum))
        packed+=record
    assert removed==1 and 32+len(packed)+needed<=first
    b[32:first]=packed+bytes(first-32-len(packed));at=32+len(packed)
    command=struct.pack('<6I',12,needed,24,2,0x10000,0x10000)+name
    b[at:at+needed]=command+bytes(needed-len(command));struct.pack_into('<II',b,16,count-removed+1,len(packed)+needed)
    pool,table,expected=bytearray(),bytearray(),[]
    for row in rows:
        ordinal,weak=row['ordinal'],row['weak']
        if row['index']==490:ordinal=55;weak=False
        name=row['name'];offset=len(pool);pool+=name.encode()+b'\0';assert offset<(1<<23)
        table+=struct.pack('<Ii',(ordinal&255)|(int(weak)<<8)|(offset<<9),row['addend'])
        expected.append(dict(name=name,ordinal=ordinal,weak=weak,addend=row['addend']))
    header=oldimports['header'];blob=bytearray(old[oldimports['data']:oldimports['data']+header[2]])+table+pool
    struct.pack_into('<7I',blob,0,0,header[1],header[2],header[2]+len(table),1056,2,0)
    start=(len(b)+7)&~7;b+=bytes(start-len(b))+blob
    fixup=next(a for c,a,z in commands(b) if c==0x80000034);struct.pack_into('<II',b,fixup+8,start,len(blob))
    le=next(g for g in segments(b) if g['name']=='__LINKEDIT');length=len(b)-le['fileoff'];struct.pack_into('<Q',b,le['command']+32,(length+16383)&~16383);struct.pack_into('<Q',b,le['command']+48,length)
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True);bundle=out/'bundle';bundle.mkdir()
    binary=bundle/'VZ27.scoped-libc-data.local.ios.dylib';binary.write_bytes(b)
    ios=next(v for v in pc['products'] if v['role']=='ios');provider=pathlib.Path(ios['provider']['path']);assert pin(provider)==ios['provider']
    copied=bundle/'VM27ScopedStringCompare.dylib';copied.write_bytes(provider.read_bytes());assert pin(copied)['sha256']==ios['provider']['sha256']
    processes=[]
    for label,argv in [('sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)]),('strict',['codesign','--verify','--strict',str(binary)]),('dyld',['xcrun','dyld_info','-validate_only',str(binary)]),('provider-strict',['codesign','--verify','--strict',str(copied)])]:
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE);so,se=p.communicate(timeout=30)
        (out/(label+'.stdout')).write_bytes(so);(out/(label+'.stderr')).write_bytes(se);processes.append(dict(name=label,pid=p.pid,wait=p.returncode,command=argv));save(out/'processes.json',processes);assert p.returncode==0,se.decode()
    final=binary.read_bytes();actual=imports(final)['imports'];assert [{k:r[k] for k in ('name','ordinal','weak','addend')} for r in actual]==expected
    after=list(chain_entries(final));assert [(e['address'],e['fileoff'],e['word']) for e in before]==[(e['address'],e['fileoff'],e['word']) for e in after]
    for g in segments(old):
        for q in g['sections']:
            off,length=q['fileoff'],q['size']
            if off and length and q['flags']&255 not in (1,12,18):assert old[off:off+length]==final[off:off+length]
    assert dependencies(final)[:54]==deps and dependencies(final)[54]['path']==private_path
    assert sum(not r['weak'] and r['ordinal']>0 for r in actual)==1011
    activeflat=[e for e in after if e['bind'] and actual[e['import_index']]['ordinal']<0];assert not activeflat
    assert actual[40]['ordinal']==-2 and actual[40]['weak']
    save(out/'candidate.json',dict(binary=pin(binary),provider=pin(copied),dataCandidate=pin(args.data_candidate),providerCandidate=pin(args.provider_candidate),strcmpIndex=490,strcmpStrongOwnerOrdinal=55,strcmpStrongOwnerPath=private_path,typedABI='int(const char*,const char*)',allOriginalChainWordsUnchanged=True,chainCount=26993,bindCount=4781,rebaseCount=22212,allPrevious54DependencyIdentitiesPreserved=True,privateLoadCommandPaddingCompacted=compacted,originalInstructionAndRelativeMetadataBytesUnchanged=True,strongImports=1011,legitimateOriginalWeakImports=44,unusedDiagnosticFlatTableEntries=[40],activeDiagnosticFlatBindings=0,originalConsumerValidationPending=[14,15,20,22,40,490],originalConsumerExecuted=False,platformSpecificDispatchPreserved=False,systemFrameworksReplaced=False,SkyLightProviderOnIPadProven=False,loaded=False,actualVZCalls=0,originalVMMExecuted=False,guestInstructions=0,full27=False,deviceOperations=0,systemModified=False))
    save(out/'inputs.json',[pin(p) for p in (args.data_candidate,args.provider_candidate,original,provider,pathlib.Path(__file__).resolve(),pathlib.Path(__file__).with_name('vz_import_addend_image.py'))])
    print(json.dumps(dict(strongImports=1011,activeDiagnosticFlatBindings=0,originalConsumerGatesPending=6,full27=False)))


if __name__=='__main__':main()
