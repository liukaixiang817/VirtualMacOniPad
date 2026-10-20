#!/usr/bin/env python3
"""Independently check the real nine-function array reexport data contract."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
sys.path.insert(0,str(READER))
from compiler_image import commands,segments,imports,chain_entries,export_trie
spec=importlib.util.spec_from_file_location('vz_array_review',NODE/'vz-typed-routes-independent-review-v1/review.py')
vz=importlib.util.module_from_spec(spec);spec.loader.exec_module(vz)

AR={
 '_$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5',
 '_$sSa16_createNewBuffer14bufferIsUnique15minimumCapacity13growForAppendySb_SiSbtFyXl_Ts5',
 '_$sSa37_appendElementAssumeUniqueAndCapacity_03newB0ySi_xntFyXl_Ts5',
 '_$ss12_ArrayBufferV19_getElementSlowPathyyXlSiFyXl_Ts5',
 '_$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5',
 '_$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5',
 '_$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5',
 '_$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5',
}
R={'_$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5'}
KIT=(AR|R)-{x for x in AR if x.startswith('_$sSa')}


def pin(path):
    body=path.read_bytes();return dict(path=str(path.resolve()),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())


def deps(buf):
    result=[]
    for cmd,at,size in commands(buf):
        if cmd not in(12,0x80000018,0x8000001f,0x80000023,0x80000020):continue
        off=struct.unpack_from('<I',buf,at+8)[0]
        result.append(dict(ordinal=len(result)+1,command=cmd,at=at,size=size,
                           path=buf[at+off:at+size].split(b'\0')[0].decode()))
    return result


def actual_exports(buf):
    for cmd,at,size in commands(buf):
        if cmd==0x80000033:
            off,z=struct.unpack_from('<II',buf,at+8)
            return {r['symbol']:r for r in export_trie(buf[off:off+z])}
    raise AssertionError('export trie required')


def verify_image(name,before,after):
    assert len(before)==len(after),'no moved or appended original image data'
    whitelist=set();oldcommands=list(commands(before));newcommands=list(commands(after))
    if name=='UniversalHID':
        count,size=struct.unpack_from('<II',before,16);end=32+size
        assert struct.unpack_from('<II',after,16)==(count+2,size+80)
        assert len(newcommands)==len(oldcommands)+2 and newcommands[:len(oldcommands)]==oldcommands
        assert not any(before[end:end+80]),'only unused zero header padding is used'
        for q,alias in enumerate(('AR','R')):
            at=end+40*q;expected=struct.pack('<6I',0x8000001f,40,24,0,0x10000,0x10000)
            path=('@loader_path/'+alias).encode()+b'\0'
            expected+=path+b'\0'*(16-len(path))
            assert after[at:at+40]==expected,'true LC_REEXPORT_DYLIB with exact private path'
        whitelist.update(range(16,24));whitelist.update(range(end,end+80))
        assert len(deps(before))==19 and len(deps(after))==21
        assert [(x['ordinal'],x['command'],x['path'])for x in deps(after)[-2:]]==[(20,0x8000001f,'@loader_path/AR'),(21,0x8000001f,'@loader_path/R')]
    else:
        assert oldcommands==newcommands
        through=1 if name=='UniversalHIDKit'else 7
        assert deps(after)[through-1]['path']=='@loader_path/UniversalHID27.dylib'
    if name=='Virtualization':
        first=vz.parse(before);second=vz.parse(after);a=first['imports'];b=second['imports']
        assert first['words']==second['words'] and first['nlists']==second['nlists']
        oldordinal=36
    else:
        a=imports(before)['imports'];b=imports(after)['imports'];oldordinal=8
        assert list(chain_entries(before))==list(chain_entries(after)),'entire original chained pointer/PAC words'
    selected=[];expectednames=KIT if name=='UniversalHIDKit'else AR|R
    for x,y in zip(a,b,strict=True):
        desired=x['ordinal']
        if x['name']in expectednames:
            assert x['ordinal']==oldordinal and not x['weak']
            desired=(20 if x['name']in AR else 21)if name=='UniversalHID'else (1 if name=='UniversalHIDKit'else 7)
            at=x['at']if name=='Virtualization'else x['command']
            assert struct.unpack_from('<I',after,at)[0]==(struct.unpack_from('<I',before,at)[0]&~255)|desired
            whitelist.add(at);selected.append(dict(index=x['index'],symbol=x['name'],oldOrdinal=oldordinal,newOrdinal=desired,at=at))
        assert y=={**x,'ordinal':desired},'only the nine exact import ordinals may change'
    assert set(x['symbol']for x in selected)==expectednames
    assert len(selected)==(6 if name=='UniversalHIDKit'else 9)
    for g in segments(before):
        for s in g['sections']:
            if not s['fileoff']or s['flags']&255 in(1,12):continue
            at=s['fileoff'];assert before[at:at+s['size']]==after[at:at+s['size']],(name,s['name'])
    assert all(i in whitelist for i,(x,y)in enumerate(zip(before,after))if x!=y),'unapproved byte mutation'
    return dict(name=name,routes=selected,allOriginalInstructionMetadataWitnessAuthAndNlistBytesExact=True,
                onlyNewTrueReexportCommandsAndImportOrdinalsChanged=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    folder=args.candidate.resolve();out=args.output.resolve();assert folder.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists();out.mkdir()
    plan=json.loads((folder/'candidate.json').read_text())
    assert plan['exactArrayStrongImportsRouted']==24 and plan['privateActualReexports']
    assert plan['conformanceMetadataAdapted'] and not plan['completeOriginal27MetadataPreserved']
    assert not any(plan[k]for k in('stockTransitiveClosureProven','fullMetadataSchema','allCurrentProvidersDeclared','nativeExecuted','codeSigned','deviceOperations','originalVZLoaded','originalVMMExecuted','full27Backend'))
    for row in json.loads((folder/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    native=Path(plan['nativeProviderDependencyAudit']['path']);abi=Path(plan['originalCallerABIAudit']['path'])
    assert pin(native)==plan['nativeProviderDependencyAudit']and pin(abi)==plan['originalCallerABIAudit']
    assert json.loads(native.read_text())['all26StrongProviderImportsResolved']
    assert json.loads(abi.read_text())['arrayProviderABICompatible']
    runtime={}
    for provider in plan['unchangedRuntimeProviders']:
        alias=provider['alias'];source=Path(provider['source']['path']);target=Path(provider['candidate']['path'])
        assert source.read_bytes()==target.read_bytes()and pin(source)==provider['source']and pin(target)==provider['candidate']
        assert provider['intendedLoadPath']=='@loader_path/'+alias
        exports=actual_exports(target.read_bytes());assert exports==provider['exports']
        assert set(exports)==(AR if alias=='AR'else R)
        assert all(not r['flags']&8 and r['address']>=0x4000 for r in exports.values())
        runtime[alias]=provider
    assert set(runtime)=={'AR','R'}
    cases=[];results=[]
    for image in plan['images']:
        name=image['name'];before=Path(image['source']['path']).read_bytes();after=Path(image['candidate']['path']).read_bytes()
        result=verify_image(name,before,after);results.append(result)
        assert result['routes']==[{k:r[k]for k in('index','symbol','oldOrdinal','newOrdinal','at')}for r in image['arrayImportRoutes']]
        def bad(label,pos,fmt,value):
            body=bytearray(after);struct.pack_into(fmt,body,pos,value);rejected=False
            try:verify_image(name,before,bytes(body))
            except(AssertionError,ValueError,struct.error):rejected=True
            assert rejected,label;cases.append(dict(image=name,name=label,rejected=True))
        at=result['routes'][0]['at'];word=struct.unpack_from('<I',after,at)[0]
        bad('wrong owner ordinal',at,'<I',(word&~255)|2)
        bad('weak array import',at,'<I',word|256)
        bad('change chained import symbol offset',at,'<I',word^(1<<9))
        text=next(s for g in segments(after)for s in g['sections']if s['name']=='__text')
        bad('modify genuine instruction',text['fileoff'],'<I',struct.unpack_from('<I',after,text['fileoff'])[0]^1)
        metadata=next(s for g in segments(after)for s in g['sections']if s['name'].startswith('__swift5_')and s['size']>=4)
        bad('modify original Swift metadata',metadata['fileoff'],'<I',struct.unpack_from('<I',after,metadata['fileoff'])[0]^1)
        if name=='UniversalHID':
            dep=deps(after)[-2]
            bad('load command instead of real reexport',dep['at'],'<I',12)
            bad('wrong private reexport path',dep['at']+24,'<I',0)
            bad('missing declared new load command',16,'<I',struct.unpack_from('<I',after,16)[0]-1)
        else:
            dep=deps(after)[(1 if name=='UniversalHIDKit'else 7)-1]
            bad('wrong reexporting UH owner path',dep['at']+24,'<I',0)
        if name!='Virtualization':
            entry=next(r for r in chain_entries(after)if r['auth']and r['bind'])
            for label,bit in [('change PAC key',49),('change PAC discriminator',32),('change PAC address diversity',48)]:
                bad(label,entry['fileoff'],'<Q',entry['word']^(1<<bit))
        check=subprocess.run(['xcrun','dyld_info','-validate_only',image['candidate']['path']],capture_output=True,text=True);assert check.returncode==0,check.stderr
    report=dict(schema='Independent real array specialization UH reexport inert data review v1',candidate=pin(folder/'candidate.json'),verifier=pin(Path(__file__)),
                verifiedImages=results,unchangedRuntimeProviders=[runtime[a]['candidate']for a in('AR','R')],negativeControls=cases,
                exactStrongArrayImportsRouted=24,originalMetadataWitnessInstructionsPACUnchangedFromSources=True,
                conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,
                fullCurrentLoadGraphProven=False,stockTransitiveClosureProven=False,fullMetadataSchema=False,nativeExecuted=False,deviceOperations=0,full27Backend=False)
    (out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    files=[Path(__file__),folder/'candidate.json',out/'review.json',native,abi,Path(spec.origin)]
    files+=[Path(row[k]['path'])for row in plan['images']for k in('source','candidate')]
    files+=[Path(row[k]['path'])for row in plan['unchangedRuntimeProviders']for k in('source','candidate')]
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(f)for f in files],nativeExecuted=False,deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),negativeControls=len(cases),routedStrongImports=24)))


if __name__=='__main__':main()
