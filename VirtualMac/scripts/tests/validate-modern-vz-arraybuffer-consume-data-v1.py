#!/usr/bin/env python3
"""Independently review exact consuming ABI, current imports and inert routing."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands,segments,imports,chain_entries,export_trie
spec=importlib.util.spec_from_file_location('vz_consume_independent_reader',NODE/'vz-typed-routes-independent-review-v1/review.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
speca=importlib.util.spec_from_file_location('actual_consume_import_reader',ROOT/'VirtualMac/scripts/development/audit-modern-array-native-dependencies-v1.py')
a=importlib.util.module_from_spec(speca);speca.loader.exec_module(a)
SYMBOL='_$ss12_ArrayBufferV20_consumeAndCreateNew14bufferIsUnique15minimumCapacity13growForAppendAByxGSb_SiSbtFyXl_Ts5'


def pin(path):
    body=path.read_bytes();return dict(path=str(path.resolve()),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())


def verify(before,after):
    assert len(before)==len(after)
    old=v.parse(before);new=v.parse(after);oldcount,oldsize=struct.unpack_from('<II',before,16);end=32+oldsize
    assert struct.unpack_from('<II',after,16)==(oldcount+1,oldsize+40)
    assert not any(before[end:end+40])
    expected=struct.pack('<6I',12,40,24,0,0x10000,0x10000)+b'@loader_path/AB\0'
    assert len(expected)==40 and after[end:end+40]==expected
    assert len(old['deps'])==61 and len(new['deps'])==62 and new['deps'][:61]==old['deps']
    assert new['deps'][-1]['name']=='@loader_path/AB'and new['deps'][-1]['cmd']==12
    assert old['words']==new['words']and old['nlists']==new['nlists']
    matches=[r for r in old['imports']if r['name']==SYMBOL];assert len(matches)==1
    row=matches[0];assert row['ordinal']==36 and not row['weak']
    for first,second in zip(old['imports'],new['imports'],strict=True):
        assert second==({**first,'ordinal':62}if first['name']==SYMBOL else first)
    assert len(new['imports'])==1056 and sum(not r['weak']for r in new['imports'])==1011
    whitelist=set(range(16,24))|set(range(end,end+40))|{row['at']}
    assert all(i in whitelist for i,(x,y)in enumerate(zip(before,after))if x!=y)
    for g in segments(before):
        for s in g['sections']:
            if not s['fileoff']or s['flags']&255 in(1,12):continue
            q=s['fileoff'];assert before[q:q+s['size']]==after[q:q+s['size']],s['name']
    return dict(index=row['index'],at=row['at'],newDependencyFileoff=end,
                originalAllInstructionsMetadataWitnessPACAndNlistsExact=True,onlyNewLoadCommandAndOneStrongOrdinalChanged=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    folder=args.candidate.resolve();out=args.output.resolve();assert folder.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists();out.mkdir()
    plan=json.loads((folder/'candidate.json').read_text())
    for row in json.loads((folder/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    assert plan['conformanceMetadataAdapted']and not plan['completeOriginal27MetadataPreserved']
    assert not any(plan[k]for k in('stockTransitiveClosureProven','fullCurrentLoadGraphProven','fullMetadataSchema','codeSigned','nativeIOSExecuted','deviceOperations','originalVZLoaded','originalVMMExecuted','full27Backend'))
    before=Path(plan['frontendSource']['path']).read_bytes();after=Path(plan['frontendCandidate']['path']).read_bytes();result=verify(before,after)
    buildpath=Path(plan['sourceBuild']['path']);build=json.loads(buildpath.read_text());abiPath=Path(plan['originalCallerABIAudit']['path']);abi=json.loads(abiPath.read_text())
    for directory in(buildpath.parent,abiPath.parent):
        for row in json.loads((directory/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    assert abi['originalCallerABICompatible']and abi['ownedBufferArgumentAndResult']and abi['noReceiverSwiftself']
    assert len(abi['originalCallerWindows'])==1 and abi['originalCallerWindows'][0]['address']==0x2260f723c
    w=bytes.fromhex(abi['originalCallerWindows'][0]['originalWindow']);assert struct.unpack_from('<3I',w,180)==(0x9a96c101,0x52800022,0xaa1503e3)
    assert struct.unpack_from('<I',w,196)[0]==0xaa0003f5
    island=abi['originalAuthenticatedIsland'];assert island['auth']==1 and island['key']==0 and island['addressDiversity']==1
    adrp,add,load,branch=struct.unpack('<4I',bytes.fromhex(island['originalInstructions']))
    assert adrp&0x9f00001f==0x90000011 and add&0xffc003ff==0x91000231 and load==0xf9400230 and branch==0xd71f0a11
    immediate=((adrp>>5&0x7ffff)<<2)|(adrp>>29&3)
    if immediate&0x100000:immediate-=0x200000
    assert island['slot']==(island['address']&~4095)+(immediate<<12)+(add>>10&4095)
    assert island['target']==abi['exactOriginalFunction']['address']==0x194f39be4
    assert island['exactChainMembershipVerified']and island['exactOriginalExportMatched']
    original=Path(abi['exactOriginalFunction']['code']['path']).read_bytes();assert len(original)==416
    assert struct.unpack_from('<I',original,0x1c)[0]==0xaa0303f3,'original x19 <- x3 receiver'
    assert struct.unpack_from('<I',original,0xe8)[0]==0xf9000a9f,'original moved-from count zero'
    # The private definition and its complete consuming helper retain precisely
    # the compiler's serialized body; no handwritten ARC or successful stub.
    roles={r['role']:r for r in build['roles']}
    for role in('mac','ios'):
        originalIR=(buildpath.parent/(role+'.original.ll')).read_text();editedIR=(buildpath.parent/(role+'.ll')).read_text()
        needle='define hidden swiftcc ptr @"'+SYMBOL[1:]+'"'
        assert originalIR.count(needle)==1 and editedIR==originalIR.replace(needle,needle.replace('hidden ',''),1)
        assert roles[role]['IRSignature']=='define swiftcc ptr @"'+SYMBOL[1:]+'"(i1 %0, i64 %1, i1 %2, ptr %3) local_unnamed_addr #0 {'
        assert 'tail call void @swift_bridgeObjectRelease(ptr %3)'in editedIR
        assert 'store i64 0'in editedIR and '@llvm.memmove.p0.p0.i64'in editedIR and '@swift_arrayInitWithCopy'in editedIR
        assert not re.search(r'^.*\b(?:call|invoke)\b.*@"'+re.escape(SYMBOL[1:])+r'"',editedIR,re.M)
    summary=json.loads((buildpath.parent/'mac-positive.stdout').read_text());assert summary==roles['mac']['actualMac']
    assert summary['checks']==59715 and summary['privateCalls']==summary['stockCalls']==1920 and summary['actualUniqueCalls']==768
    assert summary['madeObjects']==summary['destroyedObjects']==34176
    assert roles['mac']['rejectedImpossibleAllocation']['exit']==-6
    runtime=plan['unchangedRuntimeProvider'];providerpath=Path(runtime['candidate']['path']);provider=providerpath.read_bytes()
    assert provider==Path(runtime['source']['path']).read_bytes()and pin(providerpath)==runtime['candidate']
    assert not any(cmd==0x1d for cmd,at,size in commands(provider))
    for cmd,q,z in commands(provider):
        if cmd==0x80000033:offset,size=struct.unpack_from('<II',provider,q+8)
    exported={r['symbol']:r for r in export_trie(provider[offset:offset+size])};assert exported==runtime['exports']and set(exported)=={SYMBOL}
    deps={r['ordinal']:r['path']for r in a.p.dependencies(provider)};images=a.actual.captured_images();images.update(a.current_system_images());native=[]
    for row in imports(provider)['imports']:
        assert row['ordinal']>0 and not row['weak'];proof=a.actual.resolve(images,deps[row['ordinal']],row['name']);assert proof['status']=='actualDirectExport'
        native.append(dict(symbol=row['name'],proof=proof))
    assert len(native)==11
    cases=[]
    def bad(label,pos,fmt,value):
        changed=bytearray(after);struct.pack_into(fmt,changed,pos,value);rejected=False
        try:verify(before,bytes(changed))
        except(AssertionError,ValueError,struct.error):rejected=True
        assert rejected,label;cases.append(dict(name=label,rejected=True))
    at=result['at'];word=struct.unpack_from('<I',after,at)[0];end=result['newDependencyFileoff']
    bad('old unavailable SwiftCore ordinal',at,'<I',(word&~255)|36)
    bad('wrong private owner ordinal',at,'<I',(word&~255)|61)
    bad('weak array import',at,'<I',word|256)
    bad('wrong name offset',at,'<I',word^(1<<9))
    bad('weak dependency command',end,'<I',0x80000018)
    bad('wrong real provider path',end+24,'<I',0)
    bad('wrong dependency name offset',end+8,'<I',28)
    bad('missing added load command count',16,'<I',struct.unpack_from('<I',after,16)[0]-1)
    bad('wrong added load command extent',20,'<I',struct.unpack_from('<I',after,20)[0]-8)
    entry=next(r for r in v.parse(after)['words']if r['auth']and r['bind'])
    for label,bit in[('PAC key',49),('PAC discriminator',32),('PAC address diversity',48)]:bad(label,entry['at'],'<Q',entry['word']^(1<<bit))
    text=next(s for g in segments(after)for s in g['sections']if s['name']=='__text')
    bad('genuine instruction changed',text['fileoff'],'<I',struct.unpack_from('<I',after,text['fileoff'])[0]^1)
    metadata=next(s for g in segments(after)for s in g['sections']if s['name'].startswith('__swift5_')and s['size']>=4)
    bad('genuine Swift metadata changed',metadata['fileoff'],'<I',struct.unpack_from('<I',after,metadata['fileoff'])[0]^1)
    for file in(Path(plan['frontendCandidate']['path']),providerpath):
        check=subprocess.run(['xcrun','dyld_info','-validate_only',str(file)],capture_output=True);assert check.returncode==0,check.stderr
    report=dict(schema='Independent real consuming ArrayBuffer VZ inert route review v1',candidate=pin(folder/'candidate.json'),verifier=pin(Path(__file__)),
                originalCallerAndExactOriginalFunctionContractChecked=True,unmodifiedSerializedCompilerBodies=True,verification=result,
                currentNativeImports=native,ordinaryMacSummary=summary,negativeControls=cases,
                conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,fullCurrentLoadGraphProven=False,
                stockTransitiveClosureProven=False,fullMetadataSchema=False,nativeIOSExecuted=False,deviceOperations=0,full27Backend=False)
    (out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    files=[Path(__file__),Path(spec.origin),Path(speca.origin),folder/'candidate.json',out/'review.json',buildpath,abiPath,
           Path(plan['frontendSource']['path']),Path(plan['frontendCandidate']['path']),providerpath,Path(runtime['source']['path'])]
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(f)for f in files],deviceOperations=0,nativeIOSExecuted=False),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),negativeControls=len(cases),currentNativeImports=11)))


if __name__=='__main__':main()
