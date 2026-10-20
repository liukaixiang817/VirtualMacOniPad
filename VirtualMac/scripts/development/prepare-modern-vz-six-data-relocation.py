#!/usr/bin/env python3
"""New local VZ data candidate: 418 native RTTI vptrs + five exact NUL rebases.

Reuses DI2's correct native vtable+16 / import-format2 approach; no synthetic
RTTI class, destructor provider, loading or device changes. The six original
consumer gates remain unvalidated, including the strcmp resolver. Full27 false.
"""
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
INPUT=N/'vz-genuine-strong-closure-design-v2/build-v1/bundle/VZ27.exact-owner-partial.ios.dylib'


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--contract',required=True,type=pathlib.Path);ap.add_argument('--expected-contract-sha256',required=True)
    ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    assert pin(args.contract)['sha256']==args.expected_contract_sha256
    oracle=json.loads(args.contract.read_text());assert oracle['all171HaveGenuineOriginalConsumer'] is True
    assert oracle['trueOriginalRTTIVptrConsumers']==418 and oracle['trueOriginalEmptyStringConsumers']==5
    old=INPUT.read_bytes();assert pin(INPUT)['sha256']=='fbb3031b8ea906953705eedad1d294e51e611c3cddad4b6fdc50b6bcf00eb8c5'
    b=bytearray(old);before_imports=imports(old);before=list(chain_entries(old));byfile={e['fileoff']:e for e in before}
    assert before_imports['header'][5]==1 and len(before)==26993
    # Append only a new exact system data owner; all prior 53 dependency bytes
    # and ordinals remain stable, including explicitly pending SkyLight.
    linked=[cstring(old,a+struct.unpack_from('<I',old,a+8)[0],a+size) for c,a,size in commands(old) if c in (12,0x80000018,0x8000001f,0x80000023)]
    assert len(linked)==53 and '/usr/lib/libc++abi.dylib' not in linked
    count,size=struct.unpack_from('<II',b,16);path=b'/usr/lib/libc++abi.dylib\0';length=(24+len(path)+7)&~7
    first=min(s['fileoff'] for g in segments(old) for s in g['sections'] if s['fileoff'] and s['size'] and s['flags']&255 not in (1,12,18))
    # The prior new SkyLight command consumed header slack. Compact only the
    # already-private DIKit command's unused trailing NUL padding; preserve its
    # path, ordinal, timestamp/versions, and every other complete command byte.
    packed=bytearray();dependency_index=0;compacted=None;removed_signatures=0
    for c,a,z in commands(old):
        if c==0x1d:
            assert z==16
            removed_signatures+=1
            continue
        record=bytearray(old[a:a+z])
        if c in (12,0x80000018,0x8000001f,0x80000023):dependency_index+=1
        if c==12 and dependency_index==25:
            no=struct.unpack_from('<I',record,8)[0];name=cstring(record,no,z)
            assert no==24 and name=='@loader_path/DiskImageKit27.dylib'
            minimum=(no+len(name.encode())+1+7)&~7
            assert minimum<z and not any(record[minimum:])
            struct.pack_into('<I',record,4,minimum);record=record[:minimum]
            compacted=dict(ordinal=25,path=name,beforeBytes=z,afterBytes=minimum,onlyUnusedTrailingPaddingRemoved=True)
        packed+=record
    assert compacted is not None
    assert removed_signatures==1
    count-=removed_signatures
    b[32:32+size]=packed+bytes(size-len(packed));size=len(packed);struct.pack_into('<I',b,20,size);at=32+size
    assert at+length<=first and not any(b[at:at+length])
    lc=struct.pack('<6I',12,length,24,2,0x10000,0x10000)+path;b[at:at+length]=lc+bytes(length-len(lc));struct.pack_into('<II',b,16,count+1,size+length)
    owner_ordinal=54;routes={r['index']:r for r in oracle['rttiDataContracts']};assert set(routes)=={14,15,20,22}
    for index,route in routes.items():
        assert route['addend']==16 and route['originalOwner']=='/usr/lib/libc++abi.dylib'
        assert route['authKey']==2 and route['discriminator']==0 and route['addressDiversity']==0
        for site in route['sites']:
            entry=byfile[site['fileoff']]
            assert entry['import_index']==index and entry['word']==site['newBindWord'] and entry['auth']
            assert entry['word']>>49&3==2 and entry['word']>>32&65535==0 and entry['word']>>48&1==0
    # A byte-identical, existing readonly __cstring terminator supplies exact
    # empty encoding contents. No storage is allocated, made writable or cloned.
    cstr=next(s for g in segments(old) if g['name']=='__TEXT' for s in g['sections'] if s['name']=='__cstring' and s['size'])
    nul=old.find(b'\0',cstr['fileoff'],cstr['fileoff']+cstr['size']);assert nul>=0 and old[nul]==0
    local_va=cstr['address']+nul-cstr['fileoff'];base=next(g['address'] for g in segments(old) if g['name']=='__TEXT');rva=local_va-base;assert 0<=rva<(1<<43)
    changes=[]
    for site in oracle['emptyStringContracts']:
        entry=byfile[site['fileoff']]
        assert entry['bind'] and not entry['auth'] and entry['import_index']==40 and entry['word']==site['word']
        word=(entry['word']&(0x7ff<<51))|rva
        struct.pack_into('<Q',b,entry['fileoff'],word)
        changes.append(dict(fileoff=entry['fileoff'],newVA=entry['address'],before=entry['word'],after=word,localEmptyStringVA=local_va,ivarName=site['ivarName'],consumerKind=site['consumerKind']))
    assert len(changes)==5
    oldstart=before_imports['data'];header=before_imports['header'];prefix=bytearray(old[oldstart:oldstart+header[2]])
    pool,entries,expected=bytearray(),bytearray(),[]
    for row in before_imports['imports']:
        name,ordinal,weak,addend=row['name'],row['ordinal'],row['weak'],0
        if row['index'] in routes:
            assert ordinal==-2 and weak;name=routes[row['index']]['exactDataExport'];ordinal=54;weak=False;addend=16
        off=len(pool);pool+=name.encode()+b'\0';assert off<(1<<23)
        entries+=struct.pack('<Ii',(ordinal&255)|(int(weak)<<8)|(off<<9),addend)
        expected.append(dict(name=name,ordinal=ordinal,weak=weak,addend=addend))
    blob=prefix+entries+pool;struct.pack_into('<7I',blob,0,0,header[1],len(prefix),len(prefix)+len(entries),1056,2,0)
    newstart=(len(b)+7)&~7;b+=bytes(newstart-len(b))+blob
    fixup=next(a for c,a,s in commands(b) if c==0x80000034);struct.pack_into('<II',b,fixup+8,newstart,len(blob))
    le=next(g for g in segments(b) if g['name']=='__LINKEDIT');filesize=len(b)-le['fileoff'];struct.pack_into('<Q',b,le['command']+32,(filesize+16383)&~16383);struct.pack_into('<Q',b,le['command']+48,filesize)
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    binary=out/'VZ27.rtti-data-empty-string.local.ios.dylib';binary.write_bytes(b);processes=[]
    for label,argv in [('sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)]),('strict',['codesign','--verify','--strict',str(binary)]),('dyld',['xcrun','dyld_info','-validate_only',str(binary)]),('identity',['codesign','-d','--verbose=4',str(binary)])]:
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE);so,se=p.communicate(timeout=30)
        (out/(label+'.stdout')).write_bytes(so);(out/(label+'.stderr')).write_bytes(se);processes.append(dict(name=label,pid=p.pid,wait=p.returncode,command=argv));save(out/'processes.json',processes);assert p.returncode==0,se.decode()
    final=binary.read_bytes();actual=imports(final)['imports'];assert [{k:r[k] for k in ('name','ordinal','weak','addend')} for r in actual]==expected
    after=list(chain_entries(final));assert len(after)==26993
    allowed={c['fileoff'] for c in changes};assert all(a['word']==z['word'] or a['fileoff'] in allowed for a,z in zip(before,after))
    assert sum(a['word']!=z['word'] for a,z in zip(before,after))==5
    assert sum(z['bind'] and z['import_index']==40 for z in after)==0
    assert sum(z['bind'] for z in after)==4781 and sum(not z['bind'] for z in after)==22212
    assert all(a['word']==z['word'] for a,z in zip(before,after) if a['auth'])
    for seg in segments(old):
        for section in seg['sections']:
            off,size=section['fileoff'],section['size']
            if size and off and section['flags']&255 not in (1,12,18):
                diffs=[i for i,(a,z) in enumerate(zip(old[off:off+size],final[off:off+size])) if a!=z]
                assert all(any(c['fileoff']<=off+i<c['fileoff']+8 for c in changes) for i in diffs)
    native_routes=[dict(index=i,name=r['exactDataExport'],ordinal=54,addend=16,sites=len(r['sites']),originalAuthWordsUnchanged=True) for i,r in routes.items()]
    candidate=dict(binary=pin(binary),source=pin(INPUT),contract=pin(args.contract),importsFormat=2,chainedImports=1056,newExactNativeVTableOwnerOrdinal=54,newExactNativeVTableOwner='/usr/lib/libc++abi.dylib',compactedExistingPrivateCommand=compacted,oldSignatureCommandReplacedByFreshTrailingSignature=True,allPriorDependencyNamesKindsOrdinalsVersionsPreserved=True,rttiRoutes=native_routes,rttiVptrs418PACUnchanged=True,emptyStringChanges=changes,emptyStringStorageUnmodified=True,originalChainCount=26993,finalBindCount=4781,finalRebaseCount=22212,allAuthenticatedChainWordsUnchanged=True,originalInstructionAndRelativeMetadataBytesUnchanged=True,originalOtherImportNameOrdinalWeakAndZeroAddendPreserved=True,strongImports=1010,legitimateOriginalWeakImports=44,diagnosticFlatTableEntriesRemaining=[40,490],unusedQuestionMarkImportEntryRetainedFailClosed=True,originalConsumerValidationPending=[14,15,20,22,40,490],originalConsumerExecuted=False,full27=False,loaded=False,actualVZCalls=0,originalVMMExecuted=False,guestInstructions=0,deviceOperations=0,systemModified=False)
    save(out/'candidate.json',candidate);save(out/'inputs.json',[pin(p) for p in (INPUT,args.contract,pathlib.Path(__file__).resolve(),pathlib.Path(__file__).with_name('vz_import_addend_image.py'),R/'VirtualMac/scripts/development/prepare-modern-diskimages2-rtti-data.py')])
    print(json.dumps(dict(binary=str(binary),RTTIVptrs=418,emptyStringRebases=5,originalConsumerGatesPending=6,full27=False)))


if __name__=='__main__':main()
