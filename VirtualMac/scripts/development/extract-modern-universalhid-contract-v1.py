#!/usr/bin/env python3
"""Read genuine27 HID exports and extracted symbol/metadata contracts; no calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_trie import ReadExports
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CACHE=Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')
EXPECTED={'UniversalHID':'72824fab0bb73b56a40d00088410f053',
          'UniversalHIDKit':'e6801a30bcfe35eb9c88206d35fa1397'}


def pin(path):
    data=path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def commands(data):
    assert struct.unpack_from('<I',data)[0]==0xfeedfacf
    count,size=struct.unpack_from('<II',data,16)
    assert count<256 and 32+size<=len(data)
    at=32
    for _ in range(count):
        command,length=struct.unpack_from('<II',data,at)
        assert length>=8 and length%8==0 and at+length<=32+size
        yield command,at,length
        at+=length
    assert at==32+size


def parse(data):
    dependencies,sections,uuid,symbols,trie,linkedit=[],[],None,None,None,None
    for cmd,at,length in commands(data):
        if cmd in (12,13,0x80000018,0x8000001f,0x80000023):
            no,t,c,v=struct.unpack_from('<4I',data,at+8)
            assert 24<=no<length and b'\0' in data[at+no:at+length]
            path=data[at+no:at+length].split(b'\0')[0].decode()
            if cmd!=13:dependencies.append(dict(ordinal=len(dependencies)+1,command=cmd,path=path,versions=[t,c,v]))
        elif cmd==0x1b:
            assert uuid is None
            uuid=data[at+8:at+24].hex()
        elif cmd==2:symbols=struct.unpack_from('<4I',data,at+8)
        elif cmd==0x80000033:trie=struct.unpack_from('<II',data,at+8)
        elif cmd==0x19:
            segment=data[at+8:at+24].split(b'\0')[0].decode()
            if segment=='__LINKEDIT':linkedit=struct.unpack_from('<Q',data,at+24)[0]
            count=struct.unpack_from('<I',data,at+64)[0]
            assert length==72+count*80
            for index in range(count):
                offset=at+72+index*80
                name=data[offset:offset+16].split(b'\0')[0].decode()
                address,size,fo=struct.unpack_from('<QQI',data,offset+32)
                flags=struct.unpack_from('<I',data,offset+64)[0]
                sections.append(dict(segment=segment,name=name,address=address,bytes=size,fileoff=fo,flags=flags))
    return dict(UUID=uuid,dependencies=dependencies,sections=sections,symbolTable=symbols,
        exportTrie=trie,linkeditAddress=linkedit)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract',type=Path,required=True)
    args=parser.parse_args()
    output=args.contract.resolve()
    assert output.is_relative_to(NODE) and (output/'raw').is_dir()
    assert not (output/'original-contract.json').exists()
    ledger=json.loads((NODE/'vz-skylight-remaining-closure-inventory-v1/current61-1056-ledger.json').read_text())
    result=[]
    with CACHE.open('rb') as stream:
        cache=DyldContext(stream);cache.addSubCaches(CACHE)
        assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc'
        for name,uuid in EXPECTED.items():
            path=f'/System/Library/PrivateFrameworks/{name}.framework/Versions/A/{name}'
            image=next(i for i in cache.images if cache.readString(i.pathFileOffset).rstrip(b'\0').decode()==path)
            off,ctx=cache.convertAddr(image.address)
            size=struct.unpack_from('<I',ctx.getBytes(off,32),20)[0]
            h=ctx.getBytes(off,32+size);original=parse(h)
            assert original['UUID']==uuid
            raw_path=output/'raw'/name;raw=raw_path.read_bytes();extracted=parse(raw)
            assert extracted['UUID']==uuid and original['dependencies']==extracted['dependencies']
            header_path=output/(name+'.original-cache-header.bin');header_path.write_bytes(h)
            link=cache.convertAddr(original['linkeditAddress'])[1]
            exports=[]
            for e in ReadExports(link.file,*original['exportTrie']):
                symbol=e.name.rstrip(b'\0').decode()
                assert not e.flags&8
                address=e.address if e.flags&3==2 else image.address+e.address
                exports.append(dict(name=symbol,flags=e.flags,address=address))
            assert len({e['name'] for e in exports})==len(exports)
            byname={e['name']:e for e in exports}
            wanted=next(d['imports']for d in ledger if d['ordinal']==(7 if name=='UniversalHID' else 3))
            assert len(wanted)==(64 if name=='UniversalHID' else 40)
            assert all(r['name']in byname and not r['weak'] and r['addend']==0 for r in wanted)
            so,count,stro,strsize=extracted['symbolTable'];assert so+count*16<=len(raw) and stro+strsize<=len(raw)
            imports=[]
            for index in range(count):
                no,typ,section,desc,value=struct.unpack_from('<IBBHQ',raw,so+index*16)
                assert no<strsize
                symbol=raw[stro+no:stro+strsize].split(b'\0')[0].decode()
                if typ==1:
                    ordinal=desc>>8
                    assert 1<=ordinal<=len(original['dependencies'])
                    imports.append(dict(name=symbol,ordinal=ordinal,weak=bool(desc&0x40),
                        descriptor=desc,type=typ,section=section,value=value,
                        originalProvider=original['dependencies'][ordinal-1]['path']))
            swift=[dict(**s,sha256=hashlib.sha256(raw[s['fileoff']:s['fileoff']+s['bytes']]).hexdigest())
                for s in extracted['sections'] if s['name'].startswith('__swift') and s['bytes']]
            initializers=[s for s in original['sections'] if s['bytes'] and
                (s['flags']&255 in (9,10,21,22) or s['name']in ('__objc_nlclslist','__objc_nlcatlist'))]
            result.append(dict(name=name,originalPath=path,base=image.address,UUID=uuid,
                originalHeader=pin(header_path),extractedRaw=pin(raw_path),exports=exports,
                originalDependencies=original['dependencies'],originalNlistImports=imports,
                originalSwiftSections=swift,originalInitializerSections=initializers,
                exactVZStrongRequirements=[dict(**r,genuineExport=byname[r['name']])for r in wanted],
                requiredVZExportsAllPresent=True,originalCacheNotLoaded=True))
    inputs=[pin(Path(__file__)),pin(ROOT/'VirtualMac/vz/uncache.py'),
        pin(ROOT/'VirtualMac/vz/development/tools/cache-a2s-batch.py')]
    report=dict(schema='Genuine UniversalHID and UniversalHIDKit original export contract v1',
        cacheUUID='c284a291b68b3d0da1a03f866f87efdc',providers=result,inputs=inputs,
        genuineVZStrongExports=104,nativeExecuted=False,deviceOperations=0,
        fullSwiftMetadataRelocationProven=False,strongTransitiveClosureProven=False,full27Backend=False)
    (output/'original-contract.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(contract=pin(output/'original-contract.json'),
        providers=[dict(name=p['name'],exports=len(p['exports']),imports=len(p['originalNlistImports']),
            swiftSections=len(p['originalSwiftSections']),initializers=len(p['originalInitializerSections']))for p in result])))


if __name__=='__main__':main()
