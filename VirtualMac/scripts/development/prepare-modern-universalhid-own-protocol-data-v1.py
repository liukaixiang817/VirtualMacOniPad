#!/usr/bin/env python3
"""Relocate genuine HID declared protocol metadata using real existing PAC slots.

No new imports, weak fallback, metadata/witness substitutes, or native loading.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hid_owner_reader',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from compiler_image import imports,chain_entries,segments,commands
from universalhid_declared_protocols_v1 import HIDDeclaredProtocols

ROOT=p.ROOT;NODE=p.NODE;pin=p.pin;save=p.save
META=NODE/'universalhid-genuine-auth-relative-data-v1'
GENERIC=NODE/'universalhid-genuine-generic-environment-data-v1'
PYTHON=ROOT/'DeviceDiagnostics/2026-10-02-macos27-backend/toolchain/venv/bin/python3'
ORACLE=META.parent/'universalhid-metadata-auth-oracle-v1/contract.json'
UPSTREAM=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-own-generic-field-native-candidate-v1/upstream'


def run(out,label,argv):
    r=subprocess.run([str(x)for x in argv],capture_output=True,text=True)
    save(out/(label+'.json'),dict(argv=[str(x)for x in argv],exitCode=r.returncode,stdout=r.stdout,stderr=r.stderr))
    assert r.returncode==0,(label,r.stderr);return r


def add_actual_slot(before,oracle,proof):
    data=bytearray(before);segs=segments(data)
    segment=next(g for g in segs if any(s['name']=='__got'for s in g['sections']))
    got=next(s for s in segment['sections']if s['name']=='__got')
    offset=got['fileoff']+got['size'];address=got['address']+got['size']
    assert offset%8==0 and offset+8<=segment['fileoff']+segment['filesize']
    assert not any(data[offset:offset+8])
    assert not any(s['size']and s['name']!='__got'and s['fileoff']<offset+8 and s['fileoff']+s['size']>offset for s in segment['sections'])
    info=imports(data);blob=data[info['data']:info['data']+info['size']]
    assert info['header'][3]==info['header'][2]+info['header'][4]*4
    prefix=bytearray(blob[:info['header'][2]])
    words=bytearray(blob[info['header'][2]:info['header'][3]])
    names=bytearray(blob[info['header'][3]:]);index=len(info['imports'])
    assert index<65536 and len(names)<1<<23
    words+=struct.pack('<I',(len(names)<<9)|8);names+=proof['exportedSymbol'].encode()+b'\0'
    struct.pack_into('<II',prefix,12,len(prefix)+len(words),index+1)
    authword=(1<<63)|(1<<62)|(2<<49)|(1<<48)|(0xae86<<32)|index
    struct.pack_into('<Q',data,offset,authword)
    predecessor=max((r for r in chain_entries(before)if r['segment']==segment['name']and r['page']==(offset-segment['fileoff'])//16384),key=lambda r:r['fileoff'])
    assert predecessor['fileoff']+8==offset and not(predecessor['word']>>51)&0x7ff
    chained=predecessor['word']|(1<<51);struct.pack_into('<Q',data,predecessor['fileoff'],chained)
    struct.pack_into('<Q',data,got['command']+40,got['size']+8)
    data+=b'\0'*((-len(data))&7)
    newoff=len(data);newblob=prefix+words+names;data+=newblob
    for cmd,at,_ in commands(data):
        if cmd==0x80000034:struct.pack_into('<II',data,at+8,newoff,len(newblob))
        elif cmd==0x19 and data[at+8:at+24].split(b'\0')[0]==b'__LINKEDIT':
            size=len(data)-struct.unpack_from('<Q',data,at+40)[0]
            struct.pack_into('<Q',data,at+32,(size+0x3fff)&~0x3fff);struct.pack_into('<Q',data,at+48,size)
    assert len(list(chain_entries(data)))==len(list(chain_entries(before)))+1
    return bytes(data),dict(originalSlotVA=oracle['originalSlotVA'],originalAuth=oracle,
        newSlotVA=address,fileoff=offset,word=authword,importIndex=index,ordinal=8,
        symbol=proof['exportedSymbol'],genuineExport=proof,strong=True),dict(fileoff=predecessor['fileoff'],before=predecessor['word'],after=chained)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    for base in (META,GENERIC):
        for row in json.loads((base/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    manifest=json.loads((META/'candidate.json').read_text())
    old_oracle={r['originalSlotVA']:r for r in json.loads(ORACLE.read_text())['contracts']}
    results=[];files=[]
    for plan in manifest['providers']:
        name=plan['name'];raw=Path(plan['originalRaw']['path']).read_bytes()
        source=Path(plan['candidate']['path'])if name=='UniversalHID'else GENERIC/'UniversalHIDKit27.genuine-generic-environment.mac.inert.macho-data'
        original=source.read_bytes();working=original;audit=HIDDeclaredProtocols(raw,original)
        audit.protocols();audit.associated_types()
        unresolved=audit.unresolved
        assert {r['target']for r in unresolved}==({12084592176,12084594824}if name=='UniversalHID'else{12084592176})
        # Read each actual original slot; do not infer PAC from its name.
        routepath=out/(name+'.original-routes.json')
        by_slot={r['originalSlotVA']:r for r in plan['exactAuthRoutes']}
        slots=sorted({r['target']for r in unresolved})
        save(routepath,[dict(originalSlotVA=target,symbol='_$sSHMp'if target==12084592176 else'_$ss17FixedWidthIntegerMp',
                             labels=['protocol'])for target in slots])
        run(out,name+'-original-cache-auth',[PYTHON,HERE/'audit-swift-cache-indirection-auth.py',
            '--routes',routepath,'--expected-routes-sha256',pin(routepath)['sha256'],'--cache',p.CACHE,
            '--expected-cache-uuid','c284a291b68b3d0da1a03f866f87efdc','--output',out/(name+'.original-auth')])
        oracle_path=out/(name+'.original-auth')/'contract.json'
        actual={r['originalSlotVA']:r for r in json.loads(oracle_path.read_text())['contracts']}
        external={};reused=[];added=[];chainchange=None
        entries={r['address']:r for r in chain_entries(original)}
        imp=imports(original)['imports']
        for target in slots:
            oracle=actual[target]
            assert oracle['chainMembershipVerified']and (oracle['auth'],oracle['key'],oracle['addressDiversity'],oracle['diversity'])==(1,2,1,'0xae86')
            symbol=oracle['symbol']
            choices=[r for r in plan['exactAuthRoutes']if r['symbol']==symbol and r['actualOriginalTarget']==oracle['actualTarget']]
            if not choices:
                assert name=='UniversalHID'and symbol=='_$ss17FixedWidthIntegerMp'
                from DyldExtractor.dyld.dyld_context import DyldContext
                with p.CACHE.open('rb')as f:
                    cache=DyldContext(f);subs=cache.addSubCaches(p.CACHE)
                    try:proof=p.GenuineCacheExports(cache).resolve('/usr/lib/swift/libswiftCore.dylib',symbol)
                    finally:
                        for sub in subs:sub.close()
                assert proof and proof['exportAddress']==int(oracle['actualTarget'],16)
                working,newslot,chainchange=add_actual_slot(working,oracle,proof)
                external[target]=newslot['newSlotVA'];added.append(newslot);continue
            assert len(choices)==1;chosen=choices[0]
            prior=old_oracle[chosen['originalSlotVA']]
            assert (prior['auth'],prior['key'],prior['addressDiversity'],prior['diversity'],prior['actualTarget'])==(1,2,1,'0xae86',oracle['actualTarget'])
            slot=entries[chosen['newSlotVA']]
            assert slot['auth']and slot['bind']and slot['import_index']==chosen['importIndex']
            assert (slot['word']>>32)&65535==0xae86 and (slot['word']>>49)&3==2 and slot['word']&(1<<48)
            bound=imp[slot['import_index']]
            assert bound['name']==symbol and bound['ordinal']==8 and not bound['weak']
            assert chosen['genuineExport']['exportAddress']==int(oracle['actualTarget'],16)
            external[target]=slot['address'];reused.append(dict(originalSlotVA=target,originalAuth=oracle,
                existingAuthRoute=chosen,existingPAC=slot,reason='exact same genuine protocol export and original per-slot authentication'))
        applied=HIDDeclaredProtocols(raw,working);applied.protocols(external);applied.associated_types(external)
        assert not applied.unresolved
        changed=[r for r in applied.rows if r['newRelative32']!=r['beforeRelative32']]
        assert len(changed)==(6 if name=='UniversalHID'else 3)
        repaired=applied.apply();assert len(repaired)==len(working)
        assert list(chain_entries(repaired))==list(chain_entries(working))and imports(repaired)==imports(working)
        whitelist={i for r in changed for i in range(r['fileoff'],r['fileoff']+4)}
        assert all(i in whitelist for i,(a,b)in enumerate(zip(repaired,working))if a!=b)
        target=out/(name+'27.genuine-own-protocols.mac.inert.macho-data');target.write_bytes(repaired)
        run(out,name+'-dyld',['xcrun','dyld_info','-validate_only',target])
        results.append(dict(name=name,source=pin(source),originalRaw=plan['originalRaw'],candidate=pin(target),
            sourceAuthOracle=pin(ORACLE),ownDeclaredProtocols=22 if name=='UniversalHID'else 6,
            originalPerSlotOracle=pin(oracle_path),reusedActualAuthSlots=reused,
            addedActualAuthSlots=added,soleOriginalChainNextChange=chainchange,
            schemas=applied.schemas,relativeFields=applied.rows,changedFields=changed,
            declaredProtocolAndAssociatedTypeSchemasRelocated=True,existingImportContractsUnchanged=True,
            allOldPACAndInstructionsPreserved=True,fullMetadataSchema=False,nativeExecuted=False,deviceOperations=0))
        files.extend([source,Path(plan['originalRaw']['path']),target,routepath,oracle_path])
    report=dict(schema='Genuine HID own declared protocols and associated type relocation v1',
        sourceMetadataCandidate=pin(META/'candidate.json'),sourceGenericCandidate=pin(GENERIC/'candidate.json'),
        providers=results,actualChangedRelativeFields=9,newImports=1,newGOTSlots=1,
        originalDefaultsAndWitnessesPreserved=True,fullMetadataSchema=False,
        stockTransitiveClosureProven=False,nativeExecuted=False,codeSigned=False,deviceOperations=0,
        originalVZLoaded=False,originalVMMExecuted=False,full27Backend=False)
    save(out/'candidate.json',report)
    files.extend([Path(__file__),HERE/'universalhid_declared_protocols_v1.py',HERE/'audit-swift-cache-indirection-auth.py',ORACLE,out/'candidate.json'])
    files.extend(UPSTREAM/('include--swift--ABI--'+n+'.h')for n in('Metadata','MetadataValues','GenericContext'))
    files.append(UPSTREAM/'include--swift--RemoteInspection--Records.h')
    save(out/'freeze.json',dict(files=[pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),actualChangedFields=9)))


if __name__=='__main__':main()
