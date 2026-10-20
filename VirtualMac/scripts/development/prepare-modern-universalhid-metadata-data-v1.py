#!/usr/bin/env python3
"""Relocate proven HID Swift edges with genuine per-slot PAC; inert data only.

One unclassified original UHK typeref record and the complete metadata schema
remain gated. Its original bytes are preserved, never guessed or nil-bound.
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
spec=importlib.util.spec_from_file_location('hid_provider_contract',HERE/'prepare-modern-universalhid-provider-data-v1.py')
previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
from universalhid_relative_metadata_v1 import HIDRelativeMetadata
from compiler_image import commands,segments,imports,chain_entries
from DyldExtractor.dyld.dyld_context import DyldContext

ROOT=previous.ROOT;NODE=previous.NODE;pin=previous.pin;save=previous.save
BASE=NODE/'universalhid-exact-owner-private-route-v5'
ORACLE=NODE/'universalhid-metadata-auth-oracle-v1'
ORACLE_SHA='e3117bae5fbf14c2c3706c49e7b2760dc48fbb4730d2a652db2107d34789f4b7'
CONTEXT_LABELS={'protocol','conditionalProtocol','mangledSymbolicContextIndirect','indirectTypeReference','retroactiveContext'}


def auth_policy(row,labels):
    assert row['chainMembershipVerified']and row['slideInfoVersion']==5
    assert row['auth']==1 and row['key']==2 and row['addressDiversity']==1
    assert labels=={'resilientRequirement'}or labels and labels<=CONTEXT_LABELS
    expected=0x7d4c if labels=={'resilientRequirement'}else 0xae86
    assert int(row['diversity'],16)==expected
    return expected


def build(provider,facts,authrows,memo,exports,out):
    name=provider['name'];source=Path(provider['candidate']['path']);before=source.read_bytes()
    assert pin(source)==provider['candidate']
    raw=Path(provider['original']['path']).read_bytes()
    initial=HIDRelativeMetadata(raw,before);initial.singletons();initial.conformances();initial.reflection()
    desired={r['target']for r in initial.unresolved if r['label']!='mangledSymbolicReference1'}
    assert len(desired)==(194 if name=='UniversalHID'else 57)
    rows=[authrows[target]for target in sorted(desired)]
    data=bytearray(before);segs=segments(data)
    segment=next(g for g in segs if any(s['name']=='__got'for s in g['sections']))
    got=next(s for s in segment['sections']if s['name']=='__got')
    assert got['size']==0 and got['address']%8==got['fileoff']%8==0
    start=got['fileoff'];size=len(rows)*8
    assert start+size<=segment['fileoff']+segment['filesize']and not any(data[start:start+size])
    assert not any(s['size']and s['fileoff']<start+size and s['fileoff']+s['size']>start for s in segment['sections'])
    info=imports(data);oldblob=bytes(data[info['data']:info['data']+info['size']])
    assert info['header'][3]==info['header'][2]+info['header'][4]*4
    prefix=bytearray(oldblob[:info['header'][2]])
    impwords=bytearray(oldblob[info['header'][2]:info['header'][3]])
    names=bytearray(oldblob[info['header'][3]:])
    allimports=list(info['imports'])
    existing={(r['ordinal'],r['name']):r['index']for r in allimports}
    originaldeps=facts['originalDependencies'];routes=[];mapping={}
    for index,row in enumerate(rows):
        target=row['originalSlotVA'];actual=row['actualTarget'];symbol,owner=memo['symbols'][actual]
        proof=exports.resolve(owner,symbol)
        assert proof and proof['exportAddress']==int(actual,16)and proof['exportedSymbol']==symbol
        candidates=[d for d in originaldeps if d['path']==owner]
        assert len(candidates)==1,('original strong metadata owner absent',name,owner,symbol)
        ordinal=candidates[0]['ordinal']
        labels={r['label']for r in initial.unresolved if r.get('target')==target}
        assert name in row['providers']and labels<=set(row['labels'])
        discriminator=auth_policy(row,labels)
        key=(ordinal,symbol)
        impindex=existing.get(key)
        if impindex is None:
            impindex=len(allimports);existing[key]=impindex
            assert len(names)<1<<23 and impindex<65536
            impwords+=struct.pack('<I',(len(names)<<9)|ordinal)
            names+=symbol.encode()+b'\0'
            allimports.append(dict(index=impindex,ordinal=ordinal,name=symbol,weak=False))
        slot=got['address']+index*8;mapping[target]=slot
        word=(1<<63)|(1<<62)|(2<<49)|(1<<48)|(discriminator<<32)|impindex
        if index+1<len(rows):word|=1<<51
        struct.pack_into('<Q',data,start+index*8,word)
        routes.append(dict(originalSlotVA=target,originalCacheWord=row['rawCacheWord'],actualOriginalTarget=actual,
                           labels=sorted(labels),newSlotVA=slot,importIndex=impindex,symbol=symbol,ordinal=ordinal,
                           originalOwner=owner,genuineExport=proof,auth=True,key=2,addressDiversity=True,
                           discriminator=hex(discriminator),chainMembershipVerified=True,weak=False))
    originalsites=list(chain_entries(before))
    page_size=16384
    page=(start-segment['fileoff'])//page_size
    assert page==(start+size-1-segment['fileoff'])//page_size
    predecessors=[r for r in originalsites if r['segment']==segment['name']and r['page']==page]
    chainchange=None
    if predecessors:
        predecessor=max(predecessors,key=lambda r:r['fileoff'])
        assert predecessor['fileoff']<start and not(predecessor['word']>>51)&0x7ff
        stride=(start-predecessor['fileoff'])//8
        assert 0<stride<0x800 and predecessor['fileoff']+stride*8==start
        struct.pack_into('<Q',data,predecessor['fileoff'],predecessor['word']|(stride<<51))
        chainchange=dict(kind='extend existing final next stride',fileoff=predecessor['fileoff'],before=predecessor['word'],after=predecessor['word']|(stride<<51))
    else:
        starts=info['header'][1]
        segindex=segs.index(segment)
        relative=struct.unpack_from('<I',prefix,starts+4+segindex*4)[0]
        assert relative
        field=starts+relative+22+page*2
        assert struct.unpack_from('<H',prefix,field)[0]==0xffff
        offset=start-segment['fileoff']-page*page_size
        assert 0<=offset<page_size
        struct.pack_into('<H',prefix,field,offset)
        chainchange=dict(kind='start a previously empty declared page',page=page,prefixField=field,offset=offset)
    struct.pack_into('<Q',data,got['command']+40,size)
    struct.pack_into('<I',data,got['command']+52,3)
    relocated=HIDRelativeMetadata(raw,data);relocated.singletons();relocated.conformances(mapping);relocated.reflection(mapping)
    expected=[]if name=='UniversalHID'else [dict(slot=11271912929,label='mangledSymbolicReference1',target=11288690161,indirect=False)]
    assert relocated.unresolved==expected
    # Apply only recorded source/target section mappings and the exact original
    # external-slot contracts. The unclassified original record remains byte
    # identical and keeps the native load gate false.
    for row in relocated.rows:struct.pack_into('<i',data,row['fileoff'],row['newRelative32'])
    struct.pack_into('<I',prefix,12,len(prefix)+len(impwords))
    struct.pack_into('<I',prefix,16,len(allimports))
    blob=prefix+impwords+names
    newoff=len(data);data+=blob
    for cmd,at,_ in commands(data):
        if cmd==0x80000034:struct.pack_into('<II',data,at+8,newoff,len(blob))
        if cmd==0x19 and bytes(data[at+8:at+24]).split(b'\0')[0]==b'__LINKEDIT':
            fo=struct.unpack_from('<Q',data,at+40)[0];filesize=len(data)-fo
            struct.pack_into('<Q',data,at+32,(filesize+0x3fff)&~0x3fff)
            struct.pack_into('<Q',data,at+48,filesize)
    final=bytes(data);sites={r['fileoff']:r for r in chain_entries(final)}
    assert len(sites)==len(originalsites)+len(rows)
    for row in originalsites:
        expectedword=chainchange['after']if chainchange['kind'].startswith('extend')and row['fileoff']==chainchange['fileoff']else row['word']
        assert sites[row['fileoff']]['word']==expectedword
    for row in routes:
        site=sites[start+routes.index(row)*8]
        assert site['auth']and site['bind']and site['import_index']==row['importIndex']
        assert ((site['word']>>32)&0xffff)==int(row['discriminator'],16)
        assert ((site['word']>>49)&3)==2 and site['word']&(1<<48)
    assert all(not r['weak']and r['ordinal']>0 for r in imports(final)['imports'])
    for g in segments(before):
        for s in g['sections']:
            if s['size']and s['flags']&0x80000000:
                assert before[s['fileoff']:s['fileoff']+s['size']]==final[s['fileoff']:s['fileoff']+s['size']]
    if expected:
        offset=initial.offset(expected[0]['slot'])
        mapped=initial.offset(initial.mapped(expected[0]['slot']),False)
        assert before[mapped:mapped+4]==final[mapped:mapped+4]==raw[offset:offset+4]
    outfile=out/(name+'27.genuine-auth-relative.mac.inert.macho-data');outfile.write_bytes(final)
    run=subprocess.run(['xcrun','dyld_info','-validate_only',str(outfile)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr
    return dict(name=name,source=pin(source),candidate=pin(outfile),originalRaw=provider['original'],
                exactAuthRoutes=routes,relativeFieldsRelocated=relocated.rows,remainingUnclassifiedRecord=expected,
                originalChainMembershipAndPACPreserved=True,soleChainChange=chainchange,
                addedSlots=len(rows),addedImports=len(allimports)-len(info['imports']),
                allImportsPositiveAndStrong=True,instructionSectionsUnchanged=True,
                dyldValidation=dict(exitCode=run.returncode,stdout=run.stdout,stderr=run.stderr),
                selectedSchemasRelocatedExceptExplicitOriginalRecord=True,fullMetadataSchema=False,
                fullTransitiveClosureProven=False,nativeExecuted=False,deviceOperations=0)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists()
    for row in json.loads((BASE/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    assert pin(ORACLE/'contract.json')['sha256']==ORACLE_SHA
    auth=json.loads((ORACLE/'contract.json').read_text());assert not auth['libraryLoaded']and not auth['cacheModified']
    authrows={r['originalSlotVA']:r for r in auth['contracts']};assert len(authrows)==207
    memo=json.loads((ORACLE/'exact-targets.a2s.batch.json').read_text());assert memo['uuid']==auth['mainCacheUUID']
    base=json.loads((BASE/'candidate.json').read_text());facts=json.loads(Path(base['originalContract']['path']).read_text())
    out.mkdir()
    with previous.CACHE.open('rb')as stream:
        cache=DyldContext(stream);cache.addSubCaches(previous.CACHE);assert bytes(cache.header.uuid).hex()==auth['mainCacheUUID']
        exports=previous.GenuineCacheExports(cache)
        results=[build(p,f,authrows,memo,exports,out)for p,f in zip(base['providers'],facts['providers'])]
    report=dict(schema='Genuine27 HID original-auth Swift relative metadata inert data v1',
                sourceCandidate=pin(BASE/'candidate.json'),sourceAuthOracle=pin(ORACLE/'contract.json'),
                exactTargetMemo=pin(ORACLE/'exact-targets.a2s.batch.json'),providers=results,
                strongOriginalAuthenticatedSlots=sum(r['addedSlots']for r in results),
                sourceSectionInstructionBytesPreserved=True,perSlotAuthNotGuessed=True,
                fullSwiftMetadataSchema=False,remainingUnclassifiedTyperefRecords=1,
                stockTransitiveClosureProven=False,nativeExecuted=False,codeSigned=False,
                deviceOperations=0,originalVZLoaded=False,originalVMMExecuted=False,full27Backend=False)
    save(out/'candidate.json',report)
    files=[Path(__file__),HERE/'universalhid_relative_metadata_v1.py',HERE/'prepare-modern-universalhid-provider-data-v1.py',
           HERE/'swift_relative_metadata.py',ORACLE/'contract.json',ORACLE/'exact-targets.a2s.batch.json',BASE/'candidate.json',out/'candidate.json']
    for result in results:files.extend(Path(result[k]['path'])for k in('source','candidate','originalRaw'))
    save(out/'freeze.json',dict(files=[pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),providers=[dict(name=r['name'],slots=r['addedSlots'],
                           imports=r['addedImports'],relativeFields=len(r['relativeFieldsRelocated']),
                           unclassified=len(r['remainingUnclassifiedRecord']))for r in results])))


if __name__=='__main__':main()
