"""Finite own-profile property absence, removing only its proved dead class bind."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('property_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from compiler_image import imports,chain_entries,commands,segments
from swift_relative_metadata import RelativeMetadata
BASE=0x100000000
OLD_BASE=0x29fdb0000
CLASS='_OBJC_CLASS_$_NSEvent'
FUNCTION=0x66c0
CLASS_READ=0x670c
ABSENT=0x6734

def reference_proof(before):
    info=imports(before);selected=[row for row in info['imports']if row['name']==CLASS]
    assert len(selected)==1;selected=selected[0]
    assert selected['index']==190 and selected['ordinal']==5 and not selected['weak']
    entries=list(chain_entries(before));nodes=[row for row in entries if row['symbol']==CLASS]
    assert len(nodes)==1;node=nodes[0];assert not node['auth'] and node['fileoff']==68232
    assert node['word']==(1<<62)|(1<<51)|190
    old=p.ORIGINAL/'raw/UniversalHIDKit';a=RelativeMetadata(old.read_bytes(),before)
    original_conformance=0x29fdbb068;conformance=a.mapped(original_conformance);co=a.offset(conformance,False)
    flags=struct.unpack_from('<I',before,co+12)[0]
    assert (flags>>3)&7==2
    name=conformance+4+struct.unpack_from('<i',before,co+4)[0]
    no=a.offset(name,False);assert before[no:no+8]==b'NSEvent\0'
    # Kind2 is actual DirectObjCClassName. It is deliberately not converted
    # into a fake class, nullptr class object or an indirect metadata slot.
    body=before[FUNCTION:FUNCTION+136]
    assert len(body)==136 and struct.unpack_from('<I',body,0)[0]==0xd503237f
    assert struct.unpack_from('<2I',before,ABSENT)==(0x6f00e400,0xad000260)
    assert struct.unpack_from('<I',before,CLASS_READ)[0]&0x9f000000==0x90000000
    assert struct.unpack_from('<I',before,CLASS_READ+4)[0]&0xffc00000==0xf9400000
    segs=segments(before);text=next(t for g in segs for t in g['sections']if t['name']=='__text')
    from importlib.util import spec_from_file_location,module_from_spec
    sp=spec_from_file_location('original_uhk_refs',HERE/'audit-modern-uhk-mac-input-four-original-v6.py')
    reader=module_from_spec(sp);sp.loader.exec_module(reader)
    uses=[];address_materializations=[]
    code=before[text['fileoff']:text['fileoff']+text['size']]
    for delta in range(0,len(code),4):
        pc=text['address']+delta;w=struct.unpack_from('<I',code,delta)[0]
        ad=reader.adrp(pc,w)
        if ad and delta+8<=len(code):
            reg,page=ad;nextword=struct.unpack_from('<I',code,delta+4)[0]
            if nextword&0xffc00000==0xf9400000 and (nextword>>5)&31==reg:
                target=page+((nextword>>10)&4095)*8
                if target==node['address']:uses.append(dict(adrpPC=pc,loadPC=pc+4,targetSlot=target))
            if nextword&0xff000000==0x91000000 and (nextword>>5)&31==reg:
                immediate=(nextword>>10)&4095
                if nextword&(1<<22):immediate<<=12
                if page+immediate==node['address']:address_materializations.append(pc)
        if w&0x9f000000==0x10000000:
            immediate=((w>>5)&0x7ffff)<<2|((w>>29)&3)
            if immediate&0x100000:immediate-=0x200000
            if pc+immediate==node['address']:address_materializations.append(pc)
    assert uses==[dict(adrpPC=BASE+CLASS_READ,loadPC=BASE+CLASS_READ+4,targetSlot=node['address'])]
    assert not address_materializations
    relative=[];absolute=[];rebase=[];scanned=0
    header_end=32+struct.unpack_from('<I',before,20)[0]
    for segment in segs:
        if segment['name']=='__LINKEDIT':continue
        for off in range(segment['fileoff'],segment['fileoff']+segment['filesize']-3):
            address=segment['address']+off-segment['fileoff']
            if text['address']<=address<text['address']+text['size']or node['address']<=address<node['address']+8:continue
            scanned+=1;word=struct.unpack_from('<i',before,off)[0]
            if off>=header_end and (address+word==node['address']or address+word-(word&1)==node['address']):
                relative.append(dict(fileoff=off,word=word))
            if off+8<=segment['fileoff']+segment['filesize']and struct.unpack_from('<Q',before,off)[0]==node['address']:
                absolute.append(off)
    for row in entries:
        if row['bind']:continue
        target=BASE+(row['word']&0xffffffff)if row['auth']else (row['word']&((1<<43)-1))|(((row['word']>>43)&255)<<56)
        if target==node['address']:rebase.append(row)
    assert not relative and not absolute and not rebase,(relative,absolute,rebase)
    return dict(importRecord=selected,chainNode=node,textDirectClassLoads=uses,otherADROrImmediateAddressMaterializations=address_materializations,
        scannedNonTextImageBytes=scanned,relative32EdgesToSlot=relative,absolute64EdgesToSlot=absolute,rebaseEdgesToSlot=rebase,
        preservedNSEventConformance=dict(originalVA=original_conformance,candidateVA=conformance,fileoff=co,
            flags=flags,typeReferenceKind=2,className='NSEvent',classNameLocalVA=name,classObjectImportedGOTNotReferenced=True),
        propertyFunctionRVA=FUNCTION,propertyClassReadRVA=CLASS_READ,originalPropertyAbsentExitRVA=ABSENT,
        originalAbsentExitWritesGenuineAnyOptionalNone32Bytes=True,arbitraryRuntimeClassLookupOrIndirectExecutionProven=False)

def transform(before):
    proof=reference_proof(before);node=proof['chainNode'];info=imports(before);entries=list(chain_entries(before))
    prior=next(row for row in entries if row['fileoff']==node['previous']);assert prior['page_field']==node['page_field']
    nextstride=(node['word']>>51)&2047;assert nextstride==1
    skip=(node['fileoff']-prior['fileoff'])//8+nextstride;assert skip==2
    data=bytearray(before);struct.pack_into('<I',data,CLASS_READ,0x14000000|((ABSENT-CLASS_READ)//4))
    struct.pack_into('<Q',data,prior['fileoff'],(prior['word']&~(2047<<51))|(skip<<51))
    for row in entries:
        if row['bind']and row['import_index']>190:
            struct.pack_into('<Q',data,row['fileoff'],(row['word']&~65535)|(row['import_index']-1))
    blob=before[info['data']:info['data']+info['size']]
    version,starts,imp,names,count,fmt,compressed=info['header']
    assert version==compressed==0 and fmt==1 and names==imp+count*4
    prefix=bytearray(blob[:imp]);records=blob[imp:names]
    records=records[:190*4]+records[191*4:]
    struct.pack_into('<7I',prefix,0,version,starts,imp,names-4,count-1,fmt,compressed)
    newblob=prefix+records+blob[names:];at=(len(data)+7)&~7;data+=bytes(at-len(data));data+=newblob
    for command,off,z in commands(data):
        if command==0x80000034:struct.pack_into('<II',data,off+8,at,len(newblob))
        elif command==0x19 and data[off+8:off+24].split(b'\0')[0]==b'__LINKEDIT':
            first=struct.unpack_from('<Q',data,off+40)[0];struct.pack_into('<Q',data,off+32,(len(data)-first+16383)&~16383)
            struct.pack_into('<Q',data,off+48,len(data)-first)
    return bytes(data),dict(proof,predecessor=prior,skippedChainStride=skip,newFixupsFileoff=at,newFixupsBytes=len(newblob))

def validate(before,after):
    expected,proof=transform(before);assert after==expected
    old,new=imports(before),imports(after)
    assert len(new['imports'])==len(old['imports'])-1
    assert [dict(name=row['name'],ordinal=row['ordinal'],weak=row['weak'])for row in new['imports']]==[
        dict(name=row['name'],ordinal=row['ordinal'],weak=row['weak'])for row in old['imports']if row['index']!=190]
    oldentries=list(chain_entries(before));newentries=list(chain_entries(after));by={r['fileoff']:r for r in oldentries}
    assert len(newentries)==len(oldentries)-1 and all(r['fileoff']!=proof['chainNode']['fileoff']for r in newentries)
    for row in newentries:
        prior=by[row['fileoff']];assert (row['symbol'],row['bind'],row['auth'])==(prior['symbol'],prior['bind'],prior['auth'])
        mask=(65535 if row['bind']else 0)|(2047<<51 if row['fileoff']==proof['predecessor']['fileoff']else 0)
        assert row['word']&~mask==prior['word']&~mask
    assert after[proof['chainNode']['fileoff']:proof['chainNode']['fileoff']+8]==before[proof['chainNode']['fileoff']:proof['chainNode']['fileoff']+8]
    for segment in segments(before):
        for section in segment['sections']:
            off,z=section['fileoff'],section['size']
            if not off or not z or section['flags']&255 in (1,12,18):continue
            expected=bytearray(before[off:off+z])
            if off<=CLASS_READ<off+z:struct.pack_into('<I',expected,CLASS_READ-off,0x1400000a)
            for row in newentries:
                if off<=row['fileoff'] and row['fileoff']+8<=off+z:
                    struct.pack_into('<Q',expected,row['fileoff']-off,row['word'])
            assert after[off:off+z]==bytes(expected),(section['name'],off,z)
    return dict(originalImportCount=len(old['imports']),newImportCount=len(new['imports']),
        originalChainedEntries=len(oldentries),remainingChainedEntries=len(newentries),
        deadClassSlotWholeBytesKeptAsUnreferencedUnrelocatedPadding=True,allRemainingPACDiscriminatorsKeysAndNextEdgesPreserved=True,
        completeOriginalSwiftMetadataSectionsPreserved=True,onlyOneOriginalTextInstructionChanged=True,
        unsupportedMacPropertyIsOriginalAnyOptionalNone=True,unsupportedPropertyIsNotFalseBoolOrFakeClass=True,proof=proof)
