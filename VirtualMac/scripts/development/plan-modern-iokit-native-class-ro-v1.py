#!/usr/bin/env python3
"""Decode actual slide3 prefixes, then request current class RO/selectors."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_native_chains',HERE/'plan-modern-iokit-native-initializer-chains-v1.py')
plan=importlib.util.module_from_spec(spec);spec.loader.exec_module(plan)
s,p,h=plan.s,plan.p,plan.h
from current_hid_extra_three_capture_v1 import mapping


def chain(data,page_start,page_va,slide,required):
    version,size,count,pad,add=struct.unpack('<4IQ',slide)
    assert version==3 and size==4096 and count>0 and pad==0 and add==0x180000000
    assert 0<len(data)<=size and len(data)%8==0 and page_va%size==0
    assert page_start!=0xffff and page_start%8==0 and 0<=page_start<size
    assert all(page_va<=slot and slot+8<=page_va+len(data) and slot%8==0 for slot in required)
    at,rows=page_start,{}
    while at+8<=len(data):
        word=struct.unpack_from('<Q',data,at)[0]
        delta=((word>>51)&0x7ff)*8
        auth=bool(word>>63)
        target=add+(word&0xffffffff) if auth else (word&((1<<43)-1))|(((word>>43)&255)<<56)
        rows[page_va+at]=dict(slot=page_va+at,word=hex(word),target=target,authenticated=auth,
            key=(word>>49)&3 if auth else None,diversity=(word>>32)&65535 if auth else None,
            addressDiversity=bool((word>>48)&1) if auth else None,nextBytes=delta,actualSlide3ChainMembership=True)
        if not delta:break
        assert at+delta<=size-8
        at+=delta
    assert set(required)<=set(rows)
    return dict(pageVA=page_va,pageStart=page_start,actualAuthValueAdd=add,
        prefixBytes=len(data),visitedSlots=len(rows),wholePageChainClaimed=False,
        requestedSlots=[rows[slot] for slot in required])


def expected_auth(row,key,diversity):
    assert row['authenticated'] and row['key']==key and row['diversity']==diversity and row['addressDiversity']


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path=p.NODE/'ipad-current-cache-swift-leaf-headers-v1/headers.json';heads=json.loads(heads_path.read_bytes())
    capture=p.NODE/'ipad-current-iokit-native-initializer-chains-readonly-v2'
    request=p.NODE/'ipad-current-iokit-native-initializer-chains-plan-v1/request.json'
    receipt=s.checked_capture(capture,request,heads_path)
    reader=capture/'reader-source.py'
    assert receipt['readerSHA256']==p.pin(reader)['sha256']=='6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'
    # Confirm the newly pinned reader retains all source guards/budgets; its
    # difference from v6 is only the documented ordinary SSH transport setup.
    previous=p.NODE/'ipad-current-swift-iokit-stackprobe-readonly-v1/reader-source.py'
    before=previous.read_text();after=reader.read_text()
    inserted="""    # A new ordinary SSH connection avoids local multiplexed FD transfer.
    # Existing USB forwarders and the previous control socket are untouched.
    remote.IPAD_SSH = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8',
                       '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                       '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts',
                       '-o', 'StrictHostKeyChecking=yes', 'mobile@127.0.0.1']
"""
    assert after.count(inserted)==1
    assert after.replace(inserted,'').replace('; never load or modify it; use a direct SSH session.','; never load or modify it.')==before
    decoded=[];inputs=[Path(__file__),Path(plan.__file__),heads_path,request,previous]
    metadata_slide=p.NODE/'ipad-current-hid-pod-native-metadata-readonly-v1/native-metadata-mapping-slide-header.bin'
    for name,page,needed in (
        ('iokit-selectors',0x1d5cc7000,[0x1d5cc7ce0,0x1d5cc7d08]),
        ('iokit-event-class',0x1dd2c8000,[0x1dd2c8130,0x1dd2c8138,0x1dd2c8150]),
        ('iokit-message-dispatch',0x1e231f000,[0x1e231f8b0])):
        body=capture/(name+'-chain-prefix.bin');start=capture/(name+'-page-start.bin')
        slide=metadata_slide if name=='iokit-event-class' else capture/(name+'-slide-header.bin')
        result=chain(body.read_bytes(),struct.unpack('<H',start.read_bytes())[0],page,slide.read_bytes(),needed)
        result.update(name=name,actualBody=p.pin(body),actualPageStart=p.pin(start),actualSlideHeader=p.pin(slide))
        decoded.append(result);inputs += [body,start,slide]
    selectors,cls,dispatch=[row['requestedSlots']for row in decoded]
    assert all(not row['authenticated'] for row in selectors)
    for row,div in zip(cls,(0x6ae1,0xb5ab,0x61f8)):expected_auth(row,2,div)
    expected_auth(dispatch[0],0,0)
    assert cls[2]['target']==0x1df8e7348 and not cls[2]['target']&7
    native=s.primary.captured_images();pins=s.join_capture(native,'stock-extra',p.NODE/'ipad-current-cache-stock-extra-headers-v1/headers.json')
    dispatch_def=s.primary.resolve(native,'/usr/lib/libobjc.A.dylib','_objc_msgSend')
    assert dispatch_def['status']=='actualDirectExport'
    image=native[s.primary.canonical_path(dispatch_def['owner'])]
    text=next(x for x in p.segments(Path(image['header']['path']).read_bytes()) if x['name']=='__TEXT')
    assert text['address']+dispatch_def['export']['offsetOrAbsoluteAddress']==dispatch[0]['target']==0x1800b1c00
    for name in ('iokit-allocate-selector-tail','iokit-initialize-selector-tail'):
        tail=capture/(name+'.bin');words=struct.unpack('<4I',tail.read_bytes())
        assert words==(0xf9400230,0xd71f0a11,0xd4200020,0xd4200020)
        inputs.append(tail)
    ro=cls[2]['target'];page=ro&~4095
    # The actual dispatch read captured the same mapping's slide3 header.
    assert struct.unpack('<4IQ',(capture/'iokit-message-dispatch-slide-header.bin').read_bytes())==(3,4096,11920,0,0x180000000)
    mapping_row=next(m for row in heads['headers'] for m in row['maps'] if m['address']<=ro< m['address']+m['size'])
    assert mapping_row['address']==8041103360
    page_index=(page-mapping_row['address'])//4096
    ranges=[dict(name='iokit-event-class-ro-chain-prefix',**mapping(heads,page,ro+72-page)),
        dict(name='iokit-event-class-ro-page-start',cache='27-data',offset=179878256+24+page_index*2,length=2)]
    for row,name,expected in zip(selectors,('iokit-allocate-selector-name','iokit-initialize-selector-name'),
            ('allocWithZone:','initWithSize:type:timestamp:options:')):
        ranges.append(dict(name=name,**mapping(heads,row['target'],len(expected)+1)))
    assert len(ranges)==4 and sum(row['length']for row in ranges)==966
    negatives=[]
    for label,start,body in [('unaligned page start',0x131,(capture/'iokit-event-class-chain-prefix.bin').read_bytes()),
        ('no chain page',0xffff,(capture/'iokit-event-class-chain-prefix.bin').read_bytes()),
        ('chain starts after required class ISA',0x138,(capture/'iokit-event-class-chain-prefix.bin').read_bytes()),
        ('truncated class prefix',0x130,(capture/'iokit-event-class-chain-prefix.bin').read_bytes()[:-8])]:
        try:chain(body,start,0x1dd2c8000,metadata_slide.read_bytes(),[0x1dd2c8130,0x1dd2c8150])
        except (AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted malformed current class chain')
    for label,field,value in [('wrong RO data key','key',0),('wrong RO discriminator','diversity',0),('missing RO address binding','addressDiversity',False),('missing RO authentication','authenticated',False)]:
        bad=dict(cls[2]);bad[field]=value
        try:expected_auth(bad,2,0x61f8)
        except AssertionError:negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted wrong current class RO PAC')
    out.mkdir();p.save(out/'request.json',dict(ranges=ranges))
    p.save(out/'derivation.json',dict(schema='Actual old IOKit chain contracts and next class RO selector request v1',
        actualReceipt=p.pin(capture/'receipt.json'),actualHeaders=p.pin(heads_path),actualReader=p.pin(reader),
        priorV6Reader=p.pin(previous),v7SourceDifferenceOnlyOrdinarySSHTransportAndDocstring=True,
        actualChainPrefixes=decoded,actualDispatchDefinition=dispatch_def,actualComplete32BSelectorStubsProven=True,
        request=p.pin(out/'request.json'),requestedBytes=966,classROVA=ro,
        actualClassROPointerDA2AddressBinding61f8=True,currentClassROBytesRead=False,
        currentInitializerSelected=False,oldInitializerNewTypeAcceptanceProven=False,
        originalHIDLoaded=False,nativeIOSExecuted=False,deviceOperations=0,negativeControls=negatives,full27Backend=False))
    inputs += [capture/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]
    pins += [p.pin(path) for path in inputs+[out/'request.json',out/'derivation.json']]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),ranges=ranges,negativeControls=len(negatives))))


if __name__=='__main__':main()
