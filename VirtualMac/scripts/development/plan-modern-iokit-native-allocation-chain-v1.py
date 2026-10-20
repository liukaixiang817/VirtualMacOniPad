#!/usr/bin/env python3
"""Use actual legacy opt bytes to bound method names and the native malloc chain."""
import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_legacy',HERE/'plan-modern-iokit-native-legacy-selectors-v1.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
s,p,ro=legacy.s,legacy.p,legacy.ro
from current_hid_extra_three_capture_v1 import mapping
from DyldExtractor.dyld.dyld_structs import dyld_cache_header


def legacy_base(old,new):
    assert len(old)==48 and len(new)==32
    values=struct.unpack('<II8iq',old)
    assert values[:2]==(16,7)
    version,flags,header_ro,header_rw,selectors=struct.unpack('<II3Q',new)
    assert (version,flags)==(1,7)
    address=0x1800e9ab8
    # Old objc_opt_t offsets are relative to the optimization structure. Three
    # separately recorded new cache offsets verify this address interpretation.
    assert address+values[2]==0x180000000+selectors
    assert address+values[3]==0x180000000+header_ro
    assert address+values[6]==0x180000000+header_rw
    result=address+values[10]
    assert result==0x182347703
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path=p.NODE/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    heads=json.loads(heads_path.read_bytes())
    cap=p.NODE/'ipad-current-iokit-native-legacy-selectors-readonly-v1'
    request=p.NODE/'ipad-current-iokit-native-legacy-selectors-plan-v2/request.json'
    receipt=s.checked_capture(cap,request,heads_path)
    assert receipt['readerSHA256']==p.pin(cap/'reader-source.py')['sha256']=='ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'
    methods_cap=p.NODE/'ipad-current-iokit-objcopt-bounded-readonly-v1'
    old=(cap/'legacy-libobjc-optimization-header.bin').read_bytes()
    new=(methods_cap/'objc-optimization-header.bin').read_bytes()
    base=legacy_base(old,new)
    method_plan=json.loads((p.NODE/'ipad-current-iokit-native-method-bodies-plan-v1/derivation.json').read_bytes())
    entries=[dict(row,nameAddress=base+row['nameGlobalSelectorOffset'])for row in method_plan['actualMethodEntries']]
    selectors=p.NODE/'ipad-current-iokit-native-class-ro-readonly-v1'
    expected=(selectors/'iokit-initialize-selector-name.bin').read_bytes()
    chains=p.NODE/'ipad-current-iokit-native-class-ro-plan-v2/derivation.json'
    actual_selector=json.loads(chains.read_bytes())['actualChainPrefixes'][0]['requestedSlots'][1]['target']
    assert entries[3]['nameAddress']==actual_selector==0x18365cd57
    assert expected==b'initWithSize:type:timestamp:options:\0'
    assert (cap/'iokit-event-super-init-selector.bin').read_bytes()==b'init\0'
    types=(methods_cap/'iokit-event-method-and-ivar-type-encodings.bin').read_bytes()
    initial_type=types[8:].split(b'\0')[0]
    assert initial_type==b'@40@0:8Q16I24Q28I36'
    actual_ivar_type=(types[44:]+(cap/'iokit-event-own-ivar-type-tail.bin').read_bytes()).split(b'\0')[0].decode()
    expected_type='{?="timeStamp"Q"senderID"Q"typeMask"Q"options"I"attributeData"*"context"^v"attachments"^{__CFDictionary}"sender"^v"children"^{__CFArray}"parent"^{__IOHIDEvent}"attributeDataLength"q"eventCount"q"eventData"^{IOHIDEventData}}'
    assert actual_ivar_type==expected_type
    class Ivar(ctypes.Structure):
        _fields_=[('timeStamp',ctypes.c_uint64),('senderID',ctypes.c_uint64),('typeMask',ctypes.c_uint64),
            ('options',ctypes.c_uint32),('attributeData',ctypes.c_void_p),('context',ctypes.c_void_p),
            ('attachments',ctypes.c_void_p),('sender',ctypes.c_void_p),('children',ctypes.c_void_p),
            ('parent',ctypes.c_void_p),('attributeDataLength',ctypes.c_int64),('eventCount',ctypes.c_int64),('eventData',ctypes.c_void_p)]
    assert ctypes.sizeof(Ivar)==104 and Ivar.eventData.offset==96
    assert struct.unpack('<I',(methods_cap/'iokit-event-own-ivar-offset.bin').read_bytes())[0]==8
    island=(cap/'iokit-event-initializer-raw-allocation-island.bin').read_bytes()
    words=struct.unpack('<4I',island)
    assert words[1]&0xffc003ff==0x91000231 and words[2:]==(0xf9400230,0xd71f0a11)
    got=ro.plan.adrp(0x18ed0ccf8,words[0],17)+((words[1]>>10)&4095)
    assert got==0x1e22da8b8
    member=p.NODE/'ipad-current-cache-27-data-header-readonly-v1/27-data.header.bin'
    raw=member.read_bytes()
    assert p.pin(member)['sha256']==next(row['sha256']for row in heads['headers']if row['name']=='27-data')
    header=dyld_cache_header.from_buffer_copy(raw)
    slide_maps=[]
    for index in range(header.mappingWithSlideCount):
        at=header.mappingWithSlideOffset+index*ro.h.dyld_cache_mapping_and_slide_info.SIZE
        item=ro.h.dyld_cache_mapping_and_slide_info.from_buffer_copy(raw[at:])
        slide_maps.append({key:getattr(item,key)for key,_ in item._fields_})
    matched=[row for row in slide_maps if row['address']<=got and got+8<=row['address']+row['size']]
    assert len(matched)==1
    slide=matched[0];page=got&~4095;page_index=(page-slide['address'])//4096
    previous_slide=p.NODE/'ipad-current-iokit-native-initializer-chains-readonly-v2/iokit-message-dispatch-slide-header.bin'
    assert slide['slideInfoFileOffset']==179878256 and struct.unpack('<4IQ',previous_slide.read_bytes())==(3,4096,11920,0,0x180000000)
    ranges=[dict(name='iokit-event-method-'+str(row['index'])+'-selector-name',**mapping(heads,row['nameAddress'],32))for row in entries[:3]]
    ranges += [dict(name='iokit-event-allocation-chain-prefix',**mapping(heads,page,got+8-page)),
        dict(name='iokit-event-allocation-page-start',cache='27-data',offset=slide['slideInfoFileOffset']+24+page_index*2,length=2)]
    assert len(ranges)==5 and sum(row['length']for row in ranges)==2338
    negatives=[]
    for name,where,value in [('wrong old version',0,15),('wrong old flags',4,0),('incorrect old selector table',8,0),
        ('incorrect old RO table',12,0),('incorrect old RW table',24,0),('incorrect selector base',40,0)]:
        bad=bytearray(old);struct.pack_into('<I',bad,where,value)
        try:legacy_base(bytes(bad),new)
        except AssertionError:negatives.append(dict(name=name,rejected=True))
        else:raise AssertionError('accepted incorrect actual legacy header')
    out.mkdir();p.save(out/'request.json',dict(ranges=ranges))
    p.save(out/'derivation.json',dict(schema='Actual legacy ObjC selector identity and old HIDEvent ivar initialization contract v1',
        actualLegacyReceipt=p.pin(cap/'receipt.json'),actualHeaders=p.pin(heads_path),
        actualOld48B=p.pin(cap/'legacy-libobjc-optimization-header.bin'),actualNew32B=p.pin(methods_cap/'objc-optimization-header.bin'),
        legacyOffsetsRelativeToStructIndependentlyCrossCheckedAgainstThreeNewCacheOffsets=True,
        actualLegacySelectorBase=base,actualMethodEntries=entries,
        initializerSelectorMatchedActualAllocatorDispatchSelectorAddressAndString=True,
        initializerTypeEncoding=initial_type.decode(),actualCompleteInitializer=p.pin(methods_cap/'iokit-event-method-3-complete.bin'),
        exactOwnIvarTypeEncoding=actual_ivar_type,ownIvarFields=[dict(name=name,offset=getattr(Ivar,name).offset,bytes=ctypes.sizeof(kind))for name,kind in Ivar._fields_],
        ownIvarOffset=8,ownIvarSize=104,nativeInstanceSize=112,dataPointerObjectOffset=104,
        initializerAcceptsSizeAtLeast16WithoutTypeUpperBound=True,actualInitializerDataAndHeaderStoresProven=True,
        actualAllocationIsland=p.pin(cap/'iokit-event-initializer-raw-allocation-island.bin'),nativeAllocationGOTSlot=got,
        currentActualMappingHeader=p.pin(member),currentSlideHeader=p.pin(previous_slide),exactSlideMapping=slide,pageIndex=page_index,
        allocationGOTTargetAndPACStillRequireActualMembership=True,otherTwoCalleeIslandOwnersUncaptured=True,
        request=p.pin(out/'request.json'),requestedBytes=2338,negativeControls=negatives,
        oldNativeType41Or42ConstructorsExecuted=False,oldNativeKernelNewTypeConsumerValidated=False,
        nativeIOSExecuted=False,deviceOperations=0,nativeHVCalls=0,originalHIDLoaded=False,full27Backend=False))
    paths=[Path(__file__),Path(legacy.__file__),heads_path,request,member,previous_slide,chains,
        p.NODE/'ipad-current-iokit-native-method-bodies-plan-v1/derivation.json',selectors/'iokit-initialize-selector-name.bin']
    paths += [cap/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py',
        'legacy-libobjc-optimization-header.bin','iokit-event-super-init-selector.bin','iokit-event-own-ivar-type-tail.bin','iokit-event-initializer-raw-allocation-island.bin')]
    paths += [methods_cap/name for name in ('objc-optimization-header.bin','iokit-event-method-and-ivar-type-encodings.bin','iokit-event-own-ivar-offset.bin','iokit-event-method-3-complete.bin')]
    paths += [out/'request.json',out/'derivation.json']
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in map(p.pin,paths)}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),ranges=ranges,selectorBase=hex(base))))


if __name__=='__main__':main()
