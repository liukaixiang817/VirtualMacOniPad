#!/usr/bin/env python3
"""Follow actual old IOKit selectors/class reference to bounded chain prefixes."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_init_first', HERE / 'plan-modern-iokit-native-initializer-v1.py')
first = importlib.util.module_from_spec(spec); spec.loader.exec_module(first)
s, p, h = first.s, first.p, first.h
from current_hid_extra_three_capture_v1 import join, mapping
from DyldExtractor.dyld.dyld_structs import dyld_cache_header


def adrp(pc, word, register):
    assert word & 0x9f00001f == 0x90000000 | register
    value = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3)
    if value & (1 << 20): value -= 1 << 21
    return (pc & ~4095) + (value << 12)


def selectors(raw, pc):
    assert len(raw) == 16
    w = struct.unpack('<4I', raw)
    assert w[1] & 0xffc003ff == 0xf9400021
    assert w[3] & 0xffc003ff == 0x91000231
    return dict(selectorSlot=adrp(pc,w[0],1)+((w[1]>>10)&4095)*8,
                sharedTargetSlot=adrp(pc+8,w[2],17)+((w[3]>>10)&4095), words=list(w))


def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve(); assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path=p.NODE/'ipad-current-cache-swift-leaf-headers-v1/headers.json'
    heads=json.loads(heads_path.read_bytes())
    capture=p.NODE/'ipad-current-iokit-native-initializer-readonly-v1'
    request=p.NODE/'ipad-current-iokit-native-initializer-plan-v1/request.json'
    receipt=s.checked_capture(capture,request,heads_path)
    assert receipt['readerSHA256']==p.pin(capture/'reader-source.py')['sha256']=='6cb61cbad0775c70b229f6c25fca4305bcb35c640c3f492bac6fc5954193f922'
    images={}; pins, stock=join(s,images)
    io=images['/System/Library/Frameworks/IOKit.framework/IOKit']
    command=Path(io['header']['path']).read_bytes()
    text=next(x for x in p.segments(command) if x['name']=='__TEXT')
    exported_class=text['address']+io['exports']['_OBJC_CLASS_$_HIDEvent']['offsetOrAbsoluteAddress']
    class_word=struct.unpack('<Q',(capture/'iokit-event-class-reference.bin').read_bytes())[0]
    version,page_size,page_count,pad,add=struct.unpack('<4IQ',(capture/'iokit-class-mapping-slide-header.bin').read_bytes())
    assert (version,page_size,page_count,pad,add)==(3,4096,10668,0,0x180000000)
    page_start=struct.unpack('<H',(capture/'iokit-class-reference-page-start.bin').read_bytes())[0]
    assert page_start==0x380 and class_word>>63==0
    class_target=class_word & ((1<<51)-1)
    assert class_target==exported_class==0x1dd2c8130
    assert class_word>>51 & 0x7ff == 1
    allocate=selectors((capture/'iokit-allocate-selector-island.bin').read_bytes(),0x18ed2efa0)
    initialize=selectors((capture/'iokit-initialize-selector-island.bin').read_bytes(),0x18ed2efe0)
    assert allocate['sharedTargetSlot']==initialize['sharedTargetSlot']==0x1e231f8b0
    assert allocate['selectorSlot']==0x1d5cc7ce0 and initialize['selectorSlot']==0x1d5cc7d08
    stubs=next(x for x in text['sections'] if x['name']=='__objc_stubs')
    assert stubs['address']==0x18ed2efa0 and stubs['size']==96 and stubs['align']==5
    archive=p.NODE.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    archived=archive.read_bytes()[27*4096:28*4096]
    import hashlib
    physical=next(x for x in heads['headers'] if x['name']=='27-data')
    assert hashlib.sha256(archived).hexdigest()==physical['sha256']
    header=dyld_cache_header.from_buffer_copy(archived)
    slide_maps=[]
    for index in range(header.mappingWithSlideCount):
        at=header.mappingWithSlideOffset+index*h.dyld_cache_mapping_and_slide_info.SIZE
        item=h.dyld_cache_mapping_and_slide_info.from_buffer_copy(archived[at:])
        slide_maps.append({key:getattr(item,key) for key,_ in item._fields_})
    ranges=[dict(name='iokit-allocate-selector-tail',**mapping(heads,0x18ed2efb0,16)),
            dict(name='iokit-initialize-selector-tail',**mapping(heads,0x18ed2eff0,16))]
    chains=[]
    for name, addresses, size, read_slide_header in (
        ('iokit-selectors',[allocate['selectorSlot'],initialize['selectorSlot']],8,True),
        ('iokit-event-class',[class_target],40,False),
        ('iokit-message-dispatch',[allocate['sharedTargetSlot']],8,True)):
        page_va=addresses[0]&~4095
        assert all(address&~4095==page_va for address in addresses)
        end=max(address+size for address in addresses)
        matched=[row for row in slide_maps if row['address']<=page_va and end<=row['address']+row['size']]
        assert len(matched)==1
        slide=matched[0]; index=(page_va-slide['address'])//4096
        ranges.append(dict(name=name+'-chain-prefix',**mapping(heads,page_va,end-page_va)))
        ranges.append(dict(name=name+'-page-start',cache='27-data',offset=slide['slideInfoFileOffset']+24+index*2,length=2))
        if read_slide_header:
            ranges.append(dict(name=name+'-slide-header',cache='27-data',offset=slide['slideInfoFileOffset'],length=24))
        else:
            existing=p.NODE/'ipad-current-hid-pod-native-metadata-readonly-v1/native-metadata-mapping-slide-header.bin'
            assert struct.unpack('<4IQ',existing.read_bytes())==(3,4096,9328,0,0x180000000)
            assert slide['slideInfoFileOffset']==179859576
            pins.append(p.pin(existing))
        chains.append(dict(name=name,pageVA=page_va,neededSlots=addresses,bytesThroughLastSlot=size,
            pageIndex=index,guardedExactHeaderSlideMapping=slide,
            actualPageStartAndMembershipMustBeValidatedBeforeDecoding=True))
    assert len(ranges)==10 and sum(x['length'] for x in ranges)==6006
    out.mkdir(); p.save(out/'request.json',dict(ranges=ranges))
    p.save(out/'derivation.json',dict(schema='Actual old IOKit class and selector pointers to bounded chain prefix request v1',
        actualReceipt=p.pin(capture/'receipt.json'),actualHeaders=p.pin(heads_path),actualIOKitCommands=io['header'],
        currentClassExport=io['exports']['_OBJC_CLASS_$_HIDEvent'],actualClassReferenceWord=hex(class_word),
        actualClassReferenceIsFirstSlide3PageEntry=True,actualClassReferenceTarget=class_target,
        actualClassReferenceNextBytes=8,actualAllocatorSelector=allocate,actualInitializerSelector=initialize,
        actualObjCStubsSection=stubs,chainRequests=chains,request=p.pin(out/'request.json'),requestedBytes=6006,
        archivedClassOrSelectorOrFunctionBodyUsed=False,archivedHeaderOnlyHasExactCurrent4096BContract=True,
        currentInitializerSelected=False,oldInitializerNewTypeAcceptanceProven=False,currentClassInstanceSizeProven=False,
        originalHIDLoaded=False,nativeIOSExecuted=False,deviceOperations=0,full27Backend=False))
    pins += [p.pin(path) for path in (Path(__file__),Path(first.__file__),heads_path,request,archive,out/'request.json',out/'derivation.json')]
    pins += [p.pin(capture/name) for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]
    pins += [p.pin(Path(row['path'])) for row in receipt['ranges']]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),ranges=ranges,actualClass=hex(class_target))))


if __name__=='__main__':main()
