#!/usr/bin/env python3
"""Audit current guarded native old IOKit allocation and the two finite layouts."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_allocation',HERE/'plan-modern-iokit-native-allocation-chain-v1.py')
allocation=importlib.util.module_from_spec(spec);spec.loader.exec_module(allocation)
s,p,ro=allocation.s,allocation.p,allocation.ro
spec=importlib.util.spec_from_file_location('iokit_method_metadata',HERE/'plan-modern-iokit-native-method-bodies-v1.py')
methods=importlib.util.module_from_spec(spec);spec.loader.exec_module(methods)
from current_hid_extra_three_capture_v1 import join,inventory


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    captures=[
        ('ipad-current-static-cn-iokit-extra-readonly-v1','ipad-current-static-cn-iokit-extra-plan-v1','ipad-current-cache-pod-leaf-headers-v3','42cb53bcd59b526ef602fd09c0b59542e9a050203b10b7bab240b57e8563370e'),
        ('ipad-current-swift-iokit-stackprobe-readonly-v1','ipad-current-swift-iokit-stackprobe-plan-v1','ipad-current-cache-swift-leaf-headers-v1','6cb61cbad0775c70b229f6c25fca4305bcb35c640c3f492bac6fc5954193f922'),
        ('ipad-current-iokit-native-initializer-readonly-v1','ipad-current-iokit-native-initializer-plan-v1','ipad-current-cache-swift-leaf-headers-v1','6cb61cbad0775c70b229f6c25fca4305bcb35c640c3f492bac6fc5954193f922'),
        ('ipad-current-iokit-native-initializer-chains-readonly-v2','ipad-current-iokit-native-initializer-chains-plan-v1','ipad-current-cache-swift-leaf-headers-v1','6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'),
        ('ipad-current-iokit-native-class-ro-readonly-v1','ipad-current-iokit-native-class-ro-plan-v2','ipad-current-cache-swift-leaf-headers-v1','6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'),
        ('ipad-current-iokit-methods-stackprobe-readonly-v1','ipad-current-iokit-methods-stackprobe-plan-v1','ipad-current-cache-swift-leaf-headers-v1','6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'),
        ('ipad-current-iokit-objcopt-bounded-readonly-v1','ipad-current-iokit-objcopt-bounded-read-plan-v1','ipad-current-cache-objc-linkedit-header-v1','ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'),
        ('ipad-current-iokit-native-legacy-selectors-readonly-v1','ipad-current-iokit-native-legacy-selectors-plan-v2','ipad-current-cache-objc-linkedit-header-v1','ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'),
        ('ipad-current-iokit-native-allocation-chain-readonly-v1','ipad-current-iokit-native-allocation-chain-plan-v1','ipad-current-cache-objc-linkedit-header-v1','ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9')]
    pins=[];checked=[]
    for directory,plan,headers,sha in captures:
        directory,request,headers=p.NODE/directory,p.NODE/plan/'request.json',p.NODE/headers/'headers.json'
        receipt=s.checked_capture(directory,request,headers)
        assert receipt['readerSHA256']==p.pin(directory/'reader-source.py')['sha256']==sha
        checked.append(dict(receipt=p.pin(directory/'receipt.json'),ranges=receipt['requestedRanges'],bytes=receipt['requestedBytes']))
        pins += [p.pin(path)for path in [request,headers]+[directory/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]+[Path(row['path'])for row in receipt['ranges']]]
    for directory in ('ipad-current-iokit-native-method-bodies-plan-v1','ipad-current-iokit-native-allocation-chain-plan-v1'):
        for pin in json.loads((p.NODE/directory/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
    images={};extra_pins,stock=join(s,images);pins+=extra_pins
    io=images['/System/Library/Frameworks/IOKit.framework/IOKit']
    assert io['UUID']=='87ae25ce3bef39d9baa90d8cc15a34a0'
    definition=s.primary.resolve(images,'/System/Library/Frameworks/IOKit.framework/IOKit','__IOHIDEventCreate')
    assert definition['status']=='actualDirectExport'
    text=next(segment for segment in p.segments(Path(io['header']['path']).read_bytes())if segment['name']=='__TEXT')
    assert text['address']+definition['export']['offsetOrAbsoluteAddress']==0x18ec74a70
    cap=p.NODE/'ipad-current-iokit-objcopt-bounded-readonly-v1'
    legacy=p.NODE/'ipad-current-iokit-native-legacy-selectors-readonly-v1'
    chaincap=p.NODE/'ipad-current-iokit-native-allocation-chain-readonly-v1'
    base=allocation.legacy_base((legacy/'legacy-libobjc-optimization-header.bin').read_bytes(),(cap/'objc-optimization-header.bin').read_bytes())
    raw=(p.NODE/'ipad-current-iokit-methods-stackprobe-readonly-v1/iokit-event-complete-method-section.bin').read_bytes()
    entries=methods.methods(raw,0x18ed0d688)
    names=[]
    for entry in entries:
        address=base+entry['nameGlobalSelectorOffset']
        if entry['index']==3:
            name=(p.NODE/'ipad-current-iokit-native-class-ro-readonly-v1/iokit-initialize-selector-name.bin').read_bytes()
            assert address==0x18365cd57
        else:name=(chaincap/('iokit-event-method-'+str(entry['index'])+'-selector-name.bin')).read_bytes()
        assert b'\0'in name
        entry.update(nameAddress=address,name=name.split(b'\0')[0].decode())
        names.append(entry['name'])
    assert names==['dealloc','_cfTypeID','description','initWithSize:type:timestamp:options:']
    body=(cap/'iokit-event-method-3-complete.bin').read_bytes()
    assert len(body)==180
    assert p.pin(cap/'iokit-event-method-3-complete.bin')['sha256']=='b0e92f19e601de54d3487e4639adbf4908a115c7e2377e47873e8bbe105a5f03'
    words=struct.unpack('<45I',body)
    assert words[7:11]==(0xaa0503f3,0xaa0403f7,0xaa0303f5,0xaa0203f4)
    assert words[18:21]==(0xf100001f,0xfa501a80,0x54000223)
    assert words[24]==0xf90036c0 and words[28:35]==(0xf90006d7,0xb90022d3,0x52800028,0x9ad52108,0xf9000ec8,0xf94036c8,0x29005514)
    assert words[35]==0xb9000913 and words[44]==0xd65f0fff
    dealloc=(cap/'iokit-event-method-0-complete.bin').read_bytes()
    assert len(dealloc)==192 and struct.unpack_from('<I',dealloc,28)[0]==0xf9403400
    generic=p.NODE/'ipad-current-swift-iokit-stackprobe-readonly-v1/iokit-event-allocate-complete.bin'
    assert len(generic.read_bytes())==100
    assert allocation.legacy.branches(generic.read_bytes(),0x18ec74a70)==[dict(pc=0x18ec74aa0,target=0x18ed2efa0)]
    assert struct.unpack_from('<I',generic.read_bytes(),96)[0]==0x1402e944
    assert 0x18ec74ad0+(0x2e944*4)==0x18ed2efe0
    slide=p.NODE/'ipad-current-iokit-native-initializer-chains-readonly-v2/iokit-message-dispatch-slide-header.bin'
    chain=ro.chain((chaincap/'iokit-event-allocation-chain-prefix.bin').read_bytes(),
        struct.unpack('<H',(chaincap/'iokit-event-allocation-page-start.bin').read_bytes())[0],0x1e22da000,slide.read_bytes(),[0x1e22da8b8])
    pointer=chain['requestedSlots'][0];ro.expected_auth(pointer,0,0)
    assert pointer['target']==0x195110e54
    actual_inventory=json.loads((p.NODE/'ipad-current-cache-hid-extra-inventory-v1/current-images.json').read_bytes())
    owner=[row for row in actual_inventory if row['address']<=pointer['target']<row['address']+row['textSize']]
    assert len(owner)==1 and owner[0]['path']=='/usr/lib/system/libsystem_malloc.dylib' and owner[0]['UUID']=='39fb1f8c48ef3dd08d74ff55e8d07c60'
    negatives=[]
    for index in range(len(words)):
        changed=bytearray(body);changed[index*4]^=1
        assert p.pin(cap/'iokit-event-method-3-complete.bin')['sha256']!=__import__('hashlib').sha256(changed).hexdigest()
        negatives.append(dict(name='initializer machine word '+str(index),rejectedByWholeBodyContract=True))
    for field,value in [('authenticated',False),('key',2),('diversity',1),('addressDiversity',False)]:
        bad=dict(pointer);bad[field]=value
        try:ro.expected_auth(bad,0,0)
        except AssertionError:negatives.append(dict(name='malloc GOT '+field,rejected=True))
        else:raise AssertionError('accepted wrong actual malloc PAC')
    out.mkdir()
    functions=[]
    for index,entry in enumerate(entries):
        path=cap/('iokit-event-method-'+str(index)+'-complete.bin')
        functions.append(dict(**entry,actualCompleteBody=p.pin(path),instructions=ro.h.decode_body(path.read_bytes(),entry['implementationVA'])))
    report=dict(schema='Current genuine old-host IOKit initializer and double event layout contract v1',
        checkedActualCaptures=checked,currentNativeIOKitUUID=io['UUID'],currentNativeIOKitCommands=io['header'],
        actualRawFiveGPAllocatorDefinition=definition,actualRawAllocatorCompleteBody=p.pin(generic),
        actualRawAllocatorInstructions=ro.h.decode_body(generic.read_bytes(),0x18ec74a70),actualLegacyGlobalSelectorBase=base,
        actualFourCompleteMethods=functions,actualInitializerSelectedByBothMethodListAndAllocatorDispatch=True,
        initializerSizeMinimum16=True,initializerHasNoTypeUpperBoundCheck=True,initializerOnlyRejectsNilSuperOrTooSmallSizeOrAllocationFailure=True,
        actualObjectTimestampOffset=8,actualObjectTypeMaskOffset=24,actualObjectOptionsOffset=32,actualObjectDataOffset=104,
        ownIvarOffset=8,ownIvarStorageBytes=104,currentClassInstanceBytes=112,
        layoutDerivation=p.pin(p.NODE/'ipad-current-iokit-native-allocation-chain-plan-v1/derivation.json'),
        actualMallocGOTChain=chain,actualMallocPointerTextOwner=owner[0],actualMallocNamedDefinitionCaptured=False,
        actualMallocFunctionCalled=False,otherTwoCalleeIslandOwnersUncaptured=True,
        exactRawType41And42ObjectsExpressibleThroughNativeAllocator=True,
        actualIOKitKernelNewTypesConsumerProven=False,originalFullIOKitFunctionSemanticsPreserved=False,
        originalHIDInitializerExecuted=False,nativeIOSExecuted=False,deviceOperations=0,nativeHVCalls=0,
        originalHIDLoaded=False,originalVZLoaded=False,full27Backend=False,negativeControls=negatives)
    p.save(out/'audit.json',report)
    paths=[Path(__file__),Path(allocation.__file__),Path(methods.__file__),generic,slide,out/'audit.json']
    pins += [p.pin(path)for path in paths]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),names=names,negativeControls=len(negatives))))


if __name__=='__main__':main()
