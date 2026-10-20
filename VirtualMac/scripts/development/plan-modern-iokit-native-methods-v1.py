#!/usr/bin/env python3
"""Request the actual class's complete declared method section and ivar header."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_class_ro',HERE/'plan-modern-iokit-native-class-ro-v1.py')
ro=importlib.util.module_from_spec(spec);spec.loader.exec_module(ro)
s,p=ro.s,ro.p
from current_hid_extra_three_capture_v1 import join,mapping


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path=p.NODE/'ipad-current-cache-swift-leaf-headers-v1/headers.json';heads=json.loads(heads_path.read_bytes())
    capture=p.NODE/'ipad-current-iokit-native-class-ro-readonly-v1'
    request=p.NODE/'ipad-current-iokit-native-class-ro-plan-v2/request.json'
    receipt=s.checked_capture(capture,request,heads_path)
    assert receipt['readerSHA256']==p.pin(capture/'reader-source.py')['sha256']=='6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'
    prefix=capture/'iokit-event-class-ro-chain-prefix.bin';start=capture/'iokit-event-class-ro-page-start.bin'
    slide=p.NODE/'ipad-current-iokit-native-initializer-chains-readonly-v2/iokit-message-dispatch-slide-header.bin'
    base=0x1df8e7348
    decoded=ro.chain(prefix.read_bytes(),struct.unpack('<H',start.read_bytes())[0],base&~4095,slide.read_bytes(),[base+24,base+32,base+48])
    name,methods,ivars=decoded['requestedSlots']
    assert not name['authenticated'] and not ivars['authenticated']
    ro.expected_auth(methods,2,0xc310)
    raw=prefix.read_bytes()[base%4096:base%4096+72]
    assert len(raw)==72 and struct.unpack_from('<4I',raw)==(0,8,112,0)
    assert (capture/'iokit-allocate-selector-name.bin').read_bytes()==b'allocWithZone:\0'
    assert (capture/'iokit-initialize-selector-name.bin').read_bytes()==b'initWithSize:type:timestamp:options:\0'
    images={};pins,proof=join(s,images)
    io=images['/System/Library/Frameworks/IOKit.framework/IOKit']
    sections=[sec for seg in p.segments(Path(io['header']['path']).read_bytes()) for sec in seg['sections']]
    method_section=next(sec for sec in sections if sec['name']=='__objc_methlist')
    ivar_section=next(sec for seg in p.segments(Path(io['header']['path']).read_bytes()) if seg['name']=='__DATA_CONST' for sec in seg['sections'] if sec['name']=='__objc_const')
    assert method_section['address']==methods['target']==0x18ed0d688 and method_section['size']==332
    assert ivar_section['address']==ivars['target']==0x1d5cc7bc0 and ivar_section['size']==280
    assert name['target']==0x18ed2d5c4
    ranges=[dict(name='iokit-event-complete-method-section',**mapping(heads,methods['target'],method_section['size'])),
            dict(name='iokit-event-class-name',**mapping(heads,name['target'],len('HIDEvent')+1)),
            dict(name='iokit-event-ivar-list-header',**mapping(heads,ivars['target'],8))]
    assert len(ranges)==3 and sum(x['length']for x in ranges)==349
    out.mkdir();p.save(out/'request.json',dict(ranges=ranges))
    p.save(out/'derivation.json',dict(schema='Actual native HIDEvent class RO to complete method section request v1',
        actualReceipt=p.pin(capture/'receipt.json'),actualHeaders=p.pin(heads_path),actualClassRO=p.pin(prefix),
        actualClassROVA=base,actualClassInstanceStart=8,actualClassInstanceSize=112,
        actualROPointers=decoded,baseMethodsDA2AddressDiscriminator=0xc310,
        actualMethodSection=method_section,actualIvarContainingSection=ivar_section,
        actualClassNamePointer=name,selectorsExact=True,request=p.pin(out/'request.json'),requestedBytes=349,
        actualCompleteMethodListRead=False,initializerSelected=False,oldInitializerNewTypeAcceptanceProven=False,
        originalHIDLoaded=False,nativeIOSExecuted=False,deviceOperations=0,full27Backend=False))
    paths=[Path(__file__),Path(ro.__file__),heads_path,request,prefix,start,slide,out/'request.json',out/'derivation.json']
    paths += [capture/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py','iokit-allocate-selector-name.bin','iokit-initialize-selector-name.bin')]
    pins += [p.pin(path) for path in paths]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),ranges=ranges,actualInstanceSize=112)))


if __name__=='__main__':main()
