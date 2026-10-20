#!/usr/bin/env python3
"""Bound all four actual HIDEvent methods without guessing cached selector base."""
import argparse
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_methods_ro',HERE/'plan-modern-iokit-native-class-ro-v1.py')
ro=importlib.util.module_from_spec(spec);spec.loader.exec_module(ro)
spec=importlib.util.spec_from_file_location('iokit_method_index',HERE/'plan-modern-iokit-native-helper-body-v1.py')
index=importlib.util.module_from_spec(spec);spec.loader.exec_module(index)
s,p=ro.s,ro.p
from current_hid_extra_three_capture_v1 import join,mapping


def methods(raw,base):
    assert len(raw)==332
    flags,count=struct.unpack_from('<II',raw)
    assert flags==0xc000000f and count==4 and flags&0xfffc==12
    entries=[]
    for ordinal in range(count):
        entry=base+8+ordinal*12
        name_offset,type_relative,imp_relative=struct.unpack_from('<Iii',raw,8+ordinal*12)
        entries.append(dict(index=ordinal,entryVA=entry,nameGlobalSelectorOffset=name_offset,
            typeEncodingVA=entry+4+type_relative,implementationVA=entry+8+imp_relative,
            selectorBaseNotYetCaptured=True))
    return entries


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path=p.NODE/'ipad-current-cache-swift-leaf-headers-v1/headers.json';heads=json.loads(heads_path.read_bytes())
    captured=p.NODE/'ipad-current-iokit-methods-stackprobe-readonly-v1'
    request=p.NODE/'ipad-current-iokit-methods-stackprobe-plan-v1/request.json'
    receipt=s.checked_capture(captured,request,heads_path)
    assert receipt['readerSHA256']==p.pin(captured/'reader-source.py')['sha256']=='6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'
    original_request=json.loads((p.NODE/'ipad-current-iokit-native-methods-plan-v1/request.json').read_bytes())['ranges']
    actual_request=json.loads(request.read_bytes())['ranges']
    for row in original_request:assert actual_request.count(row)==1
    method_path=captured/'iokit-event-complete-method-section.bin'
    entries=methods(method_path.read_bytes(),0x18ed0d688)
    assert (captured/'iokit-event-class-name.bin').read_bytes()==b'HIDEvent\0'
    assert (captured/'iokit-event-ivar-list-header.bin').read_bytes()==struct.pack('<II',32,1)
    images={};pins,proof=join(s,images)
    image=images['/System/Library/Frameworks/IOKit.framework/IOKit']
    text=next(x for x in p.segments(Path(image['header']['path']).read_bytes())if x['name']=='__TEXT')
    indexed=p.NODE/'ipad-current-static-cn-iokit-extra-readonly-v1'
    index_request=p.NODE/'ipad-current-static-cn-iokit-extra-plan-v1/request.json'
    index_heads=p.NODE/'ipad-current-cache-pod-leaf-headers-v3/headers.json'
    index_receipt=s.checked_capture(indexed,index_request,index_heads)
    assert index_receipt['readerSHA256']==p.pin(indexed/'reader-source.py')['sha256']=='42cb53bcd59b526ef602fd09c0b59542e9a050203b10b7bab240b57e8563370e'
    starts=index.decode((indexed/'iokit-function-starts.bin').read_bytes(),text['address'])
    ranges=[]
    for entry in entries:
        at=bisect.bisect_left(starts,entry['implementationVA'])
        assert at<len(starts)-1 and starts[at]==entry['implementationVA']
        end=starts[at+1];size=end-entry['implementationVA']
        assert 0<size<=65536
        request_row=dict(name='iokit-event-method-'+str(entry['index'])+'-complete',**mapping(heads,entry['implementationVA'],size))
        assert request_row['cache']=='05'
        ranges.append(request_row);entry.update(endVA=end,exactActualLC26Bounds=True,request=request_row)
    chains=p.NODE/'ipad-current-iokit-native-initializer-chains-readonly-v2'
    prefix=(chains/'iokit-selectors-chain-prefix.bin').read_bytes()
    assert prefix[0xbc0:0xbc8]==(captured/'iokit-event-ivar-list-header.bin').read_bytes()
    ivars=ro.chain(prefix,0,0x1d5cc7000,(chains/'iokit-selectors-slide-header.bin').read_bytes(),[0x1d5cc7bc8,0x1d5cc7bd0,0x1d5cc7bd8])
    ivar_offset,ivar_name,ivar_type=ivars['requestedSlots']
    assert all(not row['authenticated']for row in ivars['requestedSlots'])
    alignment,size=struct.unpack_from('<II',prefix,0xbe0)
    assert alignment==3 and size==104
    first_type=min(row['typeEncodingVA']for row in entries)
    last=ivar_type['target']+128
    assert first_type==0x18ed2d6bf and last-first_type==172
    ranges += [dict(name='iokit-event-method-and-ivar-type-encodings',**mapping(heads,first_type,last-first_type)),
        dict(name='iokit-event-ivar-name',**mapping(heads,ivar_name['target'],32)),
        dict(name='iokit-event-own-ivar-offset',**mapping(heads,ivar_offset['target'],4))]
    assert len(ranges)==7 and sum(row['length']for row in ranges)<1024
    negatives=[]
    for label,raw in [('truncated method section',method_path.read_bytes()[:-1]),('wrong method count',struct.pack('<II',0xc000000f,5)+method_path.read_bytes()[8:]),
        ('unsupported global type encoding flag',struct.pack('<I',0xe000000f)+method_path.read_bytes()[4:]),
        ('incorrect relative method stride',struct.pack('<I',0xc0000013)+method_path.read_bytes()[4:])]:
        try:methods(raw,0x18ed0d688)
        except (AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted unsupported native method list')
    out.mkdir();p.save(out/'request.json',dict(ranges=ranges))
    p.save(out/'derivation.json',dict(schema='Current HIDEvent four complete method body and ivar layout request v1',
        actualReceipt=p.pin(captured/'receipt.json'),actualMergedRootManifest=p.pin(request),
        originalThreeRangeSubsetPreservedExactly=True,actualMethodSection=p.pin(method_path),
        actualMethodFlags=0xc000000f,actualOwnMethodsCount=4,actualMethodEntries=entries,
        actualLC26Index=p.pin(indexed/'iokit-function-starts.bin'),actualIndexReceipt=p.pin(indexed/'receipt.json'),
        actualHeaders=p.pin(heads_path),actualIvarListBytesAlreadyInGuardedSelectorPrefix=True,
        actualIvarPointerChain=ivars,actualOwnIvarAlignment=3,actualOwnIvarStorageBytes=104,
        cachedGlobalSelectorBaseNotYetCaptured=True,selectorBaseMustNotBeGuessedFromCallerString=True,
        initializerSelected=False,oldInitializerNewTypeAcceptanceProven=False,request=p.pin(out/'request.json'),
        requestedBytes=sum(row['length']for row in ranges),negativeControls=negatives,
        originalHIDLoaded=False,nativeIOSExecuted=False,deviceOperations=0,full27Backend=False))
    paths=[Path(__file__),Path(ro.__file__),Path(index.__file__),heads_path,request,index_request,index_heads,method_path,out/'request.json',out/'derivation.json']
    paths += [captured/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py','iokit-event-class-name.bin','iokit-event-ivar-list-header.bin')]
    paths += [indexed/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py','iokit-function-starts.bin')]
    paths += [chains/name for name in ('iokit-selectors-chain-prefix.bin','iokit-selectors-slide-header.bin')]
    pins += [p.pin(path)for path in paths]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),ranges=ranges,entries=entries)))


if __name__=='__main__':main()
