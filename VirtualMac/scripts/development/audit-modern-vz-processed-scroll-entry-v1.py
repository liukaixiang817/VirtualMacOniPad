#!/usr/bin/env python3
"""Read genuine27 scroll wrapper and pointing-device method bodies, never load."""
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scroll_vz_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('scroll_vz_h',p.NODE/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
VZ='/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization'

def main():
    out=p.NODE/'vz-processed-scroll-entry-original-readonly-v1';assert not out.exists();out.mkdir()
    prior=p.NODE/'vz-skylight-consumer-contract-v1/build-v3/contract.json'
    contract=json.loads(prior.read_bytes());selector_base=contract['originalSelectorBase']
    reads=[];chains=[];classes=[];functions=[];pins=[p.pin(Path(__file__)),p.pin(prior)]
    with p.CACHE.open('rb') as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc'
        subcaches=cache.addSubCaches(p.CACHE)
        try:
            genuine=p.GenuineCacheExports(cache);image=genuine.image(VZ)
            assert image['UUID']=='418efc4809d93606918eb6f95baeffdc'
            def read(va,count,label):
                assert 0<count<=2*1024*1024
                off,owner=cache.convertAddr(va);data=owner.getBytes(off,count);assert len(data)==count
                file=out/(str(len(reads)).zfill(4)+'-'+label+'.bin');file.write_bytes(data)
                row=dict(address=va,bytes=count,physicalUUID=bytes(owner.header.uuid).hex(),offset=off,data=p.pin(file));reads.append(row);pins.append(row['data']);return data
            def pointer(slot):
                raw=read(slot,8,'chain-slot');word=struct.unpack('<Q',raw)[0]
                if not word:return 0
                mapping,owner=next((m,o)for m,o in cache.mappings if m.address<=slot<m.address+m.size)
                index=owner.mappings.index((mapping,owner))
                ext=h.dyld_cache_mapping_and_slide_info(owner.file,owner.header.mappingWithSlideOffset+index*h.dyld_cache_mapping_and_slide_info.SIZE)
                slide=h.dyld_cache_slide_info5(owner.file,ext.slideInfoFileOffset);assert slide.version==5
                page=(slot-ext.address)//slide.page_size
                start=owner.readFormat('<H',ext.slideInfoFileOffset+len(slide)+page*2)[0];assert start!=65535
                pageoff=ext.fileOffset+page*slide.page_size;cursor=pageoff+start;wanted=ext.fileOffset+slot-ext.address
                for steps in range(slide.page_size//8):
                    assert pageoff<=cursor<=pageoff+slide.page_size-8
                    current=owner.readFormat('<Q',cursor)[0]
                    target,auth,key,div,address,delta=h.decodeV5Pointer(current,slide.value_add)
                    if cursor==wanted:
                        assert current==word;target&=0x00ffffffffffffff
                        chains.append(dict(slot=slot,rawWord=hex(word),target=target,auth=auth,key=key,diversity=div,addressDiversity=address,actualChainMember=True))
                        return target
                    assert delta and cursor<wanted;cursor+=delta
                raise AssertionError('unbounded chain')
            def text(va,label,count=256):
                data=read(va,count,label);head,separator,tail=data.partition(b'\0');assert separator
                return head.decode()
            prefix=read(image['base'],32,'vz-prefix');size=struct.unpack_from('<I',prefix,20)[0]
            header=read(image['base'],32+size,'vz-commands')
            assert [header[at+8:at+24].hex()for cmd,at,length in p.commands(header)if cmd==27]==[image['UUID']]
            link=next(seg for seg in p.segments(header)if seg['name']=='__LINKEDIT')
            off,length=next(struct.unpack_from('<II',header,at+8)for cmd,at,count in p.commands(header)if cmd==0x26)
            encoded=read(link['address']+off-link['fileoff'],length,'vz-lc26')
            starts=[];at=0;address=image['base']
            while at<len(encoded):
                delta,at=h.uleb(encoded,at)
                if not delta:break
                address+=delta;starts.append(address)
            assert starts==sorted(set(starts))and encoded[at:]==b'\0'*(len(encoded)-at)
            section=next(row for row in h.sections(header)if row['name']=='__objc_classlist');assert section['bytes']%8==0
            names=[]
            for at in range(0,section['bytes'],8):
                cls=pointer(section['address']+at);ro=pointer(cls+32)&~7
                name=text(pointer(ro+24),'class-name');names.append(name)
                if name!='_VZScrollWheelEvent'and 'PointingDevice'not in name:continue
                methods=[]
                def methodlist(va,meta):
                    if not va:return
                    flags,count=struct.unpack('<II',read(va,8,'method-header'));stride=flags&0xfffc;assert count<=256
                    assert flags&0x80000000 and stride==12
                    entries=read(va+8,count*12,'method-list') if count else b''
                    for index in range(count):
                        slot=va+8+index*12;selector,types,imp=struct.unpack_from('<iii',entries,index*12)
                        selector_va=selector_base+selector if flags&0x40000000 else pointer(slot+selector)
                        type_va=selector_base+types if flags&0x20000000 else slot+4+types
                        method=dict(className=name,meta=meta,selector=text(selector_va,'selector'),
                            types=text(type_va,'method-type',512),methodEntry=slot,IMP=slot+8+imp)
                        methods.append(method)
                        if name=='_VZScrollWheelEvent'or method['selector']=='sendScrollWheelEvents:':
                            begin=method['IMP'];position=bisect.bisect_left(starts,begin);assert starts[position]==begin
                            end=starts[position+1];assert 0<end-begin<=32768
                            data=read(begin,end-begin,'method-body')
                            functions.append(dict(**method,begin=begin,end=end,actualLC26Complete=True,data=reads[-1]['data'],instructions=h.decode_body(data,begin)))
                methodlist(pointer(ro+32),False)
                meta=pointer(cls);meta_ro=pointer(meta+32)&~7;methodlist(pointer(meta_ro+32),True)
                classes.append(dict(name=name,classAddress=cls,RO=ro,methods=methods))
            assert any(c['name']=='_VZScrollWheelEvent'for c in classes)
            p.save(out/'audit.json',dict(schema='Genuine27 processed scroll actual ObjC entry contract v1',
                actualImage={key:image[key]for key in ('path','UUID','base')},cacheUUID=bytes(cache.header.uuid).hex(),
                selectorBase=selector_base,selectorBaseSource=p.pin(prior),actualClassCount=len(names),selectedClasses=classes,
                completeFunctions=functions,actualS5PointerWords=chains,freshReads=reads,
                originalVZLoaded=False,functionsExecuted=0,receiverImplemented=False,
                originalInitializerABIValidated=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
        finally:
            for context in subcaches:context.close()
    pins+=[p.pin(out/'audit.json')]
    p.save(out/'freeze.json',dict(files=list({r['path']:r for r in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),classes=[dict(name=c['name'],methods=[m['selector']for m in c['methods']])for c in classes],functions=len(functions))))
if __name__=='__main__':main()
