#!/usr/bin/env python3
"""Read genuine original VZ/Core consuming ABI and its authenticated import."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1'
BUILD=NODE/'swift-arraybuffer-consume-data-build-v2'
NAME='$ss12_ArrayBufferV20_consumeAndCreateNew14bufferIsUnique15minimumCapacity13growForAppendAByxGSb_SiSbtFyXl_Ts5'
spec=importlib.util.spec_from_file_location('array_original_reader',NODE/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
specp=importlib.util.spec_from_file_location('genuine_hid',ROOT/'VirtualMac/scripts/development/prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(specp);specp.loader.exec_module(p)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    build=json.loads((BUILD/'candidate.json').read_text())
    for row in json.loads((BUILD/'freeze.json').read_text())['files']:assert p.pin(Path(row['path']))==row
    role=next(row for row in build['roles']if row['role']=='ios')
    assert role['IRSignature']=='define swiftcc ptr @"'+NAME+'"(i1 %0, i64 %1, i1 %2, ptr %3) local_unnamed_addr #0 {'
    rawpath=SOURCE/'raw/Virtualization';memopath=SOURCE/'Virtualization-symbols.a2s.batch.json'
    raw=rawpath.read_bytes();memo=json.loads(memopath.read_text())['symbols']
    stubs=[int(a,16)for a,v in memo.items()if v and v[0]=='_'+NAME];assert stubs==[0x2280566a0]
    calls=[]
    for section in h.sections(raw):
        if section['name']!='__text':continue
        fo,va,size=section['fileoff'],section['address'],section['bytes']
        for delta in range(0,size,4):
            word=struct.unpack_from('<I',raw,fo+delta)[0]
            if word&0xfc000000!=0x94000000:continue
            displacement=(word&0x3ffffff)<<2
            if displacement&0x8000000:displacement-=0x10000000
            address=va+delta
            if address+displacement not in stubs:continue
            assert delta>=192 and delta+64<=size
            code=raw[fo+delta-192:fo+delta+64]
            calls.append(dict(address=address,target=address+displacement,windowStart=address-192,
                              originalWindow=code.hex(),instructions=h.decode_body(code,address-192)))
    assert len(calls)==1 and calls[0]['address']==0x2260f723c
    window=bytes.fromhex(calls[0]['originalWindow'])
    # Capacity is selected in x1, grow is w2, the owned old buffer is x3;
    # the returned owned buffer directly replaces x21 in the original caller.
    assert list(struct.unpack_from('<3I',window,192-12))==[0x9a96c101,0x52800022,0xaa1503e3]
    assert struct.unpack_from('<I',window,192+4)[0]==0xaa0003f5
    reads=[]
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc'
        subs=cache.addSubCaches(p.CACHE)
        def read(address,size,purpose):
            offset,ctx=cache.convertAddr(address);data=ctx.getBytes(offset,size);assert len(data)==size
            reads.append(dict(address=address,bytes=size,purpose=purpose,cacheUUID=bytes(ctx.header.uuid).hex(),offset=offset,sha256=__import__('hashlib').sha256(data).hexdigest()))
            return data
        core=p.GenuineCacheExports(cache).image('/usr/lib/swift/libswiftCore.dylib')
        assert core['UUID']=='c9b36da7bb3435afbc5d91ecbcaa9ed0'
        export=core['exports']['_'+NAME];assert export.flags==0;entry=core['base']+export.address
        header=read(core['base'],32,'exact Core header extent');header=read(core['base'],32+struct.unpack_from('<I',header,20)[0],'complete exact Core header')
        for command,at,length in h.commands(header):
            if command==0x19 and header[at+8:at+24].rstrip(b'\0')==b'__LINKEDIT':
                link,lfo=struct.unpack_from('<Q',header,at+24)[0],struct.unpack_from('<Q',header,at+40)[0]
            if command==0x26:off,starts_size=struct.unpack_from('<II',header,at+8)
        startsdata=read(link+off-lfo,starts_size,'exact Core function starts');starts=[];at=0;value=core['base']
        while at<len(startsdata):
            delta,at=h.uleb(startsdata,at)
            if not delta:break
            value+=delta;starts.append(value)
        assert entry in starts;end=starts[starts.index(entry)+1];assert 0<end-entry<=65536
        body=read(entry,end-entry,'entire exact original consume function');bodypath=out/'Core-original-consume.bin';bodypath.write_bytes(body)
        obj=out/'Core-original-consume.inspection-only.macho-object';h.inspection_container(obj,entry,body)
        stub=stubs[0];code=read(stub,16,'exact original VZ import island');adrp,add,load,branch=struct.unpack('<4I',code)
        assert adrp&0x9f00001f==0x90000011 and add&0xffc003ff==0x91000231 and load==0xf9400230 and branch==0xd71f0a11
        immediate=((adrp>>5&0x7ffff)<<2)|(adrp>>29&3)
        if immediate&0x100000:immediate-=0x200000
        slot=(stub&~0xfff)+(immediate<<12)+(add>>10&0xfff)
        offset,ctx=cache.convertAddr(slot);mapping=next(m for m,c in cache.mappings if c is ctx and m.address<=slot<m.address+m.size)
        index=ctx.mappings.index((mapping,ctx))
        expanded=h.dyld_cache_mapping_and_slide_info(ctx.file,ctx.header.mappingWithSlideOffset+index*h.dyld_cache_mapping_and_slide_info.SIZE)
        slide=h.dyld_cache_slide_info5(ctx.file,expanded.slideInfoFileOffset);assert slide.version==5
        page=(slot-expanded.address)//slide.page_size;start=ctx.readFormat('<H',expanded.slideInfoFileOffset+len(slide)+page*2)[0];assert start!=0xffff
        pageoff=expanded.fileOffset+page*slide.page_size;cursor=pageoff+start
        for visits in range(slide.page_size//8):
            assert pageoff<=cursor<=pageoff+slide.page_size-8
            word=ctx.readFormat('<Q',cursor)[0];target,auth,key,diversity,addressdiversity,delta=h.decodeV5Pointer(word,slide.value_add)
            if cursor==offset:break
            assert delta and cursor<offset;cursor+=delta
        else:raise AssertionError('exact chain membership not found')
        assert target==entry and auth and key==0 and addressdiversity
        island=dict(address=stub,originalInstructions=code.hex(),slot=slot,pointerWord=word,target=target,
                    auth=auth,key=key,discriminator=diversity,addressDiversity=addressdiversity,exactChainMembershipVerified=True,exactOriginalExportMatched=True)
        for sub in subs:sub.close()
    report=dict(schema='Exact original VZ ArrayBuffer consuming SwiftCC read contract v1',sourceBuild=p.pin(BUILD/'candidate.json'),
                provider=role['provider'],originalVZRaw=p.pin(rawpath),originalSymbolMemo=p.pin(memopath),readerSource=p.pin(Path(spec.origin)),
                originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc',originalSwiftCoreUUID=core['UUID'],reads=reads,
                exactOriginalFunction=dict(address=entry,nextStart=end,code=p.pin(bodypath),inspectionContainer=p.pin(obj),instructions=h.decode_body(body,entry)),
                originalCallerWindows=calls,originalAuthenticatedIsland=island,providerIRSignature=role['IRSignature'],
                originalCallerABICompatible=True,ownedBufferArgumentAndResult=True,noReceiverSwiftself=True,
                originalVZExecuted=False,originalVMMExecuted=False,nativeIOSExecuted=False,deviceOperations=0,fullCurrentLoadGraphProven=False,full27Backend=False)
    p.save(out/'audit.json',report)
    files=[Path(__file__),Path(spec.origin),BUILD/'candidate.json',BUILD/'freeze.json',rawpath,memopath,bodypath,obj,out/'audit.json']
    p.save(out/'freeze.json',dict(files=[p.pin(f)for f in files],deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),calls=1,actualOriginalFunctionBytes=len(body))))


if __name__=='__main__':main()
