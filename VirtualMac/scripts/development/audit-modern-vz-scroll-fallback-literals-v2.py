#!/usr/bin/env python3
"""Read the exact selector literals and class size for the genuine fallback."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scroll_lit_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

def main():
    out=p.NODE/'vz-scroll-fallback-original-literals-readonly-v2';assert not out.exists();out.mkdir()
    prior=p.NODE/'vz-processed-scroll-entry-original-readonly-v1'
    for pin in json.loads((prior/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    source=json.loads((prior/'audit.json').read_bytes());reads=[];literals=[];ro=[]
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=cache.addSubCaches(p.CACHE)
        try:
            def read(va,count,label):
                off,owner=cache.convertAddr(va);raw=owner.getBytes(off,count);assert len(raw)==count
                path=out/(str(len(reads)).zfill(2)+'-'+label+'.bin');path.write_bytes(raw)
                reads.append(dict(address=va,bytes=count,offset=off,physicalUUID=bytes(owner.header.uuid).hex(),data=p.pin(path)));return raw
            for cls in source['selectedClasses']:
                if cls['name']not in ('_VZScrollWheelEvent','_VZPointingDevice'):continue
                raw=read(cls['RO'],16,'ro-header');flags,start,size,reserved=struct.unpack('<4I',raw)
                assert start==8 and size==(56 if cls['name']=='_VZScrollWheelEvent'else 32)
                ro.append(dict(className=cls['name'],RO=cls['RO'],flags=flags,instanceStart=start,instanceBytes=size,actualRead=reads[-1]))
            for pc,target,expected in [(0x225f9aba4,0x228018bc0,'hasPreciseScrollingDeltas'),
                    (0x225f9ac10,0x22801b810,'scrollingDeltaX'),(0x225f9ac1c,0x22801b820,'scrollingDeltaY'),
                    (0x225f9ac28,0x228038a50,'isDirectionInvertedFromDevice'),
                    (0x225f9ac64,0x22801a680,'phase'),(0x225f9ac70,0x228019ed0,'momentumPhase'),
                    (0x225f9ac94,0x2280388c0,'initWithScrollingDeltaX:scrollingDeltaY:acceleratedScrollingDeltaX:acceleratedScrollingDeltaY:scrollPhase:momentumPhase:')]:
                frame=next(f for f in source['completeFunctions']if f['selector']=='initWithEvent:')
                raw=Path(frame['data']['path']).read_bytes();word=struct.unpack_from('<I',raw,pc-frame['begin'])[0]
                assert word&0xfc000000==0x94000000
                delta=(word&0x3ffffff)<<2
                if delta&0x8000000:delta-=0x10000000
                assert pc+delta==target
                island=read(target,12,'selector-island');adrp,add,branch=struct.unpack('<3I',island)
                assert adrp&0x9f00001f==0x90000001 and add&0xffc003ff==0x91000021 and branch&0xfc000000==0x14000000
                immediate=((adrp>>5)&0x7ffff)<<2|((adrp>>29)&3)
                if immediate&0x100000:immediate-=0x200000
                literal=(target&~4095)+(immediate<<12)+((add>>10)&4095)
                name=read(literal,len(expected.encode())+1,'selector-name')
                assert name==expected.encode()+b'\0'
                literals.append(dict(callerPC=pc,exactOriginalBL=hex(word),target=target,literal=literal,
                    selector=expected,rawIsland=reads[-2],actualLiteral=reads[-1]))
        finally:
            for context in subs:context.close()
    p.save(out/'audit.json',dict(schema='Original27 precise processed scroll fallback exact selector literals v1',
        originalMethods=p.pin(prior/'audit.json'),actualClassRO=ro,actualSelectorBindings=literals,
        preciseFallbackNormalization=dict(primary='processed points after explicit direction handling',second='primary / 10.0',
            realOriginalInstructionConstant=10.0,hardwareAccelerationMeasured=False),
        originalSenderDirectObjectOffsets=[8,16,24,32,40,48],ownFakeWrapperCompatible=False,
        actualReads=reads,originalVZLoaded=False,functionsExecuted=0,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0))
    pins=[p.pin(Path(__file__)),p.pin(prior/'audit.json'),p.pin(prior/'freeze.json'),p.pin(out/'audit.json')]+[r['data']for r in reads]
    p.save(out/'freeze.json',dict(files=pins,deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),bindings=len(literals),RO=ro)))
if __name__=='__main__':main()
