#!/usr/bin/env python3
"""Fresh actual macOS27 SkyLight direct function bodies; never load or call."""
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('slp',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('slh',p.NODE/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
PATH='/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight'
NAMES=['_SLAssociateMouseAndMouseCursorPosition','_SLDisplayHideCursor','_SLDisplayShowCursor',
 '_SLEventCopyIOHIDEvent','_SLEventCreateFromData','_SLEventCreateKeyboardEvent','_SLEventGetIntegerValueField',
 '_SLSActuateDeviceWithPattern','_SLSIsScreenWatcherPresent','_SLSMainConnectionID','_SLSRegisterNotifyProc','_SLSRemoveNotifyProc']
def main():
    out=p.NODE/'vz-skylight-direct-providers-original-readonly-v1';assert not out.exists();out.mkdir()
    reads=[];functions=[]
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=cache.addSubCaches(p.CACHE)
        try:
            exports=p.GenuineCacheExports(cache);image=exports.image(PATH);assert image['UUID']=='8a3b348e4637368592d06cbc2f36a234'
            def read(va,length,label):
                assert 0<length<=2*1024*1024;offset,owner=cache.convertAddr(va);data=owner.getBytes(offset,length);assert len(data)==length
                file=out/(str(len(reads)).zfill(3)+'-'+label+'.bin');file.write_bytes(data)
                reads.append(dict(address=va,bytes=length,physicalUUID=bytes(owner.header.uuid).hex(),offset=offset,data=p.pin(file)));return data
            prefix=read(image['base'],32,'prefix');header=read(image['base'],32+struct.unpack_from('<I',prefix,20)[0],'commands')
            link=next(row for row in p.segments(header)if row['name']=='__LINKEDIT')
            off,length=next(struct.unpack_from('<II',header,at+8)for cmd,at,size in p.commands(header)if cmd==0x26)
            index=read(link['address']+off-link['fileoff'],length,'function-starts');starts=[];at=0;va=image['base']
            while at<len(index):
                delta,at=h.uleb(index,at)
                if not delta:break
                va+=delta;starts.append(va)
            assert starts==sorted(set(starts))and not any(index[at:])
            for name in NAMES:
                definition=exports.resolve(PATH,name);assert definition and definition['exportPath']==PATH and not definition['exportFlags']&8
                address=definition['exportAddress'];position=bisect.bisect_left(starts,address);assert starts[position]==address
                end=starts[position+1];assert end-address<=128*1024
                body=read(address,end-address,name.lstrip('_'))
                functions.append(dict(name=name,definition=definition,LC26Start=address,LC26End=end,completeLC26Function=True,
                    body=reads[-1]['data'],instructions=h.decode_body(body,address)))
        finally:
            for sub in subs:sub.close()
    p.save(out/'audit.json',dict(schema='Twelve genuine macOS27 SkyLight direct bodies exact bounded static v1',
        imagePath=PATH,imageUUID=image['UUID'],base=image['base'],functionStarts=p.pin(out/'002-function-starts.bin'),
        actualCompleteFunctions=functions,freshCacheReads=reads,originalFunctionsExecuted=0,newProvidersImplemented=False,
        deviceOperations=0,nativeCPUCalls=0,full27Backend=False))
    pins=[p.pin(Path(__file__))]+[p.pin(file)for file in out.iterdir()if file.is_file()]
    p.save(out/'freeze.json',dict(files=pins,deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),functions=[dict(name=r['name'],bytes=r['body']['bytes'])for r in functions])))
if __name__=='__main__':main()
