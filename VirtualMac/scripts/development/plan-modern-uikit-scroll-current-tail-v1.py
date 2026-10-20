#!/usr/bin/env python3
"""Join actual UIKit prefix derivation with twenty current scroll table bytes."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('uikit_tail_s', HERE/'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
p = s.p
from current_hid_extra_three_capture_v1 import mapping

def main():
    out=p.NODE/'ipad-current-uikit-scroll-bounded-tail-plan-v1'; assert not out.exists()
    headers_path=p.NODE/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    headers=json.loads(headers_path.read_bytes())
    prior=p.NODE/'ipad-current-uikit-own-input-command-prefix-plan-v1'
    capture=p.NODE/'ipad-current-uikit-own-input-command-prefix-readonly-v1'
    receipt=s.checked_capture(capture,prior/'request.json',headers_path)
    derivation=json.loads((prior/'derivation.json').read_bytes())
    ranges=[]; images=[]
    for item in derivation['images']:
        stem=item['request']['name'].removesuffix('-command-prefix')
        raw=(capture/(stem+'-command-prefix.bin')).read_bytes()
        magic,cpu,sub,kind,count,sizeofcmds,flags,reserved=struct.unpack_from('<8I',raw)
        assert magic==0xfeedfacf and kind==6 and count>0 and 0<sizeofcmds<65536
        total=32+sizeofcmds; base=item['actualImage']['address']
        if total>len(raw):
            request=dict(name=stem+'-command-tail',**mapping(headers,base+len(raw),total-len(raw)))
            ranges.append(request);images.append(dict(stem=stem,expectedCommandBytes=total,actualPrefix=p.pin(capture/(stem+'-command-prefix.bin')),request=request))
        else:
            full=raw[:total]; commands=list(p.commands(full));assert len(commands)==count
            at=next(at for cmd,at,size in commands if cmd==0x80000033)
            off,length=struct.unpack_from('<II',full,at+8)
            link=next(seg for seg in p.segments(full) if seg['name']=='__LINKEDIT')
            request=dict(name=stem+'-exports',**mapping(headers,link['address']+off-link['fileoff'],length))
            ranges.append(request);images.append(dict(stem=stem,expectedCommandBytes=total,actualPrefix=p.pin(capture/(stem+'-command-prefix.bin')),request=request,LCExportsOffset=off,LCExportsBytes=length,linkedit=link))
    scroll=p.NODE/'iokit-processed-scroll-native-contract-readonly-v2'
    for pin in json.loads((scroll/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    ranges+=json.loads((scroll/'request.json').read_bytes())['ranges']
    assert len(ranges)<=16 and sum(r['length'] for r in ranges)<65536
    out.mkdir();p.save(out/'request.json',dict(ranges=ranges))
    p.save(out/'derivation.json',dict(schema='Current UIKit actual tail and scroll table request v1',images=images,
        actualPrefixReceipt=p.pin(capture/'receipt.json'),originalPrefixPlan=p.pin(prior/'derivation.json'),
        currentHeaders=p.pin(headers_path),scrollCurrentBodyAudit=p.pin(scroll/'audit.json'),
        scrollTableRequest=p.pin(scroll/'request.json'),request=p.pin(out/'request.json'),
        actualUIKitDefinitionsProven=False,actualScrollTableBytesRead=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0))
    pins=[p.pin(Path(__file__)),p.pin(headers_path),p.pin(prior/'derivation.json'),p.pin(prior/'request.json'),p.pin(scroll/'audit.json'),p.pin(scroll/'request.json')]
    pins += [p.pin(capture/name) for name in ('receipt.json','manifest.json','reader-source.py','script.sh','stdout','stderr','uikit-command-prefix.bin','uikitcore-command-prefix.bin')]
    pins += [p.pin(out/'derivation.json'),p.pin(out/'request.json')]
    p.save(out/'freeze.json',dict(files=pins,deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),ranges=ranges,bytes=sum(r['length'] for r in ranges))))
if __name__=='__main__':main()
