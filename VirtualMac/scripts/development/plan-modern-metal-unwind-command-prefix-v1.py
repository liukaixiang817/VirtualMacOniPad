#!/usr/bin/env python3
"""Plan a bounded actual libunwind command prefix for the Metal ownership leaf."""
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('metal_current_stock',HERE/'audit-modern-genuine-hid-current-frontier-v15.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
s,p=f.s,f.p
from current_hid_extra_three_capture_v1 import inventory,mapping

def main():
    out=p.NODE/'ipad-current-metal-unwind-command-prefix-plan-v1'
    assert not out.exists()
    hp=p.NODE/'ipad-current-cache-trace-header-readonly-v1/headers.json'
    headers=json.loads(hp.read_bytes())
    assert len(headers['headers'])==14 and p.pin(hp)['sha256']=='f457d8f2168723936b1e363967b3d07ed047f89da967cc7d8eed9603ff1bb868'
    images={};pins=s.join_capture(images,'system',p.NODE/'ipad-current-cache-system-headers-v1/headers.json')
    added,_=f.join_hid_extra(s,images);pins+=added
    archive=p.NODE.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail=p.NODE/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table=p.NODE/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    rows=inventory(archive.read_bytes()[:4096],tail.read_bytes(),headers)
    assert len(rows)==2600 and rows==json.loads(table.read_bytes())
    path='/usr/lib/system/libunwind.dylib'
    targets=[x for x in rows if x['path']==path]
    assert len(targets)==1 and targets[0]['UUID']=='41f6058d8f923691ad00f37a64a36be4'
    dependencies=[x for x in images['/usr/lib/libSystem.B.dylib']['dependencies'] if x['path']==path]
    assert len(dependencies)==1 and dependencies[0]['command']==0x8000001f
    row=dict(name='metal-unwind-commands-prefix',**mapping(headers,targets[0]['address'],4096))
    assert row['offset']>=4096 and row['cache'] in {x['name']for x in headers['headers']}
    provider=p.NODE/'metal-device-array-data-build-v3/MD.unsigned.inert.macho-data'
    from macho_chained_import_records_v1 import read
    b=provider.read_bytes();records=read(b,p.commands)
    imported=[x for x in records['imports']if x['name']=='__Unwind_Resume']
    assert len(imported)==1 and not imported[0]['weak'] and imported[0]['ordinal']==3
    assert p.dependencies(b)[2]['path']=='/usr/lib/libSystem.B.dylib'
    reader=HERE/'read-ipad-current-cache-ranges-readonly-v9.py'
    assert p.pin(reader)['sha256']=='c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
    out.mkdir(mode=0o700)
    p.save(out/'request.json',dict(ranges=[row]))
    p.save(out/'derivation.json',dict(schema='Actual guarded libunwind prefix for finite Metal leaf v1',
        currentHeaders=p.pin(hp),reader=p.pin(reader),actualInventory=p.pin(table),actualImage=targets[0],
        actualLibSystemReexport=dependencies[0],actualInertProvider=p.pin(provider),actualStrongImport=imported[0],
        particularLeafDefinitionProven=False,completeCommandsCaptured=False,
        request=row,requestedRanges=1,requestedBytes=4096,deviceOperations=0,nativeCPUCalls=0,
        frameworkLoads=0,full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(x)for x in (Path(__file__),hp,reader,archive,tail,table,provider,out/'source.py',out/'request.json',out/'derivation.json')]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),freeze=p.pin(out/'freeze.json'),range=row)))

if __name__=='__main__':main()
