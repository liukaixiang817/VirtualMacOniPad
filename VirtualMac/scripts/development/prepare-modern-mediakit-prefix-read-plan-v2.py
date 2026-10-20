#!/usr/bin/env python3
"""Request only a current MediaKit command prefix, never device execution."""
import importlib.util
import json
from pathlib import Path
import sys
import struct
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('mediakit_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from current_hid_extra_three_capture_v1 import inventory,mapping
def main():
    out=p.NODE/'ipad-current-mediakit-command-prefix-plan-v2';assert not out.exists()
    heads=p.NODE/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    header=json.loads(heads.read_bytes());assert len(header['headers'])==17
    archive=p.NODE.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail=p.NODE/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows=inventory(archive.read_bytes()[:4096],tail.read_bytes(),header)
    declared=p.NODE/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    assert rows==json.loads(declared.read_bytes())
    actual=next(row for row in rows if row['path']=='/System/Library/PrivateFrameworks/MediaKit.framework/MediaKit')
    assert actual['UUID']=='bb1e22a209273ee8a614cc87ff8f34c3'
    try:mapping(header,actual['address'],4096)
    except AssertionError:pass
    else:raise AssertionError('expected explicit unguarded current member boundary')
    archive_map_path=archive.with_name('ipad-cache-mappings.json')
    archive_maps=json.loads(archive_map_path.read_bytes())
    matches=[row for row in archive_maps if row['address']<=actual['address'] and actual['address']+4096<=row['address']+row['size']]
    assert len(matches)==1 and matches[0]['path'].endswith('/dyld_shared_cache_arm64e.31')
    physical=matches[0];paths=list(dict.fromkeys(row['path']for row in archive_maps))
    assert len(paths)==45 and len(archive.read_bytes())==len(paths)*4096
    member_header=archive.read_bytes()[paths.index(physical['path'])*4096:(paths.index(physical['path'])+1)*4096]
    assert member_header[:16]==b'dyld_v1  arm64e\0\0'
    assert member_header[88:104].hex()=='8310ea2468ca31f89f68ef2075185ea2'
    mo,mc=struct.unpack_from('<II',member_header,16);assert mc==1
    address,size,offset=struct.unpack_from('<QQQ',member_header,mo)
    assert (address,size,offset)==(physical['address'],physical['size'],physical['fileOffset'])
    request=dict(name='mediakit-command-prefix',cache='31',offset=offset+actual['address']-address,length=4096)
    out.mkdir();(out/'archived-31.header.bin').write_bytes(member_header)
    p.save(out/'request.json',dict(ranges=[request]))
    p.save(out/'derivation.json',dict(schema='Current genuine MediaKit exact prefix plan v1',
        headers=p.pin(heads),actualCurrentInventoryRow=actual,
        mainHeaderArchiveUsedOnlyAfterActualIdentityGuard=True,actualInventoryTail=p.pin(tail),
        matchingActualInventory=p.pin(declared),request=p.pin(out/'request.json'),
        archivedPhysicalMappingUsedOnlyToRequestGuard=physical,archivedHeader=p.pin(out/'archived-31.header.bin'),
        archivedMemberUUID='8310ea2468ca31f89f68ef2075185ea2',
        requiredCurrentHeaderCapture=dict(filename='dyld_shared_cache_arm64e.31',bytes=4096,mainHeaderBeforeAfterRequired=True),
        existingSeventeenMemberReaderCannotAcceptThisRequest=True,newFixedCurrent31HeaderAndReaderRequired=True,
        currentMemberHeaderCaptured=False,archivedMappingIsNotCurrentMappingEvidence=True,
        previousDI2UncapturedStrongNames=['_MKCFBuildPartition','_MKCFCreateMap','_MKCFCreateMedia','_MKCFDisposeMedia','_MKCFReadMedia','_MKCFWriteMedia','_MKCreateMediaDeviceRefcon','_MKMediaCreate','_kMKMediaBlockDeviceVector'],
        currentCommandOrExportRead=False,currentDefinitionsValidated=False,deviceOperations=0))
    p.save(out/'freeze.json',dict(files=[p.pin(file)for file in [Path(__file__),heads,archive,archive_map_path,tail,declared,out/'request.json',out/'derivation.json',out/'archived-31.header.bin']],deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),range=request,freeze=p.pin(out/'freeze.json'))))
if __name__=='__main__':main()
