#!/usr/bin/env python3
"""Request only a current MediaKit command prefix, never device execution."""
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('mediakit_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from current_hid_extra_three_capture_v1 import inventory,mapping
def main():
    out=p.NODE/'ipad-current-mediakit-command-prefix-plan-v1';assert not out.exists()
    heads=p.NODE/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    header=json.loads(heads.read_bytes());assert len(header['headers'])==17
    archive=p.NODE.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail=p.NODE/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows=inventory(archive.read_bytes()[:4096],tail.read_bytes(),header)
    declared=p.NODE/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    assert rows==json.loads(declared.read_bytes())
    actual=next(row for row in rows if row['path']=='/System/Library/PrivateFrameworks/MediaKit.framework/MediaKit')
    assert actual['UUID']=='bb1e22a209273ee8a614cc87ff8f34c3'
    request=dict(name='mediakit-command-prefix',**mapping(header,actual['address'],4096))
    assert request['cache'] in {row['name']for row in header['headers']}
    out.mkdir();p.save(out/'request.json',dict(ranges=[request]))
    p.save(out/'derivation.json',dict(schema='Current genuine MediaKit exact prefix plan v1',
        headers=p.pin(heads),actualCurrentInventoryRow=actual,
        mainHeaderArchiveUsedOnlyAfterActualIdentityGuard=True,actualInventoryTail=p.pin(tail),
        matchingActualInventory=p.pin(declared),request=p.pin(out/'request.json'),
        previousDI2UncapturedStrongNames=['_MKCFBuildPartition','_MKCFCreateMap','_MKCFCreateMedia','_MKCFDisposeMedia','_MKCFReadMedia','_MKCFWriteMedia','_MKCreateMediaDeviceRefcon','_MKMediaCreate','_kMKMediaBlockDeviceVector'],
        currentCommandOrExportRead=False,currentDefinitionsValidated=False,deviceOperations=0))
    p.save(out/'freeze.json',dict(files=[p.pin(file)for file in [Path(__file__),heads,archive,tail,declared,out/'request.json',out/'derivation.json']],deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'),range=request,freeze=p.pin(out/'freeze.json'))))
if __name__=='__main__':main()
