#!/usr/bin/env python3
"""Request exactly two current UIKit command prefixes for the real own source.

Current image inventory and guarded maps only. No framework loading or device
operation is performed by this planner.
"""
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('uikit_s', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
from current_hid_extra_three_capture_v1 import join, inventory, mapping
p = s.p

def main():
    out = p.NODE / 'ipad-current-uikit-own-input-command-prefix-plan-v1'
    assert not out.exists()
    images = {}; pins, proof = join(s, images)
    headers_path = p.NODE / 'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    headers = json.loads(headers_path.read_bytes())
    prefix = p.NODE.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = p.NODE / 'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table = inventory(prefix.read_bytes()[:4096], tail.read_bytes(), headers)
    requests, selected = [], []
    for path, stem in (('/System/Library/Frameworks/UIKit.framework/UIKit', 'uikit'),
            ('/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore', 'uikitcore')):
        rows = [r for r in table if r['path'] == path]
        assert len(rows) == 1
        image = rows[0]
        request = dict(name=stem + '-command-prefix', **mapping(headers, image['address'], 4096))
        requests.append(request); selected.append(dict(actualImage=image, request=request))
    previous = p.NODE / 'uikit-own-input-surface-data-build-v6/candidate.json'
    provider = json.loads(previous.read_bytes())
    required = [r for r in provider['activeImportRecordSchema']['imports'] if r['ordinal'] == 1]
    assert len(required) == 13 and all(not r['weak'] for r in required)
    out.mkdir()
    p.save(out / 'request.json', dict(ranges=requests))
    p.save(out / 'derivation.json', dict(schema='Actual UIKit own input strong definition prefix request v1',
        currentHeaders=p.pin(headers_path), actualInventorySource=dict(prefixWhole4096SHAEqualsCurrentGuard=True,
            archivedPrefixContainer=p.pin(prefix), actualTail=p.pin(tail)), images=selected,
        requiredUIKitImports=required, actualOwnSourceCandidate=p.pin(previous),
        reader=p.pin(HERE / 'read-ipad-current-cache-ranges-readonly-v10.py'), request=p.pin(out/'request.json'),
        nativeUIKitStrongDefinitionsValidated=False, UIKitSelectorsOrRuntimeProven=False,
        sourceActuallyIntegrated=False, deviceOperations=0, nativeHVCalls=0, nativeVMCalls=0))
    pins += [p.pin(Path(__file__)), p.pin(headers_path), p.pin(prefix), p.pin(tail), p.pin(previous),
        p.pin(HERE/'read-ipad-current-cache-ranges-readonly-v10.py'), p.pin(out/'request.json'), p.pin(out/'derivation.json')]
    p.save(out/'freeze.json', dict(files=list({r['path']:r for r in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), ranges=requests, requestedBytes=8192)))

if __name__ == '__main__': main()
