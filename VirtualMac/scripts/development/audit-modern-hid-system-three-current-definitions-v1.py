#!/usr/bin/env python3
"""Audit exact changed definitions after adding three actual libSystem leaf tables."""
import collections
import copy
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('frontier', HERE/'audit-modern-genuine-hid-current-frontier-v15.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
s, p = f.s, f.p
from current_hid_system_three_capture_v1 import join


def main():
    n = p.NODE
    out = n/'current-hid-system-three-definitions-readonly-v1'
    assert not out.exists()
    images = s.primary.captured_images()
    pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins += f.join_kernel(s, images)
    extra, _ = f.join_hid_extra(s, images); pins += extra
    extra, _ = f.join_swift_two(s, images); pins += extra
    extra, _ = f.join_eight(s, images); pins += extra
    assert len(images) == 29
    before = copy.deepcopy(images)
    extra, proof = join(s, images)
    pins += extra
    assert len(images) == 32
    prior_path = n/'universalhid-current-exact-frontier-audit-v17/audit.json'
    prior = json.loads(prior_path.read_bytes())
    assert prior['currentStockImages'] == 29 and prior['declaredPrivateImages'] == 37
    changes = []
    for image in prior['auditedImages']:
        for row in image['imports']:
            owner = row['dependency']
            if not isinstance(owner, str) or not owner.startswith('/'):
                continue
            old = s.primary.resolve(before, owner, row['symbol'])
            new = s.primary.resolve(images, owner, row['symbol'])
            if old != new:
                changes.append(dict(image=image['name'], index=row['index'], symbol=row['symbol'], dependency=owner,
                                    priorNativeDefinition=old, currentNativeDefinition=new))
    uh = next(x for x in prior['auditedImages'] if x['name'] == 'UniversalHID')
    queried = []
    for row in uh['imports']:
        if row['proof']['status'] == 'ownerHasNoDefinitionReexportsUnverified':
            queried.append(dict(index=row['index'], symbol=row['symbol'], dependency=row['dependency'],
                                actualCurrentDefinition=s.primary.resolve(images, row['dependency'], row['symbol'])))
    assert len(queried) == 12
    assert collections.Counter(x['actualCurrentDefinition']['status'] for x in queried) == {
        'actualDirectExport': 10, 'ownerHasNoDefinitionReexportsUnverified': 2}
    out.mkdir(mode=0o700)
    p.save(out/'audit.json', dict(schema='Three actual current libSystem leaf definition supplement v1',
        previousFrontier=p.pin(prior_path), previousCurrentStockImages=29, currentStockImages=32,
        newNativeImages=3, actualCommandAndExportProofs=proof['actualCommandAndExportProofs'],
        negativeControls=proof['negativeControls'], allChangedNativeProofs=changes,
        changedStatuses=dict(collections.Counter(x['currentNativeDefinition']['status'] for x in changes)),
        changedImageSummaries=dict(collections.Counter(x['image'] for x in changes)),
        exactTwelveUHStrongQueries=queried, tenOriginalUHStrongDefinitionsClosed=True,
        traceTwoDefinitionsStillUncaptured=True, specialOrdinalRowsPreservedUnproved=True,
        privateCandidatesRewritten=False, currentCompleteProviderGraphProven=False,
        definitionEvidenceOnly=True, actualNativeFunctionsExecuted=False,
        originalHIDLoaded=False, originalVZLoaded=False, deviceOperations=0, nativeCPUCalls=0,
        frameworkLoads=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [prior_path, Path(__file__), HERE/'current_hid_system_three_capture_v1.py',
                                    out/'audit.json', out/'source.py']]
    p.save(out/'freeze.json', dict(files=list({pin['path']: pin for pin in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'), freeze=p.pin(out/'freeze.json'),
                          changedStatuses=collections.Counter(x['currentNativeDefinition']['status'] for x in changes),
                          imageCounts=collections.Counter(x['image'] for x in changes))))


if __name__ == '__main__':
    main()
