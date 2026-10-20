#!/usr/bin/env python3
"""Audit a newly captured CommonCrypto leaf without changing provider bytes."""
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec = importlib.util.spec_from_file_location('crypto_frontier',HERE/'audit-modern-genuine-hid-current-frontier-v18.py')
f = importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
from current_private_commoncrypto_capture_v1 import join
p,s,n = f.p,f.s,f.NODE


def main():
    out = n/'current-private-commoncrypto-definitions-readonly-v1'; assert not out.exists()
    images = s.primary.captured_images(); pins=[]
    for group in ('system','stock-extra','cxx-leaf'):
        pins += s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf','xpc-leaf'):
        pins += s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins += f.join_kernel(s,images)
    for fn in (f.join_hid_extra,f.join_swift_two,f.join_eight,f.join_three,f.join_trace,f.join_unwind,f.join_compiler):
        added,_ = fn(s,images);pins += added
    assert len(images)==35
    added, proof = join(s,images);pins += added
    assert len(images)==36
    out.mkdir();p.save(out/'audit.json',dict(schema='Current actual CommonCrypto two private strong definitions v1',
        currentNativeImages=36,evidence=proof,priorEFIAndRTTIStrongDefinitionsClosed=2,
        newCandidatesCreated=False,providerLoaded=False,deviceOperations=0,nativeCPUCalls=0,
        CRCOrSHAFunctionExecuted=False,actualOriginalVZCallerExecuted=False,full27Backend=False))
    exports=images[s.primary.canonical_path(proof['actualPath'])]['exports']
    p.save(out/'exports.json',exports)
    pins += [p.pin(x) for x in (Path(__file__),HERE/'current_private_commoncrypto_capture_v1.py',HERE/'audit-modern-genuine-hid-current-frontier-v18.py',out/'audit.json',out/'exports.json')]
    unique={row['path']:row for row in pins};assert all(unique[row['path']]==row for row in pins)
    p.save(out/'freeze.json',dict(files=list(unique.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),currentNativeImages=36,
                         privateStrongDefinitionsClosed=2,negativeControls=len(proof['negativeControls']))))


if __name__=='__main__':main()
