#!/usr/bin/env python3
"""Resolve all actual own ingress strong names against current captured native bytes."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('ingress_defs_f',HERE/'audit-modern-genuine-hid-current-frontier-v20.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
p,s,n=f.p,f.s,f.n
from macho_chained_import_records_v1 import read as import_records

def main():
    out=n/'own-uikit-genuine-input-ingress-current-definitions-readonly-v1';assert not out.exists()
    images=s.primary.captured_images();pins=[]
    for group in ('system','stock-extra','cxx-leaf'):
        pins+=s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf','xpc-leaf'):
        pins+=s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins+=f.f.join_kernel(s,images)
    for fn in (f.f.join_hid_extra,f.f.join_swift_two,f.f.join_eight,f.f.join_three,
        f.f.join_trace,f.f.join_unwind,f.f.join_compiler,f.f.join_crypto):
        added,_=fn(s,images);pins+=added
    assert len(images)==36
    source=n/'own-uikit-genuine-input-ingress-source-build-v1';candidate=json.loads((source/'candidate.json').read_bytes())
    file=Path(candidate['provider']['path']);assert p.pin(file)==candidate['provider'];raw=file.read_bytes()
    imports=import_records(raw,p.commands);owners={row['ordinal']:row['path']for row in p.dependencies(raw)}
    assert len(imports['imports'])==62;proofs=[]
    for row in imports['imports']:
        assert row['ordinal']>0 and not row['weak'];owner=owners[row['ordinal']]
        proof=s.primary.resolve(images,owner,row['name']);assert proof['status']=='actualDirectExport',(row,proof)
        proofs.append(dict(row,dependency=owner,proof=proof))
    negatives=[]
    for name in ('_class_getInstanceMethod','_OBJC_CLASS_$_NSThread','_strcmp'):
        row=next(row for row in proofs if row['name']==name);graph=copy.deepcopy(images)
        defined=row['proof']
        while 'nested'in defined:defined=defined['nested']
        graph[s.primary.canonical_path(defined['owner'])]['exports'].pop(name)
        assert s.primary.resolve(graph,row['dependency'],name)['status']!='actualDirectExport'
        negatives.append(dict(name=name,exactDefinitionRemovalRejected=True))
    out.mkdir();p.save(out/'audit.json',dict(schema='Current exact own copied UIKit genuine value source 62 strong definitions v1',
        sourceCandidate=p.pin(source/'candidate.json'),provider=p.pin(file),actualCurrentNativeTables=36,
        actualStrongImports=62,exactCurrentDefinitions=proofs,missingExactNames=0,negativeControls=negatives,
        namedDefinitionClosureOnly=True,completeTransitiveNamespaceValidated=False,originalVZClassOrSendersExecuted=False,
        UIKitOrBackendThreadRuntimeValidated=False,productionAppIntegrated=False,deviceOperations=0,
        nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
    for row in json.loads((source/'freeze.json').read_bytes())['files']:assert p.pin(Path(row['path']))==row;pins.append(row)
    pins += [p.pin(source/'freeze.json'),p.pin(Path(__file__)),p.pin(out/'audit.json')]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),actualStrongImports=62,missingExactNames=0)))
if __name__=='__main__':main()
