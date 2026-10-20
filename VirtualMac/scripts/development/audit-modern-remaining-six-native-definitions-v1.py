#!/usr/bin/env python3
"""Small exact delta audit of six captured trees and the declared 51 providers.

The VZ two-branch candidate changes code only; this audit confirms its imports
remain the same. It does not repeat a large frontier or infer runtime closure.
"""
import collections
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('six_delta_frontier',HERE/'audit-modern-genuine-hid-current-frontier-v19.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
from current_private_commoncrypto_capture_v1 import join as join_crypto
from current_remaining_six_capture_v1 import join as join_six
p,s,n=f.p,f.s,f.NODE


def main():
    out=n/'current-remaining-six-native-definitions-readonly-v1';assert not out.exists()
    prior=n/'universalhid-current-exact-frontier-audit-v24/audit.json'
    port=n/'vz-metal-singleton-selection-data-v3/candidate.json'
    pins=[]
    for source in (prior,port):
        for row in json.loads((source.parent/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(source.parent/'freeze.json'))
    before=json.loads(prior.read_bytes());branch=json.loads(port.read_bytes())
    assert before['currentStockImages']==36 and before['declaredPrivateImages']==51
    assert branch['changedWholeFileBytes']==7 and branch['totalOriginalImports']==1056
    images=s.primary.captured_images()
    for group in ('system','stock-extra','cxx-leaf'):
        pins += s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf','xpc-leaf'):
        pins += s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins += f.join_kernel(s,images)
    for fn in (f.join_hid_extra,f.join_swift_two,f.join_eight,f.join_three,f.join_trace,f.join_unwind,f.join_compiler,join_crypto):
        added,_=fn(s,images);pins+=added
    assert len(images)==36
    extra,proof=join_six(s,images);pins+=extra;assert len(images)==42
    placements={}
    for row in before['privateDefinitions']:
        pin=row['image']
        if row['path']=='@loader_path/Virtualization':pin=branch['frontendCandidate']
        declared=f.image(pin,row['path']);key=s.primary.canonical_path(row['path'])
        assert key not in images;images[key]=declared;placements[row['image']['path']]=declared
        assert declared['UUID']==row['UUID'] and declared['dependencies']==row['dependencies'] and declared['rpaths']==row['rpaths']
        pins.append(pin)
    transitions=[];summaries=[]
    for old in before['auditedImages']:
        declared=placements[old['image']['path']]
        schema=f.import_records(Path(declared['image']['path']).read_bytes(),p.commands)
        ordinary=[row for row in schema['imports']if not row['weak']]
        assert len(ordinary)==old['strongImports']
        indexes={row['index']:row for row in ordinary};counts=collections.Counter()
        for previous in old['imports']:
            record=indexes[previous['index']]
            assert (record['name'],record['ordinal'],record['addend'])==(previous['symbol'],previous['ordinal'],previous['addend'])
            if record['ordinal']<=0:current=previous['proof']
            else:
                dependency=next(row for row in declared['dependencies']if row['ordinal']==record['ordinal'])
                assert dependency['path']==previous['dependency']
                current=f.resolve(images,dependency['path'],record['name'],declared)
            counts[current['status']]+=1
            if current['status']!=previous['proof']['status']:
                transitions.append(dict(owner=old['name'],index=previous['index'],symbol=record['name'],
                    dependency=previous['dependency'],previousStatus=previous['proof']['status'],currentStatus=current['status'],currentProof=current))
        summaries.append(dict(name=old['name'],candidate=declared['image'],strongImports=old['strongImports'],previousCounts=old['counts'],counts=dict(counts)))
    assert sum(row['strongImports']for row in summaries)==3647
    out.mkdir()
    totals=dict(sum((collections.Counter(row['counts'])for row in summaries),collections.Counter()))
    p.save(out/'audit.json',dict(schema='Exact six current native export delta on declared 51-provider set v1',
        nativeImages=42,declaredPrivateImages=51,actualSixCurrentCapture=proof,sourceFrontier=p.pin(prior),
        singletonCodeOnlyCandidate=p.pin(port),summaries=summaries,strongDefinitionTransitions=transitions,totalStrongImports=3647,
        counts=totals,onlyDeclaredProviderSetAudited=True,privateImportsBytePreserved=True,
        allNewOrdinaryPositiveDefinitionsFromActualTrees=True,uncapturedUmbrellaReexportsRemainUnproved=True,
        runtimeCallerABIForNewNativeDefinitionsValidated=False,originalVZExecuted=False,nativeCPUCalls=0,nativeVMCalls=0,
        functionsExecuted=False,deviceOperations=0,currentCompleteProviderDependencyGraphValidated=False,full27Backend=False))
    for row in proof['images']:
        p.save(out/(Path(row['actualPath']).name+'-exports.json'),images[s.primary.canonical_path(row['actualPath'])]['exports'])
    pins += [p.pin(path)for path in (Path(__file__),HERE/'current_remaining_six_capture_v1.py',HERE/'current_private_commoncrypto_capture_v1.py',prior,port)]
    pins += [p.pin(path)for path in out.iterdir()if path.is_file()]
    unique={row['path']:row for row in pins};assert all(unique[row['path']]==row for row in pins)
    p.save(out/'freeze.json',dict(files=list(unique.values()),deviceOperations=0,nativeCPUCalls=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),nativeImages=42,counts=totals,
                         transitions=len(transitions),negativeControls=len(proof['negativeControls']))))


if __name__=='__main__':main()
