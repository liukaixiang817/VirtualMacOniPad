#!/usr/bin/env python3
"""Freeze unchanged Metal/VZ route bytes with fresh complete native leaf definitions."""
import copy,importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('metal_closed',HERE/'prepare-modern-vz-metal-array-real-reexport-v1.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r);p=r.p

def main():
    n=p.NODE;out=n/'vz-metal-array-real-reexport-data-v4';assert not out.exists()
    prior=n/'vz-metal-array-real-reexport-data-v3/candidate.json'
    supplement=n/'metal-current-strong-definitions-readonly-v1/audit.json'
    pins=[p.pin(Path(__file__))]
    for source in (prior,supplement):
        for pin in json.loads((source.parent/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
        pins += [p.pin(source),p.pin(source.parent/'freeze.json')]
    old=json.loads(prior.read_bytes());proof=json.loads(supplement.read_bytes())
    assert proof['currentStockImages']==34 and proof['allMDTwelvePositiveStrongDefinitionsCurrent']
    assert proof['unchangedVZRouteCandidate']==p.pin(prior)
    assert not proof['readyForDeviceExecution']and not old['originalVZLoaded']
    source_frontend=old['frontendCandidate'];source_md=old['unchangedRuntimeProvider']['candidate']
    out.mkdir(mode=0o700)
    frontend=out/'VZ27.metal-array-real-reexport.mac.inert.macho-data';md=out/'MD.unchanged-unsigned-ios-provider.inert.macho-data'
    for source,path in ((source_frontend,frontend),(source_md,md)):
        path.write_bytes(Path(source['path']).read_bytes());actual=p.pin(path)
        assert all(actual[k]==source[k]for k in ('sha256','bytes'))
    before=Path(old['sourceFrontend']['path']).read_bytes();r.contract(before,frontend.read_bytes())
    result=copy.deepcopy(old)
    result.update(schema='Finite Metal true reexport inert VZ route with current 34 stock definitions v2',
        priorFrozenRoute=p.pin(prior),actualCurrentStrongDefinitionSupplement=p.pin(supplement),frontendCandidate=p.pin(frontend),
        currentStockImages=34,positiveMDCurrentStrongDefinitions=12,remainingMDCurrentDefinitionsUnverified=[],
        completeMDCurrentStrongDefinitionsValidated=True,actualMDCurrentStrongDefinitions=proof['exactImageProofs'][0],
        ordinaryFixtureCurrentStrongDefinitions=proof['exactImageProofs'][1],currentDefinitionClosureUpdatedOnly=True,
        priorFrontendAndMDWholeBytesPreserved=True,actualIPadGPUObjectOrSelectorsValidated=False,
        candidateReadyForNativeLoading=False,originalVZLoaded=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
    result['unchangedRuntimeProvider'].update(source=source_md,candidate=p.pin(md))
    result['sources'] += [p.pin(Path(__file__)),p.pin(prior),p.pin(supplement)]
    p.save(out/'candidate.json',result)
    pins += [p.pin(x)for x in (Path(r.__file__),frontend,md,out/'candidate.json')]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),frontend=p.pin(frontend),
        MD=p.pin(md),positiveMDStrongDefinitions=12,unknownMDStrongDefinitions=0)))

if __name__=='__main__':main()
