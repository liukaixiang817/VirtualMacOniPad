#!/usr/bin/env python3
"""Add actual current unwind/trace proofs to unchanged finite Metal leaf data."""
import importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('metal_definition_frontier',HERE/'audit-modern-genuine-hid-current-frontier-v15.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);s,p=f.s,f.p
from current_hid_system_three_capture_v1 import join as join_three
from current_hid_trace_capture_v1 import join as join_trace
from current_metal_unwind_capture_v1 import join as join_unwind
from macho_chained_import_records_v1 import read

def main():
    n=p.NODE;out=n/'metal-current-strong-definitions-readonly-v1';assert not out.exists()
    sources=[n/'metal-device-array-data-build-v4/candidate.json',n/'metal-device-array-ordinary-ipad-fixture-build-v2/candidate.json',
        n/'vz-metal-array-real-reexport-data-v3/candidate.json',n/'metal-current-default-entry-readonly-v1/audit.json']
    pins=[p.pin(Path(__file__))]
    for source in sources:
        for pin in json.loads((source.parent/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
        pins += [p.pin(source),p.pin(source.parent/'freeze.json')]
    images=s.primary.captured_images()
    for group in ('system','stock-extra','cxx-leaf'):
        pins+=s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf','xpc-leaf'):
        pins+=s.join_capture(images,group,n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins+=f.join_kernel(s,images)
    evidence=[]
    for helper in (f.join_hid_extra,f.join_swift_two,f.join_eight,join_three,join_trace,join_unwind):
        added,proof=helper(s,images);pins+=added;evidence.append(proof)
    assert len(images)==34
    reports=[]
    for source,count,key in ((sources[0],12,'iosProvider'),(sources[1],23,'executable')):
        candidate=json.loads(source.read_bytes());pin=candidate[key];path=Path(pin['path']);assert p.pin(path)==pin
        raw=path.read_bytes();deps={x['ordinal']:x['path']for x in p.dependencies(raw)};schema=read(raw,p.commands)
        assert len(schema['imports'])==count
        proofs=[]
        for record in schema['imports']:
            assert record['ordinal']>0 and not record['weak'];owner=deps[record['ordinal']]
            proof=s.primary.resolve(images,owner,record['name']);assert proof['status']=='actualDirectExport',(record,proof)
            proofs.append(dict(**record,dependency=owner,definition=proof))
        unwind=next(x for x in proofs if x['name']=='__Unwind_Resume')
        assert unwind['definition']==evidence[-1]['actualNativeUnwindResumeDefinition']
        reports.append(dict(sourceCandidate=p.pin(source),image=pin,actualCurrentStrongDefinitions=proofs,
            positiveStrongDefinitions=count,weakImports=0,specialImports=0,unprovedStrongDefinitions=0,
            originalCandidateWholeBytesUnchanged=True,currentDefinitionClosureProven=True,
            actualIPadExecuted=False,originalVZCallerExecuted=False,readyForNativeProductLoading=False))
    route=json.loads(sources[2].read_bytes());md=route['unchangedRuntimeProvider']['candidate']
    assert md['sha256']==reports[0]['image']['sha256']and md['bytes']==reports[0]['image']['bytes']
    images['@loader_path/MD']=f.image(md,'@loader_path/MD')
    route_proofs=[]
    for imported in route['routedStrongImports']:
        proof=f.resolve(images,'@loader_path/MD',imported['name']);assert proof['status']=='actualDirectExport'
        assert proof==imported['actualNewDefinition']
        route_proofs.append(dict(index=imported['index'],symbol=imported['name'],proof=proof))
    out.mkdir(mode=0o700)
    p.save(out/'audit.json',dict(schema='Actual current 34 stock finite Metal leaf strong definition supplement v1',
        sources=[p.pin(x)for x in sources],currentStockImages=34,exactImageProofs=reports,
        actualTraceDefinitionCapture=evidence[-2],actualUnwindDefinitionCapture=evidence[-1],
        unchangedVZRouteCandidate=p.pin(sources[2]),exactThreeVZMetalDefinitionRoutes=route_proofs,
        allMDTwelvePositiveStrongDefinitionsCurrent=True,allOrdinaryFixtureTwentyThreePositiveStrongDefinitionsCurrent=True,
        originalProviderFixtureAndVZDataWholeBytesUnchanged=True,definitionEvidenceOnly=True,
        actualIPadGPUOrSelectorsValidated=False,independentReviewComplete=False,actualIPadExecuted=False,
        readyForDeviceExecution=False,candidateReadyForNativeLoading=False,originalVZLoaded=False,
        currentCompleteProviderGraphProven=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False))
    pins += [p.pin(x)for x in (Path(join_trace.__code__.co_filename),Path(join_unwind.__code__.co_filename),out/'audit.json')]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),stock=34,MDstrong=12,fixtureStrong=23,unproved=0)))

if __name__=='__main__':main()
