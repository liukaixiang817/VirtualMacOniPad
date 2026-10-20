#!/usr/bin/env python3
"""Audit actual historical private files as a finite definition-only subset."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from macho_chained_import_records_v1 import read
spec = importlib.util.spec_from_file_location('declaration_frontier',HERE/'audit-modern-genuine-hid-current-frontier-v9.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
p=f.p
SOURCE=p.NODE/'vz-genuine-strong-closure-design-v2/build-v1/candidate.json'


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists();out.mkdir()
    source=json.loads(SOURCE.read_text());assert not source['completeStrongVZClosure'] and source['diagnosticFlatImportsRemaining']==6
    entries=[];checks=0;negatives=[]
    for pin in source['stagedPrivateLibraries']:
        path=Path(pin['path']);assert p.pin(path)==pin
        alias='@loader_path/'+path.name;image=f.image(pin,alias);raw=path.read_bytes()
        schema=read(raw,p.commands);rows=schema['imports']
        deps={x['ordinal']:x['path'] for x in image['dependencies']}
        assert all(x['ordinal']<=0 or x['ordinal'] in deps for x in rows)
        if schema['importsFormat']==1:
            original=p.imports(raw)['imports']
            assert rows==[dict(row,addend=0) for row in original]
            checks+=len(rows)
        specials=[x for x in rows if x['ordinal']<=0 and not x['weak']]
        entries.append(dict(name=path.stem,intendedLoadPath=alias,candidate=pin,UUID=image['UUID'],
            declaredSourceIsHistoricalPartialBundle=True,definitionEvidenceOnly=True,
            sourceFunctionSemanticsNewlyAudited=False,originalMetadataSemanticsNewlyAudited=False,
            currentFullLoadClosureProven=False,exportCount=len(image['exports']),dependencies=image['dependencies'],
            activeImportSchema=schema,specialStrongProcessNamespaceUnproved=specials))
        offset=schema['activeFixupsOffset']
        for label,position,value in [('version',offset,1),('compressed symbols',offset+24,1),
                ('invalid import format',offset+20,4),('overlap symbol pool',offset+12,0),
                ('record count budget',offset+16,1048577)]:
            changed=bytearray(raw);struct.pack_into('<I',changed,position,value)
            try:read(bytes(changed),p.commands)
            except (ValueError,struct.error):negatives.append(dict(owner=path.name,name=label,rejected=True))
            else:raise AssertionError('malformed record schema accepted')
    # Format2 genuine runtime addend and special ordinal contract is independently
    # checked against the existing root parser, rather than synthesized values.
    images=f.s.primary.captured_images()
    current_pins=[]
    for group in ('system','stock-extra','cxx-leaf','dyld-leaf','xpc-leaf'):
        version=2 if group in ('dyld-leaf','xpc-leaf') else 1
        current_pins+=f.s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v'+str(version)+'/headers.json'))
    current_pins+=f.join_kernel(f.s,images);assert len(images)==17
    runtime=f.s.runtime_import_contract(images)
    pin=runtime['runtimeProvider'];rows=read(Path(pin['path']).read_bytes(),p.commands)['imports']
    assert [(r['index'],r['name'],r['ordinal'],r['weak'],r['addend']) for r in rows]==[
        (r['index'],r['symbol'],r['ordinal'],r['weak'],r['addend']) for r in runtime['imports']]
    assert next(r for r in rows if r['name']=='__ZTVN10__cxxabiv120__si_class_type_infoE')['addend']==16
    assert next(r for r in rows if r['name']=='__ZdlPv')['ordinal']==-3
    checks+=len(rows)
    assert len(entries)==21
    report=dict(schema='Pinned actual private provider declaration subset and strict import schemas v1',
        source=p.pin(SOURCE),providers=entries,checks=checks,negativeControls=negatives,
        rootRuntimeImportRecordsCrossChecked=True,sourceManifestPartialStrongClosure=True,
        originalSixFlatLookupDiagnosticsRemainUnproved=6,allCurrentProvidersDeclared=False,
        currentCompleteProviderDependencyGraphValidated=False,providerFunctionSemanticsNewlyProven=False,
        originalMetadataSemanticsNewlyProven=False,nativeIOSExecuted=False,deviceOperations=0,full27Backend=False)
    p.save(out/'audit.json',report)
    paths=[Path(__file__),HERE/'macho_chained_import_records_v1.py',SOURCE,out/'audit.json']
    p.save(out/'freeze.json',dict(files=list(map(p.pin,paths))+source['stagedPrivateLibraries']+current_pins,deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),actualProviders=21,checks=checks,rejectedControls=len(negatives))))


if __name__=='__main__':main()
