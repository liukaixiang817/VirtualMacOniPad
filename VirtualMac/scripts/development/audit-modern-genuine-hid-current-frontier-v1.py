#!/usr/bin/env python3
"""Audit the exact current inert HID/VZ/provider subset and twelve stock tries."""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('current_frontier_stock',HERE/'audit-modern-current-stock-extra-exports-v1.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
p=s.p;NODE=p.NODE
ARRAY=NODE/'universalhid-real-array-reexports-data-v1/candidate.json'
CP=NODE/'vz-cxx-six-strong-data-v2/candidate.json'
AB=NODE/'vz-arraybuffer-consume-strong-data-v1/candidate.json'
CG=NODE/'cgaffine-genuine-equal-private-v6/candidate.json'


def image(path,alias):
    assert p.pin(Path(path['path']))==path;body=Path(path['path']).read_bytes()
    uuid=None;exports=None
    for command,at,size in p.commands(body):
        if command==27:uuid=body[at+8:at+24].hex()
        if command==0x80000033:off,z=struct.unpack_from('<II',body,at+8);exports=s.primary.trie(body[off:off+z])
    assert uuid and exports is not None
    return dict(path=alias,UUID=uuid,image=path,exports=exports,dependencies=p.dependencies(body),inertApplicationPrivate=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    for source in(ARRAY,CP,AB,CG):
        for row in json.loads((source.parent/'freeze.json').read_text())['files']:assert p.pin(Path(row['path']))==row
    array=json.loads(ARRAY.read_text());cp=json.loads(CP.read_text());ab=json.loads(AB.read_text());cg=json.loads(CG.read_text())
    images=s.primary.captured_images();pins=s.join_capture(images,'system',NODE/'ipad-current-cache-system-headers-v1/headers.json')
    pins+=s.join_capture(images,'stock-extra',NODE/'ipad-current-cache-stock-extra-headers-v1/headers.json')
    assert len(images)==12
    declarations=[]
    for row in array['images']:
        if row['name']=='Virtualization':continue
        declarations.append((row['name'],'@loader_path/'+row['name']+'27.dylib',row['candidate']))
    declarations.append(('Virtualization','@loader_path/Virtualization27.dylib',ab['frontendCandidate']))
    declarations += [(r['alias'],r['intendedLoadPath'],r['candidate'])for r in array['unchangedRuntimeProviders']]
    declarations += [(r.get('alias',Path(r['candidate']['path']).name),r['intendedLoadPath'],r['candidate'])for r in cp['unchangedRuntimeProviders']]
    r=ab['unchangedRuntimeProvider'];declarations.append(('AB',r['intendedLoadPath'],r['candidate']))
    # CG's inspected, unsigned provider is a real original 108-byte leaf.
    declarations.append(('CGe','@loader_path/CGe',cg['iosProvider']))
    private=[]
    for name,alias,path in declarations:
        key=s.primary.canonical_path(alias);assert key not in images
        row=image(path,alias);images[key]=row;private.append((name,row))
    results=[]
    for name,row in private:
        body=Path(row['image']['path']).read_bytes();status='parsedExactActiveImportTable'
        try:
            if name=='Virtualization':imports=p.vz_reader.parse(body)['imports']
            else:imports=p.imports(body)['imports']
        except(ValueError,AssertionError):
            imports=[];status='unsupportedImportSchemaNotProven'
        dependencies={r['ordinal']:r['path']for r in row['dependencies']};rows=[]
        for item in imports:
            if item['weak']:continue
            ordinal=item['ordinal'];owner=dependencies.get(ordinal)
            if ordinal<=0:
                proof=dict(status='unresolvedSpecialOrdinal',specialOrdinal=ordinal,symbol=item['name'])
            else:
                assert owner is not None;proof=s.primary.resolve(images,owner,item['name'])
            rows.append(dict(index=item['index'],symbol=item['name'],ordinal=ordinal,dependency=owner,proof=proof))
        results.append(dict(name=name,path=row['path'],image=row['image'],importAuditStatus=status,strongImports=len(rows),
                            counts=dict(collections.Counter(r['proof']['status']for r in rows)),imports=rows))
    # Definitions from this declared subset only: resolved does not mean
    # metadata, provider constructors or the complete image graph are valid.
    assert s.primary.resolve(images,'@loader_path/UniversalHID27.dylib','_$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5')['status']=='actualDirectExport'
    assert s.primary.resolve(images,'@loader_path/UniversalHID27.dylib','__VM27_absent__')['status']in('actualExportAbsent','ownerHasNoDefinitionReexportsUnverified')
    assert s.primary.resolve(images,'@loader_path/VM27SwiftLookup.dylib','_swift_getTypeByMangledNameInContextInMetadataState2')['status']=='uncapturedOwner'
    report=dict(schema='Latest exact declared genuine HID/VZ strong export frontier v1',currentCacheUUID='1995ea169d0a33a0b78962cf99891168',
                sourceArray=p.pin(ARRAY),sourceCP=p.pin(CP),sourceAB=p.pin(AB),sourceEquality=p.pin(CG),
                currentStockImages=12,declaredPrivateImages=len(private),auditedImages=results,
                privateDefinitions=[{k:v for k,v in row.items()if k!='exports'}|dict(exportCount=len(row['exports']))for name,row in private],
                definitionEvidenceOnly=True,allCurrentProvidersDeclared=False,currentCompleteProviderDependencyGraphValidated=False,
                conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,metadataCompatibilityProven=False,
                originalVZLoaded=False,originalVMMExecuted=False,nativeIOSExecuted=False,deviceOperations=0,full27Backend=False)
    p.save(out/'audit.json',report)
    pins+=[p.pin(path)for path in(Path(__file__),HERE/'audit-modern-current-stock-extra-exports-v1.py',ARRAY,CP,AB,CG,out/'audit.json')]
    pins+=[row['image']for name,row in private]
    p.save(out/'freeze.json',dict(files=pins,deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),images=[dict(name=r['name'],status=r['importAuditStatus'],counts=r['counts'])for r in results])))


if __name__=='__main__':main()
