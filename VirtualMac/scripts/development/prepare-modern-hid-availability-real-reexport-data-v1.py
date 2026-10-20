#!/usr/bin/env python3
"""Route the one real UH availability entry via AR and actual AV. Inert only."""
import argparse, importlib.util, json, struct, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('availability_route_stock',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
p=s.p
BASE=p.NODE/'universalhid-coro-real-reexport-data-v2/candidate.json'
BUILD=p.NODE/'swift-os-or-variant-data-build-v7/candidate.json'
SYMBOL='_$ss042_stdlib_isOSVersionAtLeastOrVariantVersiondE0yBi1_Bw_BwBwBwBwBwtF'


def checked(path):
    for row in json.loads((path.parent/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path']))==row
    return json.loads(path.read_bytes())


def image(path,alias):
    data=Path(path['path']).read_bytes()
    for cmd,at,size in p.commands(data):
        if cmd==0x80000033:
            off,n=struct.unpack_from('<II',data,at+8);tree=s.primary.trie(data[off:off+n])
        elif cmd==27:uuid=data[at+8:at+24].hex()
    return dict(path=alias,UUID=uuid,exports=tree,dependencies=p.dependencies(data),image=path)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(p.NODE)and not out.exists();out.mkdir()
    base,build=checked(BASE),checked(BUILD)
    ios=next(x for x in build['roles']if x['role']=='ios')
    assert len(ios['currentStrongNativeDefinitions'])==3 and all(x['definition']['status']=='actualDirectExport'for x in ios['currentStrongNativeDefinitions'])
    source_ar=base['modifiedArrayReexportProvider']['candidate'];old=Path(source_ar['path']).read_bytes();new=bytearray(old)
    count,size=struct.unpack_from('<II',old,16);ordinal=p.append_dependency(new,'@loader_path/AV');assert ordinal==4
    command=p.dependencies(new)[-1];assert command['at']==32+size and command['size']==40
    struct.pack_into('<I',new,command['at'],0x8000001f)
    expected=bytearray(old);struct.pack_into('<II',expected,16,count+1,size+40);expected[32+size:32+size+40]=new[32+size:32+size+40]
    assert new==expected and p.imports(new)['imports']==p.imports(old)['imports']
    ar=out/'AR.real-availability-reexport.inert.macho-data';ar.write_bytes(new)
    av=out/'AV.unchanged-unsigned-ios-provider.inert.macho-data';av.write_bytes(Path(ios['provider']['path']).read_bytes());assert p.pin(av)['sha256']==ios['provider']['sha256']
    uhsource=next(x for x in base['images']if x['name']=='UniversalHID')['candidate'];before=Path(uhsource['path']).read_bytes();after=bytearray(before)
    items=p.imports(before)['imports'];selected=[x for x in items if x['name']==SYMBOL];assert len(selected)==1
    item=selected[0];assert item['index']==153 and item['ordinal']==8 and not item['weak'];at=item['command'];after[at]=20
    assert after[:at]==before[:at]and after[at+1:]==before[at+1:]
    newitems=p.imports(after)['imports'];assert len(newitems)==len(items)
    for a,b in zip(items,newitems,strict=True):assert b==({**a,'ordinal':20}if a['index']==153 else a)
    uh=out/'UniversalHID27.availability-real-reexport.mac.inert.macho-data';uh.write_bytes(after)
    uhk=next(x for x in base['images']if x['name']=='UniversalHIDKit')['candidate']
    images=s.primary.captured_images()
    for group,header in[('system','system-v1'),('stock-extra','stock-extra-v1'),('cxx-leaf','cxx-leaf-v1'),('dyld-leaf','dyld-leaf-v2'),('xpc-leaf','xpc-leaf-v2')]:
        stem,version=header.rsplit('-',1);s.join_capture(images,group,p.NODE/('ipad-current-cache-'+stem+'-headers-'+version+'/headers.json'))
    for alias,path in[('AR',p.pin(ar)),('AV',p.pin(av)),('CR',base['unchangedRuntimeProvider']['candidate']),('UniversalHID27.dylib',p.pin(uh))]:
        name='@loader_path/'+alias;images[s.primary.canonical_path(name)]=image(path,name)
    proof=s.primary.resolve(images,'@loader_path/AR',SYMBOL);leaf=proof
    while 'nested'in leaf:leaf=leaf['nested']
    assert proof['status']=='actualDirectExport'and leaf['owner']=='@loader_path/AV'
    validations=[]
    for path in[ar,av,uh]:
        r=subprocess.run(['xcrun','dyld_info','-validate_only',str(path)],capture_output=True,text=True);assert r.returncode==0,r.stderr
        validations.append(dict(image=p.pin(path),exit=r.returncode,stdout=r.stdout,stderr=r.stderr))
    report=dict(schema='One exact genuine availability strong reexport inert data v1',sources=[p.pin(BASE),p.pin(BUILD)],
        images=[dict(name='UniversalHID',source=uhsource,candidate=p.pin(uh),route=dict(index=153,symbol=SYMBOL,at=at,oldOrdinal=8,newOrdinal=20,strong=True),allInstructionsMetadataAndPACBytesPreserved=True),dict(name='UniversalHIDKit',source=uhk,candidate=uhk,wholeBytesUnchanged=True)],
        modifiedArrayReexportProvider=dict(alias='AR',source=source_ar,candidate=p.pin(ar),addedGenuineReexport=dict(ordinal=4,path='@loader_path/AV',bytes=40),allOriginalSectionsImportsAndChainedPointersPreserved=True,preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='AV',source=ios['provider'],candidate=p.pin(av)),preservedCoroProvider=base['unchangedRuntimeProvider'],
        exactReexportDefinition=proof,routedStrongImports=1,structuralValidations=validations,trueNativeSystemAvailabilityQueries=True,hostVersionSpoofed=False,
        originalCallerFunctionABI=p.pin(p.NODE/'swift-os-or-variant-original-abi-readonly-v3/audit.json'),
        completeOriginal27MetadataPreserved=False,allCurrentProvidersDeclared=False,currentCompleteProviderDependencyGraphValidated=False,
        metadataCompatibilityProven=False,originalUHLoaded=False,originalVZLoaded=False,nativeIOSExecuted=False,deviceOperations=0,codeSigned=False,full27Backend=False)
    p.save(out/'candidate.json',report)
    files=[Path(__file__),BASE,BUILD,BASE.parent/'freeze.json',BUILD.parent/'freeze.json',out/'candidate.json',ar,av,uh,Path(source_ar['path']),Path(uhsource['path']),Path(uhk['path']),Path(ios['provider']['path'])]
    p.save(out/'freeze.json',dict(files=[p.pin(x)for x in files],deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),strongImportsRouted=1,structuralValidations=3)))

if __name__=='__main__':main()
