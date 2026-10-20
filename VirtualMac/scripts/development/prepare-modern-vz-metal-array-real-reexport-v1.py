#!/usr/bin/env python3
"""Route VZ's Metal dependency to a finite true Metal reexport, as inert data."""
import argparse,importlib.util,json,struct,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('metal_frontier',HERE/'audit-modern-genuine-hid-current-frontier-v15.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);s,p=f.s,f.p
from current_hid_system_three_capture_v1 import join as join_three
from macho_chained_import_records_v1 import read
BASE=p.NODE/'vz-state2-oldhost-entry-data-v1/candidate.json'
BUILD=p.NODE/'metal-device-array-data-build-v4/candidate.json'
FRONTIER=p.NODE/'universalhid-current-exact-frontier-audit-v17/audit.json'
NATIVE='/System/Library/Frameworks/Metal.framework/Metal'

def checked(path):
    for row in json.loads((path.parent/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path']))==row
    return json.loads(path.read_bytes())

def contract(before,after):
    dep=p.dependencies(before)[25]
    assert dep['ordinal']==26 and dep['path']==NATIVE and dep['command']==12 and dep['size']==80
    offset=struct.unpack_from('<I',before,dep['at']+8)[0];assert offset==24
    expected=bytearray(before);start,end=dep['at']+offset,dep['at']+dep['size']
    changed=b'@loader_path/MD\0';assert len(changed)<=end-start
    expected[start:end]=changed+b'\0'*(end-start-len(changed))
    assert after==expected
    assert read(after,p.commands)==read(before,p.commands)
    old,new=p.vz_reader.parse(before),p.vz_reader.parse(after)
    assert old['words']==new['words'] and old['nlists']==new['nlists']
    actual=p.dependencies(after)
    assert actual==[dict(x,path='@loader_path/MD')if x['ordinal']==26 else x for x in p.dependencies(before)]
    return dict(ordinal=26,command=12,at=dep['at'],commandBytes=80,nameOffset=offset,
                oldPath=NATIVE,newPath='@loader_path/MD',nameStorageStart=start,nameStorageEnd=end,
                importRecordsWholeBytesUnchanged=True,allDependencyOrdinalsUnchanged=True)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    base,build,frontier=[checked(x)for x in (BASE,BUILD,FRONTIER)]
    assert not build['actualIPadProviderExecuted'] and not frontier['full27Backend']
    assert build['trueNativeMetalReexport']['command']==0x8000001f
    assert set(build['exactExports'])=={'_MTLCopyAllDevices'}
    source=base['frontendCandidate'];before=Path(source['path']).read_bytes();assert p.pin(Path(source['path']))==source
    schema=read(before,p.commands)
    native_imports=[x for x in schema['imports']if x['ordinal']==26]
    assert [(x['index'],x['name'],x['weak'])for x in native_imports]==[
        (296,'_MTLCopyAllDevices',False),(880,'_OBJC_CLASS_$_MTLRenderPassDescriptor',False),(881,'_OBJC_CLASS_$_MTLTextureDescriptor',False)]
    after=bytearray(before);dep=p.dependencies(before)[25];start=dep['at']+24;end=dep['at']+80
    replacement=b'@loader_path/MD\0';after[start:end]=replacement+b'\0'*(end-start-len(replacement))
    route=contract(before,bytes(after));out.mkdir(mode=0o700)
    vp=out/'VZ27.metal-array-real-reexport.mac.inert.macho-data';vp.write_bytes(after)
    old_md=build['iosProvider'];md=out/'MD.unchanged-unsigned-ios-provider.inert.macho-data';md.write_bytes(Path(old_md['path']).read_bytes())
    assert p.pin(md)['sha256']==old_md['sha256'] and p.pin(md)['bytes']==old_md['bytes']
    images=s.primary.captured_images();pins=[]
    for group in ('system','stock-extra','cxx-leaf'):
        pins+=s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf','xpc-leaf'):
        pins+=s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins+=f.join_kernel(s,images)
    for helper in (f.join_hid_extra,f.join_swift_two,f.join_eight,join_three):
        added,_=helper(s,images);pins+=added
    assert len(images)==32
    row=f.image(p.pin(md),'@loader_path/MD');images[s.primary.canonical_path('@loader_path/MD')]=row
    proof=f.resolve(images,'@loader_path/MD','_MTLCopyAllDevices')
    assert proof['status']=='actualDirectExport' and proof['owner']=='@loader_path/MD'
    import_proofs=[]
    for imported in native_imports:
        resolution=f.resolve(images,'@loader_path/MD',imported['name'])
        assert resolution['status']=='actualDirectExport'
        if imported['index']!=296:
            leaf=resolution
            while 'nested'in leaf:leaf=leaf['nested']
            assert leaf['owner']==NATIVE and leaf['UUID']=='8f062125748839efafda57db8cd80033'
        import_proofs.append(dict(**imported,actualNewDefinition=resolution))
    native_default=f.resolve(images,'@loader_path/MD','_MTLCreateSystemDefaultDevice')
    assert native_default['status']=='actualDirectExport'
    leaf=native_default
    while 'nested'in leaf:leaf=leaf['nested']
    assert leaf['owner']==NATIVE and leaf['UUID']=='8f062125748839efafda57db8cd80033'
    negatives=[]
    offsets=[('wrong Metal ordinal dependency command',dep['at']),('wrong replacement path',start),
        ('old instructions',9584),('old import strong bit',native_imports[0]['command']+1),
        ('old import name',native_imports[0]['command']+2)]
    chain=next(x for x in p.vz_reader.parse(before)['words']if x['auth']);offsets.append(('old PAC wholeword',chain['at']+4))
    offsets += [('old Swift metadata',next(x['fileoff']for z in p.segments(before)for x in z['sections']if x['name'].startswith('__swift5')))]
    for label,offset in offsets:
        malformed=bytearray(after);malformed[offset]^=1
        try:contract(before,bytes(malformed))
        except(AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted malformed Metal route')
    validations=[]
    for path in (vp,md):
        result=subprocess.run(['xcrun','dyld_info','-validate_only',str(path)],capture_output=True,timeout=30)
        assert result.returncode==0,result.stderr
        validations.append(dict(image=p.pin(path),exitCode=0))
    result=dict(schema='Finite owned Metal array true reexport inert VZ route v1',
        sources=[p.pin(x)for x in (Path(__file__),BASE,BUILD,FRONTIER)],sourceFrontend=source,
        frontendCandidate=p.pin(vp),unchangedRuntimeProvider=dict(alias='MD',intendedLoadPath='@loader_path/MD',source=old_md,candidate=p.pin(md)),
        modifiedDependency=route,routedStrongImports=import_proofs,routedStrongImportsCount=3,
        newlyClosedMissingStrongDefinitions=1,existingTwoClassDefinitionsPreservedThroughNativeMetalReexport=True,
        nativeMetalDefaultThroughTrueReexport=native_default,
        allOriginalCodeMetadataPACNlistAndImportRecordBytesPreserved=True,preexistingSignatureInvalidAfterHeaderMutation=True,
        currentStockImages=32,negativeControls=negatives,structuralValidations=validations,
        positiveMDCurrentStrongDefinitions=build['positiveCurrentStrongDefinitions'],remainingMDCurrentDefinitionsUnverified=build['remainingCurrentStrongDefinitionsUnverified'],
        completeMDCurrentStrongDefinitionsValidated=build['completeCurrentStrongDefinitionsValidated'],
        actualIPadGPUObjectOrSelectorsValidated=False,originalVZLoaded=False,originalVZCallerExecuted=False,
        candidateReadyForNativeLoading=False,codeSigned=False,deviceOperations=0,nativeCPUCalls=0,
        completeProviderGraphValidated=False,full27Backend=False)
    p.save(out/'candidate.json',result)
    pins += [p.pin(x)for x in (Path(__file__),Path(f.__file__),BASE,BUILD,FRONTIER,Path(source['path']),Path(old_md['path']),vp,md,out/'candidate.json')]
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),routedStrongImports=3,newlyClosedStrongDefinitions=1,negativeControls=len(negatives))))

if __name__=='__main__':main()
