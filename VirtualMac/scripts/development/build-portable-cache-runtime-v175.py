"""Runtime175: keep accepted Runtime174 and replace its parent cache helper."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess

R=Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'independent27-signed-runtime-portable-cache-v175-attempt1'
spec=importlib.util.spec_from_file_location('cache_runtime_base',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
pin=base.pin

def main():
    O.mkdir(mode=0o700)
    commands=[]
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode));base.save(O/'commands.json',commands)
        if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
    oldpath=N/'independent27-signed-runtime-vt-restore-v174-attempt1/candidate.json'
    newpath=N/'portable-vz-cache-helper-v2-attempt1/candidate.json'
    old=json.loads(oldpath.read_bytes());new=json.loads(newpath.read_bytes())
    original=Path(old['runtimeRoot']);runtime=O/'runtime'
    manifest=plistlib.loads(Path(old['manifest']['path']).read_bytes())
    rows={r['id']:r for r in manifest['files']};previous=copy.deepcopy(rows)
    helperid='parent:VM27OwnedVZStartCompat.dylib'
    proofs={r['relativePath']:r for r in json.loads(Path(old['signatureVerification']['path']).read_bytes())['actualSignedFiles']}
    for row in rows.values():
        source=original/row['path'];actual=pin(source)
        assert (actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256'])
        base.copy_regular(source,runtime/row['path'],executable=row['kind']=='mach-o')
    assert pin(new['provider']['path'])==new['provider']
    target=runtime/rows[helperid]['path'];target.unlink()
    base.copy_regular(Path(new['provider']['path']),target)
    run('sign-helper',['codesign','--force','--sign','-','--timestamp=none',
        '--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.parent.'+target.name,target])
    run('verify-helper',['codesign','--verify','--strict',target])
    # Check every new import against the same real host export index used by
    # the accepted closure. This is 16.1.1 evidence, not other-build acceptance.
    route_spec=importlib.util.spec_from_file_location('cache_native_routes',Path(__file__).with_name('build-owned-vz-start-compat-parent-v4.py'))
    route=importlib.util.module_from_spec(route_spec);route_spec.loader.exec_module(route)
    native=json.loads(route.NATIVE.read_bytes());image=base.image_profile(target.read_bytes(),helperid)
    nativeproof=[]
    for imp in image.imports:
        assert imp['ordinal']>0 and not imp['weak']
        load=next(r for r in image.loads if r['ordinal']==imp['ordinal'])
        found=route.native_routes(native,load['path'],imp['name'])
        assert found,imp
        nativeproof.append(dict(symbol=imp['name'],library=load['path'],definitions=found))
    signed=[]
    for row in rows.values():
        path=runtime/row['path']
        if row['kind']=='mach-o':
            im=base.image_profile(path.read_bytes(),row['id'])
            external={int(k):(runtime/rows[v]['path']).read_bytes()for k,v in row.get('signatureSlots',{}).items()}
            proof=base.signature(path.read_bytes(),im.uuid,external)
            row.update(uuid=proof['uuid'],cdhash=proof['cdhash'])
            prior=proofs[row['path']]
            signed.append(dict(role=prior.get('role',row['id'].split(':')[0]),key=prior.get('key',path.name),relativePath=row['path'],actualSignedFile=pin(path),**proof))
        rec=pin(path);row.update(bytes=rec['bytes'],sha256=rec['sha256'])
    graphid=manifest['dependencyProofID']
    priorgraph=json.loads((original/rows[graphid]['path']).read_bytes())
    assert priorgraph['finalStrongDefinitionGraphClosed'] and not priorgraph['unresolvedStrongImportRows']
    base.save(runtime/rows[graphid]['path'],dict(schema='Runtime175 parent cache portability delta',
        baselineRuntimeCandidate=pin(oldpath),components=pin(newpath),
        finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],newNativeImportDefinitions=nativeproof,
        originalCPUAndVMMAndGPUWhole=True,newDeviceGuestAcceptancePending=True))
    rec=pin(runtime/rows[graphid]['path']);rows[graphid].update(bytes=rec['bytes'],sha256=rec['sha256'])
    for identity,row in rows.items():
        if identity not in {helperid,graphid}:assert row==previous[identity]
    raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True)
    mp=runtime/'VM27IndependentRuntimeManifestV1.plist';mp.write_bytes(raw)
    anchor=O/'vm27_independent_runtime_product_anchor_v1.c'
    anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
    obj=O/'anchor.o';run('compile-anchor',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios15.0','-I',S,'-c',anchor,'-o',obj])
    probe=O/'preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\nint main(int n,char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)NSLog(@"%@",e);return ok?0:1;}}\n')
    exe=O/'preflight';run('compile-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe])
    run('preflight',[exe,runtime])
    sig=O/'signature-verification.json';base.save(sig,dict(actualSignedFiles=signed,actualSignedImages=len(signed),allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True))
    result=copy.deepcopy(old)
    contract=result['cacheAdapterContract'];contract['sourcePin']=new['sources'][0]
    contract.pop('nativeConfstrImageUUID',None);contract.pop('nativeConfstrRVA',None)
    contract.update(stableAppPath='/var/jb/Applications/VirtualMacIndependent27.app/VirtualMacIndependent27',nativeConfstrExactLoadedLibcExport=True)
    result.update(schema='Runtime175 portable cache helper; accepted CPU98/GIC19/MD27/GPU24 and native Hibernate retained',
        runtimeRoot=str(runtime),manifest=pin(mp),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(sig),
        builder=pin(__file__),baselineRuntimeCandidate=pin(oldpath),portableCacheComponents=pin(newpath),
        actualProductPreflightPassed=True,actualChangedRuntimeCDHashes=[rows[helperid]['cdhash']],
        deviceOperations=0,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,newDeviceGuestBootVerified=False)
    base.save(O/'candidate.json',result)
    print(json.dumps(dict(candidate=pin(O/'candidate.json'),changedHashes=result['actualChangedRuntimeCDHashes'])))

if __name__=='__main__':main()
