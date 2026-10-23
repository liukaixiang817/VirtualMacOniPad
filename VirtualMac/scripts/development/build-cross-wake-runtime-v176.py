#!/usr/bin/env python3
"""Assemble Runtime176 with CPU99 cross-owner wake version reads."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

R=Path(__file__).resolve().parents[3]; S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'independent27-signed-runtime-cross-wake-v176-attempt1'
spec=importlib.util.spec_from_file_location('portable_runtime_primitives',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
pin=base.pin

def main():
    O.mkdir(mode=0o700);commands=[]
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode))
        base.save(O/'commands.json',commands)
        if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
    oldpath=N/'independent27-signed-runtime-portable-cache-v175-attempt1/candidate.json'
    newpath=N/'cpu-cross-wake-v99-attempt3/candidate.json'
    old=json.loads(oldpath.read_bytes());new=json.loads(newpath.read_bytes())
    original=Path(old['runtimeRoot']); runtime=O/'runtime'
    manifest=plistlib.loads(Path(old['manifest']['path']).read_bytes())
    rows={x['id']:x for x in manifest['files']}; previous=copy.deepcopy(rows)
    previousProof=json.loads(Path(old['signatureVerification']['path']).read_bytes())
    proofs={x['relativePath']:x for x in previousProof['actualSignedFiles']}
    for row in rows.values():
        source=original/row['path']; actual=pin(source)
        assert (actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256'])
        base.copy_regular(source,runtime/row['path'],executable=row['kind']=='mach-o')
    replacements={'parent:VM27HVVMProduction.dylib':new['cpu'],'child:VM27HVVMProduction.dylib':new['cpu']}
    unsigned={}
    for identity,record in replacements.items():
        assert pin(record['path'])==record
        path=runtime/rows[identity]['path'];path.unlink()
        unsigned[identity]=base.copy_regular(Path(record['path']),path)
        if identity.startswith('parent:'):
            run('sign-'+identity.replace(':','-'),['codesign','--force','--sign','-',
                '--timestamp=none','--digest-algorithm=sha256','--identifier',
                'org.lkx.VirtualMacIndependent27.parent.'+path.name,path])
    childid=manifest['childEntryContract']['childID'];child=runtime/rows[childid]['path']
    rawTracePatch=copy.deepcopy(old['rawHVTracePatch'])
    xpc=child.parent.parent.parent
    entitlements=proofs[rows[childid]['path']]['embeddedEntitlements']
    assert len(entitlements)==16
    ent=O/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements))
    with tempfile.TemporaryDirectory(prefix='vm27-portable-sign-',dir='/private/tmp') as work:
        bundle=Path(work)/xpc.name;shutil.copytree(xpc,bundle)
        run('clear-xattrs',['xattr','-cr',bundle])
        for identity in replacements:
            if not identity.startswith('child:'):continue
            path=bundle/(runtime/rows[identity]['path']).relative_to(xpc)
            run('sign-'+identity.replace(':','-'),['codesign','--force','--sign','-',
                '--timestamp=none','--digest-algorithm=sha256','--identifier',
                'org.lkx.VirtualMacIndependent27.child.'+path.name,path])
        run('sign-child',['codesign','--force','--sign','-','--timestamp=none',
            '--digest-algorithm=sha256','--identifier','com.apple.Virtualization.VirtualMachine',
            '--entitlements',ent,'--generate-entitlement-der',bundle])
        run('verify-child',['codesign','--verify','--strict',bundle])
        changed=[child,runtime/rows['child-coderesources']['path']]
        changed += [runtime/rows[x]['path'] for x in replacements if x.startswith('child:')]
        for target in changed:shutil.copyfile(bundle/target.relative_to(xpc),target)
    # Code and import bindings of the original VMM remain byte-for-byte intact.
    a=base.image_profile(child.read_bytes(),'VMM'); b=base.image_profile((original/rows[childid]['path']).read_bytes(),'VMM')
    assert a.uuid==b.uuid and a.imports==b.imports and a.exports==b.exports and a.loads==b.loads
    for section in b.sections:
        at,size=section['fileoff'],section['size']
        if at and size and section['flags']&255 not in (1,12,18):
            aa=bytearray(a.data[at:at+size]);bb=b.data[at:at+size]
            assert bytes(aa)==bb
    images={};signed=[]
    for row in rows.values():
        path=runtime/row['path']
        if row['kind']=='mach-o':
            image=base.image_profile(path.read_bytes(),row['id']);images[row['id']]=image
            external={int(k):(runtime/rows[v]['path']).read_bytes() for k,v in row.get('signatureSlots',{}).items()}
            proof=base.signature(path.read_bytes(),image.uuid,external)
            if row['id']==childid:assert proof['embeddedEntitlements']==entitlements
            if row['id'] in unsigned:
                im=base.image_profile(unsigned[row['id']],row['id'])
                assert im.uuid==image.uuid and im.imports==image.imports and im.exports==image.exports
                for section in im.sections:
                    at,size=section['fileoff'],section['size']
                    if at and size and section['flags']&255 not in (1,12,18):
                        assert unsigned[row['id']][at:at+size]==image.data[at:at+size]
            row.update(uuid=proof['uuid'],cdhash=proof['cdhash'])
            signed.append(dict(role=proofs[row['path']].get('role',row['id'].split(':')[0]),key=proofs[row['path']].get('key',path.name),
                relativePath=row['path'],actualSignedFile=pin(path),**proof))
        record=pin(path);row.update(bytes=record['bytes'],sha256=record['sha256'])
    for entry in manifest['entries']:
        if entry['fileID'] in replacements:
            definition=images[entry['fileID']].exports['_'+entry['symbol']]
            assert definition['flags']==0;entry['rva']=definition['address']
    contract=manifest['childEntryContract']
    if contract['providerID'] in replacements:
        contract['providerEntryRVA']=images[contract['providerID']].exports['_'+contract['symbol']]['address']
    graphid=manifest['dependencyProofID'];prior=json.loads((original/rows[graphid]['path']).read_bytes())
    assert prior['finalStrongDefinitionGraphClosed'] and not prior['unresolvedStrongImportRows']
    graph=dict(schema='CPU99 cross-owner wake reads: same imports, exports and load semantics; two changed objects',baselineRuntimeCandidate=pin(oldpath),
        baselineDependencyProof=pin(original/rows[graphid]['path']),components=pin(newpath),
        finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],
        changedProviders=new['comparisons'],newNativeImportsRestrictedToExistingHostFrameworks=True,nonStateCPUObjectsWhole=True,
        experimentalOSRange="15.0-16.3.1", actualGPUParentIdentityRefreshed=True,newDeviceGuestAcceptancePending=True)
    base.save(runtime/rows[graphid]['path'],graph)
    record=pin(runtime/rows[graphid]['path']);rows[graphid].update(bytes=record['bytes'],sha256=record['sha256'])
    allowed=set(replacements)|{childid,'child-coderesources',graphid}
    for identity,row in rows.items():
        if identity not in allowed:assert row==previous[identity]
    raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True)
    manifestpath=runtime/'VM27IndependentRuntimeManifestV1.plist';manifestpath.write_bytes(raw)
    anchor=O/'vm27_independent_runtime_product_anchor_v1.c'
    anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(v) for v in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
    anchorobj=O/'anchor.o';run('compile-anchor',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios15.0','-I',S,'-c',anchor,'-o',anchorobj])
    probe=O/'preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\nint main(int n,char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)NSLog(@"%@",e);return ok?0:1;}}\n')
    exe=O/'preflight';run('compile-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe])
    run('preflight',[exe,runtime])
    signature=O/'signature-verification.json';base.save(signature,dict(actualSignedFiles=signed,
        actualSignedImages=len(signed),allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True))
    result=copy.deepcopy(old)
    result.update(schema='Runtime176 CPU99 cross-owner wake reads; accepted cache and native Hibernate retained; device acceptance pending',
        runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(anchorobj),
        signatureVerification=pin(signature),builder=pin(__file__),baselineRuntimeCandidate=pin(oldpath),rawHVTracePatch=rawTracePatch,
        portableHostComponents=pin(newpath),actualProductPreflightPassed=True,deviceOperations=0,
        actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,
        cpuProviders=[pin(runtime/rows[x]['path']) for x in replacements],
        cpu29SourceProof=pin(newpath),cpu29Objects=new['changedCPUObjects']+new['inheritedCPUObjects'],
        generatedGPUParentProfile=old['generatedGPUParentProfile'],gicHibernateStateCPU=pin(newpath),
        actualChangedRuntimeCDHashes=sorted({rows[x]['cdhash'] for x in allowed if rows[x]['kind']=='mach-o'}),
        newDeviceGuestBootVerified=False,OS15SupportImplemented=False,OS162To1631SupportImplemented=False)
    for key in list(result):
        if key in old and isinstance(old[key],bool) and ('Whole' in key or 'Unchanged' in key):
            result.setdefault('historicalRuntime166WholeClaims',{})[key]=result.pop(key)
    base.save(O/'candidate.json',result)
    base.save(O/'freeze.json',dict(files=[pin(p) for p in O.rglob('*') if p.is_file()]+[pin(__file__),pin(newpath),*new['sources']],deviceOperations=0))
    print(json.dumps(dict(candidate=pin(O/'candidate.json'),signedImages=len(signed),changedHashes=result['actualChangedRuntimeCDHashes'])))

if __name__=='__main__':main()
