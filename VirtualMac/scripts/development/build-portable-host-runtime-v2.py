#!/usr/bin/env python3
"""Runtime157: experimental host admission, iOS15 loader target, native ABI checks retained."""
import copy, hashlib, importlib.util, json, plistlib, re, shutil, struct, subprocess, tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'independent27-signed-runtime-portable-host-v157-attempt1'
spec=importlib.util.spec_from_file_location('portable_runtime_base',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'));base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);pin=base.pin

def ios15(data):
    data=bytearray(data);assert data[:4]==b'\xcf\xfa\xed\xfe';at=32;seen=0
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,at)
        if cmd==0x32:
            assert struct.unpack_from('<I',data,at+8)[0]==2
            struct.pack_into('<I',data,at+12,0x000f0000);seen+=1
        at+=size
    assert seen==1;return bytes(data)

def main():
    O.mkdir(mode=0o700);commands=[]
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode));base.save(O/'commands.json',commands)
        if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
        return p
    oldpath=N/'independent27-signed-runtime-portable-host-v156-attempt2/candidate.json';newpath=N/'portable-host-components-v2-attempt1/candidate.json'
    old=json.loads(oldpath.read_bytes());new=json.loads(newpath.read_bytes());original=Path(old['runtimeRoot']);runtime=O/'runtime'
    manifest=plistlib.loads(Path(old['manifest']['path']).read_bytes());rows={x['id']:x for x in manifest['files']}
    proofs={x['relativePath']:x for x in json.loads(Path(old['signatureVerification']['path']).read_bytes())['actualSignedFiles']}
    unsigned={};replacementIDs={role+':'+name:new[key] for role in ('parent','child') for name,key in (('VM27HVVMProduction.dylib','cpu'),('VM27IPALimit.dylib','ipa'))}
    for row in rows.values():
        source=original/row['path'];actual=pin(source);assert (actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256'])
        base.copy_regular(source,runtime/row['path'],executable=row['kind']=='mach-o')
        if row['kind']=='mach-o':
            raw=Path(replacementIDs[row['id']]['path']).read_bytes() if row['id'] in replacementIDs else source.read_bytes()
            unsigned[row['id']]=ios15(raw);(runtime/row['path']).write_bytes(unsigned[row['id']])
    # Sign all changed Mach-O headers, preserving original entitlements and executable identity.
    bundles=[row for row in rows.values() if row.get('signatureSlots')]
    with tempfile.TemporaryDirectory(prefix='vm27-portable15-sign-',dir='/private/tmp') as work:
        clean=Path(work)/'runtime';shutil.copytree(runtime,clean);run('clear-xattrs',['xattr','-cr',clean])
        for index,row in enumerate(rows.values()):
            if row['kind']!='mach-o' or row.get('signatureSlots'):continue
            ident='org.lkx.VirtualMacIndependent27.'+row['id'].replace(':','.')
            run('sign-leaf-'+str(index),['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',ident,clean/row['path']])
        for index,row in enumerate(bundles):
            binary=clean/row['path'];bundle=binary.parent.parent.parent
            entitlements=proofs[row['path']]['embeddedEntitlements'];ent=O/('child-'+str(index)+'.entitlements.plist');ent.write_bytes(plistlib.dumps(entitlements))
            ident=re.search(r'^Identifier=(.+)$',run('old-identity-'+str(index),['codesign','-d','--verbose=4',original/row['path']]).stderr.decode(),re.M).group(1)
            run('sign-bundle-'+str(index),['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',ident,'--entitlements',ent,'--generate-entitlement-der',bundle])
            run('verify-bundle-'+str(index),['codesign','--verify','--strict',bundle])
        for row in rows.values():shutil.copyfile(clean/row['path'],runtime/row['path'])
    images={};signed=[]
    for row in rows.values():
        path=runtime/row['path']
        if row['kind']=='mach-o':
            image=base.image_profile(path.read_bytes(),row['id']);images[row['id']]=image
            before=base.image_profile(unsigned[row['id']],row['id'])
            assert image.uuid==before.uuid and image.imports==before.imports and image.exports==before.exports and image.loads==before.loads
            for section in before.sections:
                at,size=section['fileoff'],section['size']
                if at and size and section['flags']&255 not in (1,12,18):assert before.data[at:at+size]==image.data[at:at+size]
            external={int(k):(runtime/rows[v]['path']).read_bytes() for k,v in row.get('signatureSlots',{}).items()}
            proof=base.signature(image.data,image.uuid,external)
            if row.get('signatureSlots'):assert proof['embeddedEntitlements']==proofs[row['path']]['embeddedEntitlements']
            row.update(uuid=proof['uuid'],cdhash=proof['cdhash']);signed.append(dict(role=row['id'].split(':')[0],key=path.name,relativePath=row['path'],actualSignedFile=pin(path),**proof))
        record=pin(path);row.update(bytes=record['bytes'],sha256=record['sha256'])
    for entry in manifest['entries']:
        if entry['fileID'] in replacementIDs:
            definition=images[entry['fileID']].exports['_'+entry['symbol']];assert definition['flags']==0;entry['rva']=definition['address']
    contract=manifest['childEntryContract'];contract['providerEntryRVA']=images[contract['providerID']].exports['_'+contract['symbol']]['address']
    graphid=manifest['dependencyProofID'];prior=json.loads((original/rows[graphid]['path']).read_bytes());assert prior['finalStrongDefinitionGraphClosed'] and not prior['unresolvedStrongImportRows']
    graph=dict(schema='Experimental portable host provider delta and loader floor',baselineRuntimeCandidate=pin(oldpath),components=pin(newpath),finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],changedProviders=new['comparisons'],minimumOS='15.0',experimentalOSRange='15.0-16.3.1',crossOSHostExportAuditComplete=False,actualNativeContextVersionStillRequired='0x206879700000000e',nativeContextOffsetsUnchanged=True,allOtherImageCodeSectionsUnchanged=True,newDeviceGuestAcceptancePending=True)
    base.save(runtime/rows[graphid]['path'],graph);record=pin(runtime/rows[graphid]['path']);rows[graphid].update(bytes=record['bytes'],sha256=record['sha256'])
    raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);mp=runtime/'VM27IndependentRuntimeManifestV1.plist';mp.write_bytes(raw)
    anchor=O/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(v) for v in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
    obj=O/'anchor.o';run('compile-anchor',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios15.0','-I',S,'-c',anchor,'-o',obj])
    probe=O/'preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\nint main(int n,char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)NSLog(@"%@",e);return ok?0:1;}}\n')
    exe=O/'preflight';run('compile-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('preflight',[exe,runtime])
    sig=O/'signature-verification.json';base.save(sig,dict(actualSignedFiles=signed,actualSignedImages=len(signed),allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True))
    result=copy.deepcopy(old);result.update(schema='Runtime157 experimental Dopamine iOS15-16.3.1 admission with checked native ABI',runtimeRoot=str(runtime),manifest=pin(mp),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(sig),builder=pin(__file__),baselineRuntimeCandidate=pin(oldpath),portableHostComponents=pin(newpath),actualProductPreflightPassed=True,deviceOperations=0,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,cpuProviders=[pin(runtime/rows[x]['path']) for x in replacementIDs if 'HVVM' in x],actualChangedRuntimeCDHashes=sorted({r['cdhash'] for r in rows.values() if r['kind']=='mach-o'}),newDeviceGuestBootVerified=False,OS15SupportImplemented=False,OS162To1631SupportImplemented=False,experimentalAdmissionImplemented=True,crossOSHostExportAuditComplete=False)
    base.save(O/'candidate.json',result);base.save(O/'freeze.json',dict(files=[pin(p) for p in O.rglob('*') if p.is_file()]+[pin(__file__),pin(newpath),*new['sources']],deviceOperations=0));print(json.dumps(dict(candidate=pin(O/'candidate.json'),signedImages=len(signed))))
if __name__=='__main__':main()
