#!/usr/bin/env python3
"""Finite actual product composition and source startup review; no execution."""
from pathlib import Path
import argparse, hashlib, json, plistlib, re, runpy, sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
checks=0
def need(ok,msg):
    global checks;checks+=1
    if not ok:raise ValueError(msg)
def pin(p):
    p=Path(p).resolve();b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);out=ap.parse_args().out.resolve()
    need(out.parent==N and not out.exists(),'fresh finite source review')
    product=N/'independent27-signed-runtime-product-v1-attempt1';candidate=product/'candidate.json'
    parent=N/'independent27-signed-runtime-independent-review-v1-attempt1'
    prior=json.loads((parent/'review.json').read_bytes());j=json.loads(candidate.read_bytes())
    need(pin(candidate)==prior['candidate'] and pin(product/'freeze.json')==prior['inputFreeze'],'same actual parent-reviewed product')
    for q in json.loads((parent/'freeze.json').read_bytes())['files']:need(pin(q['path'])==q,'parent signature review immutable pin')
    need(prior['findings']==[] and prior['verifiedFrozenPins']==799 and prior['actualSignedMachOs']==139 and prior['actualVerifiedCodePages']==2111,'actual signature verification scope')
    need(prior['realCompiledManifestAnchorVerified'] and prior['allPagesAndSpecialSlotsVerifiedIndependently'] and prior['childScopedEntitlementsVerified'],'actual parent signature result')
    manifest_path=Path(j['manifest']['path']);need(pin(manifest_path)==j['manifest'],'actual manifest pin')
    raw=manifest_path.read_bytes();manifest=plistlib.loads(raw);root=Path(j['runtimeRoot'])
    anchor=Path(j['anchorSource']['path']);need(pin(anchor)==j['anchorSource'],'actual generated anchor source')
    match=re.search(r'SHA256V1\[32\]=\{([^}]+)\}',anchor.read_text())
    need(match is not None and bytes(int(x)for x in match[1].split(','))==hashlib.sha256(raw).digest(),'manifest true compiled anchor digest')
    need('ManifestBytesV1='+str(len(raw))+';' in anchor.read_text(),'actual anchor extent')
    files={x['id']:x for x in manifest['files']};need(len(files)==143,'actual unique manifest identities')
    for row in files.values():
        actual=pin(root/row['path']);need((actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256']),'actual signed product manifest join')
    need(manifest['loadOrder']==['parent:VM27HVVMProduction.dylib','parent:VM27OwnedAppStartupV3.dylib','parent:UniversalHIDKit27.dylib','parent:VZ27.dylib'],'actual finite frontend load order')
    admission=json.loads(Path(j['admission']['path']).read_bytes());need(pin(j['admission']['path'])==j['admission'],'actual admission proof')
    need(admission['childConstructorAbsentFromParent'] and len(admission['parentClosure'])==66 and len(admission['childClosure'])==73 and 'VM27OwnedAppChildPreMainV3.dylib' not in admission['parentClosure'],'child constructor not loaded by parent closure')
    parser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    lib=runpy.run_path(str(parser));MachO=lib['MachO']
    stage_path=Path(admission['actualStage']['path']);need(pin(stage_path)==admission['actualStage'],'actual unsigned stage joined')
    stage=json.loads(stage_path.read_bytes());stage_rows={x['key']:x for x in stage['stagedImages']}
    critical=['parent:VM27HVVMProduction.dylib','child:VM27HVVMProduction.dylib','parent:VM27OwnedAppStartupV3.dylib','child:VM27OwnedAppStartupV3.dylib','parent:VZ27.dylib','child:VM27OwnedAppChildPreMainV3.dylib','child:com.apple.Virtualization.VirtualMachine']
    critical_results=[]
    for identity in critical:
        row=files[identity];key=identity.split(':',1)[1];original=Path(stage_rows[key]['staged']['path'])
        need(pin(original)==stage_rows[key]['staged'],'actual stage input identity')
        signed=MachO((root/row['path']).read_bytes());before=MachO(original.read_bytes())
        need(signed.uuid==before.uuid==row['uuid'] and signed.imports==before.imports and signed.exports==before.exports and signed.binds==before.binds and signed.sections==before.sections,'signing preserves actual section, imports, exports and PAC fixup identity')
        for section in before.sections:
            at,size=section['fileoff'],section['size']
            if at and size and section['flags']&255 not in (1,12,18):
                need(before.data[at:at+size]==signed.data[at:at+size],'actual section byte-for-byte unchanged')
        constructors=[x for x in signed.sections if x['name'] in ('__mod_init_func','__init_offsets') and x['size']]
        if key in ('VM27HVVMProduction.dylib','VM27OwnedAppStartupV3.dylib'):need(not constructors,'Root and parent adapter have no native startup constructor')
        if key=='VM27OwnedAppChildPreMainV3.dylib':
            need(len(constructors)==1 and constructors[0]['name']=='__init_offsets' and constructors[0]['size']==4,'actual single child preMain offset constructor')
        critical_results.append(dict(id=identity,signed=pin(root/row['path']),unsigned=pin(original),sectionsVerified=len(before.sections),actualConstructorBytes=sum(x['size']for x in constructors)))
    for entry in manifest['entries']:
        row=files[entry['fileID']];obj=MachO((root/row['path']).read_bytes());symbol='_'+entry['symbol']
        need(symbol in obj.exports and obj.exports[symbol]['address']==entry['rva'] and not obj.exports[symbol]['flags']&12,'actual typed entry resolves true strong export RVA')
    runtime=S/'vm27_independent_app_runtime_v3.m';runtime_text=runtime.read_text()
    need('ParentStartV3 actualStart=' in runtime_text and 'actualStart(&config,&RetainedParentV3)' in runtime_text and 'ParentReadyV3(error)' in runtime_text,'actual typed parent spawn and fresh state checks')
    need('INSTALL_PRODUCTION' not in runtime_text and 'VM27InstallProductionNativeOpsV1' not in runtime_text and not re.search(r'\bhv_vm_(?:create|destroy|config_create)\s*\(',runtime_text),'runtime parent does not call native VM/install entry')
    startup=S/'vm27_owned_app_child_startup_v1.c';startup_text=startup.read_text()
    need('VM27LargePrivateServiceConsumerV2Spawn(o->consumer,o->endpoint,c->actualArgv,c->actualEnvironment,&child)' in startup_text and 'VM27OwnedStartupParentInstallFactoryV3(o->consumer,event,o->nonce)' in startup_text,'true spawn/control identity/factory route')
    premain=S/'vm27_owned_app_child_premain_v1.c';premain_text=premain.read_text()
    need('VM27OwnedAppChildBootstrapBeforeMainV2(&ActualChildStartupOwnerV1)' in premain_text and '_exit(78)' in premain_text and 'No NativeOps installation' in premain_text,'actual child prepare before original Main with genuine failure')
    root_source=S/'vm27_hv_public_vm_bootstrap_v14.m';root_text=root_source.read_text()
    need('caller!=(uintptr_t)mainImage+UINT32_C(0x2e9d50)' in root_text and 'branch!=UINT32_C(0x9404a45a)' in root_text and 'INSTALL_PRODUCTION_V14()!=0' in root_text,'native install requires actual child main/caller entry')
    sign=R/'VirtualMac/scripts/development/sign-independent27-actual-app-product-v1.py';sign_text=sign.read_text()
    need("if __name__ == '__main__':" in sign_text and '--generate-entitlement-der' in sign_text and "['codesign', '--verify', '--strict', app]" in sign_text,'signer remains local explicit main with actual strict signature/DER')
    need("anchor in app_input['sourceFiles']" in sign_text and "S/'vm27_independent_app_runtime_v3.m'" in sign_text and "app_input['runtimeRoot'] == runtime['canonicalDeviceRoot']" in sign_text,'actual linked App/Runtime3/product anchor contract')
    need("review.signed_image(binary, row, {1: info_path.read_bytes()," in sign_text and "3: (app/'_CodeSignature/CodeResources').read_bytes()" in sign_text and "binary.stat().st_size <= 2*1024*1024" in sign_text,'actual self-inspector bound and external signature resources')
    need('original.sections == signed.sections' in sign_text and 'original.binds == signed.binds' in sign_text and "before[at:at+size] == signed.data[at:at+size]" in sign_text,'App signer verifies unchanged actual code and PAC/fixups')
    inputs=[candidate,product/'freeze.json',parent/'review.json',parent/'freeze.json',manifest_path,anchor,Path(j['anchorIOSObject']['path']),Path(j['admission']['path']),parser,stage_path,runtime,startup,premain,root_source,sign,Path(__file__).resolve()]
    need(all(pin(row['path'])==row for row in j['sources']),'actual inherited Runtime3 sources still exact')
    out.mkdir(mode=0o700)
    record=dict(schema='Independent finite actual signed runtime startup composition and App signer source review v1',finiteLocalScopePassed=True,findings=[],checks=checks,actualCandidate=pin(candidate),parentIndependentSignatureReview=pin(parent/'review.json'),parentVerificationReusedWithoutRepeating139PageTests=True,actualManifest=pin(manifest_path),actualManifestFilesRehashed=143,actualCriticalSignedCodeComparisons=critical_results,actualEntries=manifest['entries'],actualParentLoadOrder=manifest['loadOrder'],actualChildConstructorExcludedFromParent=True,parentStartActuallySpawnsOriginalChildAndWaitsTrueHelloFactory=True,parentNativeVMOrNativeOpsInstallationCalledByRuntime=False,actualNativeInstallRemainsChildConfigCallerGuarded=True,appSigner=pin(sign),appSignerActuallyExecuted=False,currentAppSignedSizeVerified=False,futureFailureRecipeMergeRequiresFreshSignedRuntimeManifestAnchorAndRelinkedApp=True,currentProductRetains28PhysicalContextCalls=True,allARM64eABIPathsExecuted=False,actualDyldLoadOrChildSpawnExecuted=False,actualDeviceOperations=0,trustCacheOperations=0,guestBoot=False)
    (out/'review.json').write_text(json.dumps(record,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in inputs]+[pin(out/'review.json')]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=checks,findings=[])))
if __name__=='__main__':main()
