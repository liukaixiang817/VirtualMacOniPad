#!/usr/bin/env python3
"""Runtime22: sign only the genuine Child with one observed AGX user-client exception.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime20 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime22_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='ddd040a238725b8a3d804ff416af424deec9de484a69dbe46ec4421cc076bc47'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
ENT_SOURCE=N/'child-iogpu-entitlement-source-v15-attempt1/candidate.json'
ENT_SOURCE_SHA='b01e2cec2d0fdb9852024d3c70e8aef453ad523661899121c0784cfa21911772'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)

def read_inputs(baseline_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'exact actual Runtime20 and frozen signature primitives')
 old=json.loads(base.regular_bytes(baseline_path));bf=base.frozen_rows(baseline_path.parent/'freeze.json');base.actual_frozen(pin(baseline_path),bf,'actual baseline candidate')
 for k in ('manifest','signatureVerification'):base.actual_frozen(old[k],bf,'actual baseline '+k)
 need(old['localCodeSigned'] is True and old['actualProductPreflightPassed'] is True,'actual signed baseline')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']}
 need(len(rows)==len(manifest['files'])==153 and sum(r['kind']=='mach-o'for r in rows.values())==143,'actual baseline153files143signed')
 evidence=json.loads(base.regular_bytes(old['signatureVerification']['path']));proof={r['relativePath']:r for r in evidence['actualSignedFiles']}
 need(len(proof)==143 and evidence['allCodePagesAndSpecialSlotsActuallyVerified'] is True,'actual baseline signature evidence')
 root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  need(base.relative(row['path']),'safe relative path');p=pin(root/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'baseline whole file');base.actual_frozen(p,bf,'frozen baseline file')
  if row['kind']=='mach-o':
   ss=proof[row['path']];need(ss['actualSignedFile']==p and ss['uuid']==row['uuid'] and ss['cdhash']==row['cdhash'] and ss['allPrimaryPagesAndSpecialSlotsVerified'] is True,'inherited wholefile/signature join')
 childid=manifest['childEntryContract']['childID'];childrow=rows[childid];child=base.image_profile(base.regular_bytes(root/childrow['path']),CHILD)
 need(child.uuid==CHILD_UUID,'original actual Child UUID')
 prior=proof[childrow['path']]['embeddedEntitlements'];need(isinstance(prior,dict)and len(prior)==14 and prior.get(KEY)==['IOSurfaceRootUserClient'] and prior.get('com.apple.private.virtualization.plugin')is True and prior.get('com.apple.developer.kernel.extended-virtual-addressing')is True,'original actual14 Child permissions')
 need(pin(ENT_SOURCE)['sha256']==ENT_SOURCE_SHA,'exact actual GPU permission source');ef=base.frozen_rows(ENT_SOURCE.parent/'freeze.json');base.actual_frozen(pin(ENT_SOURCE),ef,'actual frozen permission source');source=json.loads(base.regular_bytes(ENT_SOURCE))
 need(source['baselineRuntimeCandidate']==pin(baseline_path)and source['oldActualChildMain']==pin(root/childrow['path'])and source['oldActualChildEntitlements']==prior,'actual same installed baseline and permissions')
 base.actual_frozen(source['childEntitlements'],ef,'actual Child15 permission plist');ents=plistlib.loads(base.regular_bytes(source['childEntitlements']['path']))
 need(len(ents)==14 and ents[KEY]==['IOSurfaceRootUserClient','AGXDeviceUserClient'] and {k:v for k,v in ents.items()if k!=KEY}=={k:v for k,v in prior.items()if k!=KEY},'sole appended observed user-client class; all keys and other13 values unchanged')
 contract=source['gpuUserClientEntitlementContract'];need(contract['childOnly']and contract['onlyAddedUserClientClass']=='AGXDeviceUserClient'and contract['newArray']==ents[KEY]and not contract['actualChangedEntitlementNativeAcceptanceVerified'],'actual limited permission candidate, not native success')
 for k in('actualNativeRegistryReceipt','actualNativeRegistryStdout'):base.actual_frozen(contract[k],ef,'actual GPU registry '+k)
 receipt=json.loads(base.regular_bytes(contract['actualNativeRegistryReceipt']['path']));need(receipt['transportExit']==0 and receipt['stdout']==contract['actualNativeRegistryStdout'],'actual readonly registry receipt')
 registry=base.regular_bytes(contract['actualNativeRegistryStdout']['path']);need(b'<class AGXDeviceUserClient,'in registry,'current actual GPU user-client class')
 need(child.imports[327]['name']=='_dup'and child.imports[327]['ordinal']==21,'deployed genuine dup route preserved')
 graphid=manifest['dependencyProofID'];graph=json.loads(base.regular_bytes(root/rows[graphid]['path']));need(graph['finalStrongDefinitionGraphClosed'] is True and graph['unresolvedStrongImportRows']==[],'existing actual dependency proof inherited; no graph rerun')
 return dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=ents,priorEntitlements=prior,baselinePin=pin(baseline_path),permissionSourcePin=pin(ENT_SOURCE),gpuContract=contract)

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-child15-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,runtime/rows['child-coderesources']['path']):
   executable=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=executable)
 resourcepath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcepath)
 need(resources==base.regular_bytes(pathlib.Path(old['runtimeRoot'])/rows['child-coderesources']['path']),'actual CodeResources wholebytes unchanged; nested leaves/resources not changed')
 after=base.regular_bytes(childpath);actual=base.image_profile(after,CHILD)
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'all original Child namespace/PAC/code geometry unchanged')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed original code/data section unchanged')
 sig=base.signature(after,CHILD_UUID,{1:base.regular_bytes(runtime/rows['child-info']['path']),3:resources});prior=inputs['proof'][rows[childid]['path']]
 need(sig['embeddedEntitlements']==inputs['entitlements'] and len(sig['embeddedEntitlements'])==14 and sig['codeLimit']==prior['codeLimit'] and sig['signatureFileOffset']==prior['signatureFileOffset'],'actual14 permission values and original code/signature boundary')
 need({r['slot']for r in sig['actualSpecialSlots']if r['external']}=={1,3},'actual original Info1/CodeResources3')
 oldcmd=next(c for c in image.commands if c['cmd']==0x1d);newcmd=next(c for c in actual.commands if c['cmd']==0x1d);need(oldcmd['at']==newcmd['at'],'same signature metadata command location')
 expected=bytearray(before[:prior['signatureFileOffset']]);expected[oldcmd['at']+12:oldcmd['at']+16]=after[newcmd['at']+12:newcmd['at']+16]
 # Signing may resize only the LINKEDIT extent holding the enlarged signature.
 oldlink=next(c for c in image.commands if c['cmd']==0x19 and c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT');newlink=next(c for c in actual.commands if c['cmd']==0x19 and c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT')
 need(oldlink['at']==newlink['at'],'same LINKEDIT command location')
 for off in (32,48):expected[oldlink['at']+off:oldlink['at']+off+8]=after[newlink['at']+off:newlink['at']+off+8]
 need(bytes(expected)==after[:sig['signatureFileOffset']],'all pre-signature bytes unchanged except signature size and LINKEDIT extent')
 segment=next(g for g in actual.segments if g['name']=='__LINKEDIT');need(segment['fileoff']+segment['filesize']==len(after) and segment['size']>=segment['filesize'],'actual bounded LINKEDIT extent')
 p=pin(childpath);rel=rows[childid]['path'];rows[childid].update(bytes=p['bytes'],sha256=p['sha256'],cdhash=sig['cdhash']);signed=dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=p,**sig)
 unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity==childid:continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']) and rows[identity]==row,'all other product files whole unchanged');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==142,'142 untouched signed images')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']!=rel];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+[signed],actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old142SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in rows if rows[i]!=inputs['rows'][i]];need(changedids==[childid],'only original Child manifest row changes')
 delta=output/'runtime20-to-runtime22-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=153,actualNewRows=153,actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=142,unchangedFiles=unchanged,dependencyProofWholeUnchanged=True,childCodeResourcesWholeUnchanged=True,allParentFilesWholeUnchanged=True,originalChildCodeImportsPACUUIDWholeUnchanged=True,actualChildEntitlements=inputs['entitlements'],onlyChangedEntitlement={KEY:inputs['entitlements'][KEY]},childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime22 original Child observed AGX user-client exception signature product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=153,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],runtime20GPUEntitlementDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=142,codeSigningCommandsActuallyPerformed=1,existingSignedImagesResigned=1,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,child15PermissionsCandidate=inputs['permissionSourcePin'],gpuUserClientEntitlementContract=inputs['gpuContract'])
 result['historicalExtendedVirtualAddressingContract']=old['extendedVirtualAddressingContract']
 result['extendedVirtualAddressingContract']=dict(childOnly=True,entitlement='com.apple.developer.kernel.extended-virtual-addressing',value=True,actualChildEntitlements=inputs['entitlements'],prior13ValuesWholeUnchanged=False,prior13ValuesPreservedAtHistoricalRuntime15=True,onlyIOGPUExceptionArrayChangedSinceOriginalVAProduct=True,memoryLimitEntitlementAdded=False,systemOrKernelPolicyModified=False,originalRAMLengthAssertionPreserved=True,actualExtendedAddressSpaceExecutionVerified=False)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual output');inputs=read_inputs(a.baseline_runtime_candidate.resolve());o.mkdir(mode=0o700);admission=o/'admission.json';save(admission,dict(schema='Runtime22 actual Child-only signature admission',baseline=inputs['baselinePin'],original153FilesWholeVerified=True,original143SignatureProvenanceJoined=True,onlyChangedEntitlement={KEY:inputs['entitlements'][KEY]},deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result);pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['permissionSourcePin'],pin(ENT_SOURCE.parent/'freeze.json'),pin(ENT_SOURCE.parent/'Child15.entitlements.plist')];save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
