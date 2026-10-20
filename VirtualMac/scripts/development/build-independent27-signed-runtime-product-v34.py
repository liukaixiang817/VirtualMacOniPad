#!/usr/bin/env python3
"""Runtime32 product builder: replace only Child USBH offline AVP nullable-queue superclass adapter and re-seal the byte-identical original Child.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime31 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime32_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='8b10134d2070bc8e6bd29d99f0b07cc1ba1d50f612c7789ea4ec8365a456ae7f'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)

def read_inputs(baseline_path,port_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'exact actual Runtime31 and frozen signature primitives')
 old=json.loads(base.regular_bytes(baseline_path));bf=base.frozen_rows(baseline_path.parent/'freeze.json');base.actual_frozen(pin(baseline_path),bf,'actual baseline candidate')
 for k in ('manifest','signatureVerification'):base.actual_frozen(old[k],bf,'actual baseline '+k)
 need(old['localCodeSigned'] is True and old['actualProductPreflightPassed'] is True,'actual signed baseline')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']}
 need(len(rows)==len(manifest['files'])==154 and sum(r['kind']=='mach-o'for r in rows.values())==143,'actual baseline154files143signed')
 evidence=json.loads(base.regular_bytes(old['signatureVerification']['path']));proof={r['relativePath']:r for r in evidence['actualSignedFiles']}
 need(len(proof)==143 and evidence['allCodePagesAndSpecialSlotsActuallyVerified'] is True,'actual baseline signature evidence')
 root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  need(base.relative(row['path']),'safe relative path');p=pin(root/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'baseline whole file');base.actual_frozen(p,bf,'frozen baseline file')
  if row['kind']=='mach-o':
   ss=proof[row['path']];need(ss['actualSignedFile']==p and ss['uuid']==row['uuid'] and ss['cdhash']==row['cdhash'] and ss['allPrimaryPagesAndSpecialSlotsVerified'] is True,'inherited wholefile/signature join')
 childid=manifest['childEntryContract']['childID'];childrow=rows[childid];child=base.image_profile(base.regular_bytes(root/childrow['path']),CHILD)
 need(child.uuid==CHILD_UUID,'original actual Child UUID')
 prior=proof[childrow['path']]['embeddedEntitlements'];need(isinstance(prior,dict)and len(prior)==14 and prior.get(KEY)==['IOSurfaceRootUserClient','AGXDeviceUserClient'] and prior.get('com.apple.private.virtualization.plugin')is True and prior.get('com.apple.developer.kernel.extended-virtual-addressing')is True,'original actual14 Child permissions retained')
 ents=copy.deepcopy(prior)
 port_path=port_path.resolve();pf=base.frozen_rows(port_path.parent/'freeze.json');base.actual_frozen(pin(port_path),pf,'actual frozen Child USBH adapter candidate')
 port=json.loads(base.regular_bytes(port_path))
 need(port['baselineRuntimeCandidate']==pin(baseline_path) and port['providerKey']=='USBH' and port['roles']==['child'],
      'exact current Child-only USBH provider version')
 for key in ('newProvider','graph','source','header'):base.actual_frozen(port[key],pf,'actual frozen USBH '+key)
 base.actual_frozen(port['originalProvider'],bf,'actual baseline USBH')
 matches=[row for row in rows.values() if row['kind']=='mach-o' and row['path'].startswith('child-flat/') and pin(root/row['path'])==port['originalProvider']]
 need(len(matches)==1,'actual original provider joins unique Child manifest file')
 providerrow=matches[0];providerid=providerrow['id'];need(providerid=='child:VM27USBUnavailable.dylib','actual installed USBH filename retained')
 if 'originalChildMain' in port:need(port['originalChildMain']==pin(root/childrow['path']),'exact unchanged original Child')
 need('patchedChildMain' not in port and 'recipe' not in port,'provider-only adapter has no Child code/import port')
 helper=base.image_profile(base.regular_bytes(port['newProvider']['path']),'USBH');oldhelper=base.image_profile(base.regular_bytes(root/providerrow['path']),'original USBH')
 need(not any(cmd['cmd']==0x1d for cmd in helper.commands),'unsigned new USBH without stale signature command')
 need(helper.uuid==port['providerUUID'] and set(helper.exports)==set(oldhelper.exports) and all(row['flags']==0 for row in helper.exports.values()),
      'same original direct class/metaclass export namespace retained')
 contract=port['offlineAVPSuperclassContract']
 need(contract['actualCallerReturnRVA']==0x2449e8 and contract['ChildUUID']==CHILD_UUID and contract['UIDAndEffectiveUID']==501 and
      contract['originalInitializerPrefix32BytesGuard'] is True and contract['realNSObjectInitialization'] is True and
      contract['actualCapabilitiesCopied'] is True and contract['originalCapabilityOrderUnchanged'] is True and
      contract['ownedSerialQueueRetained'] is True and contract['originalCommandAndDoorbellBlocksCopied'] is True and
      contract['controllerState']=='Off' and contract['kernelUserClientCreated'] is False and
      contract['noHostCICommandsGenerated'] is True and contract['noDoorbellsGenerated'] is True and contract['noInterruptResponseFabricated'] is True and
      contract['externalControllerPortDeviceEndpointOperationsExplicitUnsupported'] is True and contract['guestAVPNodeRetained'] is True and
      contract['standardGuestUSBKeyboardPointingAndXHCIUnchanged'] is True and contract['destroyReleasesCallbacksQueueCapabilityAndWeakOwner'] is True and
      contract['parentUSBHWholeUnchangedRequired'] is True and port['actualChildCodeImportsLoadsUnchanged'] is True,
      'genuine scoped offline AVP object/capabilities/lifetime only; no physical kernel client, CI commands or fabricated hardware response')
 need(contract['nativeCallerQueueNil'] is True and contract['nativeCallerInterruptRateHz']==0 and
      contract['nullableQueueNativeSemanticsRestored'] is True and contract['realDefaultSerialQueueCreatedWhenNil'] is True and
      contract['nonNilCallerQueueRetained'] is True and contract['allocationFailureReturnsNilAndARCReleasesPartialState'] is True and
      contract['zeroInterruptRateUnchanged'] is True,
      'actual nil queue and rate zero retain original SDK semantics through a real owned serial queue')
 need(child.loads[23]['ordinal']==24 and child.loads[23]['path']=='@loader_path/VM27USBUnavailable.dylib' and child.loads[23]['cmd']==0xc,
      'deployed required Child USBH load remains unchanged')
 graph=json.loads(base.regular_bytes(port['graph']['path']));native=graph['actualProviderNativeRows'];loads={row['ordinal']:row for row in helper.loads}
 need(graph['actualProvider']==port['newProvider'] and graph['strongRows']==len(native)==len(helper.imports)==port['actualProviderNativeImportCount'] and graph['unresolved']==[],
      'actual new USBH native definitions closed without wide graph repeat')
 for row,imp in zip(native,helper.imports,strict=True):
  need(row['actualImport']==imp and imp['ordinal']>0 and not imp['weak'] and row['requiredLoad']==loads[imp['ordinal']]['path'] and row['actualDefinition'].get('UUID'),
       'actual USBH native import joins captured definition')
 consumers=graph['actualChildConsumerDefinitions']
 expected={row['index'] for row in child.imports if row['ordinal']==24 and not row['weak']}
 need({row['actualImport']['index'] for row in consumers}==expected,'all current Child USBH strong consumers accounted for')
 for row in consumers:
  imp=child.imports[row['actualImport']['index']];need(row['actualImport']==imp and row['requiredLoad']=='@loader_path/VM27USBUnavailable.dylib' and row['target']==port['newProvider'] and
      row['targetUUID']==helper.uuid and row['definition']==helper.exports[imp['name']],
      'unchanged genuine Child superclass consumers resolve to actual new USBH exports')
 need(child.imports[327]['name']=='_dup' and child.imports[327]['ordinal']==21,'deployed genuine dup route retained')
 graphid=manifest['dependencyProofID'];old_graph=json.loads(base.regular_bytes(root/rows[graphid]['path']));need(old_graph['finalStrongDefinitionGraphClosed'] is True and old_graph['unresolvedStrongImportRows']==[],'existing dependency proof inherited')
 merged=dict(schema='Runtime32 Child USBH offline AVP superclass incremental definitions',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(root/rows[graphid]['path']),inheritedBaselineDefinitionGraph=old_graph,childUSBHAdapterCandidate=pin(port_path),actualChildUSBHNativeRows=native,actualChildImports=child.imports,actualChildRequiredLoads=child.loads,actualInheritedChildUSBHDefinitions=consumers,originalChildImportSemanticsInherited=True,originalChildCodeAndImportsWholeUnchanged=True,allParentAndPGAndMDAndHVWholeUnchanged=True,oldFullGraphRecomputed=False,deviceOperations=0)
 return dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,originalChild=child,childID=childid,entitlements=ents,priorEntitlements=prior,baselinePin=pin(baseline_path),portPin=pin(port_path),port=port,md=helper,mdID=providerid,graphRaw=(json.dumps(merged,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 replacements={inputs['mdID']:inputs['port']['newProvider']}
 leafraw={};leafimages={inputs['mdID']:inputs['md']}
 for identity,source in replacements.items():
  path=runtime/rows[identity]['path'];path.unlink();base.copy_regular(pathlib.Path(source['path']),path);leafraw[identity]=base.regular_bytes(path)
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-child-usbh32-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  for identity in replacements:
   path=txpc/(runtime/rows[identity]['path']).relative_to(xpc);label='USBH'
   run('sign-child-'+label,['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.child.'+path.name,path]);run('verify-child-'+label,['codesign','--verify','--strict',path])
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,runtime/rows['child-coderesources']['path'],*(runtime/rows[i]['path']for i in replacements)):
   executable=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=executable)
 resourcepath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcepath)
 oldresources=plistlib.loads(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/inputs['rows']['child-coderesources']['path']));sealed=plistlib.loads(resources)
 leafsigned=[]
 for identity in replacements:
  path=runtime/rows[identity]['path'];raw=leafraw[identity];im=leafimages[identity];afterleaf=base.regular_bytes(path);actualleaf=base.image_profile(afterleaf,path.name)
  need(actualleaf.sections==im.sections and actualleaf.imports==im.imports and actualleaf.binds==im.binds and actualleaf.exports==im.exports and actualleaf.loads==im.loads and actualleaf.uuid==im.uuid,'actual leaf signing preserves code/import/PAC/namespace')
  for sec in im.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(raw[at:at+z]==afterleaf[at:at+z],'every actual new leaf backed section preserved by signing')
  ls=base.signature(afterleaf,im.uuid);lp=pin(path);rows[identity].update(bytes=lp['bytes'],sha256=lp['sha256'],uuid=ls['uuid'],cdhash=ls['cdhash']);leafsigned.append(dict(role='child',key=path.name,relativePath=rows[identity]['path'],actualSignedFile=lp,**ls))
  key='MacOS/'+path.name;need(sealed['files2'][key]['cdhash']==bytes.fromhex(ls['cdhash']),'actual replacement nested seal '+key)
 inherited=copy.deepcopy(sealed);original=copy.deepcopy(oldresources)
 for table in ('files','files2'):
  for identity in replacements:
   key='MacOS/'+pathlib.PurePosixPath(rows[identity]['path']).name
   if table in inherited:inherited[table].pop(key,None)
   if table in original:original[table].pop(key,None)
 need(inherited==original,'all other resources, native shader, rules and nested seals preserved; only Child USBH seal replaced; PG fully preserved')
 cr=pin(runtime/rows['child-coderesources']['path']);rows['child-coderesources'].update(bytes=cr['bytes'],sha256=cr['sha256'])
 after=base.regular_bytes(childpath);actual=base.image_profile(after,CHILD)
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'all original Child namespace/PAC/code geometry unchanged')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed original code/data section unchanged')
 sig=base.signature(after,CHILD_UUID,{1:base.regular_bytes(runtime/rows['child-info']['path']),3:resources});prior=inputs['proof'][rows[childid]['path']]
 need(sig['embeddedEntitlements']==inputs['entitlements'] and len(sig['embeddedEntitlements'])==14 and sig['signatureFileOffset']==sig['codeLimit'],'actual14 permission values and original code/signature boundary')
 need({r['slot']for r in sig['actualSpecialSlots']if r['external']}=={1,3},'actual original Info1/CodeResources3')
 need(actual.ncmds==image.ncmds and actual.sizeofcmds==image.sizeofcmds and len(actual.commands)==len(image.commands),
      're-signing retains every original Child load command')
 for oldcommand,newcommand in zip(image.commands,actual.commands,strict=True):
  expectedcommand=bytearray(oldcommand['raw'])
  if oldcommand['cmd']==0x1d:expectedcommand[12:16]=newcommand['raw'][12:16]
  if oldcommand['cmd']==0x19 and oldcommand['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT':
   for off in(32,48):expectedcommand[off:off+8]=newcommand['raw'][off:off+8]
  need(bytes(expectedcommand)==newcommand['raw'],'all Child commands whole except CodeSignature size and LINKEDIT signature extent')
 need(sig['codeLimit']==prior['codeLimit'] and sig['signatureFileOffset']==prior['signatureFileOffset'],'same original Child signature/code boundary')
 expected=bytearray(before[:prior['codeLimit']]);expected[32:32+actual.sizeofcmds]=b''.join(command['raw'] for command in actual.commands)
 need(bytes(expected)==after[:sig['codeLimit']],'entire original Child pre-signature bytes preserved except signature metadata')
 segment=next(g for g in actual.segments if g['name']=='__LINKEDIT');need(segment['fileoff']+segment['filesize']==len(after) and segment['size']>=segment['filesize'],'actual bounded LINKEDIT extent')
 p=pin(childpath);rel=rows[childid]['path'];rows[childid].update(bytes=p['bytes'],sha256=p['sha256'],cdhash=sig['cdhash']);signed=dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=p,**sig)
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/rows[proofid]['path'];proofpath.write_bytes(inputs['graphRaw']);pp=pin(proofpath);rows[proofid].update(bytes=pp['bytes'],sha256=pp['sha256'])
 unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity in (childid,'child-coderesources',proofid,*replacements):continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']) and rows[identity]==row,'all other product files whole unchanged');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==141,'141 untouched signed images')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements)}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed],actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old141SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements},'only Child USBH/main/seal and incremental dependency proof rows change')
 delta=output/'runtime31-to-runtime32-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=141,unchangedFiles=unchanged,dependencyProofOnlyActualChildUSBHExistingOwnedRoutesUpdated=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesWholeUnchanged=True,originalChildCodeImportsAndPACWholeUnchanged=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime32 Child-only offline USBH AVP superclass adapter product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],childUSBHAdapterCandidate=inputs['portPin'],childUSBHAdapterContract=inputs['port']['offlineAVPSuperclassContract'],runtime31ChildUSBHDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=141,codeSigningCommandsActuallyPerformed=2,existingSignedImagesResigned=2,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,actualChildUSBHAdapterExecuted=False)
 result['actualChildMachineBodyChanged']=False
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--child-port-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual output');inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.child_port_candidate.resolve());o.mkdir(mode=0o700);admission=o/'admission.json';save(admission,dict(schema='Runtime32 actual Child USBH offline superclass signature admission',baseline=inputs['baselinePin'],original154FilesWholeVerified=True,original143SignatureProvenanceJoined=True,allChildEntitlementsWholeUnchanged=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result);pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['portPin'],pin(a.child_port_candidate.parent/'freeze.json')]+[v for v in inputs['port'].values()if isinstance(v,dict)and all(k in v for k in('path','bytes','sha256'))];save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))

 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
