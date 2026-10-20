#!/usr/bin/env python3
"""Incremental bounded ordinary SYS exception handoffs; Root alone signs.

The 140 unchanged signed files inherit their exact prior signature proofs.
No old dependency graph or old GIC model is rerun, and no iOS image is executed.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys,tempfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime40_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='adb247f19f1a20f7d1716426161b406083d7b621381c2c836630c374e41f5d8a'
KEY='VM27HVVMProduction.dylib';CHILD='com.apple.Virtualization.VirtualMachine';IDS=('parent:'+KEY,'child:'+KEY)
pin,save=base.pin,base.save
def need(value,why):
 if not value:raise ValueError(why)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in('path','bytes','sha256')},'exact whole file '+row['path']);return pathlib.Path(row['path'])
def frozen(path):
 path=pathlib.Path(path).resolve();rows=base.frozen_rows(path.parent/'freeze.json');need(rows.get(str(path))==pin(path),'frozen actual candidate');return rows
def semantic(row):return{k:v for k,v in row.items()if k!='at'}
def read_inputs(baseline_path,port_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'fixed actual product inputs')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path);port=json.loads(base.regular_bytes(port_path));pf=frozen(port_path)
 for k in('manifest','signatureVerification'):base.actual_frozen(old[k],bf,'actual old '+k)
 need(old['localCodeSigned']and old['actualProductPreflightPassed'],'actual old signed product')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']};need(len(rows)==len(manifest['files'])==154,'actual154 baseline files')
 proof=json.loads(base.regular_bytes(old['signatureVerification']['path']));signatures={r['relativePath']:r for r in proof['actualSignedFiles']};need(len(signatures)==143 and proof['allCodePagesAndSpecialSlotsActuallyVerified'],'actual143 prior signature proofs')
 root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  need(base.relative(row['path']),'safe relative path');p=pin(root/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'old wholebytes');base.actual_frozen(p,bf,'baseline whole file frozen')
  if row['kind']=='mach-o':
   ss=signatures[row['path']];need(ss['actualSignedFile']==p and ss['uuid']==row['uuid']and ss['cdhash']==row['cdhash']and ss['allPrimaryPagesAndSpecialSlotsVerified'],'prior exact signature join')
 base.actual_frozen(port['provider'],pf,'actual bounded ordinary SYS exception handoff provider');provider=base.image_profile(base.regular_bytes(exact(port['provider'])),KEY)
 need(port['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True,'actual compiled ordinary SYS exception handoff provider')
 handoff_contract=port['ordinarySystemExitForwardingContract']
 need(port['cpuRunResultDiagnosticsCandidate']==old['cpuRunReceiptDiagnosticsCandidate'] and len(port['actualChangedObjects'])==1 and len(port['inheritedWholeObjects'])==28 and port['allOther28ObjectsWholeUnchanged'] is True,'only actual ExitReducerV2 object replaces V1; Life29 and FactoryV3 remain whole')
 base.actual_frozen(port['cpuRunResultDiagnosticsCandidate'],pf,'actual R39 diagnostic provider baseline')
 for row in port['actualChangedObjects']+port['inheritedWholeObjects']:
  base.actual_frozen(row,pf,'actual linked provider object');exact(row)
 need(port['actualExports']==155 and port['actualNativeImports']==93 and port['actualLoads']==4,'actual same155/93/4 provider namespace')
 need(handoff_contract['actualFailingReceipt']==dict(rawReason=8,ESR='0x6230010f',nativeReturn=0,knownFields=15,selector='0xc038',instruction='MRS ID_AA64MMFR0_EL1, Rt8'),'actual Normal41 precise ordinary SYS failure')
 need(all(handoff_contract[k] is True for k in ('admitsOnlyUnhandledEC18IL1Op0AtLeast2','GICAndTimerHandlersStillRunBeforeReducer','existingMutationPoisonAndIdentityGatesUnchanged','preservesExactNativeESRVAIPAIn32BytePublicException','noGuestPCOrGPRWrites','noCPUContextReadsOrNativeCalls','noSYSGetterOrSetterSuccessFabricated','originalVMMConsumesExceptionAndAdvancesPC','HVCAndPrivateEC3FRemainUnsupported','nonRegisterSYSAndMalformedILRemainUnsupported','schemaAndExistingLinkedSymbolUnchanged','allOriginalInputValidationAndRefusalOutputPreservationUnchanged','ChildBodyWholeUnchanged','Life29FactoryV3RunDiagnosticsWholeUnchanged')),'genuine ordinary SYS handoff preserves original consumers, exact payload, refusal and mutation/identity rules')
 oldproviders={i:base.image_profile(base.regular_bytes(root/rows[i]['path']),KEY)for i in IDS}
 for image in oldproviders.values():
  need([semantic(r)for r in image.imports]==[semantic(r)for r in provider.imports]and [semantic(r)for r in image.loads]==[semantic(r)for r in provider.loads],'all actual native import/load semantics unchanged')
  need(set(image.exports)==set(provider.exports)and all(image.exports[k]['flags']==provider.exports[k]['flags']for k in image.exports),'same actual public export names/kinds')
 need(len(provider.imports)==93 and len(provider.exports)==155,'actual unchanged155 exports and93 native imports')
 entry=provider.exports['_hv_vm_config_create'];need(entry['flags']==0 and entry['address']==port['hvVMConfigCreateActualRVA'],'actual direct new bootstrap entry')
 childid=manifest['childEntryContract']['childID'];child_path=root/rows[childid]['path'];child=base.image_profile(base.regular_bytes(child_path),CHILD)
 oldgraphpath=root/rows[manifest['dependencyProofID']]['path'];oldgraph=json.loads(base.regular_bytes(oldgraphpath));need(oldgraph['finalStrongDefinitionGraphClosed']and oldgraph['unresolvedStrongImportRows']==[],'actual inherited closed definition graph')
 graph=dict(schema='Actual Runtime40 bounded ordinary SYS exception handoff incremental definition proof',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(oldgraphpath),inheritedBaselineDefinitionGraph=oldgraph,cpuSYSExceptionHandoffCandidate=pin(port_path),currentChildCodeAndImportsWholeUnchanged=True,changedProviderIDs=list(IDS),actualCurrentProviderUUID=provider.uuid,actualCurrentProviderExports=provider.exports,actualCurrentProviderImports=provider.imports,actualCurrentProviderLoads=provider.loads,allNativeImportAndLoadSemanticsWholeUnchanged=True,allOriginalImporterNamespaceSemanticsWholeUnchanged=True,oldInheritedExportAddressesDescribeBaselineOnly=True,currentChangedProvidersUseActualCurrentExportTable=True,oldGraphRerun=False,deviceOperations=0)
 return dict(old=old,manifest=manifest,rows=rows,signatures=signatures,port=port,handoffContract=handoff_contract,provider=provider,child=child,childid=childid,childInput=pin(child_path),baselinePin=pin(baseline_path),portPin=pin(port_path),graphRaw=(json.dumps(graph,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 signed=[];changedrel=set();image=inputs['provider']
 for identity in IDS:
  path=runtime/rows[identity]['path'];path.unlink();raw=base.copy_regular(exact(inputs['port']['provider']),path);role=identity.split(':')[0]
  run('sign-'+role+'-cpu-sys-exception',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.'+role+'.'+KEY,path]);run('verify-'+role+'-cpu-sys-exception',['codesign','--verify','--strict',path])
  after=base.regular_bytes(path);actual=base.image_profile(after,KEY);need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'signature preserves actual ordinary SYS exception handoff provider code/import/PAC/exports')
  for sec in image.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(raw[at:at+z]==after[at:at+z],'signed backed sections unchanged')
  sig=base.signature(after,image.uuid);p=pin(path);rel=rows[identity]['path'];rows[identity].update(bytes=p['bytes'],sha256=p['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash']);signed.append(dict(role=role,key=KEY,relativePath=rel,actualSignedFile=p,**sig));changedrel.add(rel)
 childid=inputs['childid'];childpath=runtime/rows[childid]['path'];childraw=base.regular_bytes(childpath);need(pin(childpath)['sha256']==inputs['childInput']['sha256'],'actual current Child input whole unchanged from Runtime39');entitlements=inputs['signatures'][rows[childid]['path']]['embeddedEntitlements'];need(len(entitlements)==14 and entitlements['com.apple.private.virtualization.plugin']is True and entitlements['com.apple.developer.kernel.extended-virtual-addressing']is True,'actual previous child14 permissions')
 ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements,sort_keys=True));xpc=childpath.parent.parent.parent
 # File Provider may add FinderInfo to this newly created local .xpc directory.
 # Remove only that unsigned directory attribute, never any baseline artifact.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'new own XPC directory attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Sign this own XPC in a local temporary directory: File Provider continually
 # recreates FinderInfo on the Documents .xpc directory. Only exact signed
 # file bytes and CodeResources return to the fresh output; no xattrs ship.
 with tempfile.TemporaryDirectory(prefix='vm27-cpu-sys-exception40-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,runtime/rows['child-coderesources']['path']):
   originalMode=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=originalMode)

 resourcepath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcepath);seal=plistlib.loads(resources);oldseal=plistlib.loads(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/rows['child-coderesources']['path']));nested=seal['files2']['MacOS/'+KEY];need(nested['cdhash']==bytes.fromhex(rows[IDS[1]]['cdhash'])and not nested.get('optional')and not nested.get('omit'),'actual new required nested ordinary SYS exception handoff provider seal')
 restored=copy.deepcopy(seal);restored['files2']['MacOS/'+KEY]=oldseal['files2']['MacOS/'+KEY];need(restored==oldseal,'only ordinary SYS exception handoff provider resource seal changed')
 sig=base.signature(base.regular_bytes(childpath),inputs['child'].uuid,{1:base.regular_bytes(runtime/rows['child-info']['path']),3:resources});need(sig['embeddedEntitlements']==entitlements,'child14 permissions preserved')
 childafter=base.regular_bytes(childpath);actual=base.image_profile(childafter,CHILD);image=inputs['child'];need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'current Child namespace/code geometry unchanged')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(childraw[at:at+z]==childafter[at:at+z],'current Child backed code/data whole unchanged by signing')
 prior=inputs['signatures'][rows[childid]['path']]
 need(actual.ncmds==image.ncmds and actual.sizeofcmds==image.sizeofcmds and len(actual.commands)==len(image.commands),'unchanged original Child command count')
 for before_command,after_command in zip(image.commands,actual.commands,strict=True):
  expected_command=bytearray(before_command['raw'])
  if before_command['cmd']==0x1d:expected_command[12:16]=after_command['raw'][12:16]
  if before_command['cmd']==0x19 and before_command['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT':
   for off in (32,48):expected_command[off:off+8]=after_command['raw'][off:off+8]
  need(bytes(expected_command)==after_command['raw'],'Child load commands whole except signature size and extent')
 need(sig['codeLimit']==prior['codeLimit'] and sig['signatureFileOffset']==prior['signatureFileOffset'],'same original Child code-signature boundary')
 expected_body=bytearray(childraw[:prior['codeLimit']]);expected_body[32:32+actual.sizeofcmds]=b''.join(x['raw']for x in actual.commands)
 need(bytes(expected_body)==childafter[:sig['codeLimit']],'entire current Child presignature body whole unchanged from Runtime39 except signature metadata')
 p=pin(childpath);rel=rows[childid]['path'];rows[childid].update(bytes=p['bytes'],sha256=p['sha256'],cdhash=sig['cdhash']);signed.append(dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=p,**sig));changedrel.add(rel);p=pin(resourcepath);rows['child-coderesources'].update(bytes=p['bytes'],sha256=p['sha256'])
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/rows[proofid]['path'];proofpath.write_bytes(inputs['graphRaw']);p=pin(proofpath);rows[proofid].update(bytes=p['bytes'],sha256=p['sha256'])
 changedids=set(IDS)|{childid,'child-coderesources',proofid};unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity in changedids:continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256'])and rows[identity]==row,'untouched file wholebytes');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==140,'actual140 untouched signed leaves')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];entryRVA=inputs['provider'].exports['_hv_vm_config_create']['address']
 for entry in manifest['entries']:
  if entry['fileID']==IDS[0]and entry['symbol']=='hv_vm_config_create':entry['rva']=entryRVA
 manifest['childEntryContract']['providerEntryRVA']=entryRVA;raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['signatures'].values()if r['relativePath']not in changedrel];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+signed,actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old140SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 delta=output/'runtime39-to-runtime40-cpu-sys-exception-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],changedExistingRuntimeIDs=sorted(changedids),addedRuntimeIDs=[],wholeByteUnchangedSignedImages=140,unchangedFiles=unchanged,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,actualCurrentChildInput=inputs['childInput'],allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged=True,allExistingAMXGuardCodeWholeUnchanged=True,childApprovalDerivedFromActualManifest=True,actualBootstrapEntryRVA=entryRVA,deviceOperations=0))

 result=copy.deepcopy(old);result.update(schema='Actual Runtime40 incremental bounded ordinary SYS exception handoff product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=154,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],cpuSYSExceptionHandoffCandidate=inputs['portPin'],ordinarySystemExitForwardingContract=inputs['handoffContract'],runtime39CPUSYSExceptionDeltaVerification=pin(delta),currentChildPresignatureBodyWholeExceptExactAMXGuardRangesAndSignatureMetadata=False,allExistingAMXGuardCodeWholeUnchanged=True,actualChildMachineBodyChanged=False,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged=True,wholeByteUnchangedSignedImages=140,codeSigningCommandsActuallyPerformed=3,existingSignedImagesResigned=3,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0);result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--cpu-sys-exception-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual product output');inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.cpu_sys_exception_candidate.resolve());o.mkdir(mode=0o700)
 try:
  result=assemble(inputs,o);candidate=o/'candidate.json';save(candidate,result);files=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],inputs['portPin'],pin(a.cpu_sys_exception_candidate.parent/'freeze.json'),inputs['port']['provider'],inputs['childInput']]+inputs['port']['sourceFiles'];save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
