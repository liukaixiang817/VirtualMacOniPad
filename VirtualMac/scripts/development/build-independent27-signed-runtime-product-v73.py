#!/usr/bin/env python3
"""Incremental truthful panic prefixes; Root alone signs.

The 140 unchanged signed files inherit their exact prior signature proofs.
No old dependency graph or old GIC model is rerun, and no iOS image is executed.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys,tempfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime70_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='b9f9376cb1f9d7fb4facee0c481eb516a2c4ed555dd42c6749da2b708f3e39eb'
PORT_SHA='4cf8e36b6edb53ea1d55e6ee5647ff4ef18ead4c9ed19d8516083f57c1c84c74'
CONTRACT_KEY='cpuResetPanicPrefixV1Contract'
PLAN_SHA='90c1b7417d5773f52c3b31c7820dfb4b239fdf304ac01d36c35245bac051cc6d'
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
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA and pin(port_path)['sha256']==PORT_SHA,'fixed actual Runtime69 and compiled panic prefix inputs')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path);port=json.loads(base.regular_bytes(port_path));pf=frozen(port_path)
 for key in ('manifest','signatureVerification'):base.actual_frozen(old[key],bf,'actual Runtime69 '+key)
 need(old['localCodeSigned'] and old['actualProductPreflightPassed'],'actual signed Runtime69 baseline')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={row['id']:row for row in manifest['files']}
 need(len(rows)==len(manifest['files'])==154,'actual154 baseline runtime files')
 proof=json.loads(base.regular_bytes(old['signatureVerification']['path']));signatures={row['relativePath']:row for row in proof['actualSignedFiles']}
 need(len(signatures)==143 and proof['allCodePagesAndSpecialSlotsActuallyVerified'],'actual143 Runtime69 signature proofs')
 root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  need(base.relative(row['path']),'safe runtime relative path');actual=pin(root/row['path'])
  need((actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256']),'whole installed baseline file');base.actual_frozen(actual,bf,'frozen actual baseline file')
  if row['kind']=='mach-o':
   sig=signatures[row['path']]
   need(sig['actualSignedFile']==actual and sig['uuid']==row['uuid'] and sig['cdhash']==row['cdhash'] and sig['allPrimaryPagesAndSpecialSlotsVerified'],'exact prior signed-file proof join')
 base.actual_frozen(port['provider'],pf,'actual compiled Life58 provider');provider=base.image_profile(base.regular_bytes(exact(port['provider'])),KEY)
 need(port['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True,'actual Life58 strict compilation/link/validation')
 reader_contract=port[CONTRACT_KEY]
 need(reader_contract['onlyLife58ObjectChanged']is True,'actual one-Life58 panic prefix delta; remaining finite limits bind the Root-reviewed plan below')
 prior_pin=old['cpuResetSnapshotV1Candidate']
 need(port['cpuResetSnapshotV1Candidate']==prior_pin and port['allOther28ObjectsWholeUnchanged'] is True and len(port['actualChangedObjects'])==1 and len(port['inheritedWholeObjects'])==28,'actual oneLife58/28whole from installed Runtime69 source')
 base.actual_frozen(prior_pin,bf,'installed Life57 Factory10 source');base.actual_frozen(prior_pin,pf,'compiled Life58 baseline source')
 prior=json.loads(base.regular_bytes(exact(prior_pin)));old_objects=prior['actualChangedObjects']+prior['inheritedWholeObjects']
 expected_whole={row['path']:row for row in old_objects if pathlib.Path(row['path']).name!='modern_cpu_kernel_lifecycle_v57.o'}
 need(len(old_objects)==29 and len(expected_whole)==28 and {row['path']:row for row in port['inheritedWholeObjects']}==expected_whole and pathlib.Path(port['actualChangedObjects'][0]['path']).name=='modern_cpu_kernel_lifecycle_v58.o','exact whole29 object closure replaces only Life57 with Life58')
 for row in port['actualChangedObjects']+port['inheritedWholeObjects']:base.actual_frozen(row,pf,'actual linked CPU object');exact(row)
 unchanged_objects={name:old[key]for name,key in (('Factory10','factory10ObjectWholeRuntime68'),('Bootstrap28','bootstrap28ObjectWholeRuntime68'),('Production8','production8ObjectWholeRuntime68'),('Engine5','gicEngine5ObjectWholeRuntime68'),('Mandatory4','mandatory4ObjectWholeRuntime68'))}
 need(all(row in port['inheritedWholeObjects']for row in unchanged_objects.values()),'Factory10 Bootstrap28 Production8 Engine5 Mandatory4 actually whole Runtime69')
 need(port['actualExports']==155 and port['actualNativeImports']==94 and port['actualLoads']==4 and port['all94NativeImportSemanticsSame'] is True,'actual155/94/4 preserved')
 base.actual_frozen(port['sourcePlan'],pf,'actual panic prefix source plan');source_plan=json.loads(base.regular_bytes(exact(port['sourcePlan'])))
 need(source_plan['contract']==reader_contract and pin(port['sourcePlan']['path'])['sha256']==PLAN_SHA,'exact Root-reviewed panic prefix source plan and compiled contract')
 proofs=source_plan['proofs']
 for key,row in proofs.items():need(port[key]==row,'actual snapshot source proof '+key);base.actual_frozen(row,pf,'actual snapshot proof '+key);exact(row)
 additional_contracts=source_plan.get('additionalContracts',{})
 for key,value in additional_contracts.items():need(port[key]==value,'actual additional snapshot contract '+key)
 binding=port['actualSameImageVCPUsExitBinding'];call=binding['actualDirectBL'];own_exit=provider.exports['_hv_vcpus_exit']
 need(own_exit['flags']==0 and own_exit['address']==binding['ownExportRVA']==call['targetRVA'] and binding['externalVCPUsExitImportPresent']is False and not any('_hv_vcpus_exit' in row.values()for row in provider.imports),'same-image actual hv_vcpus_exit strong export without external import')
 sections=[sec for sec in provider.sections if sec['va']<=call['callRVA'] and call['callRVA']+4<=sec['va']+sec['size'] and sec['fileoff']]
 need(len(sections)==1,'actual callback BL in one backed section');sec=sections[0];at=sec['fileoff']+call['callRVA']-sec['va'];word=struct.unpack_from('<I',base.regular_bytes(exact(port['provider'])),at)[0]
 displacement=word&0x3ffffff;displacement=displacement-(1<<26)if displacement&(1<<25)else displacement
 need(word==call['instructionWord'] and word&0xfc000000==0x94000000 and call['callRVA']+(displacement<<2)==binding['ownExportRVA'],'actual callback machine BL targets own hv_vcpus_exit')
 base.actual_frozen(binding['callbackAssembly'],pf,'actual callback disassembly');exact(binding['callbackAssembly'])
 def import_semantics(imports):return sorted([{k:v for k,v in row.items()if k not in ('at','index')}for row in imports],key=lambda row:json.dumps(row,sort_keys=True))
 for identity in IDS:
  image=base.image_profile(base.regular_bytes(root/rows[identity]['path']),KEY)
  need(len(image.imports)==94 and import_semantics(image.imports)==import_semantics(provider.imports) and [semantic(row)for row in image.loads]==[semantic(row)for row in provider.loads],'all94 native import and4 load semantics whole Runtime69')
  need(set(image.exports)==set(provider.exports) and all(image.exports[key]['flags']==provider.exports[key]['flags']for key in image.exports),'same155 actual export names/kinds')
 need(len(provider.imports)==94 and len(provider.exports)==155,'actual155 exports94 imports')
 allowed_imports=old['additionalNativeImports'];native_proof=old['additionalNativeImportStrongDefinitionProof']
 need(allowed_imports==[dict(ordinal=4,weak=0,name='_pthread_cond_wait',addend=0)] and native_proof['resolved']is True and native_proof['actualImport']==allowed_imports[0],'existing cond_wait closure remains inherited with unchanged namespace; no new native import')
 entry=provider.exports['_hv_vm_config_create'];need(entry['flags']==0 and entry['address']==port['hvVMConfigCreateActualRVA'],'actual direct bootstrap entry')
 childid=manifest['childEntryContract']['childID'];child_path=root/rows[childid]['path'];child=base.image_profile(base.regular_bytes(child_path),CHILD)
 graphpath=root/rows[manifest['dependencyProofID']]['path'];graphpin=pin(graphpath);oldgraph=json.loads(base.regular_bytes(graphpath));need(oldgraph['finalStrongDefinitionGraphClosed']and oldgraph['unresolvedStrongImportRows']==[],'actual Runtime69 definition graph retained')
 graph=dict(schema='Actual Runtime70 panic prefix incremental definition proof',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=graphpin,inheritedBaselineDefinitionGraphReference=graphpin,cpuResetPanicPrefixV1Candidate=pin(port_path),actualSameImageVCPUsExitBinding=binding,currentChildCodeAndImportsWholeUnchanged=True,changedProviderIDs=list(IDS),consumerProvidersWholeRuntime69=True,actualCurrentProviderUUID=provider.uuid,actualCurrentProviderExports=provider.exports,actualCurrentProviderImports=provider.imports,actualCurrentProviderLoads=provider.loads,all94NativeImportSemanticsPreserved=True,all4LoadSemanticsWholeUnchanged=True,onlyAddedNativeImport=[],additionalNativeImportStrongDefinitionProof=native_proof,allExistingImporterNamespaceSemanticsPreserved=True,oldInheritedExportAddressesDescribeBaselineOnly=True,currentChangedProvidersUseActualCurrentExportTable=True,oldGraphRerun=False,deviceOperations=0)
 return dict(old=old,baselineFrozen=bf,manifest=manifest,rows=rows,signatures=signatures,port=port,provider=provider,readerContract=reader_contract,sourcePlan=port['sourcePlan'],sourceProofs=proofs,additionalContracts=additional_contracts,life58Object=port['actualChangedObjects'][0],unchangedObjects=unchanged_objects,sameImageExitBinding=binding,child=child,childid=childid,childInput=pin(child_path),consumerPins=[pin(root/rows[role+':VM27LargeConsumerV2.dylib']['path'])for role in ('parent','child')],baselinePin=pin(baseline_path),portPin=pin(port_path),baselineProof=graphpin,graphRaw=(json.dumps(graph,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 signed=[];changedrel=set();image=inputs['provider']
 for identity in IDS:
  path=runtime/rows[identity]['path'];path.unlink();raw=base.copy_regular(exact(inputs['port']['provider']),path);role=identity.split(':')[0]
  run('sign-'+role+'-borrowed-host-input',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.'+role+'.'+KEY,path]);run('verify-'+role+'-borrowed-host-input',['codesign','--verify','--strict',path])
  after=base.regular_bytes(path);actual=base.image_profile(after,KEY);need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'signature preserves actual disabled AMX configuration provider code/import/PAC/exports')
  for sec in image.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(raw[at:at+z]==after[at:at+z],'signed backed sections unchanged')
  sig=base.signature(after,image.uuid);p=pin(path);rel=rows[identity]['path'];rows[identity].update(bytes=p['bytes'],sha256=p['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash']);signed.append(dict(role=role,key=KEY,relativePath=rel,actualSignedFile=p,**sig));changedrel.add(rel)
 childid=inputs['childid'];childpath=runtime/rows[childid]['path'];childraw=base.regular_bytes(childpath);need(pin(childpath)['sha256']==inputs['childInput']['sha256'],'actual current Child input whole unchanged from Runtime63');entitlements=inputs['signatures'][rows[childid]['path']]['embeddedEntitlements'];need(len(entitlements)==14 and entitlements['com.apple.private.virtualization.plugin']is True and entitlements['com.apple.developer.kernel.extended-virtual-addressing']is True,'actual previous child14 permissions')
 ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements,sort_keys=True));xpc=childpath.parent.parent.parent
 # File Provider may add FinderInfo to this newly created local .xpc directory.
 # Remove only that unsigned directory attribute, never any baseline artifact.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'new own XPC directory attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Sign this own XPC in a local temporary directory: File Provider continually
 # recreates FinderInfo on the Documents .xpc directory. Only exact signed
 # file bytes and CodeResources return to the fresh output; no xattrs ship.
 with tempfile.TemporaryDirectory(prefix='vm27-borrowed-host-input64-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,runtime/rows['child-coderesources']['path']):
   originalMode=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=originalMode)

 resourcepath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcepath);seal=plistlib.loads(resources);oldseal=plistlib.loads(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/rows['child-coderesources']['path']));nested=seal['files2']['MacOS/'+KEY];need(nested['cdhash']==bytes.fromhex(rows[IDS[1]]['cdhash'])and not nested.get('optional')and not nested.get('omit'),'actual new required nested disabled AMX configuration provider seal')
 restored=copy.deepcopy(seal);restored['files2']['MacOS/'+KEY]=oldseal['files2']['MacOS/'+KEY];need(restored==oldseal,'only disabled AMX configuration provider resource seal changed')
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
 need(bytes(expected_body)==childafter[:sig['codeLimit']],'entire current Child presignature body whole unchanged from Runtime63 except signature metadata')
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
 delta=output/'runtime69-to-runtime70-panic-prefix-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],changedExistingRuntimeIDs=sorted(changedids),addedRuntimeIDs=[],wholeByteUnchangedSignedImages=140,unchangedFiles=unchanged,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,actualCurrentChildInput=inputs['childInput'],childApprovalDerivedFromActualManifest=True,actualBootstrapEntryRVA=entryRVA,actualChangedCPUObjects=1,actualWholeCPUObjects=28,deviceOperations=0))
 result=copy.deepcopy(old)
 historical_keys=('cpu28OtherObjectsWholeRuntime68','consumerProvidersWholeRuntime68','gicEngine5ObjectWholeRuntime68','factory10ObjectWholeRuntime68','bootstrap28ObjectWholeRuntime68','production8ObjectWholeRuntime68','life57ActualChangedObject','mandatory4ObjectWholeRuntime68','currentConsumerWholeR68','actualSameImageVCPUsExitBinding','cpuResetSnapshotV1Candidate','cpuResetSnapshotV1Contract','cpuResetSnapshotSourcePlan','runtime68CPUResetSnapshotV1DeltaVerification')
 result['historicalRuntime69ResetSnapshotV1Verification']={key:old[key]for key in historical_keys}
 for key in historical_keys[:9]:result.pop(key,None)
 result.update(schema='Actual Runtime70 incremental panic prefix product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=154,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],cpuResetPanicPrefixV1Candidate=inputs['portPin'],cpuResetPanicPrefixV1Contract=inputs['readerContract'],cpuResetPanicPrefixSourcePlan=inputs['sourcePlan'],actualSameImageVCPUsExitBinding=inputs['sameImageExitBinding'],runtime69CPUResetPanicPrefixV1DeltaVerification=pin(delta),cpu28OtherObjectsWholeRuntime69=True,consumerProvidersWholeRuntime69=True,life58ActualChangedObject=inputs['life58Object'],actualCurrentCPUExports=155,actualCurrentCPUImports=94,actualCurrentCPULoads=4,wholeByteUnchangedSignedImages=140,codeSigningCommandsActuallyPerformed=3,existingSignedImagesResigned=3,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path'])
 result['cpuResetSnapshotV1ContractAppliesToHistoricalV1DeltaOnly']=True
 for name,row in inputs['unchangedObjects'].items():result[('gicEngine5'if name=='Engine5'else name[0].lower()+name[1:])+'ObjectWholeRuntime69']=row
 result.update(inputs['sourceProofs']);result.update(inputs['additionalContracts'])
 result['baselineDependencyProofReferencedWithoutRecursiveInline']=inputs['baselineProof']
 consumerFiles=[pin(runtime/rows[role+':VM27LargeConsumerV2.dylib']['path'])for role in ('parent','child')]
 need(all((a['bytes'],a['sha256'])==(b['bytes'],b['sha256'])for a,b in zip(consumerFiles,inputs['consumerPins'],strict=True)),'both actual ConsumerV6 signed leaves whole Runtime69')
 result['currentConsumerWholeR69']=dict(wholeBytesUnchanged=True,baselineRuntimeCandidate=inputs['baselinePin'],baselineFiles=inputs['consumerPins'],actualCurrentFiles=consumerFiles)
 return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--panic-prefix-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual product output');inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.panic_prefix_candidate.resolve());o.mkdir(mode=0o700)
 try:
  result=assemble(inputs,o);candidate=o/'candidate.json';save(candidate,result)
  files=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],inputs['portPin'],pin(a.panic_prefix_candidate.parent/'freeze.json'),inputs['port']['provider'],inputs['childInput'],inputs['sourcePlan'],inputs['baselineProof'],inputs['sameImageExitBinding']['callbackAssembly']]+inputs['port']['sourceFiles']+inputs['port']['actualChangedObjects']+inputs['port']['inheritedWholeObjects']+inputs['consumerPins']+list(inputs['sourceProofs'].values())+list(inputs['baselineFrozen'].values())
  save(o/'freeze.json',dict(files=list({row['path']:row for row in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
