#!/usr/bin/env python3
"""Incremental additive-only live-CPU RAM and bounded failure diagnostics; Root alone signs.

The 140 unchanged signed files inherit their exact prior signature proofs.
No old dependency graph or old GIC model is rerun, and no iOS image is executed.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys,tempfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime61_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='53687ff6515388714af36dd978e083b01534d47ac0b837d1d0a37b96c5ccef55'
PORT_SHA='acf29a10e48c1bfc1b9953c004faade3c0c9137eb307914623552aeb6abdfebf'
CONTRACT_KEY='cpuAdditiveRAMV1Contract'
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
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA and pin(port_path)['sha256']==PORT_SHA,'fixed actual product inputs')
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
 base.actual_frozen(port['provider'],pf,'actual disabled AMX configuration provider');provider=base.image_profile(base.regular_bytes(exact(port['provider'])),KEY)
 need(port['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True,'actual compiled disabled AMX configuration provider')
 reader_contract=port[CONTRACT_KEY]
 need(port['cpuPinnedRAMReadV1Candidate']==old['cpuPinnedRAMReadV1Candidate'] and len(port['actualChangedObjects'])==3 and len(port['inheritedWholeObjects'])==26 and port['allOther26ObjectsWholeUnchanged'] is True,'actual Life50 Factory6 Bootstrap25 replacements; other26 CPU objects whole Runtime60')
 base.actual_frozen(port['cpuPinnedRAMReadV1Candidate'],pf,'actual Runtime60 pinned RAM source baseline')
 for row in port['actualChangedObjects']+port['inheritedWholeObjects']:base.actual_frozen(row,pf,'actual linked provider object');exact(row)
 prior_cpu=json.loads(base.regular_bytes(exact(port['cpuPinnedRAMReadV1Candidate'])))
 old_replaced_names={'modern_cpu_kernel_lifecycle_v49.o','modern_cpu_native_public_factory_startup_failure_v5.o','vm27_hv_public_vm_bootstrap_v24.o'}
 new_replaced_names={'modern_cpu_kernel_lifecycle_v50.o','modern_cpu_native_public_factory_startup_failure_v6.o','vm27_hv_public_vm_bootstrap_v25.o'}
 old_objects=prior_cpu['actualChangedObjects']+prior_cpu['inheritedWholeObjects']
 old_replaced=[row for row in old_objects if pathlib.Path(row['path']).name in old_replaced_names]
 expected_whole=[row for row in old_objects if pathlib.Path(row['path']).name not in old_replaced_names]
 need(len(old_objects)==29 and len(old_replaced)==3 and port['inheritedWholeObjects']==expected_whole and {pathlib.Path(row['path']).name for row in port['actualChangedObjects']}==new_replaced_names,'actual whole-object29 closure with exactly intended3 replacements and26 inherited files')
 prior_factory_engine=old['factory5AndGICEngine5ObjectsWholeRuntime59'];engine5=prior_factory_engine[1]
 factory6=next(row for row in port['actualChangedObjects']if pathlib.Path(row['path']).name=='modern_cpu_native_public_factory_startup_failure_v6.o')
 bootstrap25=next(row for row in port['actualChangedObjects']if pathlib.Path(row['path']).name=='vm27_hv_public_vm_bootstrap_v25.o')
 need(len(prior_factory_engine)==2 and prior_factory_engine[0]in old_replaced and engine5 in port['inheritedWholeObjects'],'Factory5 is replaced by Factory6; Engine5 alone remains whole Runtime60')
 factory_engine=[factory6,engine5]
 need(port['actualExports']==155 and port['actualNativeImports']==93 and port['actualLoads']==4,'actual same155/93/4 provider namespace')
 need(all(reader_contract[key]is True for key in ('CPUHandlesMayExistOnlyForCreateAdoptAndFreshDisjointMap', 'FactoryAndKernelOwnerEpochRegistryDisjointAndAdmissionPreserved', 'WriteProtectUnmapFreeStillRejectAnyCPUAttachment', 'MapRequiresUnmappedNonUncertainOwnRAMHandle', 'MapGPARangeStrictlyDisjointFromAllMappedOrUncertainRanges', 'ExistingMappedGPAHostFlagsAndBytesRemainImmutableUnderCPUAttachment', 'NewRAMRegistryLinksAndMapUncertainGuestAddressAndFinalPublicationUseVMMutex', 'Native3RemainsOutsideRegistryAndVMMutex', 'FailedNative3PreservesUncertainExactGPAAndBorrowedHostLease', 'NoNativeFailureTreatedAsNoSideEffects', 'CPUPostIdentityAndLifetimePinStillRequiredForRAMReads', 'ReaderStillHoldsRegistryThenVMMutexDuringActualUniqueOwnReadableLookupAndMachCopy', 'ReaderWaitsOnlyForItsOwnNewUncertainRAMNative3Publication', 'ReaderNeverWaitsWithRegistryMutexHeld', 'PublicationWaitReleasesVMMutexAndRechecksActualMapInFlightPredicate', 'PublicationCompletionRequiresMappedAndNonUncertainThenCompleteIdentityAndRangeRetry', 'PublicationWaitTimeoutOrNativeFailureIsExplicitContextUnreadableNeverUndefinedInjection', 'NoGuestPCAdvanceOrNativeGuestRunRetryForPublicationWait', 'PublicationCondInitDestroyFollowsActualVMLifetime', 'AllExistingPagewalkValidationDescriptorReReadActualMachCopyChecksPreserved', 'AllExistingRaw8AMXConfigAMXStateC1PACAndTrueUndefinedRoutesOtherwiseWhole', 'ActualMapFailureFirst8StageHostGPABytesStatusNativeInvokedOnly', 'MapLogPreservesErrnoAndOriginalAPIResult', 'ActualRegisterFailureFirst8AndAMXFailureFirst8PreserveResultAndErrno', 'InheritedRenamedEntryPointsHiddenBeforeDefinition', 'Other26CPUObjectsWholeR60', 'Engine5ProductionOpsV6ConsumerV6AndChildWholeR60', 'FullAMXExecutionAndAdvancedRAMProtectUnmapWithLiveCPUsRemainDeferred')) and reader_contract['DeviceExecutionProved'] is False and {key:reader_contract[key]for key in ('PublicationWaitUsesOneAbsoluteCLOCK_REALTIMEDeadlineSeconds', 'ChangedCPUObjects')}=={'PublicationWaitUsesOneAbsoluteCLOCK_REALTIMEDeadlineSeconds': 1, 'ChangedCPUObjects': 3},'strict additive-only create/adopt/fresh nonoverlap map with CPU attachments; old mapped bytes immutable, uncertain publication waits bounded1s without registry lock, original real native3 failures retained, existing protect/unmap/free refusal and identity/RAM/descriptor guards')
 base.actual_frozen(port['sourcePlan'],pf,'actual source-owner additive RAM and diagnostics plan');source_plan=json.loads(base.regular_bytes(exact(port['sourcePlan'])))
 need(source_plan['contract']==reader_contract,'actual compiled source plan contract equality')
 additive_proofs=source_plan['proofs'];additional_contracts=source_plan.get('additionalContracts',{})
 for key,row in additive_proofs.items():need(port[key]==row,'actual source proof '+key);base.actual_frozen(row,pf,'actual additive RAM proof '+key);exact(row)
 for key,value in additional_contracts.items():need(port[key]==value,'actual register/map failure diagnostic contract '+key)
 for key in ('actualNormal65SecondaryCPUAndRAMBusySnapshot','actualRAMCPUImmutabilitySource','originalVMOperationReadGateSource'):base.actual_frozen(old[key],bf,'inherited pinned RAM reader source proof '+key);exact(old[key])
 for key in ('actualNormal64EncodedIDAndAMXStateSnapshot','actualNativeAMXStateZeroBranchDisassembly','actualNativeAMXBank57SaveDisassembly'):base.actual_frozen(old[key],bf,'inherited absent AMX state source proof '+key);exact(old[key])
 for key in ('actualNormal63AcceptedConfigAndRaw8Snapshot','original13EncodedExitDecoderDisassembly','actualNativeABI14EncodedExitConsumerDisassembly'):base.actual_frozen(old[key],bf,'inherited additive-ram source proof '+key);exact(old[key])
 for key in ('actualNormal62Operand100Snapshot','actualNativeBootConfig100Disassembly','actualNativeContextEnable63Disassembly'):base.actual_frozen(old[key],bf,'inherited disabled config100 source proof '+key);exact(old[key])
 base.actual_frozen(old['actualNormal61RepeatedFaultSnapshot'],bf,'inherited actual repeated AMX fault source');exact(old['actualNormal61RepeatedFaultSnapshot'])
 base.actual_frozen(old['actualNormal60FaultInstructionSnapshot'],bf,'inherited actual AMX instruction source');exact(old['actualNormal60FaultInstructionSnapshot'])
 base.actual_frozen(old['actualNormal59KernelPanicSnapshot'],bf,'inherited actual kernel panic source');exact(old['actualNormal59KernelPanicSnapshot'])
 for key in('uninstalledPrecedingPCSourceHistory','original13PACServiceDisassembly','original13HypervisorBinary','currentKernelActualNative9Disassembly','original13Raw7UndefinedDisassembly','original13RunDisassembly','original13ExceptionInjectionHelper','actualNormal58PostSnapshot','uninstalledKernelTTBR1SnapshotSourceHistory'):base.actual_frozen(old[key],bf,'inherited source provenance '+key);exact(old[key])
 binding=port['actualSameImageVCPUsExitBinding'];call=binding['actualDirectBL'];own_exit=provider.exports['_hv_vcpus_exit']
 need(own_exit['flags']==0 and own_exit['address']==binding['ownExportRVA']==call['targetRVA'] and binding['externalVCPUsExitImportPresent']is False and not any('_hv_vcpus_exit' in row.values() for row in provider.imports),'actual same-image public hv_vcpus_exit strong export and no external import')
 call_sections=[sec for sec in provider.sections if sec['va']<=call['callRVA'] and call['callRVA']+4<=sec['va']+sec['size'] and sec['fileoff']]
 need(len(call_sections)==1,'actual callback BL is in one backed section');sec=call_sections[0];at=sec['fileoff']+call['callRVA']-sec['va'];word=struct.unpack_from('<I',base.regular_bytes(exact(port['provider'])),at)[0]
 displacement=word&0x3ffffff;displacement=displacement-(1<<26)if displacement&(1<<25)else displacement
 need(word==call['instructionWord'] and word&0xfc000000==0x94000000 and call['callRVA']+(displacement<<2)==binding['ownExportRVA'],'actual callback machine-code BL targets own hv_vcpus_exit export')
 base.actual_frozen(binding['callbackAssembly'],pf,'actual callback disassembly source proof');exact(binding['callbackAssembly'])
 oldproviders={i:base.image_profile(base.regular_bytes(root/rows[i]['path']),KEY)for i in IDS}
 for image in oldproviders.values():
  need([semantic(r)for r in image.imports]==[semantic(r)for r in provider.imports]and [semantic(r)for r in image.loads]==[semantic(r)for r in provider.loads],'all actual native import/load semantics unchanged')
  need(set(image.exports)==set(provider.exports)and all(image.exports[k]['flags']==provider.exports[k]['flags']for k in image.exports),'same actual public export names/kinds')
 need(len(provider.imports)==93 and len(provider.exports)==155,'actual unchanged155 exports and93 native imports')
 entry=provider.exports['_hv_vm_config_create'];need(entry['flags']==0 and entry['address']==port['hvVMConfigCreateActualRVA'],'actual direct new bootstrap entry')
 childid=manifest['childEntryContract']['childID'];child_path=root/rows[childid]['path'];child=base.image_profile(base.regular_bytes(child_path),CHILD)
 oldgraphpath=root/rows[manifest['dependencyProofID']]['path'];oldgraph=json.loads(base.regular_bytes(oldgraphpath));need(oldgraph['finalStrongDefinitionGraphClosed']and oldgraph['unresolvedStrongImportRows']==[],'actual inherited closed definition graph')
 graph=dict(schema='Actual Runtime61 additive-only live-CPU RAM incremental definition proof',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(oldgraphpath),inheritedBaselineDefinitionGraphReference=pin(oldgraphpath),cpuAdditiveRAMV1Candidate=pin(port_path),actualSameImageVCPUsExitBinding=binding,currentChildCodeAndImportsWholeUnchanged=True,changedProviderIDs=list(IDS),consumerStdioInheritanceCandidate=old['consumerStdioInheritanceCandidate'],consumerProvidersWholeRuntime60=True,actualCurrentProviderUUID=provider.uuid,actualCurrentProviderExports=provider.exports,actualCurrentProviderImports=provider.imports,actualCurrentProviderLoads=provider.loads,allNativeImportAndLoadSemanticsWholeUnchanged=True,allOriginalImporterNamespaceSemanticsWholeUnchanged=True,oldInheritedExportAddressesDescribeBaselineOnly=True,currentChangedProvidersUseActualCurrentExportTable=True,oldGraphRerun=False,deviceOperations=0)
 return dict(old=old,manifest=manifest,rows=rows,signatures=signatures,port=port,readerContract=reader_contract,faultOpcodeSource=old['actualNormal59KernelPanicSnapshot'],disabledAMXSource=old['actualNormal60FaultInstructionSnapshot'],activeGetterSource=old['actualNormal61RepeatedFaultSnapshot'],config100SourceProofs={key:old[key]for key in ('actualNormal62Operand100Snapshot','actualNativeBootConfig100Disassembly','actualNativeContextEnable63Disassembly')},encodedExitSourceProofs={key:old[key]for key in ('actualNormal63AcceptedConfigAndRaw8Snapshot','original13EncodedExitDecoderDisassembly','actualNativeABI14EncodedExitConsumerDisassembly')},amxStateSourceProofs={key:old[key]for key in ('actualNormal64EncodedIDAndAMXStateSnapshot','actualNativeAMXStateZeroBranchDisassembly','actualNativeAMXBank57SaveDisassembly')},pinnedRAMSourceProofs={key:old[key]for key in ('actualNormal65SecondaryCPUAndRAMBusySnapshot','actualRAMCPUImmutabilitySource','originalVMOperationReadGateSource')},additiveRAMSourceProofs=additive_proofs,additionalContracts=additional_contracts,sourcePlan=port['sourcePlan'],uninstalledSnapshotSource=old['uninstalledKernelTTBR1SnapshotSourceHistory'],kernelSnapshotSource=old['actualNormal58PostSnapshot'],officialARMAddressSizeGuideURL=old['officialARMAddressSizeGuideURL'],officialAppleTCRDefinitionsURL=old['officialAppleTCRDefinitionsURL'],baselineProof=pin(oldgraphpath),raw7SourceProofs={key:old[key]for key in('original13Raw7UndefinedDisassembly','original13RunDisassembly','original13ExceptionInjectionHelper','currentKernelActualNative9Disassembly')},pacSourceProofs={key:old[key]for key in('uninstalledPrecedingPCSourceHistory','original13PACServiceDisassembly','original13HypervisorBinary','currentKernelActualNative9Disassembly')},officialSDK=old['officialSDKTimerInterruptIDs'],armTranslationGuide=old['officialARMTranslationGuideURL'],armDescriptorFormats=old['officialARMNonLPA2DescriptorFormatsURL'],sameImageExitBinding=binding,factory6Object=factory6,engine5Object=engine5,bootstrap25Object=bootstrap25,factoryEngineObjects=factory_engine,provider=provider,consumerPins=[pin(root/rows[role+':VM27LargeConsumerV2.dylib']['path'])for role in('parent','child')],child=child,childid=childid,childInput=pin(child_path),baselinePin=pin(baseline_path),portPin=pin(port_path),graphRaw=(json.dumps(graph,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 signed=[];changedrel=set();image=inputs['provider']
 for identity in IDS:
  path=runtime/rows[identity]['path'];path.unlink();raw=base.copy_regular(exact(inputs['port']['provider']),path);role=identity.split(':')[0]
  run('sign-'+role+'-additive-ram',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.'+role+'.'+KEY,path]);run('verify-'+role+'-additive-ram',['codesign','--verify','--strict',path])
  after=base.regular_bytes(path);actual=base.image_profile(after,KEY);need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'signature preserves actual disabled AMX configuration provider code/import/PAC/exports')
  for sec in image.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(raw[at:at+z]==after[at:at+z],'signed backed sections unchanged')
  sig=base.signature(after,image.uuid);p=pin(path);rel=rows[identity]['path'];rows[identity].update(bytes=p['bytes'],sha256=p['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash']);signed.append(dict(role=role,key=KEY,relativePath=rel,actualSignedFile=p,**sig));changedrel.add(rel)
 childid=inputs['childid'];childpath=runtime/rows[childid]['path'];childraw=base.regular_bytes(childpath);need(pin(childpath)['sha256']==inputs['childInput']['sha256'],'actual current Child input whole unchanged from Runtime60');entitlements=inputs['signatures'][rows[childid]['path']]['embeddedEntitlements'];need(len(entitlements)==14 and entitlements['com.apple.private.virtualization.plugin']is True and entitlements['com.apple.developer.kernel.extended-virtual-addressing']is True,'actual previous child14 permissions')
 ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements,sort_keys=True));xpc=childpath.parent.parent.parent
 # File Provider may add FinderInfo to this newly created local .xpc directory.
 # Remove only that unsigned directory attribute, never any baseline artifact.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'new own XPC directory attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Sign this own XPC in a local temporary directory: File Provider continually
 # recreates FinderInfo on the Documents .xpc directory. Only exact signed
 # file bytes and CodeResources return to the fresh output; no xattrs ship.
 with tempfile.TemporaryDirectory(prefix='vm27-additive-ram61-sign-',dir='/private/tmp') as temporary:
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
 need(bytes(expected_body)==childafter[:sig['codeLimit']],'entire current Child presignature body whole unchanged from Runtime60 except signature metadata')
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
 delta=output/'runtime60-to-runtime61-additive-ram-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],changedExistingRuntimeIDs=sorted(changedids),addedRuntimeIDs=[],wholeByteUnchangedSignedImages=140,unchangedFiles=unchanged,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,actualCurrentChildInput=inputs['childInput'],allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged=True,allExistingAMXGuardCodeWholeUnchanged=True,childApprovalDerivedFromActualManifest=True,actualBootstrapEntryRVA=entryRVA,deviceOperations=0))

 result=copy.deepcopy(old);result.update(schema='Actual Runtime61 incremental additive-only live-CPU RAM product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=154,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],cpuAdditiveRAMV1Candidate=inputs['portPin'],cpuAdditiveRAMV1Contract=inputs['readerContract'],officialSDKTimerInterruptIDs=inputs['officialSDK'],officialARMTranslationGuideURL=inputs['armTranslationGuide'],officialARMNonLPA2DescriptorFormatsURL=inputs['armDescriptorFormats'],actualSameImageVCPUsExitBinding=inputs['sameImageExitBinding'],runtime60CPUAdditiveRAMV1DeltaVerification=pin(delta),cpu26OtherObjectsWholeRuntime60=True,consumerProvidersWholeRuntime60=True,factory6AndGICEngine5CurrentObjects=inputs['factoryEngineObjects'],actualCurrentCPUExports=155,actualCurrentCPUImports=93,actualCurrentCPULoads=4,currentChildPresignatureBodyWholeExceptExactAMXGuardRangesAndSignatureMetadata=False,allExistingAMXGuardCodeWholeUnchanged=True,actualChildMachineBodyChanged=False,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged=True,wholeByteUnchangedSignedImages=140,codeSigningCommandsActuallyPerformed=3,existingSignedImagesResigned=3,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0);result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path'])
 result['historicalRuntime60PinnedRAMReadV1Verification']={k:old[k]for k in('cpu28OtherObjectsWholeRuntime59','consumerProvidersWholeRuntime59','factory5AndGICEngine5ObjectsWholeRuntime59','currentConsumerWholeR59','actualSameImageVCPUsExitBinding','cpuPinnedRAMReadV1Candidate','cpuPinnedRAMReadV1Contract','factory5ObjectWholeRuntime43')}
 for key in('cpu28OtherObjectsWholeRuntime59','consumerProvidersWholeRuntime59','factory5AndGICEngine5ObjectsWholeRuntime59','currentConsumerWholeR59','factory5ObjectWholeRuntime43'):result.pop(key,None)
 result['cpuKernelTTBR1SnapshotContractAppliesToHistoricalDiagnosticDeltaOnly']=True
 result['cpuRaw7FaultOpcodeSnapshotContractAppliesToHistoricalDiagnosticDeltaOnly']=True
 result['cpuDisabledAMXConfigContractAppliesToHistoricalV1DeltaOnly']=True
 result['cpuDisabledAMXConfigV2ContractAppliesToHistoricalV2DeltaOnly']=True
 result['cpuDisabledAMXConfigV3ContractAppliesToHistoricalV3DeltaOnly']=True
 result['cpuEncodedExitV1ContractAppliesToHistoricalV1DeltaOnly']=True
 result['cpuDisabledAMXStateV1ContractAppliesToHistoricalV1DeltaOnly']=True
 result['cpuPinnedRAMReadV1ContractAppliesToHistoricalV1DeltaOnly']=True
 result['factory5WholeClaimsApplyToHistoricalSourceDeltasOnly']=True
 result['gicEngine5ObjectWholeRuntime60']=inputs['engine5Object']
 result['factory6ActualChangedObject']=inputs['factory6Object']
 result['bootstrap25ActualChangedObject']=inputs['bootstrap25Object']
 result['historicalReaderGlobalVMOperationGuardsApplyToPriorSourceDeltasOnly']=True
 result['cpuProviderAndAll29CPUObjectsWholeR41']=False
 result['cpuEL1VirtualTimerPagewalkContractAppliesToHistoricalDeltaOnly']=True
 result.update(inputs['pacSourceProofs'])
 result.update(inputs['raw7SourceProofs'])
 result['actualNormal58PostSnapshot']=inputs['kernelSnapshotSource']
 result['actualNormal59KernelPanicSnapshot']=inputs['faultOpcodeSource']
 result['actualNormal60FaultInstructionSnapshot']=inputs['disabledAMXSource']
 result['actualNormal61RepeatedFaultSnapshot']=inputs['activeGetterSource']
 result.update(inputs['config100SourceProofs'])
 result.update(inputs['encodedExitSourceProofs'])
 result.update(inputs['amxStateSourceProofs'])
 result.update(inputs['pinnedRAMSourceProofs'])
 result.update(inputs['additiveRAMSourceProofs'])
 result.update(inputs['additionalContracts'])
 result['cpuAdditiveRAMSourcePlan']=inputs['sourcePlan']
 result['uninstalledKernelTTBR1SnapshotSourceHistory']=inputs['uninstalledSnapshotSource']
 result['officialARMAddressSizeGuideURL']=inputs['officialARMAddressSizeGuideURL']
 result['officialAppleTCRDefinitionsURL']=inputs['officialAppleTCRDefinitionsURL']
 result['currentRaw7InjectionMaximumExistingNative8Calls']=1
 result['baselineDependencyProofReferencedWithoutRecursiveInline']=inputs['baselineProof']
 result['currentPACServiceMaximumExistingNative8Calls']=3
 result['cpuVirtualTimerGICContractAppliesToHistoricalFunctionalDeltaOnly']=True
 result['currentDiagnosticMaximumExistingPrepareSystemNative8Calls']=1
 consumerFiles=[pin(runtime/rows[role+':VM27LargeConsumerV2.dylib']['path'])for role in('parent','child')]
 need(all((a['bytes'],a['sha256'])==(b['bytes'],b['sha256'])for a,b in zip(consumerFiles,inputs['consumerPins'],strict=True)),'both actual ConsumerV6 signed leaves whole R54')
 result['currentConsumerWholeR60']=dict(wholeBytesUnchanged=True,baselineRuntimeCandidate=inputs['baselinePin'],baselineFiles=inputs['consumerPins'],actualCurrentFiles=consumerFiles)
 return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--additive-ram-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual product output');inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.additive_ram_candidate.resolve());o.mkdir(mode=0o700)
 try:
  result=assemble(inputs,o);candidate=o/'candidate.json';save(candidate,result);files=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],inputs['portPin'],pin(a.additive_ram_candidate.parent/'freeze.json'),inputs['port']['provider'],inputs['childInput']]+inputs['port']['sourceFiles']+inputs['port']['actualChangedObjects']+inputs['port']['inheritedWholeObjects']+inputs['consumerPins']+[inputs['sameImageExitBinding']['callbackAssembly']]+list(inputs['pacSourceProofs'].values())+list(inputs['raw7SourceProofs'].values())+[inputs['baselineProof'],inputs['kernelSnapshotSource'],inputs['uninstalledSnapshotSource'],inputs['faultOpcodeSource'],inputs['disabledAMXSource'],inputs['activeGetterSource']]+list(inputs['config100SourceProofs'].values())+list(inputs['encodedExitSourceProofs'].values())+list(inputs['amxStateSourceProofs'].values())+list(inputs['pinnedRAMSourceProofs'].values())+list(inputs['additiveRAMSourceProofs'].values())+[inputs['sourcePlan']];save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
