#!/usr/bin/env python3
"""Runtime74: published-GIC action serialization and finite remaining PG BOOL queries; Root alone signs.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime73 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime74_factory12_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
BASELINE_SHA='6538c5d275196ce5b13bb685159b09bb7278be61cf7a90f84e47856fe9f8b7ed'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'exact file '+row['path']);return pathlib.Path(row['path'])
def frozen(path):
 rows=base.frozen_rows(path.parent/'freeze.json');base.actual_frozen(pin(path),rows,'actual frozen candidate');return rows
def semantic(r):return{k:v for k,v in r.items()if k not in ('at','index')}
def multiset(rows):return sorted([semantic(r)for r in rows],key=lambda r:json.dumps(r,sort_keys=True))

def read_inputs(baseline_path,cpu_path,pg_path=None):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'actual signed Runtime73 baseline and reviewed signature primitives')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path)
 for key in ('manifest','signatureVerification'):base.actual_frozen(old[key],bf,'actual Runtime73 '+key)
 need(old['localCodeSigned']is True and old['actualProductPreflightPassed']is True,'actual signed Runtime73 product')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']}
 need(len(rows)==len(manifest['files'])==154,'actual154 Runtime73 files')
 evidence=json.loads(base.regular_bytes(old['signatureVerification']['path']));proof={r['relativePath']:r for r in evidence['actualSignedFiles']}
 need(len(proof)==143 and evidence['allCodePagesAndSpecialSlotsActuallyVerified']is True,'actual143 prior signature proofs')
 root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  need(base.relative(row['path']),'safe runtime relative path');p=pin(root/row['path'])
  need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'whole installed baseline file');base.actual_frozen(p,bf,'frozen actual baseline file')
  if row['kind']=='mach-o':
   sig=proof[row['path']]
   need(sig['actualSignedFile']==p and sig['uuid']==row['uuid']and sig['cdhash']==row['cdhash']and sig['allPrimaryPagesAndSpecialSlotsVerified']is True,'inherited actual signature join')
 childid=manifest['childEntryContract']['childID'];child=base.image_profile(base.regular_bytes(root/rows[childid]['path']),CHILD)
 need(child.uuid==CHILD_UUID and len(child.imports)==1207,'actual Runtime73 Child with VT two-entry route retained')
 prior=proof[rows[childid]['path']]['embeddedEntitlements']
 need(isinstance(prior,dict)and len(prior)==14 and prior.get(KEY)==['IOSurfaceRootUserClient','AGXDeviceUserClient']and
      prior.get('com.apple.private.virtualization.plugin')is True and prior.get('com.apple.developer.kernel.extended-virtual-addressing')is True,'same exact14 Child entitlements')
 cpupin=old['cpu29SourceProof'];base.actual_frozen(cpupin,bf,'inherited exact29 CPU source proof');exact(cpupin)
 cpuobjects=old['cpu29Objects'];need(len(cpuobjects)==29,'actual Runtime73 CPU29 proof')
 graphid=manifest['dependencyProofID'];graphpath=root/rows[graphid]['path'];oldgraph=json.loads(base.regular_bytes(graphpath))
 need(oldgraph['finalStrongDefinitionGraphClosed']is True and oldgraph['unresolvedStrongImportRows']==[],'actual Runtime73 definition graph closure inherited by reference')
 graph=dict(schema='Actual Runtime74 CPU-only serialization incremental definition proof',finalStrongDefinitionGraphClosed=True,
  unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(graphpath),
  inheritedBaselineDefinitionGraphReference=pin(graphpath),allMDPGVTAndOtherProviderFilesWholeRuntime73=True,
  originalRuntime73ChildCodeImportsAndVTAuthSlotsWhole=True,oldGraphRerun=False,oldGraphNotInlined=True,deviceOperations=0)
 inputs=dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=copy.deepcopy(prior),
  baselinePin=pin(baseline_path),graphRaw=(json.dumps(graph,indent=2)+'\n').encode(),cpu29SourceProof=cpupin,cpu29Objects=cpuobjects)
 inputs=admit_cpu_delta(inputs,cpu_path)
 return admit_pg_delta(inputs,pg_path)if pg_path else inputs

CPU_KEY='VM27HVVMProduction.dylib'
CPU_IDS=('parent:'+CPU_KEY,'child:'+CPU_KEY)
CPU_PORT_SHA='79e83de55d83042847d9cdb4eb787079e7a1ae1f738fc6925d2cdb6be8e2f9f6'
ACTIVATION=N/'independent27-normal88-real-gic-busy-activation-v1.json'
ACTIVATION_SHA='5d6f3b60303d1a68ddba4a37bf296d3cbf556d143c6448954ec27e0aaf33d564'
PG_PORT_SHA='0a200504487cceaecccf2b909504bd6996addb97e845c07f4423eae0dfb04941'
PG_PLAN_SHA='c9615fd07e4cfbbec8d59dfc7248d1c144ccbf43e981c6d1afbf353a4032bc3d'
PG_CONTRACT_KEY='ownedPGCmd58RemainingBOOLCapabilitiesV1Contract'
CPU_CONTRACT_KEY='cpuGICVMSerializedActionsV1Contract'
def admit_cpu_delta(inputs,cpu_path):
 need(len(CPU_PORT_SHA)==64 and pin(cpu_path)['sha256']==CPU_PORT_SHA,'actual Root-compiled Factory12 serialized-actions source candidate')
 need(pin(ACTIVATION)['sha256']==ACTIVATION_SHA,'actual Root Factory11 BUSY activation decision')
 activation=json.loads(base.regular_bytes(ACTIVATION));exact(activation['actualStartStdout'])
 need(activation['CPUObjectSelected']=='modern_cpu_native_public_factory_startup_failure_v12.o'and
      activation['actualNativeOperationRetryRequested']is False and activation['futureFactory12DeviceFixClaimed']is False,
      'Root selected actual Factory12 after real BUSY; no source-build or device-fix claim')
 cpu=json.loads(base.regular_bytes(cpu_path));cf=frozen(cpu_path)
 for key in ('provider','sourcePlan'):base.actual_frozen(cpu[key],cf,'actual Factory12 '+key);exact(cpu[key])
 need(cpu['actualIOSCompileStrictLinkAndDyldValidatePassed']is True and cpu['actualExports']==155 and
      cpu['actualNativeImports']==94 and cpu['actualLoads']==4 and cpu['all94NativeImportSemanticsSame']is True and
      cpu['all155ExistingExportNamesAndKindsSame']is True and cpu['all4LoadSemanticsSame']is True,'actual strict Factory12 compile/link/validation with same155/94/4')
 need(cpu['baselineCPU']==inputs['old']['cpu29SourceProof']and cpu['allOther28ObjectsWholeUnchanged']is True and
      len(cpu['actualChangedObjects'])==1 and len(cpu['inheritedWholeObjects'])==28,'actual one Factory12 object from Runtime73 CPU29 proof')
 changed=cpu['actualChangedObjects'][0]
 need(pathlib.Path(changed['path']).name=='modern_cpu_native_public_factory_startup_failure_v12.o','only actual Factory12 object changed')
 expected={r['path']:r for r in inputs['old']['cpu29Objects']if pathlib.Path(r['path']).name!='modern_cpu_native_public_factory_startup_failure_v11.o'}
 need(len(expected)==28 and {r['path']:r for r in cpu['inheritedWholeObjects']}==expected,'exact other28 CPU objects whole Runtime73')
 objects=cpu['actualChangedObjects']+cpu['inheritedWholeObjects']
 for row in objects:base.actual_frozen(row,cf,'actual linked CPU object');exact(row)
 plan=json.loads(base.regular_bytes(exact(cpu['sourcePlan'])))
 need(plan['contractKey']==CPU_CONTRACT_KEY and plan['contract']==cpu[CPU_CONTRACT_KEY]and plan['baselineCPU']==cpu['baselineCPU'],'actual reviewed Factory12 source contract')
 provider=base.image_profile(base.regular_bytes(exact(cpu['provider'])),CPU_KEY);root=pathlib.Path(inputs['old']['runtimeRoot'])
 for identity in CPU_IDS:
  original=base.image_profile(base.regular_bytes(root/inputs['rows'][identity]['path']),CPU_KEY)
  need(set(original.exports)==set(provider.exports)and all(original.exports[s]['flags']==provider.exports[s]['flags']for s in original.exports)and
       multiset(original.imports)==multiset(provider.imports)and [semantic(r)for r in original.loads]==[semantic(r)for r in provider.loads],
       'both actual CPU providers retain155 export names/kinds and94 native/4 load semantics')
 need(len(provider.exports)==155 and len(provider.imports)==94 and len(provider.loads)==4,'actual CPU155/94/4')
 binding=cpu['actualSameImageVCPUsExitBinding'];call=binding['actualDirectBL'];own=provider.exports['_hv_vcpus_exit']
 need(own['flags']==0 and own['address']==binding['ownExportRVA']==call['targetRVA'] and
      binding['externalVCPUsExitImportPresent']is False and not any(r['name']=='_hv_vcpus_exit'for r in provider.imports),'same-image real hv_vcpus_exit export without external import')
 section=next(s for s in provider.sections if s['fileoff']and s['va']<=call['callRVA']and call['callRVA']+4<=s['va']+s['size'])
 at=section['fileoff']+call['callRVA']-section['va'];word=struct.unpack_from('<I',base.regular_bytes(exact(cpu['provider'])),at)[0]
 displacement=word&0x3ffffff;displacement=displacement-(1<<26)if displacement&(1<<25)else displacement
 need(word==call['instructionWord']and word&0xfc000000==0x94000000 and call['callRVA']+(displacement<<2)==own['address'],'actual native wake callback machine BL targets own export')
 base.actual_frozen(binding['callbackAssembly'],cf,'actual same-image CPU callback disassembly');exact(binding['callbackAssembly'])
 need(provider.exports['_hv_vm_config_create']['flags']==0 and provider.exports['_hv_vm_config_create']['address']==cpu['hvVMConfigCreateActualRVA'],'actual bootstrap entry RVA')
 entryDefinitions=[]
 for entry in inputs['manifest']['entries']:
  if entry['fileID']not in CPU_IDS:continue
  definition=provider.exports['_'+entry['symbol']]
  need(definition['flags']==0,'each CPU manifest symbol has its actual new direct export')
  entryDefinitions.append(dict(fileID=entry['fileID'],symbol=entry['symbol'],oldRVA=entry['rva'],actualDefinition=definition))
 childContract=inputs['manifest']['childEntryContract'];childEntryDefinition=None
 if childContract['providerID']in CPU_IDS:
  childEntryDefinition=provider.exports['_'+childContract['symbol']]
  need(childEntryDefinition['flags']==0,'actual CPU Child contract export')
 graph=json.loads(inputs['graphRaw']);graph.pop('all29CPUObjectsWholeRuntime73',None)
 graph.update(schema='Actual Runtime74 CPU-only published-GIC serialization incremental definitions',
  cpuGICVMSerializedActionsV1Candidate=pin(cpu_path),cpuGICVMSerializedActionsV1Contract=cpu[CPU_CONTRACT_KEY],
  cpu28OtherObjectsWholeRuntime73=True,cpu29SourceProof=pin(cpu_path),actualChangedCPUObjects=cpu['actualChangedObjects'],
  actualWholeCPUObjects=cpu['inheritedWholeObjects'],actualCurrentCPUExports=provider.exports,actualCurrentCPUImports=provider.imports,
  actualCurrentCPURequiredLoads=provider.loads,actualSameImageVCPUsExitBinding=binding,
  onlyChangedProviderIDs=list(CPU_IDS),actualCPUManifestEntryDefinitions=entryDefinitions,
  actualCPUChildContractDefinition=childEntryDefinition,actualGICBUSYActivationEvidence=pin(ACTIVATION))
 inputs.update(cpu=cpu,cpuProvider=provider,cpuPortPin=pin(cpu_path),cpuSourcePlan=cpu['sourcePlan'],
  inheritedCPU29SourceProof=inputs['cpu29SourceProof'],inheritedCPU29Objects=inputs['cpu29Objects'],
  cpu29SourceProof=pin(cpu_path),cpu29Objects=objects,cpuContract=cpu[CPU_CONTRACT_KEY],sameImageExitBinding=binding,
  activationEvidence=pin(ACTIVATION),activation=activation,graphRaw=(json.dumps(graph,indent=2)+'\n').encode())
 return inputs


def exact_new_slots(original,patched,expected):
 need(patched.uuid==original.uuid and patched.exports==original.exports and
      [semantic(r)for r in patched.loads]==[semantic(r)for r in original.loads],'actual unchanged PG UUID/export/load semantics')
 need([semantic(r)for r in patched.imports[:len(original.imports)]]==[semantic(r)for r in original.imports],'all original PG native semantics retained')
 slots={x[0]for x in expected}
 for slot,oldindex,index,symbol,ordinal in expected:
  before=next(r for r in original.binds if r['fileoff']==slot);after=next(r for r in patched.binds if r['fileoff']==slot);imp=patched.imports[index]
  need(before['index']==oldindex and before['name']=='_objc_msgSend' and after['index']==index and imp['name']==symbol and imp['ordinal']==ordinal and
       not imp['weak']and imp['addend']==0 and after['word']==(before['word']&~65535)|index,'one approved PG auth slot changes only its import index')
 need([(r['fileoff'],r['word'])for r in original.binds if r['fileoff']not in slots]==
      [(r['fileoff'],r['word'])for r in patched.binds if r['fileoff']not in slots],'all other PG auth bindings whole')

def admit_pg_delta(inputs,pg_path):
 need(len(PG_PORT_SHA)==64 and pin(pg_path)['sha256']==PG_PORT_SHA,'final Root-compiled actual remaining BOOL capability port')
 port=json.loads(base.regular_bytes(pg_path));pf=frozen(pg_path);old=inputs['old'];rows=inputs['rows'];root=pathlib.Path(old['runtimeRoot'])
 mdid='child:MD';pgid='child:ParavirtualizedGraphics27.dylib'
 need(port['baselineRuntimeCandidate']==inputs['baselinePin']and port['providerKey']=='MD'and port['roles']==['child'],'actual Runtime73 MD/PG-only port ancestry')
 for key in ('newProvider','patchedChildPG','recipe','sourcePlan','actualIOSCompile','actualIOSLink','actualMDValidate','actualPGValidate'):
  base.actual_frozen(port[key],pf,'actual frozen finite capability '+key);exact(port[key])
 need(port['originalProvider']==pin(root/rows[mdid]['path'])and port['originalChildPG']==pin(root/rows[pgid]['path'])and
      port['originalChild']==pin(root/rows[inputs['childID']]['path']),'actual Runtime73 MD/PG and unchanged Child inputs')
 need('patchedChild'not in port and 'patchedChildMain'not in port,'this capability port leaves original Child code and VT bindings whole')
 need(port['compileLinkAndBothValidateExit']==[0,0,0,0]and port['newRequiredLoadsAdded']==0 and port['globalAppleClassMutation']is False,'actual one-root compile/link/two validations; no new load or class mutation')
 sourceplan=json.loads(base.regular_bytes(exact(port['sourcePlan'])));contracts=port['capabilityContracts']
 need(port['sourcePlan']['sha256']==PG_PLAN_SHA and sourceplan['contractKey']==port['contractKey']==PG_CONTRACT_KEY and
      port[PG_CONTRACT_KEY]==sourceplan[PG_CONTRACT_KEY]and contracts==sourceplan['capabilityContracts']and len(contracts)==15,
      'exact reviewed fifteen remaining no-argument BOOL source contract and finite slot list')
 symbols={r['symbol']for r in contracts};slots={r['authSlotRVA']for r in contracts}
 need(len(symbols)==len(slots)==15 and set(port['addedExports'])==symbols,'unique finite getter exports and auth slots')
 for i,row in enumerate(contracts):
  need(row['signature']=='BOOL(id,SEL)'and row['newImportIndex']==270+i and row['originalImportIndex']==144 and row['requiredOrdinal']==10 and
       all(row[k]is True for k in ('nativeMethodPresentExactBOOLCalledOnce','nativeMissingOrUnknownABIReturnsFalseUnsupported',
        'nativeBOOLAndErrnoPreserved','noAppleClassMutation','noResourceFabrication')),'only exact typed, once, genuine capability queries admitted')
 md=base.image_profile(base.regular_bytes(exact(port['newProvider'])),'MD');oldmd=base.image_profile(base.regular_bytes(root/rows[mdid]['path']),'old MD')
 pg=base.image_profile(base.regular_bytes(exact(port['patchedChildPG'])),'PG');originalpg=base.image_profile(base.regular_bytes(root/rows[pgid]['path']),'original PG')
 need(len(oldmd.exports)==14 and set(md.exports)==set(oldmd.exports)|symbols and
      all(md.exports[s]['flags']==oldmd.exports[s]['flags']for s in oldmd.exports)and all(md.exports[s]['flags']==0 for s in symbols),
      'all14 MD exports including depth24, three queries, VT and diagnostics retained; only fifteen getters added')
 need(len(oldmd.imports)==len(md.imports)==50 and multiset(md.imports)==multiset(oldmd.imports)and
      [semantic(r)for r in md.loads]==[semantic(r)for r in oldmd.loads],'all50 MD native imports and required loads retained')
 prior=json.loads(base.regular_bytes(exact(old['ownedPGFramebufferCapabilityCandidate'])))
 newobjects=port['actualIOSObjects'];need(len(newobjects)==len(prior['actualIOSObjects'])==3 and newobjects[1:]==prior['actualIOSObjects'][1:],'actual exception bridge and VT objects whole; only current MD root recompiled')
 for row in newobjects:base.actual_frozen(row,pf,'actual linked MD object');exact(row)
 need(len(originalpg.imports)==270 and len(pg.imports)==285,'only fifteen reviewed PG imports appended')
 exact_new_slots(originalpg,pg,[(r['authSlotRVA'],144,r['newImportIndex'],r['symbol'],10)for r in contracts])
 a=base.regular_bytes(root/rows[pgid]['path']);b=base.regular_bytes(exact(port['patchedChildPG']))
 need(len(pg.sections)==len(originalpg.sections),'same PG section geometry')
 for before,after in zip(originalpg.sections,pg.sections,strict=True):
  need(before==after,'same original PG section metadata');at,z=before['fileoff'],before['size']
  if not at or not z or before['flags']&255 in(1,12,18):continue
  expected=bytearray(a[at:at+z])
  for slot in slots:
   if at<=slot<at+z:expected[slot-at:slot-at+8]=b[slot:slot+8]
  need(bytes(expected)==b[at:at+z],'all PG code/data whole except fifteen reviewed auth slots')
 childdefs=[];pgdefs=[];metal=[];graph=json.loads(inputs['graphRaw'])
 for image,ordinal,target in [(inputs['child'],3,childdefs),(pg,10,pgdefs)]:
  for imp in image.imports:
   if imp['ordinal']!=ordinal:continue
   symbol=imp['name']
   if symbol not in md.exports or md.exports[symbol]['flags']!=0:
    need(image is inputs['child']and symbol in ('_MTLSetShaderCachePath','_OBJC_CLASS_$_MTLTextureDescriptor')and
         md.loads[1]['cmd']==0x8000001f and md.loads[1]['path']=='/System/Library/Frameworks/Metal.framework/Metal',
         'only two exact inherited native Metal reexports remain indirect')
    metal.append(dict(actualImport=imp,requiredLoad='@loader_path/MD',currentMDMetalReexport=md.loads[1],inheritedBaselineDefinitionGraphReference=graph['baselineDependencyProof']));continue
   target.append(dict(actualImport=imp,requiredLoad='@loader_path/MD',target=port['newProvider'],targetUUID=md.uuid,definition=md.exports[symbol]))
 need(len(metal)==2,'exact two inherited native Metal reexports')
 graph.pop('allMDPGVTAndOtherProviderFilesWholeRuntime73',None)
 graph.update(schema='Actual Runtime74 GIC serialization and fifteen remaining PG BOOL incremental definitions',
  ownedPGCmd58RemainingBOOLCapabilitiesV1Candidate=pin(pg_path),ownedPGCmd58RemainingBOOLCapabilitiesV1Contract=port[PG_CONTRACT_KEY],
  actualCurrentMDExports=md.exports,actualCurrentMDImports=md.imports,actualCurrentMDRequiredLoads=md.loads,
  actualCurrentChildMDDefinitions=childdefs,actualCurrentPGMDDefinitions=pgdefs,actualInheritedNativeMetalReexportRows=metal,
  all50PriorMDNativeSemanticsInherited=True,actualNewNativeImportRows=[],onlyChangedProviderIDs=[*CPU_IDS,mdid,pgid],
  originalVTAndExceptionObjectsWholeRuntime73=True,originalRuntime73ChildCodeImportsAndVTAuthSlotsWhole=True)
 inputs.update(pgPort=port,pgPortPin=pin(pg_path),pgSourcePlan=port['sourcePlan'],md=md,pg=pg,mdID=mdid,pgID=pgid,
  capabilityContract=port[PG_CONTRACT_KEY],capabilityContracts=contracts,graphRaw=(json.dumps(graph,indent=2)+'\n').encode())
 return inputs


def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 # The parent CPU provider uses its established role-specific identifier.
 # Child CPU joins the existing nested-leaf signing loop below.
 parentidentity=CPU_IDS[0];parentpath=runtime/rows[parentidentity]['path'];parentpath.unlink()
 parentraw=base.copy_regular(exact(inputs['cpu']['provider']),parentpath);cpuimage=inputs['cpuProvider']
 run('sign-parent-cpu',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.parent.'+CPU_KEY,parentpath])
 run('verify-parent-cpu',['codesign','--verify','--strict',parentpath])
 parentafter=base.regular_bytes(parentpath);parentimage=base.image_profile(parentafter,CPU_KEY)
 need(parentimage.sections==cpuimage.sections and parentimage.imports==cpuimage.imports and parentimage.binds==cpuimage.binds and
      parentimage.exports==cpuimage.exports and parentimage.loads==cpuimage.loads and parentimage.uuid==cpuimage.uuid,'parent CPU signing preserves actual code/import/PAC/exports')
 for section in cpuimage.sections:
  at,z=section['fileoff'],section['size']
  if at and z and section['flags']&255 not in(1,12,18):need(parentraw[at:at+z]==parentafter[at:at+z],'all backed parent CPU sections preserved by signing')
 ps=base.signature(parentafter,cpuimage.uuid);pp=pin(parentpath);rows[parentidentity].update(bytes=pp['bytes'],sha256=pp['sha256'],uuid=ps['uuid'],cdhash=ps['cdhash'])
 parentsigned=dict(role='parent',key=CPU_KEY,relativePath=rows[parentidentity]['path'],actualSignedFile=pp,**ps)
 replacements={CPU_IDS[1]:inputs['cpu']['provider']}
 leafraw={};leafimages={CPU_IDS[1]:inputs['cpuProvider']}
 if 'pgPort'in inputs:
  replacements.update({inputs['mdID']:inputs['pgPort']['newProvider'],inputs['pgID']:inputs['pgPort']['patchedChildPG']})
  leafimages.update({inputs['mdID']:inputs['md'],inputs['pgID']:inputs['pg']})
 untouchedSigned=143-(len(replacements)+2)
 for identity,source in replacements.items():
  path=runtime/rows[identity]['path'];path.unlink();base.copy_regular(pathlib.Path(source['path']),path);leafraw[identity]=base.regular_bytes(path)
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-gic-serialization74-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  for identity in replacements:
   path=txpc/(runtime/rows[identity]['path']).relative_to(xpc);label='CPU'if identity==CPU_IDS[1]else'MD'if identity==inputs['mdID']else'PG'
   run('sign-child-'+label,['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.child.'+path.name,path]);run('verify-child-'+label,['codesign','--verify','--strict',path])
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,runtime/rows['child-coderesources']['path'],*(runtime/rows[i]['path']for i in replacements)):
   executable=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=executable)
 resourcepath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcepath)
 oldresources=plistlib.loads(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/inputs['rows']['child-coderesources']['path']));sealed=plistlib.loads(resources)
 leafsigned=[parentsigned]
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
 need(inherited==original,'all other resources, native shader, rules and nested seals preserved outside actual replacement leaves')
 cr=pin(runtime/rows['child-coderesources']['path']);rows['child-coderesources'].update(bytes=cr['bytes'],sha256=cr['sha256'])
 after=base.regular_bytes(childpath);actual=base.image_profile(after,CHILD)
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'actual Runtime73 Child namespace/PAC/code geometry retained')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed Runtime73 Child section retained')
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
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/rows[proofid]['path'];proofpath.write_bytes(inputs['graphRaw']);pp=pin(proofpath);rows[proofid].update(bytes=pp['bytes'],sha256=pp['sha256'])
 unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity in (childid,'child-coderesources',proofid,*replacements,CPU_IDS[0]):continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']) and rows[identity]==row,'all other product files whole unchanged');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==untouchedSigned,'actual untouched signed-image count')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']]
 cpuEntryUpdates=[]
 for entry in manifest['entries']:
  if entry['fileID']not in CPU_IDS:continue
  name='_'+entry['symbol'];definition=inputs['cpuProvider'].exports[name]
  need(definition['flags']==0,'every actual CPU manifest entry resolves to its real direct export')
  cpuEntryUpdates.append(dict(fileID=entry['fileID'],symbol=entry['symbol'],beforeRVA=entry['rva'],afterRVA=definition['address']))
  entry['rva']=definition['address']
 contract=manifest['childEntryContract']
 if contract['providerID']in CPU_IDS:
  definition=inputs['cpuProvider'].exports['_'+contract['symbol']]
  need(definition['flags']==0,'actual Child provider contract direct CPU export')
  contract['providerEntryRVA']=definition['address']
 raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements,CPU_IDS[0])}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed],actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,wholeSignedFilesAndCDProofInherited=untouchedSigned,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements,CPU_IDS[0]},'only two CPU providers and Child MD/PG/main/seal and incremental proof rows change')
 delta=output/'runtime73-to-runtime74-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=untouchedSigned,unchangedFiles=unchanged,dependencyProofOnlyActualChangedProvidersAndCPUManifestEntryRVAsUpdated=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesExceptCPUProviderWholeUnchanged=True,originalRuntime73ChildCodeImportsAndVTAuthSlotsWhole=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime74 published-GIC action serialization and optional finite PG BOOL product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],runtime73CPUSerializedActionsDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=untouchedSigned,codeSigningCommandsActuallyPerformed=len(replacements)+2,existingSignedImagesResigned=len(replacements)+2,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,cpu28OtherObjectsWholeRuntime73=True,originalRuntime73ChildCodeImportsAndVTAuthSlotsWhole=True,cpu29SourceProof=inputs['cpu29SourceProof'],cpu29Objects=inputs['cpu29Objects'])
 result['historicalRuntime73CPUFailureResultVerification']=dict(cpu29SourceProof=inputs['inheritedCPU29SourceProof'],
  cpu29Objects=inputs['inheritedCPU29Objects'],cpuGICVMFailureResultV1Candidate=old['cpuGICVMFailureResultV1Candidate'],
  cpuGICVMFailureResultV1Contract=old['cpuGICVMFailureResultV1Contract'])
 result.pop('factory11ActualChangedObject',None);result.pop('cpu28OtherObjectsWholeRuntime72',None)
 result.update(cpuGICVMSerializedActionsV1Candidate=inputs['cpuPortPin'],cpuGICVMSerializedActionsV1Contract=inputs['cpuContract'],
  cpuGICVMSerializedActionsSourcePlan=inputs['cpuSourcePlan'],cpu28OtherObjectsWholeRuntime73=True,
  factory12ActualChangedObject=inputs['cpu']['actualChangedObjects'][0],actualSameImageVCPUsExitBinding=inputs['sameImageExitBinding'],
  actualCurrentCPUExports=155,actualCurrentCPUImports=94,actualCurrentCPULoads=4,
  actualChangedCPUObjects=inputs['cpu']['actualChangedObjects'],actualWholeCPUObjects=inputs['cpu']['inheritedWholeObjects'],
  cpuGICVMFailureResultV1ContractAppliesToHistoricalV1DeltaOnly=True,
  actualCPUManifestEntryUpdates=cpuEntryUpdates,actualChangedRuntimeCDHashes=sorted({row['cdhash']for row in leafsigned+[signed]}),
  actualChangedSignedRuntimeFiles=len(leafsigned)+1,allMDPGVTAndOtherProvidersWholeRuntime73='pgPort'not in inputs,
  actualGICBUSYActivationEvidence=inputs['activationEvidence'])
 if 'pgPort'in inputs:
  result.update(ownedPGCmd58RemainingBOOLCapabilitiesV1Candidate=inputs['pgPortPin'],
   ownedPGCmd58RemainingBOOLCapabilitiesV1Contract=inputs['capabilityContract'],ownedPGCmd58RemainingBOOLCapabilitiesSourcePlan=inputs['pgSourcePlan'],
   remainingBOOLCapabilityContracts=inputs['capabilityContracts'],actualOtherProvidersExceptCPUAndMDPGWholeRuntime73=True,
   actualVTAndExceptionBridgeObjectsWholeRuntime73=True,ownedPGFramebufferCapabilityV1ContractAppliesToHistoricalV1DeltaOnly=True)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--cpu-serialized-actions-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--pg-port-candidate',type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path)
 ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve()
 need(o.parent==N and not o.exists(),'fresh actual Runtime74 output')
 inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.cpu_serialized_actions_candidate.resolve(),a.pg_port_candidate.resolve()if a.pg_port_candidate else None)
 o.mkdir(mode=0o700);admission=o/'admission.json'
 save(admission,dict(schema='Runtime74 actual serialization and optional finite capability signature admission',baseline=inputs['baselinePin'],
  cpuSerializedActions=inputs['cpuPortPin'],pgCapabilityPort=inputs.get('pgPortPin'),actualGICBUSYActivationEvidence=inputs['activationEvidence'],cpu28OtherObjectsWholeRuntime73=True,originalRuntime73ChildCodeImportsAndVTAuthSlotsWhole=True,
  original154FilesWholeVerified=True,original143SignatureProvenanceJoined=True,allChildEntitlementsWholeUnchanged=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result)
  pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],
   pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],
   pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['cpuPortPin'],
   pin(a.cpu_serialized_actions_candidate.parent/'freeze.json'),inputs['cpu']['provider'],inputs['cpuSourcePlan'],
   inputs['sameImageExitBinding']['callbackAssembly'],*inputs['cpu']['sourceFiles'],*inputs['cpu29Objects'],
   inputs['activationEvidence'],inputs['activation']['actualStartStdout']]
  if 'pgPort'in inputs:
   pins.extend([inputs['pgPortPin'],pin(a.pg_port_candidate.parent/'freeze.json'),inputs['pgSourcePlan'],
    inputs['pgPort']['newProvider'],inputs['pgPort']['patchedChildPG'],inputs['pgPort']['recipe'],
    *inputs['pgPort']['actualIOSObjects'],*inputs['pgPort']['sourceFiles']])
  save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0))
  print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
