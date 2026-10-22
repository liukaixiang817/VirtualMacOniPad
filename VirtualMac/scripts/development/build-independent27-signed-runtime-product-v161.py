#!/usr/bin/env python3
"""Incremental explicit standard-stream inheritance; Root alone signs.

The 140 unchanged signed files inherit their exact prior signature proofs.
No old dependency graph or old GIC model is rerun, and no iOS image is executed.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys,tempfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime42_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='3d83dda8df9e3ca245a7c661d2e33fc15a82ea6d6a25222f8a1f2e9f5bd43cf3'
PORT_SHA='6db52878d4ef549faf57095df92d94fbdd6a940cdaa09fea499d151d3c32a180'
NATIVE_INDEX=N/'current-native-header-export-index-v3/index.json'
NATIVE_INDEX_SHA='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
KEY='VM27LargeConsumerV2.dylib';HVKEY='VM27HVVMProduction.dylib';CHILD='com.apple.Virtualization.VirtualMachine';IDS=('parent:'+KEY,'child:'+KEY)
pin,save=base.pin,base.save
def need(value,why):
 if not value:raise ValueError(why)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in('path','bytes','sha256')},'exact whole file '+row['path']);return pathlib.Path(row['path'])
def frozen(path):
 path=pathlib.Path(path).resolve();rows=base.frozen_rows(path.parent/'freeze.json');need(rows.get(str(path))==pin(path),'frozen actual candidate');return rows
def semantic(row):return{k:v for k,v in row.items()if k!='at'}
def import_semantic(row):return{k:row[k]for k in('ordinal','weak','name','addend')}
def load_semantic(row):return{k:row[k]for k in('ordinal','cmd','path')}
def deployed_loads(image):
 result=[]
 for row in image.loads:
  row=copy.deepcopy(row)
  if row['path'].startswith('@rpath/'):
   need(row['ordinal'] in(1,2,3,4),'only four own consumer dependency loads normalized')
   row['path']='@loader_path/'+row['path'][len('@rpath/'):]
  result.append(row)
 return result

def consumer_definition_graph(root,rows,provider):
 need(pin(NATIVE_INDEX)['sha256']==NATIVE_INDEX_SHA,'fixed current iPad native export index')
 nf=frozen(NATIVE_INDEX);native=json.loads(base.regular_bytes(NATIVE_INDEX))['images']
 captured={};owned={};resolutions=[]
 def native_rows(path):
  if path not in native:raise LookupError('no captured definition route '+path)
  record=native[path]
  sources=[record['actualCompleteExportSource']['rangePin'],record['actualCompleteCommands']]
  sources += [r['rangePin']for r in record.get('actualCommandSourceRanges',[])]
  for source in sources:
   exact(source);captured[source['path']]=source
  return record
 def resolve(path,symbol,role,seen):
  key=(path,symbol,role);need(key not in seen,'acyclic exact definition route');seen=seen|{key}
  if path.startswith('/'):
   record=native_rows(path);definition=record['definitions'].get(symbol);deps=record['dependencies']
   node={'provider':path,'uuid':record['UUID'],'symbol':symbol}
  else:
   if path==KEY:image=provider
   else:
    identity=role+':'+path;need(identity in rows,'same-role relative provider '+identity)
    if identity not in owned:
     actualpin=pin(root/rows[identity]['path']);need((actualpin['bytes'],actualpin['sha256'])==(rows[identity]['bytes'],rows[identity]['sha256']),'exact role dependency')
     owned[identity]=(base.image_profile(base.regular_bytes(actualpin['path']),path),actualpin)
    image=owned[identity][0]
   definition=image.exports.get(symbol);deps=image.loads
   node={'provider':role+':'+path,'uuid':image.uuid,'symbol':symbol}
  def child_path(dep):
   value=dep['path']
   if value.startswith(('@loader_path/','@rpath/')):return value.split('/',1)[1]
   need(value.startswith('/'),'finite actual dependency');return value
  if definition is not None:
   node['actualExport']=definition
   if definition['flags']&8:
    dep=next((d for d in deps if d['ordinal']==definition['ordinal']),None);need(dep is not None,'real export reexport ordinal')
    alias=definition.get('alias') or definition.get('name') or symbol
    return [node]+resolve(child_path(dep),alias,role,seen)
   need((definition['flags']&3)==0 and not(definition['flags']&16),'regular direct strong native/own definition')
   return [node]
  for dep in deps:
   if dep.get('command',dep.get('cmd'))!=0x8000001f:continue
   try:return [node|{'actualReexportLoad':dep}]+resolve(child_path(dep),symbol,role,seen)
   except LookupError:continue
  raise LookupError('unresolved '+path+' '+symbol)
 for role in('parent','child'):
  for imp in provider.imports:
   need(not imp['weak'] and imp['ordinal']>0 and imp['addend']==0,'actual strong ordinary consumer import')
   dep=next((d for d in deployed_loads(provider) if d['ordinal']==imp['ordinal']),None);need(dep is not None,'actual import ordinal dependency')
   path=dep['path'];path=path.split('/',1)[1]if path.startswith('@loader_path/')else path
   route=resolve(path,imp['name'],role,set());resolutions.append(dict(importer=role+':'+KEY,actualImport=imp,resolution=dict(resolved=True,route=route)))
 need(len(resolutions)==160,'all80 actual consumer strong imports per role resolved')
 return dict(actualStrongImportRows=resolutions,currentNativeIndex=pin(NATIVE_INDEX),currentNativeIndexFreeze=pin(NATIVE_INDEX.parent/'freeze.json'),actualNativeSourcePins=list(captured.values()),actualOwnedProviderPins=[p for image,p in owned.values()],allActualConsumerStrongImportsResolved=True)

def read_inputs(baseline_path,port_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA and pin(port_path)['sha256']==PORT_SHA,'fixed actual Runtime150 product and ConsumerV7 inputs')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path);port=json.loads(base.regular_bytes(port_path));pf=frozen(port_path)
 for k in('manifest','signatureVerification'):base.actual_frozen(old[k],bf,'actual old '+k)
 need(old['localCodeSigned']and old['actualProductPreflightPassed'],'actual old signed product')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']};need(len(rows)==len(manifest['files'])==161,'actual161 baseline files')
 proof=json.loads(base.regular_bytes(old['signatureVerification']['path']));signatures={r['relativePath']:r for r in proof['actualSignedFiles']};need(len(signatures)==146 and proof['allCodePagesAndSpecialSlotsActuallyVerified'],'actual146 prior signature proofs')
 root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  need(base.relative(row['path']),'safe relative path');p=pin(root/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'old wholebytes');base.actual_frozen(p,bf,'baseline whole file frozen')
  if row['kind']=='mach-o':
   ss=signatures[row['path']];need(ss['actualSignedFile']==p and ss['uuid']==row['uuid']and ss['cdhash']==row['cdhash']and ss['allPrimaryPagesAndSpecialSlotsVerified'],'prior exact signature join')
 need(port['provider']==port['consumer'] and exact(port['baselineRuntimeCandidate']).is_file(),'exact ConsumerV7 source joins actual Runtime150')
 base.actual_frozen(port['consumer'],pf,'actual ConsumerV7 provider');provider=base.image_profile(base.regular_bytes(exact(port['consumer'])),KEY)
 need(port['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True,'actual compiled ConsumerV7 provider')
 contract=port['stdioInheritanceContract']
 required=('onlyOwnedBundleModeV5Changed','usesPublicDarwinAddinheritNPForSTDOUTAndSTDERR','childOnlyCloseOnExecClearing','parentDescriptorAndStatusFlagsUnchanged','noNewOpenTruncateOrPathRedirection','checksRealpathFGetPathAndSameDevInode','requiresRegularUID501GID501Mode0600Nlink1AppendWritable','checksBeforeActionsAndImmediatelyBeforeActualSpawn','logsActualParentFDFlagsOncePerStream','argvEnvRegisteredPortsPermissionsAndOwnerStateUnchanged','fileActionsFailuresPreventSpawnAndDestroyInitializedActions','successfulSpawnPIDStateRetainedBeforeCleanupErrors','allStrictNativeLegacyModesUnchanged')
 need(all(contract[k] is True for k in required)and contract['newRootPermissions']is False and contract['exactOwnLogTarget']=='/tmp/VirtualMacIndependent27.log','exact owned stdio inheritance contract')
 need(len(port['actualChangedObjects'])==1 and len(port['inheritedWholeObjects'])==3,'Consumer4objects onechanged threewhole')
 for row in port['actualChangedObjects']+port['inheritedWholeObjects']+port['sourceFiles']+[port['stdioInheritanceBasis']]:base.actual_frozen(row,pf,'actual Consumer source/object basis');exact(row)
 need(provider.imports==port['actualConsumerImportRows']and provider.loads==port['actualConsumerLoadRows']and provider.exports==port['actualConsumerExportRows'],'actual Consumer namespace tables')
 need(len(provider.imports)==80 and len(provider.exports)==9 and len(provider.loads)==7,'actual Consumer9/80/7')
 oldproviders={i:base.image_profile(base.regular_bytes(root/rows[i]['path']),KEY)for i in IDS}
 expected_new=set()
 for image in oldproviders.values():
  before={json.dumps(import_semantic(r),sort_keys=True)for r in image.imports};after={json.dumps(import_semantic(r),sort_keys=True)for r in provider.imports}
  need(before==after and len(before)==80 and len(after)==80,'all80 old actual import semantics preserved')
  added=[json.loads(x)for x in sorted(after-before)];need({r['name']for r in added}==expected_new and all(r['ordinal']==7 and not r['weak']and r['addend']==0 for r in added),'no native imports added')
  need([load_semantic(r)for r in image.loads]==[load_semantic(r)for r in deployed_loads(provider)],'same7 deployed dependency loads after finite4 path normalization')
  need(set(image.exports)==set(provider.exports)and all(image.exports[k]['flags']==provider.exports[k]['flags']for k in image.exports),'same9 public export names/kinds')
 childid=manifest['childEntryContract']['childID'];child_path=root/rows[childid]['path'];child=base.image_profile(base.regular_bytes(child_path),CHILD)
 oldgraphpath=root/rows[manifest['dependencyProofID']]['path'];oldgraph=json.loads(base.regular_bytes(oldgraphpath));need(oldgraph['finalStrongDefinitionGraphClosed']and oldgraph['unresolvedStrongImportRows']==[],'actual inherited closed definition graph')
 closure=consumer_definition_graph(root,rows,provider)
 hvPins=[]
 for role in('parent','child'):
  hvpath=root/rows[role+':'+HVKEY]['path'];hv=base.image_profile(base.regular_bytes(hvpath),HVKEY)
  need(len(hv.exports)==155 and len(hv.imports)==97 and len(hv.loads)==4 and hv.uuid=='2587477aa0763149aa104f9af185eeac','unchanged Runtime150 CPU155/97/4');hvPins.append(pin(hvpath))
 graph=dict(schema='Actual Runtime151 ConsumerV7 stdio inheritance incremental definition proof',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(oldgraphpath),inheritedBaselineDefinitionGraph=oldgraph,consumerStdioInheritanceCandidate=pin(port_path),currentChildCodeAndImportsWholeUnchanged=True,changedProviderIDs=list(IDS),actualCurrentConsumerUUID=provider.uuid,actualCurrentConsumerExports=provider.exports,actualCurrentConsumerImports=provider.imports,actualCurrentDeployedConsumerLoads=deployed_loads(provider),actualConsumerAddedImports=[],all80PriorConsumerImportSemanticsUnchanged=True,consumerFourOwnDependencyLoadsNormalizeToBaselineLoaderPath=True,allOriginalImporterNamespaceSemanticsWholeUnchanged=True,oldInheritedExportAddressesDescribeBaselineOnly=True,currentChangedProvidersUseActualCurrentExportTable=True,cpuProviderWholeRuntime150=hvPins,actualCPU91NamespacesWhole=True,oldGraphRerun=False,deviceOperations=0,**closure)
 return dict(old=old,manifest=manifest,rows=rows,signatures=signatures,port=port,stdioContract=contract,provider=provider,child=child,childid=childid,childInput=pin(child_path),baselinePin=pin(baseline_path),portPin=pin(port_path),nativeClosure=closure,hvPins=hvPins,graphRaw=(json.dumps(graph,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 signed=[];changedrel=set();image=inputs['provider'];deployedConsumerProfiles=[]
 for identity in IDS:
  path=runtime/rows[identity]['path'];path.unlink();raw=base.copy_regular(exact(inputs['port']['consumer']),path);role=identity.split(':')[0]
  changes=[]
  for dep in inputs['provider'].loads:
   if dep['path'].startswith('@rpath/'):
    target='@loader_path/'+dep['path'][len('@rpath/'):];changes+=['-change',dep['path'],target]
  need(len(changes)==12,'exact four own dependency path normalizations')
  run('normalize-'+role+'-consumer-own-loads',['/usr/bin/install_name_tool',*changes,path])
  normalized=base.regular_bytes(path);image=base.image_profile(normalized,KEY)
  need(image.uuid==inputs['provider'].uuid and image.exports==inputs['provider'].exports and [import_semantic(x)for x in image.imports]==[import_semantic(x)for x in inputs['provider'].imports]and [load_semantic(x)for x in image.loads]==[load_semantic(x)for x in deployed_loads(inputs['provider'])],'only actual four own load paths normalized')
  need(image.sections==inputs['provider'].sections,'consumer section geometry retained by load normalization')
  for sec in inputs['provider'].sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(raw[at:at+z]==normalized[at:at+z],'all consumer backed code/data whole under own-load normalization')
  raw=normalized
  run('sign-'+role+'-consumer-stdio',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.'+role+'.'+KEY,path]);run('verify-'+role+'-consumer-stdio',['codesign','--verify','--strict',path])
  after=base.regular_bytes(path);actual=base.image_profile(after,KEY);need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'signature preserves actual ConsumerV7 stdio inheritance provider code/import/PAC/exports')
  for sec in image.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(raw[at:at+z]==after[at:at+z],'signed backed sections unchanged')
  sig=base.signature(after,image.uuid);p=pin(path);rel=rows[identity]['path'];rows[identity].update(bytes=p['bytes'],sha256=p['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash']);signed.append(dict(role=role,key=KEY,relativePath=rel,actualSignedFile=p,**sig));changedrel.add(rel)
  deployedConsumerProfiles.append(dict(id=identity,actualSignedFile=p,actualUUID=actual.uuid,actualImports=actual.imports,actualExports=actual.exports,actualLoads=actual.loads))
 childid=inputs['childid'];childpath=runtime/rows[childid]['path'];childraw=base.regular_bytes(childpath);need(pin(childpath)['sha256']==inputs['childInput']['sha256'],'actual current Child input whole unchanged from Runtime41');entitlements=inputs['signatures'][rows[childid]['path']]['embeddedEntitlements'];need(len(entitlements)==14 and entitlements['com.apple.private.virtualization.plugin']is True and entitlements['com.apple.developer.kernel.extended-virtual-addressing']is True,'actual previous child14 permissions')
 ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements,sort_keys=True));xpc=childpath.parent.parent.parent
 # File Provider may add FinderInfo to this newly created local .xpc directory.
 # Remove only that unsigned directory attribute, never any baseline artifact.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'new own XPC directory attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Sign this own XPC in a local temporary directory: File Provider continually
 # recreates FinderInfo on the Documents .xpc directory. Only exact signed
 # file bytes and CodeResources return to the fresh output; no xattrs ship.
 with tempfile.TemporaryDirectory(prefix='vm27-consumer-stdio42-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,runtime/rows['child-coderesources']['path']):
   originalMode=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=originalMode)

 resourcepath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcepath);seal=plistlib.loads(resources);oldseal=plistlib.loads(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/rows['child-coderesources']['path']));nested=seal['files2']['MacOS/'+KEY];need(nested['cdhash']==bytes.fromhex(rows[IDS[1]]['cdhash'])and not nested.get('optional')and not nested.get('omit'),'actual new required nested ConsumerV7 stdio inheritance provider seal')
 restored=copy.deepcopy(seal);restored['files2']['MacOS/'+KEY]=oldseal['files2']['MacOS/'+KEY];need(restored==oldseal,'only ConsumerV7 stdio inheritance provider resource seal changed')
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
 need(bytes(expected_body)==childafter[:sig['codeLimit']],'entire current Child presignature body whole unchanged from Runtime41 except signature metadata')
 p=pin(childpath);rel=rows[childid]['path'];rows[childid].update(bytes=p['bytes'],sha256=p['sha256'],cdhash=sig['cdhash']);signed.append(dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=p,**sig));changedrel.add(rel);p=pin(resourcepath);rows['child-coderesources'].update(bytes=p['bytes'],sha256=p['sha256'])
 graph=json.loads(inputs['graphRaw']);graph['actualDeployedConsumerProfiles']=deployedConsumerProfiles
 graph['actualCurrentDeployedConsumerLoads']=deployedConsumerProfiles[0]['actualLoads']
 for deployed in deployedConsumerProfiles:need([load_semantic(r)for r in deployed['actualLoads']]==[load_semantic(r)for r in deployed_loads(inputs['provider'])],'deployed graph joins actual normalized load offsets and paths')
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/rows[proofid]['path'];proofpath.write_bytes((json.dumps(graph,indent=2)+'\n').encode());p=pin(proofpath);rows[proofid].update(bytes=p['bytes'],sha256=p['sha256'])
 changedids=set(IDS)|{childid,'child-coderesources',proofid};unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity in changedids:continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256'])and rows[identity]==row,'untouched file wholebytes');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==143,'actual143 untouched signed leaves')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];entryRVA=inputs['manifest']['childEntryContract']['providerEntryRVA']
 need(manifest['entries']==inputs['manifest']['entries'] and manifest['childEntryContract']==inputs['manifest']['childEntryContract'],'CPU bootstrap entry and original Child entry contract whole unchanged')
 raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['signatures'].values()if r['relativePath']not in changedrel];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+signed,actualSignedImages=146,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old143SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 delta=output/'runtime150-to-runtime151-log-growth-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],changedExistingRuntimeIDs=sorted(changedids),addedRuntimeIDs=[],wholeByteUnchangedSignedImages=143,unchangedFiles=unchanged,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,actualCurrentChildInput=inputs['childInput'],allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged=True,allExistingAMXGuardCodeWholeUnchanged=True,childApprovalDerivedFromActualManifest=True,actualBootstrapEntryRVA=entryRVA,deviceOperations=0))

 result=copy.deepcopy(old);result.update(schema='Actual Runtime151 incremental bounded ConsumerV7 stdio inheritance product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=161,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],consumerStdioInheritanceCandidate=inputs['portPin'],consumerStdioInheritanceContract=inputs['stdioContract'],consumerLogGrowthDoesNotRejectSpawn=True,onlyOwnedLogUpperSizeGateRemoved=True,runtime150ConsumerLogGrowthDeltaVerification=pin(delta),actualConsumerExports=9,actualConsumerImports=80,actualConsumerLoads=7,actualConsumerAddedImports=inputs['port']['actualConsumerAddedImports'],consumerFourOwnDependencyLoadsNormalizedToBaselineLoaderPath=True,cpuProviderWholeRuntime150=inputs['hvPins'],cpuProviderAndAll29CPUObjectsWholeRuntime150=True,currentChildPresignatureBodyWholeExceptExactAMXGuardRangesAndSignatureMetadata=False,allExistingAMXGuardCodeWholeUnchanged=True,actualChildMachineBodyChanged=False,currentChildCodeAndImportsWholeUnchanged=True,currentChildPresignatureBodyWholeExceptSignatureMetadata=True,allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged=True,wholeByteUnchangedSignedImages=143,codeSigningCommandsActuallyPerformed=3,existingSignedImagesResigned=3,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0);result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--consumer-stdio-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual product output');inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.consumer_stdio_candidate.resolve());o.mkdir(mode=0o700)
 try:
  result=assemble(inputs,o);candidate=o/'candidate.json';save(candidate,result);files=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],inputs['portPin'],pin(a.consumer_stdio_candidate.parent/'freeze.json'),inputs['port']['consumer'],inputs['childInput'],pin(NATIVE_INDEX),pin(NATIVE_INDEX.parent/'freeze.json')]+inputs['port']['sourceFiles']+inputs['port']['actualChangedObjects']+inputs['port']['inheritedWholeObjects']+[inputs['port']['stdioInheritanceBasis']]+inputs['nativeClosure']['actualNativeSourcePins']+inputs['nativeClosure']['actualOwnedProviderPins']+inputs['hvPins'];save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
