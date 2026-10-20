#!/usr/bin/env python3
"""Runtime88: native owned GPU task transport; Root alone signs.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime86 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime88_owned_gpu_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
BASELINE_SHA='aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'exact file '+row['path']);return pathlib.Path(row['path'])
def frozen(path):
 rows=base.frozen_rows(path.parent/'freeze.json');base.actual_frozen(pin(path),rows,'actual frozen candidate');return rows
def semantic(r):return{k:v for k,v in r.items()if k not in ('at','index')}
def multiset(rows):return sorted([semantic(r)for r in rows],key=lambda r:json.dumps(r,sort_keys=True))

def read_inputs(baseline_path,pg_path,gpu_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'actual signed Runtime86 baseline and reviewed signature primitives')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path)
 for key in ('manifest','signatureVerification'):base.actual_frozen(old[key],bf,'actual Runtime86 '+key)
 need(old['localCodeSigned']is True and old['actualProductPreflightPassed']is True,'actual signed Runtime86 product')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']}
 need(len(rows)==len(manifest['files'])==154,'actual154 Runtime86 files')
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
 need(child.uuid==CHILD_UUID and len(child.imports)==1207,'actual Runtime86 Child with VT two-entry route retained')
 prior=proof[rows[childid]['path']]['embeddedEntitlements']
 need(isinstance(prior,dict)and len(prior)==14 and prior.get(KEY)==['IOSurfaceRootUserClient','AGXDeviceUserClient']and
      prior.get('com.apple.private.virtualization.plugin')is True and prior.get('com.apple.developer.kernel.extended-virtual-addressing')is True,'same exact14 Child entitlements')
 cpupin=old['cpu29SourceProof'];exact(cpupin)
 cpuobjects=old['cpu29Objects'];need(len(cpuobjects)==29,'actual Runtime86 CPU29 proof')
 graphid=manifest['dependencyProofID'];graphpath=root/rows[graphid]['path'];oldgraph=json.loads(base.regular_bytes(graphpath))
 need(oldgraph['finalStrongDefinitionGraphClosed']is True and oldgraph['unresolvedStrongImportRows']==[],'actual Runtime86 definition graph closure inherited by reference')
 graph=dict(schema='Actual Runtime88 owned GPU task incremental definition proof',finalStrongDefinitionGraphClosed=True,
  unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(graphpath),
  inheritedBaselineDefinitionGraphReference=pin(graphpath),all29CPUObjectsAndBothSignedCPUProvidersWholeRuntime86=True,
  originalRuntime86ChildCodeImportsAndVTAuthSlotsWhole=True,oldGraphRerun=False,oldGraphNotInlined=True,deviceOperations=0)
 inputs=dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=copy.deepcopy(prior),
  baselinePin=pin(baseline_path),graphRaw=(json.dumps(graph,indent=2)+'\n').encode(),cpu29SourceProof=cpupin,cpu29Objects=cpuobjects)
 return admit_gpu_delta(admit_pg_delta(inputs,pg_path),gpu_path)

PORT_PLAN_SHA='6db8f96ff690367b020f8d90f139512114d32ef122044fc28b3651239449007a'
CONTRACT='ownedPGRemoteTaskParentTransportV1Contract'
TARGET='/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'
GPU_XPC='gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc'
GPU_EXE='com.apple.gpusw.ParavirtualizedGraphicsGPUTask'
NATIVE_INDEX=N/'current-native-header-export-index-v3/index.json'
NATIVE_INDEX_SHA='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'

def md_definition_graph(inputs,md):
 """Resolve only the actual changed MD imports; old graph stays a frozen reference."""
 need(pin(NATIVE_INDEX)['sha256']==NATIVE_INDEX_SHA,'actual captured native definition index')
 native=json.loads(base.regular_bytes(NATIVE_INDEX))['images'];captured={};owned={};root=pathlib.Path(inputs['old']['runtimeRoot']);rows=inputs['rows']
 def resolve(path,symbol,seen=()):
  if path.startswith(TARGET+'/child-flat/'):
   rel=path[len(TARGET+'/'):];path=next((r['id'].split(':',1)[1]for r in rows.values()if r['path']==rel and r['id'].startswith('child:')),path)
  if path.startswith(('@loader_path/','@rpath/')):path=path.split('/',1)[1]
  key=(path,symbol);need(key not in seen and len(seen)<64,'finite real definition route');seen=seen+(key,)
  if path.startswith('/'):
   if path not in native:raise LookupError('native definition image '+path)
   record=native[path];sources=[record['actualCompleteExportSource']['rangePin'],record['actualCompleteCommands']]+[r['rangePin']for r in record.get('actualCommandSourceRanges',[])]
   for row in sources:exact(row);captured[row['path']]=row
   ex=record['definitions'].get(symbol);deps=record['dependencies'];node=dict(provider=path,uuid=record['UUID'],symbol=symbol)
  else:
   if path=='MD':image=md
   else:
    identity='child:'+path;need(identity in rows,'actual same-role MD dependency '+identity)
    if identity not in owned:
     p=pin(root/rows[identity]['path']);need((p['bytes'],p['sha256'])==(rows[identity]['bytes'],rows[identity]['sha256']),'whole own provider dependency');owned[identity]=(base.image_profile(base.regular_bytes(p['path']),path),p)
    image=owned[identity][0]
   ex=image.exports.get(symbol);deps=image.loads;node=dict(provider='child:'+path,uuid=image.uuid,symbol=symbol)
  if ex is not None:
   node['actualExport']=ex
   if ex['flags']&8:
    dep=next(d for d in deps if d['ordinal']==ex['ordinal']);return [node]+resolve(dep['path'],ex.get('alias')or ex.get('importedName')or symbol,seen)
   need((ex['flags']&3)==0 and not(ex['flags']&16),'real regular strong definition');return [node]
  for dep in deps:
   if dep.get('command',dep.get('cmd'))!=0x8000001f:continue
   try:return [dict(node,actualReexportLoad=dep)]+resolve(dep['path'],symbol,seen)
   except LookupError:pass
  raise LookupError('unresolved actual MD import '+path+' '+symbol)
 resolutions=[]
 for imp in md.imports:
  need(not imp['weak'] and imp['ordinal']>0 and imp['addend']==0,'actual strong ordinary MD import')
  dep=next(d for d in md.loads if d['ordinal']==imp['ordinal']);resolutions.append(dict(actualImport=imp,requiredLoad=dep,resolution=resolve(dep['path'],imp['name'])))
 return dict(actualCurrentMDStrongDefinitions=resolutions,currentNativeIndex=pin(NATIVE_INDEX),actualNativeSourcePins=list(captured.values()),actualOwnedProviderPins=[p for image,p in owned.values()])

def admit_pg_delta(inputs,path):
 port=json.loads(base.regular_bytes(path));pf=frozen(path);root=pathlib.Path(inputs['old']['runtimeRoot']);rows=inputs['rows'];mdid='child:MD';pgid='child:ParavirtualizedGraphics27.dylib'
 need(port['baselineRuntimeCandidate']==inputs['baselinePin'] and port['providerKey']=='MD'and port['roles']==['child'],'actual R86 child-only MD/PG parent transport port')
 for key in('newProvider','patchedChildPG','recipe','sourcePlan','actualIOSCompile','actualIOSLink','actualMDValidate','actualPGValidate','generatedParentProfile','existingMDImportDefinitionEquivalence'):
  base.actual_frozen(port[key],pf,'actual Root-compiled GPU parent '+key);exact(port[key])
 need(port['sourcePlan']['sha256']==PORT_PLAN_SHA and port['contractKey']==CONTRACT and port['compileLinkAndBothValidateExit']==[0,0,0,0]and port['globalAppleClassMutation']is False,'final reviewed parent source/strict compile/link/validation')
 plan=json.loads(base.regular_bytes(exact(port['sourcePlan'])));need(port[CONTRACT]==plan[CONTRACT],'exact genuine parent transport contract')
 need(port['originalProvider']==pin(root/rows[mdid]['path'])and port['originalChildPG']==pin(root/rows[pgid]['path'])and port['originalChild']==pin(root/rows[inputs['childID']]['path']),'actual baseline original images')
 need('patchedChild'not in port and 'patchedChildMain'not in port,'VMM machine body unchanged by source port')
 selected=port['selectedSlots'];need(len(selected)==1,'one exact service initializer slot');slot=selected[0]
 need(slot['authSlotRVA']==0x6c850 and slot['newImportIndex']==287 and slot['originalImportIndex']==144 and slot['symbol']=='_VM27OwnedGPUTaskConnectionInitV1'and slot['requiredOrdinal']==10 and slot['callerReturnRVA']==0x36398,'actual unique PGRemoteTask initializer ABI')
 md=base.image_profile(base.regular_bytes(exact(port['newProvider'])),'MD');oldmd=base.image_profile(base.regular_bytes(root/rows[mdid]['path']),'old MD');pg=base.image_profile(base.regular_bytes(exact(port['patchedChildPG'])),'PG');before=base.image_profile(base.regular_bytes(root/rows[pgid]['path']),'old PG')
 need(set(md.exports)==set(oldmd.exports)|{slot['symbol']}and all(md.exports[k]['flags']==oldmd.exports[k]['flags']for k in oldmd.exports)and md.exports[slot['symbol']]['flags']==0,'all31 current MD exports plus one actual strong initializer')
 equivalence=json.loads(base.regular_bytes(exact(port['existingMDImportDefinitionEquivalence'])))
 need(equivalence['allOldImportNamesWeakAndAddendsPreserved']is True and equivalence['allActualTerminalNativeDefinitionsSame']is True and equivalence['nativeIndex']==pin(NATIVE_INDEX),'exact actual old/new native definition proof')
 need([r['originalImport']for r in equivalence['rows']]==oldmd.imports,'all original50 MD imports each have actual equivalence row')
 for row in equivalence['rows']:
  oldimp,newimp=row['originalImport'],row['actualImport'];need(newimp in md.imports and all(oldimp[k]==newimp[k]for k in('name','weak','addend')),'same actual old symbol/weak/addend with exact current import')
  need(row['sameActualNativeDefinition']is True and row['originalResolution'][-1]==row['actualResolution'][-1],'same terminal native UUID/symbol/regular export/address; reexport owner may differ')
 for source in equivalence['actualNativeSourcePins']:base.actual_frozen(source,pf,'captured native definition source');exact(source)
 need([semantic(r)for r in md.loads[:len(oldmd.loads)]]==[semantic(r)for r in oldmd.loads] and len(md.loads)==len(oldmd.loads)+3,'all six old dependency ordinals whole plus three actual own providers')
 need([pathlib.PurePosixPath(r['path']).name for r in md.loads[len(oldmd.loads):]]==['VM27LargeConsumerV2.dylib','VM27LargeRegistry.dylib','VM27OwnedAppStartupV3.dylib'],'only existing own transport providers appended')
 need(pg.uuid==before.uuid and pg.exports==before.exports and pg.sections==before.sections and [semantic(r)for r in pg.loads]==[semantic(r)for r in before.loads]and len(before.imports)==287 and len(pg.imports)==288,'original PG geometry/UUID/exports/loads and one added import')
 need([semantic(r)for r in pg.imports[:287]]==[semantic(r)for r in before.imports],'all287 old PG import semantics whole')
 a=base.regular_bytes(root/rows[pgid]['path']);b=base.regular_bytes(exact(port['patchedChildPG']));oldbind=next(r for r in before.binds if r['fileoff']==0x6c850);newbind=next(r for r in pg.binds if r['fileoff']==0x6c850)
 need(oldbind['word']==plan['selectedAuthSlot']['oldWord']and oldbind['index']==144 and newbind['index']==287 and newbind['word']==(oldbind['word']&~65535)|287 and pg.imports[287]['name']==slot['symbol']and pg.imports[287]['ordinal']==10 and not pg.imports[287]['weak']and pg.imports[287]['addend']==0,'one real typed authenticated import changes only index')
 need([(r['fileoff'],r['word'])for r in before.binds if r['fileoff']!=0x6c850]==[(r['fileoff'],r['word'])for r in pg.binds if r['fileoff']!=0x6c850],'all other PG bindings whole')
 for sec in before.sections:
  at,z=sec['fileoff'],sec['size']
  if not at or not z or sec['flags']&255 in(1,12,18):continue
  expected=bytearray(a[at:at+z])
  if at<=0x6c850<at+z:expected[0x6c850-at:0x6c858-at]=b[0x6c850:0x6c858]
  need(bytes(expected)==b[at:at+z],'all actual PG backed sections whole except one auth slot')
 prior=json.loads(base.regular_bytes(exact(inputs['old']['ownedPGDisplayHandshakeObservationV1Candidate'])))
 need(len(port['actualIOSObjects'])==3 and port['actualIOSObjects'][1:]==prior['actualIOSObjects'][1:],'VT/exception object bytes whole, only MD root26 compiled')
 for row in port['actualIOSObjects']+port['sourceFiles']:base.actual_frozen(row,pf,'actual parent linked object/source');exact(row)
 closure=md_definition_graph(inputs,md);graph=json.loads(inputs['graphRaw']);graph.update(schema='Actual Runtime88 owned native GPU service incremental strong definitions',ownedPGRemoteTaskParentTransportV1Candidate=pin(path),ownedPGRemoteTaskParentTransportV1Contract=port[CONTRACT],actualCurrentMDExports=md.exports,actualCurrentMDImports=md.imports,actualCurrentMDLoads=md.loads,actualCurrentPGImports=pg.imports,actualCurrentPGInitializerDefinition=dict(actualImport=pg.imports[287],provider=port['newProvider'],definition=md.exports[slot['symbol']]),onlyChangedExistingProviderIDs=[mdid,pgid],oldMDImportDefinitionEquivalence=port['existingMDImportDefinitionEquivalence'],oldMDImportOwnerMayChangeOnlyToSameActualNativeDefinition=True,**closure)
 inputs.update(pgPort=port,pgPortPin=pin(path),pgSourcePlan=port['sourcePlan'],md=md,pg=pg,mdID=mdid,pgID=pgid,observationContract=port[CONTRACT],selectedSlots=selected,nativeClosure=closure,graphRaw=(json.dumps(graph,indent=2)+'\n').encode());return inputs

def admit_gpu_delta(inputs,path):
 gpu=json.loads(base.regular_bytes(path));gf=frozen(path)
 need(gpu['schema']=='NativeGPUTaskOwnedEntryProductV1'and gpu['actualIOSCompileStrictLinkDyldAndSigningPassed']is True and gpu['sandboxProfileApplied']is False,'actual signed original native GPU task, no fake sandbox claim')
 need(inputs['pgPort']['gpuTaskCandidate']==pin(path),'parent profile pins this exact previously signed child')
 task_signature=next(r for r in gpu['signedFiles']if r['actualSignedFile']==gpu['task'])
 need(task_signature['embeddedEntitlements'].get('com.apple.private.security.no-container')is True,'actual native GPU task receives required no-container permission')
 keys=('task','compat','taskInfo','outerBundleInfo','taskCodeResources','defaultMetallib','sourcePlan','actualImportClosure')
 for key in keys:base.actual_frozen(gpu[key],gf,'actual signed GPU helper '+key);exact(gpu[key])
 closure=json.loads(base.regular_bytes(exact(gpu['actualImportClosure'])))
 need(closure['unresolved']==[] and len(gpu['signedFiles'])==2,'all186 native task imports plus shim definitions closed, two actual signatures')
 root=pathlib.Path(inputs['old']['runtimeRoot']);helperroot=pathlib.Path(gpu['runtimeRoot']);additions=[];signatures={r['actualSignedFile']['path']:r for r in gpu['signedFiles']}
 ids=dict(task='gpu-task:main',compat='gpu-task:compat',taskInfo='gpu-task-info',outerBundleInfo='gpu-task-bundle-info',taskCodeResources='gpu-task-coderesources',defaultMetallib='gpu-task-metallib')
 for key in keys[:6]:
  src=exact(gpu[key]);relative='gpu-task-flat/'+str(src.relative_to(helperroot));need(base.relative(relative),'safe finite GPU runtime path')
  row=dict(id=ids[key],path=relative,kind='mach-o'if key in('task','compat')else'resource',role='gpu-task',bytes=gpu[key]['bytes'],sha256=gpu[key]['sha256'])
  if key in('task','compat'):
   sig=signatures[str(src)];image=base.image_profile(base.regular_bytes(src),src.name)
   need(sig['allPrimaryPagesAndSpecialSlotsVerified']is True and sig['uuid']==image.uuid,'actual signed GPU image pages/slots/UUID')
   resolved=[r for r in closure['rows']if r['image']['path']==str(src)]
   need([semantic(r['actualImport'])for r in resolved]==[semantic(r)for r in image.imports]and all(r['actualDefinition']or r['actualImport']['weak']for r in resolved),'signed GPU import semantics join exact pre-signing strong closure; prior image byte pins describe pre-signing only')
   row.update(uuid=image.uuid,cdhash=sig['cdhash'])
   if key=='task':row['signatureSlots']={'1':ids['taskInfo'],'3':ids['taskCodeResources']}
  additions.append(dict(key=key,source=gpu[key],row=row))
 need(next(a['row']['path']for a in additions if a['key']=='task')==GPU_XPC+'/Contents/MacOS/'+GPU_EXE and next(a['row']['path']for a in additions if a['key']=='compat')==GPU_XPC+'/Contents/MacOS/VM27OwnedGPUTaskCompatV1.dylib','exact canonical native task and compat layout')
 for row in gpu['frozenReuseProviders']:
  exact(row);r=next(r for r in inputs['rows'].values()if root/r['path']==pathlib.Path(row['path']));need((r['bytes'],r['sha256'])==(row['bytes'],row['sha256']),'all four GPU dependencies are actual whole baseline providers')
 graph=json.loads(inputs['graphRaw']);graph.update(nativeOwnedGPUTaskProduct=pin(path),actualGPUImportClosure=gpu['actualImportClosure'],actualGPUImportClosureUnresolved=[],actualSignedGPUImportTablesJoinedToPriorClosure=True,gpuClosureImageBytePinsDescribePreSigningOnly=True,nativeGPUOriginal186ImportsRetained=True,actualGPUFrozenReuseProviders=gpu['frozenReuseProviders'],gpuOwnBootstrapDoesNotClaimNativeHandshake=True,gpuSandboxProfileApplied=False)
 inputs.update(gpu=gpu,gpuPin=pin(path),gpuAdditions=additions,gpuSignatures=signatures,graphRaw=(json.dumps(graph,indent=2)+'\n').encode());return inputs


def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 # Both existing signed CPU providers remain exact Runtime86 bytes.
 replacements={inputs['mdID']:inputs['pgPort']['newProvider'],inputs['pgID']:inputs['pgPort']['patchedChildPG']}
 leafraw={};leafimages={inputs['mdID']:inputs['md'],inputs['pgID']:inputs['pg']}
 untouchedSigned=143-(len(replacements)+1)
 for identity,source in replacements.items():
  path=runtime/rows[identity]['path'];path.unlink();base.copy_regular(pathlib.Path(source['path']),path);leafraw[identity]=base.regular_bytes(path)
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-owned-gpu88-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  for identity in replacements:
   path=txpc/(runtime/rows[identity]['path']).relative_to(xpc);label='MD'if identity==inputs['mdID']else'PG'
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
 need(inherited==original,'all other resources, native shader, rules and nested seals preserved outside actual replacement leaves')
 cr=pin(runtime/rows['child-coderesources']['path']);rows['child-coderesources'].update(bytes=cr['bytes'],sha256=cr['sha256'])
 after=base.regular_bytes(childpath);actual=base.image_profile(after,CHILD)
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'actual Runtime86 Child namespace/PAC/code geometry retained')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed Runtime86 Child section retained')
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
  if identity in (childid,'child-coderesources',proofid,*replacements):continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']) and rows[identity]==row,'all other product files whole unchanged');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==untouchedSigned,'actual untouched signed-image count')
 # Add the already signed native task and its finite bundle resources, without resigning either image.
 added=[];gpuSigned=[]
 for addition in inputs['gpuAdditions']:
  row=copy.deepcopy(addition['row']);identity=row['id'];need(identity not in rows and not(runtime/row['path']).exists(),'new GPU path must be absent in baseline')
  destination=runtime/row['path'];base.copy_regular(exact(addition['source']),destination,executable=row['kind']=='mach-o');rows[identity]=row;added.append(identity)
  actualpin=pin(destination);need((actualpin['bytes'],actualpin['sha256'])==(row['bytes'],row['sha256']),'whole signed GPU product bytes copied')
  if row['kind']=='mach-o':
   im=base.image_profile(base.regular_bytes(destination),destination.name)
   external={1:base.regular_bytes(exact(inputs['gpu']['taskInfo'])),3:base.regular_bytes(exact(inputs['gpu']['taskCodeResources']))}if addition['key']=='task'else None
   ss=base.signature(base.regular_bytes(destination),im.uuid,external);need(ss['cdhash']==row['cdhash'],'inherited actual GPU CD/page/special-slot verification')
   if addition['key']=='task':need(len(im.imports)==186,'actual whole native GPU task186 import rows')
   gpuSigned.append(dict(role='gpu-task',key=destination.name,relativePath=row['path'],actualSignedFile=actualpin,**ss))
 need(len(added)==6 and len(gpuSigned)==2,'finite six native GPU bundle files / two new signed images')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']]+[rows[identity]for identity in added]
 need(manifest['entries']==inputs['manifest']['entries']and manifest['childEntryContract']==inputs['manifest']['childEntryContract'],'all actual CPU manifest entry RVAs and Child entry contract whole Runtime86')
 raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements)}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed]+gpuSigned,actualSignedImages=145,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,wholeSignedFilesAndCDProofInherited=untouchedSigned,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements},'only Child MD/PG/main/seal and incremental proof rows change')
 delta=output/'runtime86-to-runtime88-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=145,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=added,wholeByteUnchangedSignedImages=untouchedSigned,unchangedFiles=unchanged,dependencyProofOnlyActualMDAndPGAndNativeGPUDefinitionsUpdated=True,allCPUManifestEntriesAndChildEntryContractWholeRuntime86=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesWholeUnchanged=True,originalRuntime86ChildCodeImportsAndVTAuthSlotsWhole=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old)
 historical={k:result.pop(k)for k in list(result)if result[k]is True and (k.startswith('allMDPGVTAndOtherProvidersWholeRuntime')or k.startswith('allNonCPUProviderFilesWholeRuntime'))}
 result['historicalRuntime86UnchangedProviderClaims']=historical
 result['priorMDWholeClaimsDescribeHistoricalProductsOnly']=True
 result.update(schema='Actual Runtime88 native owned GPU task and exact PGRemoteTask parent transport product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],runtime86PGDisplayHandshakeObservationDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=untouchedSigned,codeSigningCommandsActuallyPerformed=len(replacements)+1,existingSignedImagesResigned=len(replacements)+1,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,all29CPUObjectsWholeRuntime86=True,bothSignedCPUProvidersWholeRuntime86=True,allCPUManifestEntriesAndChildEntryContractWholeRuntime86=True,originalRuntime86ChildCodeImportsAndVTAuthSlotsWhole=True,cpu29SourceProof=inputs['cpu29SourceProof'],cpu29Objects=inputs['cpu29Objects'])
 result.update(ownedPGRemoteTaskParentTransportV1Candidate=inputs['pgPortPin'],
  ownedPGRemoteTaskParentTransportV1Contract=inputs['observationContract'],ownedGPUParentSourcePlan=inputs['pgSourcePlan'],
  nativeOwnedGPUTaskProduct=inputs['gpuPin'],nativeOwnedGPUTaskSourcePlan=inputs['gpu']['sourcePlan'],nativeOwnedGPUTaskImportClosure=inputs['gpu']['actualImportClosure'],
  gpuParentSelectedAuthSlots=inputs['selectedSlots'],actualOtherProvidersExceptChildMDAndPGWholeRuntime86=True,
  actualVTAndExceptionBridgeObjectsWholeRuntime86=True,allChildEntitlementsWholeUnchanged=True,
  all29CPUObjectsWholeRuntime86=True,bothSignedCPUProvidersWholeRuntime86=True,
  cpuProvidersWholeRuntime86=[pin(runtime/rows['parent:VM27HVVMProduction.dylib']['path']),pin(runtime/rows['child:VM27HVVMProduction.dylib']['path'])],
  nativeGPUTaskImagesPreviouslySignedAndWholeInherited=2,nativeGPUTaskImagesResigned=0,nativeGPUTaskSandboxProfileApplied=False,
  nativeGPUTaskNoContainerEntitlementActuallyPresent=True,nativeGPUTaskActualEntitlements=next(r['embeddedEntitlements']for r in inputs['gpu']['signedFiles']if r['actualSignedFile']==inputs['gpu']['task']),
  gpuOwnBootstrapDoesNotClaimOriginalNativeHandshakeSuccess=True,
  actualChangedRuntimeCDHashes=sorted({row['cdhash']for row in leafsigned+[signed]+gpuSigned}),
  actualChangedSignedRuntimeFiles=len(leafsigned)+1,actualAddedSignedRuntimeFiles=len(gpuSigned),addedRuntimeIDs=added)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--pg-port-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--gpu-task-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path)
 ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve()
 need(o.parent==N and not o.exists(),'fresh actual Runtime88 output')
 inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.pg_port_candidate.resolve(),a.gpu_task_candidate.resolve())
 o.mkdir(mode=0o700);admission=o/'admission.json'
 save(admission,dict(schema='Runtime88 actual owned native GPU task signature admission',baseline=inputs['baselinePin'],parentSourcePort=inputs['pgPortPin'],nativeGPUProduct=inputs['gpuPin'],all29CPUObjectsAndBothCPUProvidersWholeRuntime86=True,originalVMMBodyImportsAnd14EntitlementsWhole=True,originalVMMCodeResourcesAndSignatureWillBeResealed=True,original154FilesWholeVerified=True,original143SignatureProvenanceJoined=True,newNativeGPUImagesAlreadySigned=2,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result)
  pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['cpu29SourceProof'],*inputs['cpu29Objects'],inputs['pgPortPin'],pin(a.pg_port_candidate.parent/'freeze.json'),inputs['pgSourcePlan'],inputs['pgPort']['newProvider'],inputs['pgPort']['patchedChildPG'],inputs['pgPort']['recipe'],inputs['pgPort']['generatedParentProfile'],inputs['pgPort']['existingMDImportDefinitionEquivalence'],*inputs['pgPort']['actualIOSObjects'],*inputs['pgPort']['sourceFiles'],inputs['gpuPin'],pin(a.gpu_task_candidate.parent/'freeze.json'),*[inputs['gpu'][k]for k in('task','compat','taskInfo','outerBundleInfo','taskCodeResources','defaultMetallib','sourcePlan','actualImportClosure')],*inputs['gpu']['frozenReuseProviders'],inputs['nativeClosure']['currentNativeIndex'],*inputs['nativeClosure']['actualNativeSourcePins'],*inputs['nativeClosure']['actualOwnedProviderPins']]
  save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0))
  print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
