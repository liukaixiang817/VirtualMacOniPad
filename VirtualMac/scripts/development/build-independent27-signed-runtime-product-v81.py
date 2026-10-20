#!/usr/bin/env python3
"""Runtime75 draft: two exact typed PG display-handshake observations; Root alone signs.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime74 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime75_pg_display_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
BASELINE_SHA='ca6e15db641596a4a66ba1b62fc6d3586cc4f1a27b59cfbfcb7737e4c2d46ad9'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'exact file '+row['path']);return pathlib.Path(row['path'])
def frozen(path):
 rows=base.frozen_rows(path.parent/'freeze.json');base.actual_frozen(pin(path),rows,'actual frozen candidate');return rows
def semantic(r):return{k:v for k,v in r.items()if k not in ('at','index')}
def multiset(rows):return sorted([semantic(r)for r in rows],key=lambda r:json.dumps(r,sort_keys=True))

def read_inputs(baseline_path,pg_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'actual signed Runtime74 baseline and reviewed signature primitives')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path)
 for key in ('manifest','signatureVerification'):base.actual_frozen(old[key],bf,'actual Runtime74 '+key)
 need(old['localCodeSigned']is True and old['actualProductPreflightPassed']is True,'actual signed Runtime74 product')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']}
 need(len(rows)==len(manifest['files'])==154,'actual154 Runtime74 files')
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
 need(child.uuid==CHILD_UUID and len(child.imports)==1207,'actual Runtime74 Child with VT two-entry route retained')
 prior=proof[rows[childid]['path']]['embeddedEntitlements']
 need(isinstance(prior,dict)and len(prior)==14 and prior.get(KEY)==['IOSurfaceRootUserClient','AGXDeviceUserClient']and
      prior.get('com.apple.private.virtualization.plugin')is True and prior.get('com.apple.developer.kernel.extended-virtual-addressing')is True,'same exact14 Child entitlements')
 cpupin=old['cpu29SourceProof'];base.actual_frozen(cpupin,bf,'inherited exact29 CPU source proof');exact(cpupin)
 cpuobjects=old['cpu29Objects'];need(len(cpuobjects)==29,'actual Runtime74 CPU29 proof')
 graphid=manifest['dependencyProofID'];graphpath=root/rows[graphid]['path'];oldgraph=json.loads(base.regular_bytes(graphpath))
 need(oldgraph['finalStrongDefinitionGraphClosed']is True and oldgraph['unresolvedStrongImportRows']==[],'actual Runtime74 definition graph closure inherited by reference')
 graph=dict(schema='Actual Runtime75 typed display observation incremental definition proof',finalStrongDefinitionGraphClosed=True,
  unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(graphpath),
  inheritedBaselineDefinitionGraphReference=pin(graphpath),all29CPUObjectsAndBothSignedCPUProvidersWholeRuntime74=True,
  originalRuntime74ChildCodeImportsAndVTAuthSlotsWhole=True,oldGraphRerun=False,oldGraphNotInlined=True,deviceOperations=0)
 inputs=dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=copy.deepcopy(prior),
  baselinePin=pin(baseline_path),graphRaw=(json.dumps(graph,indent=2)+'\n').encode(),cpu29SourceProof=cpupin,cpu29Objects=cpuobjects)
 return admit_pg_delta(inputs,pg_path)

CPU_KEY='VM27HVVMProduction.dylib'
CPU_IDS=('parent:'+CPU_KEY,'child:'+CPU_KEY)
PG_PORT_SHA='a1a3d13888889934cad11a01c79f91c7510caf2b5f4a4e3ea61e6f3a7b24ba37'
PG_PLAN_SHA='314448dc15d30069dc739ffe2657ffc166bb8bc8ae258e3c06955ad1977da20f'
PG_CONTRACT_KEY='ownedPGDisplayHandshakeObservationV1Contract'
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
 need(len(PG_PORT_SHA)==64 and pin(pg_path)['sha256']==PG_PORT_SHA,'final Root-compiled actual two-slot typed display observation port')
 port=json.loads(base.regular_bytes(pg_path));pf=frozen(pg_path);old=inputs['old'];rows=inputs['rows'];root=pathlib.Path(old['runtimeRoot'])
 mdid='child:MD';pgid='child:ParavirtualizedGraphics27.dylib'
 need(port['baselineRuntimeCandidate']==inputs['baselinePin']and port['providerKey']=='MD'and port['roles']==['child'],'actual Runtime74 MD/PG-only port ancestry')
 for key in ('newProvider','patchedChildPG','recipe','sourcePlan','actualIOSCompile','actualIOSLink','actualMDValidate','actualPGValidate'):
  base.actual_frozen(port[key],pf,'actual frozen finite capability '+key);exact(port[key])
 need(port['originalProvider']==pin(root/rows[mdid]['path'])and port['originalChildPG']==pin(root/rows[pgid]['path'])and
      port['originalChild']==pin(root/rows[inputs['childID']]['path']),'actual Runtime74 MD/PG and unchanged Child inputs')
 need('patchedChild'not in port and 'patchedChildMain'not in port,'this capability port leaves original Child code and VT bindings whole')
 need(port['compileLinkAndBothValidateExit']==[0,0,0,0]and port['newRequiredLoadsAdded']==0 and port['globalAppleClassMutation']is False,'actual one-root compile/link/two validations; no new load or class mutation')
 sourceplan=json.loads(base.regular_bytes(exact(port['sourcePlan'])));contracts=port['selectedSlots']
 need(port['sourcePlan']['sha256']==PG_PLAN_SHA and sourceplan['contractKey']==port['contractKey']==PG_CONTRACT_KEY and
      port[PG_CONTRACT_KEY]==sourceplan[PG_CONTRACT_KEY]and contracts==sourceplan['selectedSlots']and len(contracts)==2,
      'exact reviewed two typed display observation source contracts and finite slot list')
 symbols={r['symbol']for r in contracts};slots={r['authSlotRVA']for r in contracts}
 need(len(symbols)==len(slots)==2 and set(port['addedExports'])==symbols and
      symbols=={'_VM27OwnedPGDisplayStateMachineObserveV1','_VM27OwnedPGDisplaySwapObserveV1'},'only two exact typed observation exports and auth slots')
 for i,row in enumerate(contracts):
  need(row['newImportIndex']==285+i and row['originalImportIndex']==144 and row['requiredOrdinal']==10,'two exact strong PG imports on existing MD ordinal10')
 md=base.image_profile(base.regular_bytes(exact(port['newProvider'])),'MD');oldmd=base.image_profile(base.regular_bytes(root/rows[mdid]['path']),'old MD')
 pg=base.image_profile(base.regular_bytes(exact(port['patchedChildPG'])),'PG');originalpg=base.image_profile(base.regular_bytes(root/rows[pgid]['path']),'original PG')
 need(len(oldmd.exports)==29 and set(md.exports)==set(oldmd.exports)|symbols and
      all(md.exports[s]['flags']==oldmd.exports[s]['flags']for s in oldmd.exports)and all(md.exports[s]['flags']==0 for s in symbols),
      'all29 MD exports and functional routes retained; only two typed observation exports added')
 need(len(oldmd.imports)==len(md.imports)==50 and multiset(md.imports)==multiset(oldmd.imports)and
      [semantic(r)for r in md.loads]==[semantic(r)for r in oldmd.loads],'all50 MD native imports and required loads retained')
 prior=json.loads(base.regular_bytes(exact(old['ownedPGCmd58RemainingBOOLCapabilitiesV1Candidate'])))
 newobjects=port['actualIOSObjects'];need(len(newobjects)==len(prior['actualIOSObjects'])==3 and newobjects[1:]==prior['actualIOSObjects'][1:],'actual exception bridge and VT objects whole; only current MD root recompiled')
 for row in newobjects:base.actual_frozen(row,pf,'actual linked MD object');exact(row)
 need(len(originalpg.imports)==285 and len(pg.imports)==287,'only two reviewed typed PG imports appended')
 exact_new_slots(originalpg,pg,[(r['authSlotRVA'],144,r['newImportIndex'],r['symbol'],10)for r in contracts])
 a=base.regular_bytes(root/rows[pgid]['path']);b=base.regular_bytes(exact(port['patchedChildPG']))
 need(len(pg.sections)==len(originalpg.sections),'same PG section geometry')
 for before,after in zip(originalpg.sections,pg.sections,strict=True):
  need(before==after,'same original PG section metadata');at,z=before['fileoff'],before['size']
  if not at or not z or before['flags']&255 in(1,12,18):continue
  expected=bytearray(a[at:at+z])
  for slot in slots:
   if at<=slot<at+z:expected[slot-at:slot-at+8]=b[slot:slot+8]
  need(bytes(expected)==b[at:at+z],'all PG code/data whole except two reviewed auth slots')
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
 graph.update(schema='Actual Runtime75 two typed display-handshake observation incremental definitions',
  ownedPGDisplayHandshakeObservationV1Candidate=pin(pg_path),ownedPGDisplayHandshakeObservationV1Contract=port[PG_CONTRACT_KEY],
  actualCurrentMDExports=md.exports,actualCurrentMDImports=md.imports,actualCurrentMDRequiredLoads=md.loads,
  actualCurrentChildMDDefinitions=childdefs,actualCurrentPGMDDefinitions=pgdefs,actualInheritedNativeMetalReexportRows=metal,
  all50PriorMDNativeSemanticsInherited=True,actualNewNativeImportRows=[],onlyChangedProviderIDs=[mdid,pgid],
  originalVTAndExceptionObjectsWholeRuntime74=True,originalRuntime74ChildCodeImportsAndVTAuthSlotsWhole=True)
 inputs.update(pgPort=port,pgPortPin=pin(pg_path),pgSourcePlan=port['sourcePlan'],md=md,pg=pg,mdID=mdid,pgID=pgid,
  observationContract=port[PG_CONTRACT_KEY],selectedSlots=contracts,graphRaw=(json.dumps(graph,indent=2)+'\n').encode())
 return inputs


def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 # Both existing signed CPU providers remain exact Runtime74 bytes.
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
 with tempfile.TemporaryDirectory(prefix='vm27-pg-display75-sign-',dir='/private/tmp') as temporary:
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
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'actual Runtime74 Child namespace/PAC/code geometry retained')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed Runtime74 Child section retained')
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
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']]
 need(manifest['entries']==inputs['manifest']['entries']and manifest['childEntryContract']==inputs['manifest']['childEntryContract'],'all actual CPU manifest entry RVAs and Child entry contract whole Runtime74')
 raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements)}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed],actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,wholeSignedFilesAndCDProofInherited=untouchedSigned,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements},'only Child MD/PG/main/seal and incremental proof rows change')
 delta=output/'runtime74-to-runtime75-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=untouchedSigned,unchangedFiles=unchanged,dependencyProofOnlyActualMDAndPGDefinitionsUpdated=True,allCPUManifestEntriesAndChildEntryContractWholeRuntime74=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesWholeUnchanged=True,originalRuntime74ChildCodeImportsAndVTAuthSlotsWhole=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime75 two typed PG display-handshake observation product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],runtime74PGDisplayHandshakeObservationDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=untouchedSigned,codeSigningCommandsActuallyPerformed=len(replacements)+1,existingSignedImagesResigned=len(replacements)+1,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,all29CPUObjectsWholeRuntime74=True,bothSignedCPUProvidersWholeRuntime74=True,allCPUManifestEntriesAndChildEntryContractWholeRuntime74=True,originalRuntime74ChildCodeImportsAndVTAuthSlotsWhole=True,cpu29SourceProof=inputs['cpu29SourceProof'],cpu29Objects=inputs['cpu29Objects'])
 result.update(ownedPGDisplayHandshakeObservationV1Candidate=inputs['pgPortPin'],
  ownedPGDisplayHandshakeObservationV1Contract=inputs['observationContract'],ownedPGDisplayHandshakeObservationSourcePlan=inputs['pgSourcePlan'],
  displayHandshakeSelectedSlots=inputs['selectedSlots'],actualOtherProvidersExceptMDAndPGWholeRuntime74=True,
  actualVTAndExceptionBridgeObjectsWholeRuntime74=True,allChildEntitlementsWholeUnchanged=True,
  actualChangedRuntimeCDHashes=sorted({row['cdhash']for row in leafsigned+[signed]}),actualChangedSignedRuntimeFiles=len(leafsigned)+1)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--pg-port-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path)
 ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve()
 need(o.parent==N and not o.exists(),'fresh actual Runtime75 output')
 inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.pg_port_candidate.resolve())
 o.mkdir(mode=0o700);admission=o/'admission.json'
 save(admission,dict(schema='Runtime75 actual typed display observation signature admission',baseline=inputs['baselinePin'],
  pgObservationPort=inputs['pgPortPin'],all29CPUObjectsWholeRuntime74=True,bothSignedCPUProvidersWholeRuntime74=True,
  originalRuntime74ChildCodeImportsAndVTAuthSlotsWhole=True,original154FilesWholeVerified=True,
  original143SignatureProvenanceJoined=True,allChildEntitlementsWholeUnchanged=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result)
  pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],
   pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],
   pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['cpu29SourceProof'],*inputs['cpu29Objects'],
   inputs['pgPortPin'],pin(a.pg_port_candidate.parent/'freeze.json'),inputs['pgSourcePlan'],inputs['pgPort']['newProvider'],
   inputs['pgPort']['patchedChildPG'],inputs['pgPort']['recipe'],*inputs['pgPort']['actualIOSObjects'],*inputs['pgPort']['sourceFiles']]
  save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0))
  print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
