#!/usr/bin/env python3
"""Runtime102: native owned GPU task transport; Root alone signs.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime86 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime102_owned_gpu_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
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


TARGET='/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'
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


GPU_PIN={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-gpu-task-resident-resource-source-port-v22-attempt1/candidate.json', 'bytes': 33752, 'sha256': '9a31ad622b67b9812b6850dff059ae4bf7f20cc7264398eb8cdbff1236b972ae'}
MD_PORT='/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-null-connection-parent-port-v1-attempt1'
def read_inputs(path,mdpath):
 need(pin(BASE)['sha256']==BASE_SHA and pin(path)['sha256']=='e88a7ab2febbafed5fcb99d0e16a4b71998542f0af0653deddfa3da7a1863cf0','actual R102 and signature primitives')
 old=json.loads(base.regular_bytes(path));bf=frozen(path);manifest=plistlib.loads(base.regular_bytes(exact(old['manifest'])));rows={r['id']:r for r in manifest['files']};proof={r['relativePath']:r for r in json.loads(base.regular_bytes(exact(old['signatureVerification'])))['actualSignedFiles']};root=pathlib.Path(old['runtimeRoot'])
 for row in rows.values():
  p=pin(root/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'whole R102 file');base.actual_frozen(p,bf,'actual frozen R102 input')
  if row['kind']=='mach-o':need(proof[row['path']]['actualSignedFile']==p and proof[row['path']]['allPrimaryPagesAndSpecialSlotsVerified'],'actual inherited signed file')
 childid=manifest['childEntryContract']['childID'];child=base.image_profile(base.regular_bytes(root/rows[childid]['path']),CHILD);ent=proof[rows[childid]['path']]['embeddedEntitlements'];need(len(ent)==14,'same14 entitlements')
 md=base.image_profile(base.regular_bytes(mdpath),'MD');oldmd=base.image_profile(base.regular_bytes(root/rows['child:MD']['path']),'MD')
 need(set(md.exports)==set(oldmd.exports) and [semantic(x) for x in md.loads]==[semantic(x) for x in oldmd.loads],'same MD exports/dependency ordinals')
 i=dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=ent,baselinePin=pin(path),mdID='child:MD',md=md,newMD=pin(mdpath))
 closure=md_definition_graph(i,md);graphid=manifest['dependencyProofID'];prior=root/rows[graphid]['path'];g=json.loads(base.regular_bytes(prior));need(g['finalStrongDefinitionGraphClosed'] and g['unresolvedStrongImportRows']==[],'actual prior closed graph')
 graph=dict(schema='Runtime103 owned VMM one-shot fatal context incremental MD definitions',baselineDependencyProof=pin(prior),finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],onlyChangedExistingProviderIDs=['child:MD','child:ParavirtualizedGraphics27.dylib'],all29CPUObjectsAndBothSignedCPUProvidersWholeRuntime102=True,**closure)
 gpu=json.loads(exact(GPU_PIN).read_bytes());gf=base.frozen_rows(pathlib.Path(GPU_PIN['path']).parent/'freeze.json')
 need(gpu['actualCurrentTaskImportRows']==193 and gpu['nativeTaskPort']['exactChangedInstructionWordCount']==22,'actual corrected GPU193 / twenty-word source product')
 for key in ('task','compat','taskCodeResources','taskInfo','outerBundleInfo','defaultMetallib','actualImportClosure','sourcePlan'):
  base.actual_frozen(gpu[key],gf,'actual new GPU source '+key);exact(gpu[key])
 need(json.loads(exact(gpu['actualImportClosure']).read_bytes())['unresolved']==[],'all193 actual GPU imports and new shim definitions closed')
 for role,key in (('gpu-task:main','task'),('gpu-task:compat','compat')):
  oldsig=proof[rows[role]['path']];new=next(x for x in gpu['signedFiles']if x['actualSignedFile']==gpu[key])
  need(new['allPrimaryPagesAndSpecialSlotsVerified'] and new['embeddedEntitlements']==oldsig['embeddedEntitlements'],'new GPU image entitlements and signature pages whole')
 graph.update(schema='Runtime112 PG native null-connection failure guard retaining all proven graphics fixes',actualGPUProduct=GPU_PIN,actualGPUImportClosure=gpu['actualImportClosure'],nativeGPUActualTaskImports=193,exactTaskChangedInstructionWords=22,onlyChangedExistingProviderIDs=['child:MD','child:ParavirtualizedGraphics27.dylib'],originalRuntime105CoreMediaAndAMXCodeWhole=True)
 i.update(graphRaw=(json.dumps(graph,indent=2)+'\n').encode(),nativeClosure=closure,gpu=gpu);return i
def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 # Both existing signed CPU providers remain exact Runtime86 bytes.
 replacements={inputs['mdID']:inputs['newMD'],'child:ParavirtualizedGraphics27.dylib':{'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-null-connection-port-v1-attempt1/ParavirtualizedGraphics27.dylib', 'bytes': 835568, 'sha256': '05b406ceba790d47e56371181d431d2cc75abcae00c92d58d746e2b6139191d3'}}
 leafraw={};leafimages={inputs['mdID']:inputs['md'],'child:ParavirtualizedGraphics27.dylib':base.image_profile(exact({'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-null-connection-port-v1-attempt1/ParavirtualizedGraphics27.dylib', 'bytes': 835568, 'sha256': '05b406ceba790d47e56371181d431d2cc75abcae00c92d58d746e2b6139191d3'}),'PG')}
 untouchedSigned=len(inputs['proof'])-(len(replacements)+1)
 gpu=inputs['gpu'];gpu_changed=[]
 for identity,key in [('gpu-task:main','task'),('gpu-task:compat','compat'),('gpu-task-info','taskInfo'),('gpu-task-bundle-info','outerBundleInfo'),('gpu-task-coderesources','taskCodeResources'),('gpu-task-metallib','defaultMetallib')]:
  source=gpu[key];destination=runtime/rows[identity]['path'];oldpin=pin(destination)
  if (oldpin['bytes'],oldpin['sha256'])==(source['bytes'],source['sha256']):continue
  destination.unlink();base.copy_regular(exact(source),destination,executable=rows[identity]['kind']=='mach-o');p=pin(destination);rows[identity].update(bytes=p['bytes'],sha256=p['sha256']);gpu_changed.append(identity)
  if rows[identity]['kind']=='mach-o':
   actual=next(x for x in gpu['signedFiles']if x['actualSignedFile']==source);rows[identity].update(uuid=actual['uuid'],cdhash=actual['cdhash']);inputs['proof'][rows[identity]['path']]=dict(actual,relativePath=rows[identity]['path'],actualSignedFile=p)
 need(not gpu_changed,'all GPU193 files including resident-resource operands whole installed Runtime108')
 for identity,source in replacements.items():
  path=runtime/rows[identity]['path'];path.unlink();base.copy_regular(pathlib.Path(source['path']),path);leafraw[identity]=base.regular_bytes(path)
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-owned-gpu95-sign-',dir='/private/tmp') as temporary:
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
  if identity in (childid,'child-coderesources',proofid,*replacements,*gpu_changed):continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']) and rows[identity]==row,'all other product files whole unchanged');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==untouchedSigned,'actual untouched signed-image count')

 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']] for r in manifest['files']]
 raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements)}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed],actualSignedImages=len(inputs['proof']),allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,wholeSignedFilesAndCDProofInherited=untouchedSigned,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 delta=output/'runtime102-to-runtime103-delta.json';changedids=[i for i in inputs['rows']if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,'child:MD','child:ParavirtualizedGraphics27.dylib',*gpu_changed},'only MD/VMM seal/dependency changes');save(delta,dict(baselineCandidate=inputs['baselinePin'],changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=untouchedSigned,unchangedFiles=unchanged,allChildEntitlementsWholeUnchanged=True,all29CPUObjectsAndBothCPUProvidersWhole=True,originalVMMBodyPreserved=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime112 PG native null-connection failure guard retaining all proven graphics fixes',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),builder=pin(__file__),incrementalBaselineRuntimeCandidate=inputs['baselinePin'],runtime102FatalContextDelta=pin(delta),wholeByteUnchangedSignedImages=untouchedSigned,codeSigningCommandsActuallyPerformed=3,existingSignedImagesResigned=3,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,actualChangedRuntimeCDHashes=sorted(r['cdhash']for r in leafsigned+[signed]),actualAddedSignedRuntimeFiles=0,addedRuntimeIDs=[],ownedVMMFatalContextSource=pin(S/'vm27_owned_vmm_fatal_context_v1.inc'),onlyMDOneShotFatalContextAdded=False,nativeOwnedGPUTaskProduct=GPU_PIN,nativeOwnedGPUTaskSourcePlan=gpu['sourcePlan'],currentGPUActualImports=193,currentGPUExactTaskChangedWords=22,linearPitchParentProfile={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-gpu-resident-resource-parent-profile-port-v1-attempt1/vm27_owned_gpu_task_parent_generated_v1.h', 'bytes': 704, 'sha256': '01791311b976a89ec9e753b6230d42071dc158a10c4067fe883a948d4d3e19fc'},allRuntime105CoreMediaLoadAndAMXAdvertisementInstructionsWhole=True,actualChangedSignedRuntimeFiles=3,actualMDSource={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/VirtualMac/vz/host/modern_metal_device_array_v32.m', 'bytes': 2492, 'sha256': '8fe0d02de20e217d066066a7db4fef218386fc33fdee33f28cac4dd44fbe5567'},actualGPUParentSource={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/VirtualMac/vz/host/vm27_owned_gpu_task_parent_v4.inc', 'bytes': 19216, 'sha256': '8e98aeb03109d29b0a866d7b2eebe221689378c2ccf509e1e889b68406897bd6'},onlyOwnedGPUChildMetalValidationEnvironmentAdded=False,allNativeGPU193FilesWholeRuntime106=False,onlyNativeVolatileDiscardOptimizationDeferred=False,originalVolatileDiscardDeferralWhole=True,onlyMissingFramebufferReadCapabilityMapped=False,framebufferReadFixWholeRuntime109=True,onlyGPUChildDebugEnvironmentRemoved=False,productionGPUEnvironmentWholeRuntime111=True,originalPGNullConnectionGuard={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-null-connection-port-v1-attempt1/source-contract.json', 'bytes': 3100, 'sha256': 'f45c89fe6839feb370f93f1b8c836c3ce5f7960685682f6aae464f1c141af3d6'},onlyOriginalPGNullFailureBranchMovedEarlier=True,nativePerformanceSourceContract={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-native-performance-parent-port-v1-attempt1/source-contract.json', 'bytes': 1151, 'sha256': '5079f8b1895b45a252a9d2f16bab90bacc8f6d3a7df99efe91a5f3def8b7cc24'},allGPUFilesWholeRuntime108=True,framebufferReadSourceContract={'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-framebuffer-read-parent-port-v2-attempt1/source-contract.json', 'bytes': 1296, 'sha256': '51743c0cd1ae0438bd2bea85cce8335c3c0e7de7b26f5cbf1a2879aa3bdbbdb1'},allGPUCompatibilityObjectsAndNativeCommandsWhole=True)
 return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--md',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh103 output');i=read_inputs(a.baseline_runtime_candidate.resolve(),a.md.resolve());o.mkdir(mode=0o700);r=assemble(i,o);save(o/'candidate.json',r)
 files=[pin(p)for p in o.rglob('*')if p.is_file()]+[GPU_PIN,pin(pathlib.Path(GPU_PIN['path']).parent/'freeze.json'),*i['gpu']['signedFiles'][0:0],*[pin(p)for p in pathlib.Path(MD_PORT).iterdir()if p.is_file()]]+[pin(__file__),pin(BASE),i['baselinePin'],i['old']['manifest'],i['old']['signatureVerification'],i['newMD'],pin(S/'modern_metal_device_array_v32.m'),pin(S/'modern_metal_device_array_v30.m'),pin(S/'vm27_owned_gpu_task_parent_v4.inc'),{'path': '/Users/liukaixiang/Documents/VirtualMacOniPad/DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/owned-pvg-null-connection-port-v1-attempt1/source-contract.json', 'bytes': 3100, 'sha256': 'f45c89fe6839feb370f93f1b8c836c3ce5f7960685682f6aae464f1c141af3d6'},r['ownedVMMFatalContextSource'],*i['old']['cpu29Objects'],i['old']['cpu29SourceProof'],i['nativeClosure']['currentNativeIndex'],*i['nativeClosure']['actualNativeSourcePins'],*i['nativeClosure']['actualOwnedProviderPins']]
 save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),unchangedSignedImages=r['wholeByteUnchangedSignedImages'],changedSigned=2)))
if __name__=='__main__':main()
