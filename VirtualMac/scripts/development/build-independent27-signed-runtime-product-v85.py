#!/usr/bin/env python3
"""Runtime79: bounded one-shot guest msgbuf read; Root alone signs.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime78 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime79_factory12_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
BASELINE_SHA='021fbce0fd8ff3820eb6b8f6734d92a7ea277251f36fe5e11ce2ea7d7162c0d4'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'exact file '+row['path']);return pathlib.Path(row['path'])
def frozen(path):
 rows=base.frozen_rows(path.parent/'freeze.json');base.actual_frozen(pin(path),rows,'actual frozen candidate');return rows
def semantic(r):return{k:v for k,v in r.items()if k not in ('at','index')}
def multiset(rows):return sorted([semantic(r)for r in rows],key=lambda r:json.dumps(r,sort_keys=True))

def read_inputs(baseline_path,cpu_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'actual signed Runtime78 baseline and reviewed signature primitives')
 old=json.loads(base.regular_bytes(baseline_path));bf=frozen(baseline_path)
 for key in ('manifest','signatureVerification'):base.actual_frozen(old[key],bf,'actual Runtime78 '+key)
 need(old['localCodeSigned']is True and old['actualProductPreflightPassed']is True,'actual signed Runtime78 product')
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']}
 need(len(rows)==len(manifest['files'])==154,'actual154 Runtime78 files')
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
 need(child.uuid==CHILD_UUID and len(child.imports)==1207,'actual Runtime78 Child with VT two-entry route retained')
 prior=proof[rows[childid]['path']]['embeddedEntitlements']
 need(isinstance(prior,dict)and len(prior)==14 and prior.get(KEY)==['IOSurfaceRootUserClient','AGXDeviceUserClient']and
      prior.get('com.apple.private.virtualization.plugin')is True and prior.get('com.apple.developer.kernel.extended-virtual-addressing')is True,'same exact14 Child entitlements')
 cpupin=old['cpu29SourceProof'];base.actual_frozen(cpupin,bf,'inherited exact29 CPU source proof');exact(cpupin)
 cpuobjects=old['cpu29Objects'];need(len(cpuobjects)==29,'actual Runtime78 CPU29 proof')
 graphid=manifest['dependencyProofID'];graphpath=root/rows[graphid]['path'];oldgraph=json.loads(base.regular_bytes(graphpath))
 need(oldgraph['finalStrongDefinitionGraphClosed']is True and oldgraph['unresolvedStrongImportRows']==[],'actual Runtime78 definition graph closure inherited by reference')
 graph=dict(schema='Actual Runtime79 CPU-only guest msgbuf incremental definition proof',finalStrongDefinitionGraphClosed=True,
  unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(graphpath),
  inheritedBaselineDefinitionGraphReference=pin(graphpath),allMDPGVTAndOtherProviderFilesWholeRuntime78=True,
  originalRuntime78ChildCodeImportsAndVTAuthSlotsWhole=True,oldGraphRerun=False,oldGraphNotInlined=True,deviceOperations=0)
 inputs=dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=copy.deepcopy(prior),
  baselinePin=pin(baseline_path),graphRaw=(json.dumps(graph,indent=2)+'\n').encode(),cpu29SourceProof=cpupin,cpu29Objects=cpuobjects)
 inputs=admit_cpu_delta(inputs,cpu_path)
 return inputs

CPU_KEY='VM27HVVMProduction.dylib'
CPU_IDS=('parent:'+CPU_KEY,'child:'+CPU_KEY)
CPU_PORT_SHA='bfb99b38b5af683ff298d8ce1b626ab9a2b9cefa9b1ed659c95d25fb0d3bd7e4'
CPU_PLAN_SHA='27d4c308b89c7c59feccd2bc5e427bd9bbb87e9ea37727a4183988c0592e667e'
CPU_CONTRACT_KEY='cpuGuestMsgbufReadV1Contract'

def admit_cpu_delta(inputs,cpu_path):
 need(len(CPU_PORT_SHA)==64 and pin(cpu_path)['sha256']==CPU_PORT_SHA,'actual Root-compiled Life63 source product')
 cpu=json.loads(base.regular_bytes(cpu_path));cf=frozen(cpu_path)
 for key in ('provider','sourcePlan'):base.actual_frozen(cpu[key],cf,'actual Life63 '+key);exact(cpu[key])
 need(pin(cpu['sourcePlan']['path'])['sha256']==CPU_PLAN_SHA,'exact Root-reviewed Life63 source plan')
 need(cpu['actualIOSCompileStrictLinkAndDyldValidatePassed']is True and cpu['actualExports']==155 and
      cpu['actualNativeImports']==94 and cpu['actualLoads']==4 and cpu['all94NativeImportSemanticsSame']is True and
      cpu['all155ExistingExportNamesAndKindsSame']is True and cpu['all4LoadSemanticsSame']is True,'actual strict Life63 compile/link/validation with same155/94/4')
 need(cpu['baselineCPU']==inputs['old']['cpu29SourceProof']and cpu['allOther28ObjectsWholeUnchanged']is True and
      len(cpu['actualChangedObjects'])==1 and len(cpu['inheritedWholeObjects'])==28,'actual one Life63 object from Runtime78 CPU29 proof')
 changed=cpu['actualChangedObjects'][0]
 need(pathlib.Path(changed['path']).name=='modern_cpu_kernel_lifecycle_v63.o','only actual Life63 object changed')
 expected={r['path']:r for r in inputs['old']['cpu29Objects']if pathlib.Path(r['path']).name!='modern_cpu_kernel_lifecycle_v62.o'}
 need(len(expected)==28 and {r['path']:r for r in cpu['inheritedWholeObjects']}==expected,'exact other28 CPU objects whole Runtime78')
 objects=cpu['actualChangedObjects']+cpu['inheritedWholeObjects']
 for row in objects:base.actual_frozen(row,cf,'actual linked CPU object');exact(row)
 plan=json.loads(base.regular_bytes(exact(cpu['sourcePlan'])))
 need(plan['contractKey']==CPU_CONTRACT_KEY and plan['contract']==cpu[CPU_CONTRACT_KEY]and plan['baselineCPU']==cpu['baselineCPU'],'actual reviewed Life63 contract')
 provider=base.image_profile(base.regular_bytes(exact(cpu['provider'])),CPU_KEY);root=pathlib.Path(inputs['old']['runtimeRoot'])
 for identity in CPU_IDS:
  original=base.image_profile(base.regular_bytes(root/inputs['rows'][identity]['path']),CPU_KEY)
  need(set(original.exports)==set(provider.exports)and all(original.exports[s]['flags']==provider.exports[s]['flags']for s in original.exports)and
       multiset(original.imports)==multiset(provider.imports)and [semantic(r)for r in original.loads]==[semantic(r)for r in provider.loads],
       'both actual CPU providers retain155 export names/kinds and94 native/4 load semantics')
 binding=cpu['actualSameImageVCPUsExitBinding'];call=binding['actualDirectBL'];own=provider.exports['_hv_vcpus_exit']
 need(own['flags']==0 and own['address']==binding['ownExportRVA']==call['targetRVA'] and
      binding['externalVCPUsExitImportPresent']is False and not any(r['name']=='_hv_vcpus_exit'for r in provider.imports),'same-image real hv_vcpus_exit without external import')
 section=next(s for s in provider.sections if s['fileoff']and s['va']<=call['callRVA']and call['callRVA']+4<=s['va']+s['size'])
 at=section['fileoff']+call['callRVA']-section['va'];word=struct.unpack_from('<I',base.regular_bytes(exact(cpu['provider'])),at)[0]
 displacement=word&0x3ffffff;displacement=displacement-(1<<26)if displacement&(1<<25)else displacement
 need(word==call['instructionWord']and word&0xfc000000==0x94000000 and call['callRVA']+(displacement<<2)==own['address'],'actual native wake callback BL targets own export')
 base.actual_frozen(binding['callbackAssembly'],cf,'actual same-image callback disassembly');exact(binding['callbackAssembly'])
 need(provider.exports['_hv_vm_config_create']['flags']==0 and provider.exports['_hv_vm_config_create']['address']==cpu['hvVMConfigCreateActualRVA'],'actual bootstrap entry RVA')
 graph=json.loads(inputs['graphRaw'])
 graph.update(schema='Actual Runtime79 one-shot guest msgbuf incremental definitions',
  cpuGuestMsgbufReadV1Candidate=pin(cpu_path),cpuGuestMsgbufReadV1Contract=cpu[CPU_CONTRACT_KEY],
  cpu28OtherObjectsWholeRuntime78=True,cpu29SourceProof=pin(cpu_path),actualChangedCPUObjects=cpu['actualChangedObjects'],
  actualWholeCPUObjects=cpu['inheritedWholeObjects'],actualCurrentCPUExports=provider.exports,actualCurrentCPUImports=provider.imports,
  actualCurrentCPURequiredLoads=provider.loads,actualSameImageVCPUsExitBinding=binding,
  onlyChangedProviderIDs=list(CPU_IDS))
 inputs.update(cpu=cpu,cpuProvider=provider,cpuPortPin=pin(cpu_path),cpuSourcePlan=cpu['sourcePlan'],
  inheritedCPU29SourceProof=inputs['cpu29SourceProof'],inheritedCPU29Objects=inputs['cpu29Objects'],
  cpu29SourceProof=pin(cpu_path),cpu29Objects=objects,cpuContract=cpu[CPU_CONTRACT_KEY],sameImageExitBinding=binding,
  graphRaw=(json.dumps(graph,indent=2)+'\n').encode())
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
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'actual Runtime78 Child namespace/PAC/code geometry retained')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed Runtime78 Child section retained')
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
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements,CPU_IDS[0]},'only two CPU providers and Child main/seal and incremental proof rows change')
 delta=output/'runtime78-to-runtime79-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=untouchedSigned,unchangedFiles=unchanged,dependencyProofOnlyActualChangedProvidersAndCPUManifestEntryRVAsUpdated=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesExceptCPUProviderWholeUnchanged=True,originalRuntime78ChildCodeImportsAndVTAuthSlotsWhole=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime79 bounded one-shot guest msgbuf product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],runtime78CPUGuestMsgbufDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=untouchedSigned,codeSigningCommandsActuallyPerformed=len(replacements)+2,existingSignedImagesResigned=len(replacements)+2,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,cpu28OtherObjectsWholeRuntime78=True,originalRuntime78ChildCodeImportsAndVTAuthSlotsWhole=True,cpu29SourceProof=inputs['cpu29SourceProof'],cpu29Objects=inputs['cpu29Objects'])
 result['historicalRuntime78CPUVerification']=dict(cpu29SourceProof=inputs['inheritedCPU29SourceProof'],cpu29Objects=inputs['inheritedCPU29Objects'])
 for key in ('all29CPUObjectsWholeRuntime74','bothSignedCPUProvidersWholeRuntime74','allCPUManifestEntriesAndChildEntryContractWholeRuntime74'):
  if key in result:result[key+'AppliesToHistoricalRuntime78Only']=result.pop(key)
 result.update(cpuGuestMsgbufReadV1Candidate=inputs['cpuPortPin'],cpuGuestMsgbufReadV1Contract=inputs['cpuContract'],
  cpuGuestMsgbufReadSourcePlan=inputs['cpuSourcePlan'],life63ActualChangedObject=inputs['cpu']['actualChangedObjects'][0],
  actualSameImageVCPUsExitBinding=inputs['sameImageExitBinding'],actualCurrentCPUExports=155,actualCurrentCPUImports=94,actualCurrentCPULoads=4,
  actualChangedCPUObjects=inputs['cpu']['actualChangedObjects'],actualWholeCPUObjects=inputs['cpu']['inheritedWholeObjects'],
  actualCPUManifestEntryUpdates=cpuEntryUpdates,actualChangedRuntimeCDHashes=sorted({row['cdhash']for row in leafsigned+[signed]}),
  actualChangedSignedRuntimeFiles=len(leafsigned)+1,allMDPGVTAndOtherProvidersWholeRuntime78=True)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--cpu-msgbuf-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path)
 ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve()
 need(o.parent==N and not o.exists(),'fresh actual Runtime79 output')
 inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.cpu_msgbuf_candidate.resolve())
 o.mkdir(mode=0o700);admission=o/'admission.json'
 save(admission,dict(schema='Runtime79 actual guest msgbuf signature admission',baseline=inputs['baselinePin'],
  cpuGuestMsgbuf=inputs['cpuPortPin'],cpu28OtherObjectsWholeRuntime78=True,originalRuntime78ChildCodeImportsAndVTAuthSlotsWhole=True,
  original154FilesWholeVerified=True,original143SignatureProvenanceJoined=True,allChildEntitlementsWholeUnchanged=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result)
  pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],
   pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],
   pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['cpuPortPin'],
   pin(a.cpu_msgbuf_candidate.parent/'freeze.json'),inputs['cpu']['provider'],inputs['cpuSourcePlan'],
   inputs['sameImageExitBinding']['callbackAssembly'],*inputs['cpu']['sourceFiles'],*inputs['cpu29Objects']]
  save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0))
  print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
