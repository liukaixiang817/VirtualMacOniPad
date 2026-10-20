#!/usr/bin/env python3
"""Runtime27 product builder: replace only Child MD/PG and re-seal the original Child.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime26 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime27_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='56cf658760a4dffee368d818f3a416102758873b5e5b9a8c267e62fcdc4ba98f'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
PORT_SOURCE=N/'owned-pvg-unified-storage-source-port-v4-attempt3/candidate.json'
PORT_SOURCE_SHA='a2e63ea886fa7afdbf31115f36574cdda753e49cfa5ed4d602681987fadd7387'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)

def read_inputs(baseline_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'exact actual Runtime26 and frozen signature primitives')
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
 need(pin(PORT_SOURCE)['sha256']==PORT_SOURCE_SHA,'exact owned PG capability port candidate')
 pf=base.frozen_rows(PORT_SOURCE.parent/'freeze.json');base.actual_frozen(pin(PORT_SOURCE),pf,'actual frozen capability source port')
 port=json.loads(base.regular_bytes(PORT_SOURCE));need(port['baselineRuntimeCandidate']==pin(baseline_path)and port['providerKey']=='MD'and port['roles']==['child']and port['pipelineDiagnosticNotIncluded']is True,'exact child-only MD/PG port; no unrelated pipeline hook')
 for key in ('newProvider','patchedChildPG','recipe','graph','source','header','unifiedStorageEvidence'):base.actual_frozen(port[key],pf,'actual frozen port '+key)
 for key in ('originalProvider','originalChildPG'):base.actual_frozen(port[key],bf,'actual baseline input '+key)
 mdid='child:MD';pgid='child:ParavirtualizedGraphics27.dylib'
 need(port['originalProvider']==pin(root/rows[mdid]['path'])and port['originalChildPG']==pin(root/rows[pgid]['path']),'port original inputs match current installed MD/PG')
 md=base.image_profile(base.regular_bytes(port['newProvider']['path']),'MD');pg=base.image_profile(base.regular_bytes(port['patchedChildPG']['path']),'ParavirtualizedGraphics27.dylib');originalpg=base.image_profile(base.regular_bytes(root/rows[pgid]['path']),'original PG')
 semantic=lambda r:{k:v for k,v in r.items()if k!='at'}
 inherited_contracts=[port['inheritedBufferContract'],port['adapterContract'],port['detachAdapterContract']]
 contracts=port['unifiedStorageContracts'];need(len(contracts)==2,'final two-port unified storage contract')
 added=pg.imports[len(originalpg.imports):];new_names={r['name']for r in added}
 need(pg.uuid==originalpg.uuid and pg.exports==originalpg.exports and len(added)==len(contracts)==len(port['addedExports']) and
      [semantic(r)for r in pg.imports[:len(originalpg.imports)]]==[semantic(r)for r in originalpg.imports] and
      [semantic(r)for r in pg.loads]==[semantic(r)for r in originalpg.loads],
      'all existing PG imports including three capabilities and required loads/UUID/exports preserved')
 need(new_names==set(port['addedExports'])=={'_VM27OwnedPVGNewBufferWithLengthOptionsV1','_VM27OwnedPVGDidModifyManagedRangeV1'} and
      set(md.exports)==set(base.image_profile(base.regular_bytes(root/rows[mdid]['path']),'old MD').exports)|new_names and md.uuid==port['providerUUID'] and
      port['existingCapabilityRoutes261262263WholeUnchanged']is True and port['heapCreationAndHeapBufferRoutesWholeUnchanged']is True,
      'only actual Length/DidModify exports/imports added; three capabilities and both Heap routes retained')
 for contract in contracts:
  index=contract['newImportIndex'];symbol=contract['symbol'];imp=pg.imports[index]
  need(imp['index']==index and imp['name']==symbol and imp['ordinal']==contract['requiredOrdinal']==10 and not imp['weak']and
       pg.loads[-1]['ordinal']==10 and pg.loads[-1]['path']=='@loader_path/MD'and pg.loads[-1]['cmd']==0xc and md.exports[symbol]['flags']==0,
       'actual named resource operations use existing required MD10 and direct definitions')
  selected_slot=next(row for row in pg.binds if row['fileoff']==contract['authSlotRVA'])
  old_slot=next(row for row in originalpg.binds if row['fileoff']==contract['authSlotRVA'])
  need(selected_slot['index']==index and old_slot['name']=='_objc_msgSend'and
       selected_slot['word']==(old_slot['word']&~65535)|index,
       'exact selected auth slot changes only its import index')
 length_contract,didmodify_contract=contracts
 need(length_contract['originalSelector']=='newBufferWithLength:options:'and
      length_contract['genuineHasUnifiedMemoryRequiredForConversion']is True and length_contract['allOtherOptionsPreserved']is True and
      length_contract['nativeMethodTypedAndCalledOnce']is True and length_contract['nativeNewResourcePlusOneOwnershipPreserved']is True and
      didmodify_contract['originalSelector']=='didModifyRange:'and didmodify_contract['skipManagedSynchronizationOnlyActualSharedAndNativeUnified']is True and
      didmodify_contract['nonSharedNativeTypedMethodForwarded']is True and didmodify_contract['originalCommandSubmissionAndCompletionUnchanged']is True and
      port['globalAppleClassMutation']is False and port['genuineUnifiedSharedResourceOperationsActuallyExecuted']is False,
      'genuine unified memory and exact Shared resource govern adaptation; native object/ownership/other modes preserved')
 graph=json.loads(base.regular_bytes(port['graph']['path']));native=graph['actualProviderNativeRows'];loads={r['ordinal']:r for r in md.loads}
 need(graph['actualProvider']==port['newProvider']and graph['strongRows']==len(native)==len(md.imports)==port['actualProviderNativeImportCount']and
      graph['unresolved']==[],'actual incremental MD definitions closed')
 for row,imp in zip(native,md.imports,strict=True):
  need(row['actualImport']==imp and imp['ordinal']>0 and not imp['weak']and row['requiredLoad']==loads[imp['ordinal']]['path']and row['actualDefinition'].get('UUID'),
       'actual new MD import joins its captured native definition without re-running the old graph')
 selected=graph['selectedPGImportsNewStrongDefinitions']
 expected_indices=[row['requiredPGImportIndex']for row in inherited_contracts]+[row['newImportIndex']for row in contracts]
 need(len(selected)==len(expected_indices)and [row['actualImport']['index']for row in selected]==expected_indices,
      'all actual inherited capability and new operation routes are closed')
 for row,index in zip(selected,expected_indices,strict=True):
  imp=pg.imports[index];symbol=imp['name']
  need(row['actualImport']==imp and row['requiredLoad']=='@loader_path/MD'and row['target']==port['newProvider']and
       row['targetUUID']==md.uuid and row['definition']==md.exports[symbol]and md.exports[symbol]['flags']==0,
       'each actual owned PG import resolves to the new direct MD definition')
 need(child.imports[327]['name']=='_dup'and child.imports[327]['ordinal']==21,'deployed genuine dup route preserved')
 graphid=manifest['dependencyProofID'];old_graph=json.loads(base.regular_bytes(root/rows[graphid]['path']));need(old_graph['finalStrongDefinitionGraphClosed']is True and old_graph['unresolvedStrongImportRows']==[],'existing actual baseline dependency proof inherited')
 merged=dict(schema='Runtime27 only Child MD and actual unified resource operation incremental definitions',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(root/rows[graphid]['path']),inheritedBaselineDefinitionGraph=old_graph,pvgUnifiedStorageCandidate=pin(PORT_SOURCE),actualChildMDNativeRows=native,actualChildPGImports=pg.imports,actualChildPGRequiredLoads=pg.loads,actualSelectedPGDefinitions=selected,originalPGImportSemanticsInherited=True,allParentNamespaceWholeUnchanged=True,oldFullGraphRecomputed=False,deviceOperations=0)
 return dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,childID=childid,entitlements=ents,priorEntitlements=prior,baselinePin=pin(baseline_path),portPin=pin(PORT_SOURCE),port=port,md=md,pg=pg,mdID=mdid,pgID=pgid,graphRaw=(json.dumps(merged,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 replacements={inputs['mdID']:inputs['port']['newProvider'],inputs['pgID']:inputs['port']['patchedChildPG']}
 leafraw={};leafimages={inputs['mdID']:inputs['md'],inputs['pgID']:inputs['pg']}
 for identity,source in replacements.items():
  path=runtime/rows[identity]['path'];path.unlink();base.copy_regular(pathlib.Path(source['path']),path);leafraw[identity]=base.regular_bytes(path)
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-pvg-unified27-sign-',dir='/private/tmp') as temporary:
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
 need(inherited==original,'all other resources, native shader, rules and nested seals preserved; only Child MD/PG seals replaced')
 cr=pin(runtime/rows['child-coderesources']['path']);rows['child-coderesources'].update(bytes=cr['bytes'],sha256=cr['sha256'])
 after=base.regular_bytes(childpath);actual=base.image_profile(after,CHILD)
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'all original Child namespace/PAC/code geometry unchanged')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed original code/data section unchanged')
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
 need(sum(r['signed']for r in unchanged)==140,'140 untouched signed images')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements)}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed],actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old140SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements},'only Child MD/PG/main/seal and incremental dependency proof rows change')
 delta=output/'runtime26-to-runtime27-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=140,unchangedFiles=unchanged,dependencyProofOnlyActualChildMDAndSelectedPGRoutesUpdated=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesWholeUnchanged=True,originalChildCodeImportsPACUUIDWholeUnchanged=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime27 Child-only genuine unified Shared resource product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],pvgUnifiedStorageCandidate=inputs['portPin'],pvgUnifiedStorageContracts=inputs['port']['unifiedStorageContracts'],pvgUnifiedStorageEvidence=inputs['port']['unifiedStorageEvidence'],runtime26UnifiedStorageDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=140,codeSigningCommandsActuallyPerformed=3,existingSignedImagesResigned=3,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,genuineUnifiedSharedResourceOperationsActuallyExecuted=False)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual output');inputs=read_inputs(a.baseline_runtime_candidate.resolve());o.mkdir(mode=0o700);admission=o/'admission.json';save(admission,dict(schema='Runtime27 actual Child MD/PG unified Shared storage-only signature admission',baseline=inputs['baselinePin'],original154FilesWholeVerified=True,original143SignatureProvenanceJoined=True,allChildEntitlementsWholeUnchanged=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result);pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['portPin'],pin(PORT_SOURCE.parent/'freeze.json')]+[v for v in inputs['port'].values()if isinstance(v,dict)and all(k in v for k in('path','bytes','sha256'))];save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))

 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
