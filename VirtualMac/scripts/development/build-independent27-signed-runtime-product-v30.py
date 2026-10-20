#!/usr/bin/env python3
"""Runtime28 product builder: replace only Child MD and actual Main constructor call routes and re-seal the original Child.

Root alone runs the signing path. Read-only admission does not sign, change the
baseline, run an iOS image, or invoke any device API. All unchanged leaves and
the dependency proof inherit the exact Runtime27 bytes and signature evidence.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime28_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASELINE_SHA='3a92c3bfcdcf1a0b589a0d3029d227a02e8e9a655298482d724948fd1e6665a8'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.security.exception.iokit-user-client-class'
PORT_SOURCE=N/'owned-child-structured-error-diagnostic-source-port-v2-attempt1/candidate.json'
PORT_SOURCE_SHA='39e427a07c2de183509ecb0f82ce88c4e045c4fce952825784a05137dfc73870'
pin,save=base.pin,base.save

def need(v,why):
 if not v:raise ValueError(why)

def read_inputs(baseline_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASELINE_SHA,'exact actual Runtime27 and frozen signature primitives')
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
 need(pin(PORT_SOURCE)['sha256']==PORT_SOURCE_SHA,'exact frozen native Error reason source port')
 pf=base.frozen_rows(PORT_SOURCE.parent/'freeze.json');base.actual_frozen(pin(PORT_SOURCE),pf,'actual frozen diagnostic port')
 port=json.loads(base.regular_bytes(PORT_SOURCE))
 need(port['baselineRuntimeCandidate']==pin(baseline_path)and port['providerKey']=='MD'and port['roles']==['child'],
      'exact current Child-only MD and constructor port')
 for key in ('newProvider','patchedChildMain','recipe','graph','source','header','actualABIEvidence'):base.actual_frozen(port[key],pf,'actual frozen port '+key)
 for key in ('originalProvider','originalChildMain'):base.actual_frozen(port[key],bf,'actual baseline input '+key)
 mdid='child:MD';need(port['originalProvider']==pin(root/rows[mdid]['path'])and port['originalChildMain']==pin(root/childrow['path']),
      'port exact current MD and Child originals')
 originalchild=child;child=base.image_profile(base.regular_bytes(port['patchedChildMain']['path']),CHILD)
 md=base.image_profile(base.regular_bytes(port['newProvider']['path']),'MD');oldmd=base.image_profile(base.regular_bytes(root/rows[mdid]['path']),'old MD')
 contract=port['errorReasonContract'];symbol=contract['symbol'];index=contract['newImportIndex'];semantic=lambda row:{k:v for k,v in row.items()if k!='at'}
 need(symbol=='_VM27OwnedChildBuildErrorReasonDiagnosticV1'and contract['existingRequiredOrdinal']==3 and index==len(originalchild.imports)and
      child.uuid==originalchild.uuid and child.sections==originalchild.sections and child.exports==originalchild.exports and
      len(child.imports)==len(originalchild.imports)+1 and [semantic(row)for row in child.imports[:-1]]==[semantic(row)for row in originalchild.imports]and
      [semantic(row)for row in child.loads]==[semantic(row)for row in originalchild.loads],
      'only one named import to existing MD3; original namespace/UUID/section geometry retained')
 selected=child.imports[index];need(selected['name']==symbol and selected['ordinal']==3 and not selected['weak']and selected['addend']==0 and
      child.loads[2]['path']=='@loader_path/MD'and child.loads[2]['cmd']==0xc,'actual required named Child import')
 need(not any(cmd['cmd']==0x1d for cmd in child.commands)and not any(cmd['cmd']==0x1d for cmd in md.commands),
      'actual terminal unsigned Child and MD inputs without stale signature commands')
 need(md.uuid==port['providerUUID']and set(md.exports)==set(oldmd.exports)|{symbol}and md.exports[symbol]['flags']==0,
      'one added direct MD export retains all existing capability and resource API names')
 need(contract['originalErrorConstructorRVA']==0x3e4fb0 and contract['selectedCallABI']['originalFunctionCalledOnce']is True and
      contract['observesNativeCodeAfterOriginalConstruction']is True and contract['reasonCapturedBeforeOriginalMove']is True and contract['reasonUnavailableIsDiagnosticOnly']is True and contract['inputAndOutputMemoryNeverWrittenByDiagnostic']is True and
      contract['originalMoveOwnershipVariantsAndExceptionsUnchanged']is True and contract['incomingErrnoRestoredBeforeNativeCall']is True and
      contract['nativeErrnoRestoredAfterDiagnostic']is True and contract['resultSuccessFabricated']is False and
      contract['allOtherChildAPIsAndPGWholeByteUnchanged']is True,
      'only bounded observation of real constructor destination; native result/move/exception/errno preserved')
 recipe=json.loads(base.regular_bytes(port['recipe']['path']));need(recipe['original']==port['originalChildMain']and recipe['patched']==port['patchedChildMain']and
      recipe['newSymbol']==symbol and recipe['newImportIndex']==index and recipe['existingRequiredOrdinal']==3 and recipe['newRequiredLoads']==0 and
      recipe['originalErrorFunctionRVA']==contract['originalErrorConstructorRVA']and
      [row['returnRVA']for row in recipe['selectedOriginalCalls']]==contract['selectedConstructorCallerReturnRVAs'],
      'actual selected calls and new auth import recipe join original constructor contract')
 oldbytes=base.regular_bytes(root/childrow['path']);newbytes=base.regular_bytes(port['patchedChildMain']['path'])
 for row in recipe['selectedOriginalCalls']:
  at=row['at'];need(struct.unpack_from('<I',oldbytes,at)[0]==row['oldWord']and struct.unpack_from('<I',newbytes,at)[0]==row['newWord'],
      'actual selected original and patched branch words')
  olddelta=row['oldWord']&0x3ffffff;olddelta=olddelta-(1<<26)if olddelta&(1<<25)else olddelta
  newdelta=row['newWord']&0x3ffffff;newdelta=newdelta-(1<<26)if newdelta&(1<<25)else newdelta
  need(row['oldWord']>>26==row['newWord']>>26==0x25 and at+olddelta*4==0x3e4fb0 and at+newdelta*4==recipe['thunkRVA'],
       'real BL preserves explicit destination/moved-string ABI through authenticated named thunk')
 need(oldbytes[recipe['thunkRVA']:recipe['thunkRVA']+16]==bytes(16)and
      newbytes[recipe['thunkRVA']:recipe['thunkRVA']+16]==bytes.fromhex(recipe['thunkBytes'])and
      oldbytes[recipe['newAuthSlotRVA']:recipe['newAuthSlotRVA']+8]==bytes(8)and
      struct.unpack_from('<Q',newbytes,recipe['newAuthSlotRVA'])[0]==recipe['newAuthWord']and
      struct.unpack_from('<Q',oldbytes,recipe['previousChainTailRVA'])[0]==recipe['previousOldWord']and
      struct.unpack_from('<Q',newbytes,recipe['previousChainTailRVA'])[0]==recipe['previousNewWord']and
      recipe['previousNewWord']==recipe['previousOldWord']|(1<<51),
      'real unused thunk/slot and sole prior chain next stride update')
 for sec in originalchild.sections:
  at,size=sec['fileoff'],sec['size']
  if not at or not size or sec['flags']&255 in(1,12,18):continue
  expected=bytearray(oldbytes[at:at+size])
  for row in recipe['selectedOriginalCalls']:
   if at<=row['at']<at+size:struct.pack_into('<I',expected,row['at']-at,row['newWord'])
  if at<=recipe['previousChainTailRVA']<at+size:struct.pack_into('<Q',expected,recipe['previousChainTailRVA']-at,recipe['previousNewWord'])
  need(bytes(expected)==newbytes[at:at+size],'all original backed sections except precise selected branch/next words retained')
 graph=json.loads(base.regular_bytes(port['graph']['path']));native=graph['actualProviderNativeRows'];loads={row['ordinal']:row for row in md.loads}
 need(graph['actualProvider']==port['newProvider']and graph['strongRows']==len(native)==len(md.imports)==port['actualProviderNativeImportCount']and
      graph['unresolved']==[],'actual new MD native definitions closed without wide graph repeat')
 for row,imp in zip(native,md.imports,strict=True):
  need(row['actualImport']==imp and imp['ordinal']>0 and not imp['weak']and row['requiredLoad']==loads[imp['ordinal']]['path']and row['actualDefinition'].get('UUID'),
       'actual native import row joins captured definition')
 pgid='child:ParavirtualizedGraphics27.dylib';pg=base.image_profile(base.regular_bytes(root/rows[pgid]['path']),'PG')
 pgrows=graph['selectedPGImportsNewStrongDefinitions'];need(len(pgrows)==port['inheritedPGOwnedImportDefinitionCount'],'actual existing PG route count')
 for row in pgrows:
  imp=pg.imports[row['actualImport']['index']];need(row['actualImport']==imp and row['requiredLoad']=='@loader_path/MD'and
      row['target']==port['newProvider']and row['targetUUID']==md.uuid and row['definition']==md.exports[imp['name']],
      'every unchanged PG owned import resolves to the new MD actual definition')
 own=graph['actualSelectedChildDefinition'];need(own['actualImport']==selected and own['requiredLoad']=='@loader_path/MD'and
      own['target']==port['newProvider']and own['targetUUID']==md.uuid and own['definition']==md.exports[symbol],
      'actual new Child strong import resolves uniquely to direct new MD definition')
 need(child.imports[327]['name']=='_dup'and child.imports[327]['ordinal']==21,'deployed genuine dup route preserved')
 graphid=manifest['dependencyProofID'];old_graph=json.loads(base.regular_bytes(root/rows[graphid]['path']));need(old_graph['finalStrongDefinitionGraphClosed']is True and old_graph['unresolvedStrongImportRows']==[],'existing actual dependency proof inherited')
 merged=dict(schema='Runtime28 only Child MD and original Error reason constructor incremental definitions',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(root/rows[graphid]['path']),inheritedBaselineDefinitionGraph=old_graph,childErrorReasonDiagnosticCandidate=pin(PORT_SOURCE),actualChildMDNativeRows=native,actualChildImports=child.imports,actualChildRequiredLoads=child.loads,actualExistingPGDefinitions=pgrows,actualSelectedChildDefinition=own,originalChildImportSemanticsInherited=True,allParentAndPGWholeUnchanged=True,oldFullGraphRecomputed=False,deviceOperations=0)
 return dict(old=old,manifest=manifest,rows=rows,proof=proof,child=child,originalChild=originalchild,childID=childid,entitlements=ents,priorEntitlements=prior,baselinePin=pin(baseline_path),portPin=pin(PORT_SOURCE),port=port,md=md,mdID=mdid,graphRaw=(json.dumps(merged,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  argv=list(map(str,args));r=subprocess.run(argv,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=argv,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 replacements={inputs['mdID']:inputs['port']['newProvider']}
 leafraw={};leafimages={inputs['mdID']:inputs['md']}
 for identity,source in replacements.items():
  path=runtime/rows[identity]['path'];path.unlink();base.copy_regular(pathlib.Path(source['path']),path);leafraw[identity]=base.regular_bytes(path)
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];childpath.unlink();base.copy_regular(pathlib.Path(inputs['port']['patchedChildMain']['path']),childpath);before=base.regular_bytes(childpath);image=inputs['child'];ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(inputs['entitlements'],sort_keys=True));xpc=childpath.parent.parent.parent
 # Remove only FinderInfo introduced on this fresh, unsigned local directory.
 attrs=subprocess.run(['/usr/bin/xattr',str(xpc)],capture_output=True,timeout=10);need(attrs.returncode==0,'fresh own XPC attributes')
 if b'com.apple.FinderInfo' in attrs.stdout.splitlines():run('remove-new-xpc-finderinfo',['/usr/bin/xattr','-d','com.apple.FinderInfo',xpc])
 # Preserve the established temporary-XPC signing path; no File Provider xattrs ship.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-child-reason28-sign-',dir='/private/tmp') as temporary:
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
 need(inherited==original,'all other resources, native shader, rules and nested seals preserved; only Child MD seal replaced; PG fully preserved')
 cr=pin(runtime/rows['child-coderesources']['path']);rows['child-coderesources'].update(bytes=cr['bytes'],sha256=cr['sha256'])
 after=base.regular_bytes(childpath);actual=base.image_profile(after,CHILD)
 need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'all original Child namespace/PAC/code geometry unchanged')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every backed original code/data section unchanged')
 sig=base.signature(after,CHILD_UUID,{1:base.regular_bytes(runtime/rows['child-info']['path']),3:resources});prior=inputs['proof'][rows[childid]['path']]
 need(sig['embeddedEntitlements']==inputs['entitlements'] and len(sig['embeddedEntitlements'])==14 and sig['signatureFileOffset']==sig['codeLimit'],'actual14 permission values and original code/signature boundary')
 need({r['slot']for r in sig['actualSpecialSlots']if r['external']}=={1,3},'actual original Info1/CodeResources3')
 newcmd=next(c for c in actual.commands if c['cmd']==0x1d);nonsig=[c for c in actual.commands if c['cmd']!=0x1d]
 need(len(nonsig)==len(image.commands)and actual.ncmds==image.ncmds+1 and actual.sizeofcmds==image.sizeofcmds+16,
      'signing adds only one CodeSignature metadata command to actual unsigned Child')
 for oldcommand,newcommand in zip(image.commands,nonsig,strict=True):
  expectedcommand=bytearray(oldcommand['raw'])
  if oldcommand['cmd']==0x19 and oldcommand['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT':
   for off in(32,48):expectedcommand[off:off+8]=newcommand['raw'][off:off+8]
  need(bytes(expectedcommand)==newcommand['raw'],'every non-signature load command whole except signature LINKEDIT extent')
 need(len(before)<=sig['signatureFileOffset']<=len(before)+16,'only bounded signature-alignment padding added')
 expected=bytearray(before)+bytes(sig['signatureFileOffset']-len(before));struct.pack_into('<II',expected,16,actual.ncmds,actual.sizeofcmds)
 expected[32:32+actual.sizeofcmds]=b''.join(command['raw']for command in actual.commands)
 need(bytes(expected)==after[:sig['signatureFileOffset']],'every unsigned port byte preserved except signer header/extent metadata and bounded zero padding')
 segment=next(g for g in actual.segments if g['name']=='__LINKEDIT');need(segment['fileoff']+segment['filesize']==len(after) and segment['size']>=segment['filesize'],'actual bounded LINKEDIT extent')
 p=pin(childpath);rel=rows[childid]['path'];rows[childid].update(bytes=p['bytes'],sha256=p['sha256'],cdhash=sig['cdhash']);signed=dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=p,**sig)
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/rows[proofid]['path'];proofpath.write_bytes(inputs['graphRaw']);pp=pin(proofpath);rows[proofid].update(bytes=pp['bytes'],sha256=pp['sha256'])
 unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity in (childid,'child-coderesources',proofid,*replacements):continue
  p=pin(runtime/row['path']);need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']) and rows[identity]==row,'all other product files whole unchanged');unchanged.append(dict(id=identity,file=p,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==141,'141 untouched signed images')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n');exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in{rows[i]['path']for i in (childid,*replacements)}];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+leafsigned+[signed],actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old141SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 changedids=[i for i in inputs['rows'] if rows[i]!=inputs['rows'][i]];need(set(changedids)=={childid,'child-coderesources',proofid,*replacements},'only Child MD/main/seal and incremental dependency proof rows change')
 delta=output/'runtime27-to-runtime28-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=len(rows),actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=changedids,addedRuntimeIDs=[],wholeByteUnchangedSignedImages=141,unchangedFiles=unchanged,dependencyProofOnlyActualChildMDAndSelectedPGRoutesUpdated=True,childCodeResourcesWholeUnchanged=False,oldOtherNestedAndResourceSealsPreserved=True,nativeIOS16ShaderWholeUnchanged=True,allParentFilesWholeUnchanged=True,originalChildCodeOnlySelectedConstructorBranchesAndImport=True,actualChildEntitlements=inputs['entitlements'],allChildEntitlementsWholeUnchanged=True,childApprovalSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime28 Child-only original structured Error reason diagnostic product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),files=len(rows),builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],childErrorReasonDiagnosticCandidate=inputs['portPin'],childErrorReasonDiagnosticContract=inputs['port']['errorReasonContract'],runtime27ErrorReasonDeltaVerification=pin(delta),wholeByteUnchangedSignedImages=141,codeSigningCommandsActuallyPerformed=2,existingSignedImagesResigned=2,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,actualErrorReasonDiagnosticExecuted=False)
 result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh actual output');inputs=read_inputs(a.baseline_runtime_candidate.resolve());o.mkdir(mode=0o700);admission=o/'admission.json';save(admission,dict(schema='Runtime28 actual Child MD/Main original structured error diagnostic signature admission',baseline=inputs['baselinePin'],original154FilesWholeVerified=True,original143SignatureProvenanceJoined=True,allChildEntitlementsWholeUnchanged=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result);pins=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c'),inputs['portPin'],pin(PORT_SOURCE.parent/'freeze.json')]+[v for v in inputs['port'].values()if isinstance(v,dict)and all(k in v for k in('path','bytes','sha256'))];save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))

 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
