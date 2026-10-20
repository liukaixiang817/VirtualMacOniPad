#!/usr/bin/env python3
"""Runtime82: preserve Runtime81 CPU and parent; observe five Child native disk calls."""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime82_signature_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASE_CANDIDATE_SHA='fe6f7f6a3bbdf80bc7dab80e10a59235b2f5a57ffaeeeff81a0df0d2ebbaf8c4'
CHILD='com.apple.Virtualization.VirtualMachine';CHILD_UUID='4a6a588d1afd30f5a64d6304eb79be0b';HELPER='VM27OwnedChildGestaltCompat.dylib';SYMBOL='_VM27OwnedChildMGGetSInt32AnswerV1'
def need(v,why):
 if not v:raise ValueError(why)
pin,save=base.pin,base.save
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in('path','bytes','sha256')},'actual exact pin '+row['path']);return pathlib.Path(row['path'])
def frozen(p):
 p=pathlib.Path(p).resolve();f=base.frozen_rows(p.parent/'freeze.json');need(f.get(str(p))==pin(p),'candidate itself frozen');return f

def read_inputs(baseline_path,port_path,graph_path):
 need(pin(BASE)['sha256']==BASE_SHA and pin(baseline_path)['sha256']==BASE_CANDIDATE_SHA,'actual Runtime81 baseline/primitives')
 old=json.loads(base.regular_bytes(baseline_path));f=frozen(baseline_path)
 for key in ('manifest','signatureVerification'):base.actual_frozen(old[key],f,'baseline '+key);exact(old[key])
 manifest=plistlib.loads(base.regular_bytes(old['manifest']['path']));rows={r['id']:r for r in manifest['files']};need(len(rows)==len(manifest['files'])==154,'actual154 baseline rows')
 signatures=json.loads(base.regular_bytes(old['signatureVerification']['path']));proof={r['relativePath']:r for r in signatures['actualSignedFiles']};need(len(proof)==143 and signatures['allCodePagesAndSpecialSlotsActuallyVerified'],'actual143 signed proof')
 root=pathlib.Path(old['runtimeRoot']);childid=manifest['childEntryContract']['childID'];helperid='child:'+HELPER
 for row in rows.values():
  need(base.relative(row['path']),'safe relative path');q=pin(root/row['path']);need((q['bytes'],q['sha256'])==(row['bytes'],row['sha256']),'whole baseline file');base.actual_frozen(q,f,'baseline file frozen')
  if row['kind']=='mach-o':
   ss=proof[row['path']];need(ss['actualSignedFile']==q and ss['uuid']==row['uuid']and ss['cdhash']==row['cdhash']and ss['allPrimaryPagesAndSpecialSlotsVerified'],'actual wholefile signature join')
 port=json.loads(base.regular_bytes(port_path));pf=frozen(port_path)
 for key in ('newProvider','patchedChildMain','graph'):base.actual_frozen(port[key],pf,'actual port '+key);exact(port[key])
 need(port['baselineRuntimeCandidate']==pin(baseline_path) and port['providerKey']==HELPER and port['originalChildMain']==pin(root/rows[childid]['path']),'actual port exact baseline')
 child=base.image_profile(base.regular_bytes(exact(port['patchedChildMain'])),CHILD);original=base.image_profile(base.regular_bytes(root/rows[childid]['path']),CHILD);helper=base.image_profile(base.regular_bytes(exact(port['newProvider'])),HELPER)
 need(child.uuid==CHILD_UUID and len(child.imports)==1207 and [{k:v for k,v in x.items()if k!='at'}for x in child.loads]==[{k:v for k,v in x.items()if k!='at'}for x in original.loads] and [{k:v for k,v in x.items()if k not in ('name','ordinal')}for x in child.binds]==[{k:v for k,v in x.items()if k not in ('name','ordinal')}for x in original.binds] and child.sections==original.sections,'same Child code geometry and raw PAC binds and loads')
 changes=[(x,y)for x,y in zip(original.imports,child.imports)if {k:x[k]for k in ('index','ordinal','weak','name','addend')}!={k:y[k]for k in ('index','ordinal','weak','name','addend')}]
 need({x['index']for x,y in changes}=={347,401,402,417,418},'only five typed native disk imports changed')
 for x,y in changes:
  need(x['ordinal']==15 and y['ordinal']==57 and not x['weak']and not y['weak']and x['addend']==y['addend']==0 and y['name']in helper.exports and helper.exports[y['name']]['flags']==0,'actual typed direct observer route')
 need(len(helper.exports)==6 and SYMBOL in helper.exports,'old MG export plus five observer exports')
 graph=json.loads(base.regular_bytes(graph_path));need(pin(graph_path)==port['graph']and graph['baselineRuntimeCandidate']==pin(baseline_path) and graph['allProviderNativeStrongImportsClosed'],'new observer native graph closed')
 oldgraphpath=root/rows[manifest['dependencyProofID']]['path'];oldgraph=json.loads(base.regular_bytes(oldgraphpath));need(oldgraph['finalStrongDefinitionGraphClosed']is True and oldgraph['unresolvedStrongImportRows']==[],'actual closed baseline graph')
 merged=dict(schema='Runtime82 five Child disk observations incremental graph',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(oldgraphpath),inheritedBaselineDefinitionGraphReference=pin(oldgraphpath),childPortCandidate=pin(port_path),actualChildIncrementalGraph=graph,actualChangedChildImports=[dict(before=x,after=y,providerExport=helper.exports[y['name']])for x,y in changes],allOtherChildImportsWhole=True,allParentCPUAndOtherProvidersWholeRuntime81=True,deviceOperations=0)
 return dict(old=old,manifest=manifest,rows=rows,proof=proof,port=port,child=child,helper=helper,childID=childid,baselinePin=pin(baseline_path),portPin=pin(port_path),graphPin=pin(graph_path),graphRaw=(json.dumps(merged,indent=2)+'\n').encode())

def assemble(inputs,output):
 old=inputs['old'];rows=copy.deepcopy(inputs['rows']);runtime=output/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(result.stdout);(output/(label+'.stderr')).write_bytes(result.stderr);commands.append(dict(label=label,argv=args,exit=result.returncode));save(output/'commands.json',commands);need(result.returncode==0,label+': '+result.stderr.decode(errors='replace'))
 for row in rows.values():base.copy_regular(pathlib.Path(old['runtimeRoot'])/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 childid=inputs['childID'];childpath=runtime/rows[childid]['path'];macos=childpath.parent;helperpath=macos/HELPER;helperid='child:'+HELPER;helperpath.unlink();helperraw=base.copy_regular(exact(inputs['port']['newProvider']),helperpath)
 childpath.unlink();childraw=base.copy_regular(exact(inputs['port']['patchedChildMain']),childpath)
 prior_child_sig=inputs['proof'][rows[childid]['path']];entitlements=prior_child_sig['embeddedEntitlements'];need(isinstance(entitlements,dict)and len(entitlements)==14 and entitlements.get('com.apple.private.virtualization.plugin')is True,'same actual prior14 child permissions')
 ent=output/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements,sort_keys=True))
 xpc=macos.parent.parent
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-diskio82-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for file in xpc.rglob('*'):
   if file.is_file():base.copy_regular(file,txpc/file.relative_to(xpc),executable=bool(file.stat().st_mode&0o111))
  th=txpc/helperpath.relative_to(xpc)
  run('sign-new-child-helper',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.child.'+HELPER,th]);run('verify-new-child-helper',['codesign','--verify','--strict',th])
  run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-child-xpc',['codesign','--verify','--strict',txpc])
  for file in (childpath,helperpath,runtime/rows['child-coderesources']['path']):
   executable=bool(file.stat().st_mode&0o111);file.unlink();base.copy_regular(txpc/file.relative_to(xpc),file,executable=executable)
 helper_signature=base.signature(base.regular_bytes(helperpath),inputs['helper'].uuid)
 resourcespath=runtime/rows['child-coderesources']['path'];resources=base.regular_bytes(resourcespath);seal=plistlib.loads(resources);old_seal=plistlib.loads(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/rows['child-coderesources']['path']));helper_seal=seal['files2'].get('MacOS/'+HELPER);need(helper_seal and helper_seal['cdhash']==bytes.fromhex(helper_signature['cdhash'])and not helper_seal.get('optional')and not helper_seal.get('omit'),'new actual nested helper seal')
 stripped=copy.deepcopy(seal);stripped['files2']['MacOS/'+HELPER]=old_seal['files2']['MacOS/'+HELPER];need(stripped==old_seal,'only existing helper nested seal changed, all other old seals whole unchanged')
 child_signature=base.signature(base.regular_bytes(childpath),CHILD_UUID,{1:base.regular_bytes(runtime/rows['child-info']['path']),3:resources});need(child_signature['embeddedEntitlements']==entitlements and{r['slot']for r in child_signature['actualSpecialSlots']if r['external']}=={1,3},'real child14 permissions and Info1/CodeResources3')
 signed=[]
 for identity,path,raw,image,sig in[(childid,childpath,childraw,inputs['child'],child_signature),(helperid,helperpath,helperraw,inputs['helper'],helper_signature)]:
  after=base.regular_bytes(path);actual=base.image_profile(after,path.name);need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.loads==image.loads and actual.uuid==image.uuid,'sign preserves actual code/import/auth/export/namespace')
  for sec in image.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in(1,12,18):need(after[at:at+z]==raw[at:at+z],'actual backed code/data unchanged by signature')
  p=pin(path);rel=str(path.relative_to(runtime));rows[identity]=dict(id=identity,path=rel,kind='mach-o',role='child'if identity==childid else'dependency',bytes=p['bytes'],sha256=p['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash']);signed.append(dict(role='child',key=path.name,relativePath=rel,actualSignedFile=p,**sig))
 rows[childid]['signatureSlots']=inputs['rows'][childid]['signatureSlots'];p=pin(resourcespath);rows['child-coderesources'].update(bytes=p['bytes'],sha256=p['sha256'])
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/rows[proofid]['path'];proofpath.write_bytes(inputs['graphRaw']);p=pin(proofpath);rows[proofid].update(bytes=p['bytes'],sha256=p['sha256'])
 unchanged=[]
 for identity,row in inputs['rows'].items():
  if identity in(childid,helperid,'child-coderesources',proofid):continue
  actual=pin(runtime/row['path']);need((actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256'])and rows[identity]==row,'all untouched parent/child/resource wholebytes same');unchanged.append(dict(id=identity,file=actual,signed=row['kind']=='mach-o'))
 need(sum(r['signed']for r in unchanged)==141,'141 actual unchanged signed files')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[rows[r['id']]for r in manifest['files']];raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n');obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n')
 exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(r,actualSignedFile=pin(runtime/r['relativePath']))for r in inputs['proof'].values()if r['relativePath']not in(inputs['rows'][childid]['path'],inputs['rows'][helperid]['path'])];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+signed,actualSignedImages=143,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,old141SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 delta=output/'runtime81-to-runtime82-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=154,actualNewRows=154,actualOldSignedImages=143,actualNewSignedImages=143,changedExistingRuntimeIDs=[childid,helperid,'child-coderesources',proofid],addedRuntimeIDs=[],wholeByteUnchangedSignedImages=141,allParentFilesWholeUnchanged=True,unchangedFiles=unchanged,childApprovalWholeSHA256=rows[childid]['sha256'],childApprovalCDHash=rows[childid]['cdhash'],childApprovalDerivedFromNewActualManifest=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual Runtime82 Child native disk IO observation product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),childImages=old['childImages'],files=154,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],childPortCandidate=inputs['portPin'],roleAwareChildGraphProof=inputs['graphPin'],runtime81DiskIOObservationDeltaVerification=pin(delta),adapterContract=inputs['port']['adapterContract'],wholeByteUnchangedSignedImages=141,codeSigningCommandsActuallyPerformed=2,existingSignedImagesResigned=2,unchangedSignedImagesResigned=0,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0)
 result.update(actualChangedRuntimeCDHashes=sorted({r['cdhash']for r in signed}),actualChangedSignedRuntimeFiles=2,allCPU29ObjectsAndProvidersWholeRuntime81=True,allCPUManifestEntriesWholeRuntime81=True,allParentFilesWholeRuntime81=True);result['genuineSandboxResource']=pin(runtime/rows['child-sandbox-profile']['path']);return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--child-port-candidate',required=True,type=pathlib.Path);ap.add_argument('--verification',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'new diagnostic output')
 inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.child_port_candidate.resolve(),a.verification.resolve());o.mkdir(mode=0o700);admission=o/'admission.json';save(admission,dict(schema='Actual Runtime82 frozen child helper version admission',baseline=inputs['baselinePin'],childPort=inputs['portPin'],graph=inputs['graphPin'],old154FilesWholeVerified=True,old143CDProvenanceJoined=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result);files=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],inputs['portPin'],pin(a.child_port_candidate.parent/'freeze.json'),inputs['graphPin']]+[v for v in inputs['port'].values()if isinstance(v,dict)and all(k in v for k in('path','bytes','sha256'))];save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
