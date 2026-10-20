#!/usr/bin/env python3
"""Parent-only incremental Runtime11; no old signed leaf is re-signed.

A frozen merged port candidate and role-aware definition graph are mandatory.
Only Root runs the signing path. --check-inputs-only never signs or executes VZ.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,stat,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('runtime11_frozen_runtime10_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
BASE_SHA='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d'
BASE_CANDIDATE_SHA='b53bd51fe0350ad9dd4fba704879abcea75ed79f74f4ce7f955f38a13ed31917'
VZ_UUID='418efc4809d93606918eb6f95baeffdc'
def need(v,why):
 if not v:raise ValueError(why)
def pin(p):return base.pin(p)
def exact(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'actual exact pin '+row['path']);return pathlib.Path(row['path'])
def save(p,value):base.save(p,value)
def frozen(candidate):
 p=pathlib.Path(candidate);rows=base.frozen_rows(p.parent/'freeze.json');need(rows.get(str(p.resolve()))==pin(p),'candidate must itself be frozen');return rows

def baseline(candidate):
 p=pathlib.Path(candidate).resolve();need(pin(p)['sha256']==BASE_CANDIDATE_SHA,'exact actual signed Runtime10 baseline')
 c=json.loads(base.regular_bytes(p));f=frozen(p);base.actual_frozen(c['manifest'],f,'actual baseline manifest frozen');base.actual_frozen(c['signatureVerification'],f,'actual baseline signature proof frozen')
 manifest=plistlib.loads(base.regular_bytes(c['manifest']['path']));need(c['localCodeSigned']and c['actualProductPreflightPassed'],'actual signed product/preflight')
 rows={r['id']:r for r in manifest['files']};need(len(rows)==len(manifest['files'])==151 and sum(r['kind']=='mach-o'for r in rows.values())==141,'exact actual151/141 baseline')
 sig=json.loads(base.regular_bytes(c['signatureVerification']['path']));need(sig['allCodePagesAndSpecialSlotsActuallyVerified']and len(sig['actualSignedFiles'])==141,'genuine actual baseline signed proof')
 root=pathlib.Path(c['runtimeRoot']);proof={r['relativePath']:r for r in sig['actualSignedFiles']};need(len(proof)==141,'unique actual prior signed files')
 for row in rows.values():
  need(base.relative(row['path']),'safe baseline relative path');p=root/row['path'];record=pin(p);need((record['bytes'],record['sha256'])==(row['bytes'],row['sha256']),'whole frozen baseline file '+row['id']);base.actual_frozen(record,f,'baseline wholefile')
  if row['kind']=='mach-o':
   s=proof[row['path']];need(s['actualSignedFile']==record and s['uuid']==row['uuid']and s['cdhash']==row['cdhash']and s['allPrimaryPagesAndSpecialSlotsVerified'],'actual prior signed file/CD join')
 return c,manifest,rows,proof

def read_inputs(baseline_path,port_path,verification_path):
 need(pin(BASE)['sha256']==BASE_SHA,'frozen Runtime10 primitive implementation')
 old,manifest,rows,proof=baseline(baseline_path);port_path=pathlib.Path(port_path).resolve();f=frozen(port_path);port=json.loads(base.regular_bytes(port_path))
 # The merged producer supplies exactly one final parent VZ and its new helper.
 # Producer/source peers must separately attest the finite cache/localizer patch.
 for field in ('patchedParentVZ','newProvider','recipe','cacheSourceCandidate','localizerCandidate'):
  base.actual_frozen(port[field],f,'actual merged port '+field)
 need(port['parentOnly']is True and port['sourcePreservedOriginalCPUAndVMCodeOutsideScopedLocalizer']is True,'explicit parent-only route, no child/DI2 changes')
 need(port['nativeZeroReceipt']and port['cacheAdapterContract']['selectedActualImportIndex']==504,'actual failure/selected import504')
 provider=port['newProvider'];provider_key=port['providerKey'];contract=port['cacheAdapterContract'];need(base.relative(provider_key)and'/'not in provider_key,'simple genuine provider filename')
 need('parent:'+provider_key not in rows,'new provider must not replace a baseline file')
 parent=base.image_profile(base.regular_bytes(exact(port['patchedParentVZ'])),'VZ27.dylib');helper=base.image_profile(base.regular_bytes(exact(provider)),provider_key)
 old_vz=base.m.MachO(base.regular_bytes(pathlib.Path(old['runtimeRoot'])/rows['parent:VZ27.dylib']['path']))
 need(parent.uuid==old_vz.uuid==VZ_UUID and parent.sections==old_vz.sections and parent.exports==old_vz.exports,'parent code geometry/UUID/strong public exports')
 selected=parent.imports[504];prior=old_vz.imports[504];need(prior['name']=='_confstr'and prior['ordinal']==19 and not prior['weak']and prior['addend']==0,'actual original selected native504')
 need(selected['name']==contract['symbol']and selected['ordinal']==contract['newRequiredOrdinal']and not selected['weak']and selected['addend']==0,'actual selected named cache API')
 local=port['localizerContract'];need(local['symbol']=='_VM27OwnedVZLocalizedStringOrEnglishKeyV1' and local['newRequiredOrdinal']==contract['newRequiredOrdinal'],'precise second named API on the same provider')
 need(len(parent.imports)==len(old_vz.imports)+1,'exactly one additional genuine localizer import')
 appended=parent.imports[-1];need(appended['index']==len(old_vz.imports) and appended['name']==local['symbol'] and appended['ordinal']==local['newRequiredOrdinal'] and not appended['weak'] and appended['addend']==0,'actual new localizer import, not native symbol borrowing')
 for a,b in zip(parent.imports,old_vz.imports):
  if a['index']!=504:need({k:v for k,v in a.items()if k!='at'}=={k:v for k,v in b.items()if k!='at'},'all other true import semantics unchanged')
 load=next(x for x in parent.loads if x['ordinal']==selected['ordinal']);need(load['path']=='@loader_path/'+provider_key and load['cmd']==12,'new required explicit provider LC_LOAD')
 export=helper.exports.get(selected['name']);need(export and export['flags']==0,'actual helper direct strong named API export')
 graph_path=pathlib.Path(verification_path).resolve();graph=json.loads(base.regular_bytes(graph_path));gf=frozen(graph_path)
 need(graph['parentOnly']is True and graph['baselineRuntimeCandidate']==pin(baseline_path),'role-aware graph anchored to exact actual baseline')
 need(graph['originalParentSignedPin']==port['originalParentVZ']and graph['originalParentSignedPin']==pin(pathlib.Path(old['runtimeRoot'])/rows['parent:VZ27.dylib']['path']),'exact signed parent baseline')
 need(graph['originalChildClosureWholeUnchanged']is True and graph['diskImages2NativeConfstrWholeUnchanged']is True,'untouched child/DI2 declaration plus actual product whole-copy check')
 need(graph['actualSelectedParentImport']==selected and graph['actualSelectedParentRequiredLoad']==load,'graph selected import/LC exact actual fields')
 need(graph['actualAppendedParentLocalizerImport']==appended,'graph appended localizer import exact actual fields')
 need(graph['newProviderStrongImportsClosed']is True and graph['newProvider']==provider,'genuine helper native closure')
 native_path=N/'current-native-header-export-index-v3/index.json';native=json.loads(base.regular_bytes(native_path))['images']
 def resolve_native(path,symbol,seen=None):
  seen=set()if seen is None else set(seen)
  if (path,symbol)in seen:return []
  seen.add((path,symbol));need(path in native,'captured required native provider '+path);im=native[path];d=im['definitions'].get(symbol)
  if d:
   if d['flags']&8:
    target=next(x for x in im['dependencies']if x['ordinal']==d['ordinal'])
    return resolve_native(target['path'],d.get('alias')or d.get('importedName')or d.get('name')or symbol,seen)
   return [dict(path=path,UUID=im['UUID'],symbol=symbol,definition=d)]
  answer=[]
  for dep in im['dependencies']:
   if dep['command']==0x8000001f and dep['path']in native:answer+=resolve_native(dep['path'],symbol,seen)
  return list({(r['path'],r['symbol']):r for r in answer}.values())
 loads={r['ordinal']:r for r in helper.loads};actualrows=graph['actualProviderNativeRows'];need(len(actualrows)==len(helper.imports)==36,'actual36 helper strong imports')
 for row,imp in zip(actualrows,helper.imports):
  need(row['actualImport']==imp and not imp['weak']and imp['ordinal']>0 and imp['addend']==0,'every actual helper import row')
  required=loads[imp['ordinal']];need(row['requiredLoad']==required,'actual helper namespace')
  need(resolve_native(required['path'],imp['name'])==[row['resolvedDefinition']],'actual captured native recursive definition route')
 for source in graph['sourcePins']:exact(source)
 # Incremental proof embeds the real baseline graph rather than calling this
 # limited delta a newly rerun full graph. Old imports keep their exact routes.
 baseline_proof_path=pathlib.Path(old['runtimeRoot'])/rows[manifest['dependencyProofID']]['path'];old_graph=json.loads(base.regular_bytes(baseline_proof_path))
 need(old_graph['finalStrongDefinitionGraphClosed']and old_graph['unresolvedStrongImportRows']==[],'actual old closed graph inherited by whole-file/CD proof')
 old_parent={r['actualImport']['index']:r for r in old_graph['actualStrongImportRows']if r['importer']=='VZ27.dylib'}
 for weakrow in old_graph.get('actualNativeWeakDefinitionRows',[]):
  if weakrow['importer']=='VZ27.dylib':old_parent[weakrow['actualImport']['index']]=dict(actualImport=weakrow['actualImport'],resolution=weakrow.get('actualDefinition',weakrow.get('resolution')))
 role_rows=[]
 for imp in parent.imports:
  if imp['weak']:continue
  if imp['index']in (504,len(old_vz.imports)):
   ex=helper.exports[imp['name']];res=dict(resolved=True,route=[dict(kind='owned-parent',path='parent-flat/'+provider_key,symbol=imp['name'],actualExport=ex,UUID=helper.uuid)])
  else:
   previous=old_parent[imp['index']];need({k:v for k,v in previous['actualImport'].items()if k!='at'}=={k:v for k,v in imp.items()if k!='at'},'old parent import/route semantic join');res=previous['resolution']
  role_rows.append(dict(importer='parent:VZ27.dylib',actualImport=imp,resolution=res))
 merged=dict(schema='Actual Runtime11 parent-role incremental definition proof',finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],baselineRuntimeCandidate=pin(baseline_path),baselineDependencyProof=pin(baseline_proof_path),inheritedBaselineDefinitionGraph=old_graph,parentPortCandidate=pin(port_path),actualParentIncrementalGraph=graph,actualStrongParentImportRows=role_rows,originalChildClosureWholeUnchanged=True,oldGraphRerun=False,newActualHelperStrongImports=36,newSelectedParentStrongRoutes=2,deviceOperations=0)
 graph_raw=(json.dumps(merged,indent=2)+'\n').encode()
 return dict(old=old,manifest=manifest,rows=rows,oldSignatures=proof,port=port,parent=parent,helper=helper,providerKey=provider_key,graphRaw=graph_raw,graphPin=pin(graph_path),portPin=pin(port_path),baselinePin=pin(baseline_path))

def assemble(inputs,output):
 old=inputs['old'];runtime=output/'runtime';runtime.mkdir(mode=0o700);oldroot=pathlib.Path(old['runtimeRoot']);oldrows=inputs['rows'];newrows=copy.deepcopy(oldrows);commands=[]
 def run(label,args):
  args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60);(output/(label+'.stdout')).write_bytes(r.stdout);(output/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));save(output/'commands.json',commands);need(r.returncode==0,label+': '+r.stderr.decode(errors='replace'))
 for row in oldrows.values():
  source=oldroot/row['path'];target=runtime/row['path'];base.copy_regular(source,target,executable=row['kind']=='mach-o')
 # The baseline manifest is superseded below. Its digest is never reused.
 changes=[('parent:VZ27.dylib',oldrows['parent:VZ27.dylib']['path'],inputs['port']['patchedParentVZ'],inputs['parent']),
          ('parent:'+inputs['providerKey'],'parent-flat/'+inputs['providerKey'],inputs['port']['newProvider'],inputs['helper'])]
 signatures=[]
 for identity,relative,source,image in changes:
  p=runtime/relative
  if p.exists():p.unlink()
  before=base.copy_regular(exact(source),p)
  key=relative.split('/')[-1]
  run('sign-parent-'+key,['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.parent.'+key,p])
  run('verify-parent-'+key,['codesign','--verify','--strict',p])
  after=base.regular_bytes(p);actual=base.image_profile(after,key);need(actual.sections==image.sections and actual.imports==image.imports and actual.binds==image.binds and actual.exports==image.exports and actual.uuid==image.uuid,'sign only metadata, code/data/PAC/imports preserved')
  for sec in image.sections:
   at,z=sec['fileoff'],sec['size']
   if at and z and sec['flags']&255 not in (1,12,18):need(before[at:at+z]==after[at:at+z],'actual backed section unchanged after signing')
  sig=base.signature(after,image.uuid);record=pin(p);signatures.append(dict(role='parent',key=key,relativePath=relative,actualSignedFile=record,**sig));newrows[identity]=dict(id=identity,path=relative,kind='mach-o',role='frontend'if identity=='parent:VZ27.dylib'else'dependency',bytes=record['bytes'],sha256=record['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash'])
 proofid=inputs['manifest']['dependencyProofID'];proofpath=runtime/newrows[proofid]['path'];proofpath.write_bytes(inputs['graphRaw']);proofpath.chmod(0o600);pp=pin(proofpath);newrows[proofid].update(bytes=pp['bytes'],sha256=pp['sha256'])
 unchanged=[]
 for identity,oldrow in oldrows.items():
  if identity in ('parent:VZ27.dylib',proofid):continue
  current=pin(runtime/oldrow['path']);need((current['bytes'],current['sha256'])==(oldrow['bytes'],oldrow['sha256'])and newrows[identity]==oldrow,'every untouched actual signed/resource file wholebytes same')
  unchanged.append(dict(id=identity,actualFile=current,signedImage=oldrow['kind']=='mach-o'))
 need(sum(x['signedImage']for x in unchanged)==140,'entire child closure and all other140 signed files unchanged')
 manifest=copy.deepcopy(inputs['manifest']);manifest['files']=[newrows[row['id']]for row in inputs['manifest']['files']]+[newrows['parent:'+inputs['providerKey']]];raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True)
 need(len(manifest['files'])==152 and len(raw)<=512*1024,'true152 manifest rows and runtime bound');manifestpath=runtime/pathlib.Path(old['manifest']['path']).name;manifestpath.write_bytes(raw);manifestpath.chmod(0o600);save(output/'manifest.json',manifest)
 anchor=output/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
 obj=output/'vm27_independent_runtime_product_anchor_v1.ios.o';run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=output/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n')
 exe=output/'actual-product-preflight';run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(row,actualSignedFile=pin(runtime/row['relativePath']))for row in inputs['oldSignatures'].values()if row['relativePath']!='parent-flat/VZ27.dylib'];signaturepath=output/'signature-verification.json';save(signaturepath,dict(actualSignedFiles=inherited+signatures,actualSignedImages=142,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,actualNewPrimaryPagesAndSpecialSlotsActuallyVerified=True,old140SignedWholeFilesAndCDProofInherited=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 delta=output/'runtime10-to-runtime11-delta.json';save(delta,dict(baselineCandidate=inputs['baselinePin'],actualOldRows=151,actualNewRows=152,actualOldSignedImages=141,actualNewSignedImages=142,changedExistingRuntimeIDs=['parent:VZ27.dylib',proofid],addedRuntimeIDs=['parent:'+inputs['providerKey']],wholeByteUnchangedSignedImages=140,unchangedFiles=unchanged,childSubtreeInfoCodeResourcesMainPremainWholeUnchanged=True,onlyTwoParentMachOsSigned=True,deviceOperations=0))
 result=copy.deepcopy(old);result.update(schema='Actual parent-only incremental independent27 Runtime11 own cache and truthful localized error product',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(signaturepath),parentImages=old['parentImages']+1,files=152,actualProductPreflightPassed=True,builder=pin(__file__),baselineRuntimeCandidate=inputs['baselinePin'],parentPortCandidate=inputs['portPin'],roleAwareGraphProof=inputs['graphPin'],runtime10DeltaVerification=pin(delta),codeSigningCommandsActuallyPerformed=2,existingSignedImagesResigned=1,unchangedSignedImagesResigned=0,wholeByteUnchangedSignedImages=140,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0)
 result['genuineSandboxResource']=pin(runtime/newrows['child-sandbox-profile']['path']);result['cacheAdapterContract']=inputs['port']['cacheAdapterContract'];result['localizerContract']=inputs['port']['localizerContract'];return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--parent-port-candidate',required=True,type=pathlib.Path);ap.add_argument('--verification',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);ap.add_argument('--check-inputs-only',action='store_true');a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh diagnostics output')
 inputs=read_inputs(a.baseline_runtime_candidate.resolve(),a.parent_port_candidate.resolve(),a.verification.resolve());o.mkdir(mode=0o700);admission=o/'admission.json';save(admission,dict(schema='Actual Runtime11 parent-only frozen product admission',baseline=inputs['baselinePin'],parentPort=inputs['portPin'],definitionGraph=inputs['graphPin'],newNamedProvider=inputs['port']['newProvider'],parentOnly=True,old151FilesWholeVerified=True,old141SignedCDProvenanceJoined=True,deviceOperations=0))
 if a.check_inputs_only:print(json.dumps(dict(admission=pin(admission),signed=False,deviceOperations=0)));return
 try:
  result=assemble(inputs,o);result['admission']=pin(admission);candidate=o/'candidate.json';save(candidate,result);rows=[pin(p)for p in o.rglob('*')if p.is_file()]+[pin(__file__),pin(BASE),inputs['baselinePin'],pin(a.baseline_runtime_candidate.parent/'freeze.json'),inputs['old']['manifest'],inputs['old']['signatureVerification'],inputs['portPin'],pin(a.parent_port_candidate.parent/'freeze.json'),inputs['graphPin'],pin(a.verification.parent/'freeze.json')]+[v for v in inputs['port'].values()if isinstance(v,dict)and all(k in v for k in ('path','bytes','sha256'))];save(o/'freeze.json',dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0,onlyParentLeavesLocallySigned=True));print(json.dumps(dict(candidate=pin(candidate),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
 except Exception as error:save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__=='__main__':main()
