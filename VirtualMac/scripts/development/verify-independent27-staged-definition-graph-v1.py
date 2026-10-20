"""Verify actual staged LOAD/import words against actual current native exports.

Weak coalescing definitions are audited separately; this does not claim that
the iPad process has run its loader or that the remaining six calls work.
"""
import argparse,collections,hashlib,importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 d=a.output.resolve();need(d.is_relative_to(N)and not d.exists(),'fresh output');d.mkdir()
 stagePath=N/'independent27-flat-graph-stage-v1-attempt3/candidate.json';stage=json.loads(stagePath.read_bytes())
 need(pin(stagePath)['sha256']=='97d9def83ebe8c240bfe3b752d25e28365ffe6bec51f95a25d3150f3a308a206','actual stage')
 indexPath=N/'current-native-header-export-index-v3/index.json';native=json.loads(indexPath.read_bytes())['images']
 need(pin(indexPath)['sha256']=='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019','current actual native67')
 reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
 spec=importlib.util.spec_from_file_location('actual_stage_graph',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 own={}
 for row in stage['stagedImages']:
  need(pin(row['staged']['path'])==row['staged'],'actual staged bytes')
  own[row['key']]=dict(pin=row['staged'],image=m.MachO(pathlib.Path(row['staged']['path']).read_bytes()))
 need(len(own)==71,'actual71 staged images')
 def target(path):
  if path in native:return 'native',path
  if path.startswith('@loader_path/')and path[len('@loader_path/'):]in own:
   return 'own',path[len('@loader_path/'):]
  return 'missing',path
 def deps(kind,key):
  if kind=='native':return native[key]['dependencies']
  return [dict(ordinal=r['ordinal'],command=r['cmd'],path=r['path'])for r in own[key]['image'].loads]
 def definition(kind,key,symbol,seen=()):
  if kind=='missing':return dict(resolved=False,cause='selectedDependencyNotPresent',path=key,symbol=symbol)
  ident=(kind,key,symbol)
  if ident in seen:return dict(resolved=False,cause='actualReexportCycle',path=key,symbol=symbol)
  seen=seen+(ident,);image=native[key]if kind=='native'else own[key]['image']
  exports=image['definitions']if kind=='native'else image.exports
  row=exports.get(symbol);step=dict(kind=kind,path=key,symbol=symbol)
  if row:
   step['actualExport']=row
   if row['flags']&8:
    dep=next((r for r in deps(kind,key)if r['ordinal']==row['ordinal']),None)
    need(dep is not None,'actual named reexport ordinal')
    rest=definition(*target(dep['path']),row.get('alias',row.get('importedName',''))or symbol,seen)
    rest['route']=[step]+rest.get('route',[]);return rest
   step['UUID']=image['UUID']if kind=='native'else image.uuid
   return dict(resolved=True,route=[step])
  for dep in deps(kind,key):
   if dep['command']==0x8000001f:
    rest=definition(*target(dep['path']),symbol,seen)
    if rest['resolved']:rest['route']=[step]+rest.get('route',[]);return rest
  return dict(resolved=False,cause='actualRequiredExportAbsent',path=key,symbol=symbol)
 loads=[];imports=[];weak=[]
 for key,row in sorted(own.items()):
  image=row['image']
  for dep in deps('own',key):
   kind,t=target(dep['path']);required=dep['command']!=0x80000018 or any(
    not r['weak']and r['ordinal']==dep['ordinal']for r in image.imports)
   loads.append(dict(importer=key,**dep,targetKind=kind,target=t,required=required,
    strongImportCount=sum(not r['weak']and r['ordinal']==dep['ordinal']for r in image.imports)))
  for imp in image.imports:
   if imp['weak']:continue
   if imp['ordinal']>0:
    dep=next((r for r in deps('own',key)if r['ordinal']==imp['ordinal']),None)
    need(dep is not None,'actual positive import ordinal');res=definition(*target(dep['path']),imp['name'])
   elif imp['ordinal']==0:res=definition('own',key,imp['name'])
   elif imp['ordinal']==-3:
    need(imp['addend']==0,'actual weak coalescing addend')
    res=definition('native','/usr/lib/libc++.1.dylib',imp['name'])
    need(res['resolved']and res['route'][-1]['actualExport']['flags']&4,'actual captured native weak definition')
    weak.append(dict(importer=key,actualImport=imp,actualDefinition=res,scopeExecuted=False,
     SDKSpecialOrdinal='BIND_SPECIAL_DYLIB_WEAK_LOOKUP',weakImportFlagIsSeparate=True))
    continue
   else:res=dict(resolved=False,cause='unprovedSpecialNamespace',ordinal=imp['ordinal'])
   imports.append(dict(importer=key,actualImport=imp,resolution=res))
 missing=[r for r in imports if not r['resolution']['resolved']]
 absent=[r for r in loads if r['required']and r['targetKind']=='missing']
 libcxx=[r for r in loads if r['required']and r['targetKind']=='native'and r['target']=='/usr/lib/libc++.1.dylib']
 need(libcxx and len(weak)==13,'actual required libc++ load and thirteen weak-lookup definitions')
 expected={'_MTLCopyAllDevices','_xpc_add_bundle_with_lwcr','_CGDisplayCopyColorSpace',
  '_SLSDisplayGetPotentialHeadroom','_IOSurfaceAcceleratorParavirtProcessGuestData','_OBJC_CLASS_$_DisplayServicesClient'}
 need({r['actualImport']['name']for r in missing}==expected and len(missing)==6,'exact six strong definition blockers')
 need(not absent,'all required selected image loads are available')
 need(all('ModernCPURuntimeCompat'not in r['path']and 'StartupV9'not in r['path']
  and 'OriginalV9Transport'not in r['path']and 'OwnedStartupV2'not in r['path']for r in loads),'old CPU and startup absent')
 result=dict(schema='Actual staged independent27 definition graph finite verification v1',
  actualImages=71,actualLoadRows=loads,actualStrongImportRows=imports,
  unresolvedStrongImportRows=missing,actualNativeWeakDefinitionRows=weak,
  actualRequiredNativeLibCxxLoadRows=libcxx,requiredSelectedLoadGaps=absent,
  actualStrongImports=len(imports)+len(weak),remainingActualStrongSymbols=6,
  nativeWeakDefinitionsResolved=13,actualWeakCoalescingExecuted=False,
  allSelectedFirstLoadImagePathsAvailable=True,stockNativeCacheInternalHeaderTreeFullyCaptured=False,
  actualRetargetingPerformed=True,allOriginalVMMCodeAndPointerWordsPreserved=True,
  finalStrongDefinitionGraphClosed=False,loaderExecuted=False,deviceOperations=0,guestBoot=False,
  sources=[pin(stagePath),pin(indexPath),pin(reader),pin(__file__)])
 (d/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
 (d/'freeze.json').write_text(json.dumps(dict(verification=pin(d/'verification.json'),pins=result['sources']+
  [r['pin']for r in own.values()]),indent=2)+'\n')
 print(json.dumps(dict(verification=pin(d/'verification.json'),freeze=pin(d/'freeze.json'),images=71,
  strongImports=result['actualStrongImports'],unresolved=6,weakDefinitionRows=13,requiredSelectedLoadsMissing=0)))
if __name__=='__main__':main()
