"""Offline exact candidate LC_LOAD/strong-import/native export inventory.
Never loads a DSO, changes a candidate, guesses basename aliases, or uses SSH.
An optional --catalog JSON supplies explicit logical-file keys and source pins.
"""
import pathlib,json,hashlib,struct,sys,importlib.util,argparse,collections
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';D=N/'independent27-runtime-strong-inventory-v3'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def need(v):
 if not v:raise ValueError('runtime inventory invariant')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--catalog');ap.add_argument('--load-map');a=ap.parse_args();need(not D.exists());D.mkdir()
 parser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';sp=importlib.util.spec_from_file_location('macho',parser);lib=importlib.util.module_from_spec(sp);sp.loader.exec_module(lib)
 indexPath=N/'current-native-header-export-index-v3/index.json';need(pin(indexPath)['sha256']=='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019');index=json.loads(indexPath.read_text());native=index['images'];need(len(native)==67)
 catalog={};basis={indexPath,parser,pathlib.Path(__file__)};rejected=[]
 def add(key,p,record=None):
  p=pathlib.Path(p).resolve();actual=pin(p)
  if record:need(all(actual[k]==record[k] for k in ['path','bytes','sha256']))
  if key=='ModernCPURuntimeCompat.dylib' or p.name=='ModernCPURuntimeCompat.dylib':rejected.append(actual);return
  catalog[key]={'source':actual,'macho':lib.MachO(p.read_bytes())};basis.add(p)
 def candidate(sub):
  p=N/sub/'candidate.json';basis.add(p);return json.loads(p.read_text())
 vz=candidate('vz-own-uikit-notification-source-port-data-v1');vmm=candidate('original27-debug-flags-source-port-data-v2-attempt1');uhk=candidate('uhk-own-uikit-mac-unavailable-source-port-v1-attempt2');hv=candidate('vm-hv-public-bootstrap-integration-local-v16-adoption1')
 add('VZ27.dylib',vz['frontendCandidate']['path'],vz['frontendCandidate']);add('com.apple.Virtualization.VirtualMachine',vmm['candidate']['path'],vmm['candidate']);add('UniversalHIDKit27.dylib',uhk['providerCandidate']['path'],uhk['providerCandidate']);add('VM27HVVMProduction.dylib',hv['provider']['path'],hv['provider'])
 base=candidate('vz-genuine-strong-closure-design-v1/build-v1')
 for row in base['stagedPrivateLibraries']:add(pathlib.Path(row['path']).name,row['path'],row)
 di=candidate('diskimages2-owned-raw-build-v4')
 for row in di['files']:
  if row['name'].endswith('.dylib'):add(row['name'],row['path'],row)
 for row in vz['wholeCopiedPreviousProviders']:add(pathlib.Path(row['candidate']['path']).name,row['candidate']['path'],row['candidate'])
 for row in [vz['frontendAggregate'],vz['hostNotificationProvider']]:add(pathlib.Path(row['path']).name,row['path'],row)
 add('VM27MacInputUnavailableV1.dylib',uhk['ownSourceProvider']['path'],uhk['ownSourceProvider'])
 if a.catalog:
  extra=pathlib.Path(a.catalog).resolve();basis.add(extra)
  for key,row in json.loads(extra.read_text()).items():add(key,row['path'],row)
 loadMap={}
 if a.load_map:
  mp=pathlib.Path(a.load_map).resolve();basis.add(mp);loadMap=json.loads(mp.read_text())['proposedLoadPathMap']
 mode='actual'
 roots=['VZ27.dylib','com.apple.Virtualization.VirtualMachine','UniversalHIDKit27.dylib','VM27HVVMProduction.dylib']
 def target(path):
  if mode=='proposed' and path in loadMap:path=loadMap[path]['target']
  if path in native:return ('native',path)
  if path.startswith('@loader_path/') or path.startswith('@rpath/'):
   key=path.split('/',1)[1]
   if key in catalog:return ('candidate',key)
  return ('uncaptured',path)
 def dependencies(kind,key):
  if kind=='native':return native[key]['dependencies']
  return [{'ordinal':x['ordinal'],'command':x['cmd'],'path':x['path']} for x in catalog[key]['macho'].loads]
 def resolve(kind,key,name,seen=()):
  ident=(kind,key,name)
  if ident in seen:return {'resolved':False,'cause':'cycle','at':ident}
  seen=seen+(ident,)
  if kind=='uncaptured':return {'resolved':False,'cause':'imagePathNotCapturedOrSelected','path':key,'symbol':name}
  entries=native[key]['definitions'] if kind=='native' else catalog[key]['macho'].exports
  row=entries.get(name);step={'kind':kind,'path':key,'symbol':name}
  if row is not None:
   step['definition']=row
   if row['flags']&8:
    ordinal=row['ordinal'];dep=next((x for x in dependencies(kind,key) if x['ordinal']==ordinal),None)
    if not dep:return {'resolved':False,'cause':'invalidReexportOrdinal','route':[step]}
    alias=row.get('alias',row.get('importedName','')) or name;t=target(dep['path']);rest=resolve(*t,alias,seen);rest['route']=[step]+rest.get('route',[]);return rest
   if kind=='native':step['UUID']=native[key]['UUID'];step['address']=row.get('offset',0)+(0 if row['flags']&3==2 else native[key]['base'])
   else:step['UUID']=catalog[key]['macho'].uuid
   return {'resolved':True,'route':[step]}
  failures=[];valid=[]
  for dep in dependencies(kind,key):
   if dep['command']==0x8000001f:
    rest=resolve(*target(dep['path']),name,seen)
    if rest['resolved']:valid.append(rest)
    else:failures.append({'path':dep['path'],'cause':rest['cause']})
  if valid:return {'resolved':True,'route':[step]+valid[0]['route'],'additionalExactReexportRoutes':len(valid)-1}
  return {'resolved':False,'cause':'symbolAbsentFromCapturedExportAndExactReexports','path':key,'symbol':name,'unclosedReexports':failures}
 def collect(selectedMode):
  nonlocal mode
  mode=selectedMode
  queue=collections.deque(roots);visited=set();images={};rows=[];loads=[]
  while queue:
   key=queue.popleft()
   if key in visited:continue
   visited.add(key);m=catalog[key]['macho'];images[key]={'source':catalog[key]['source'],'UUID':m.uuid,'imports':len(m.imports),'exports':len(m.exports),'loads':dependencies('candidate',key),'possibleConstructorObjCAndSwiftMetadataSections':[x for x in m.sections if x['size'] and (x['name'].startswith('__objc_') or x['name'].startswith('__swift') or x['name'] in ['__mod_init_func','__init_offsets','__mod_term_func'])],'metadataPresenceDoesNotProveDeletionSafe':True}
   for dep in dependencies('candidate',key):
    kind,tk=target(dep['path']);required=dep['command']!=0x80000018 or any(not x['weak'] and x['ordinal']==dep['ordinal'] for x in m.imports)
    loads.append({'importer':key,'ordinal':dep['ordinal'],'actualPath':dep['path'],'actualCommand':dep['command'],'required':required,'targetKind':kind,'targetKey':tk,'strongImportCount':sum(not x['weak'] and x['ordinal']==dep['ordinal'] for x in m.imports),'weakImportCount':sum(bool(x['weak']) and x['ordinal']==dep['ordinal'] for x in m.imports),'loadStillRequiredWhenZeroImports':required})
    if kind=='candidate':queue.append(tk)
   for imp in m.imports:
    if imp['weak']:continue
    record={'importer':key,'importerUUID':m.uuid,'actualImport':imp}
    if imp['ordinal']>0:
     dep=next((x for x in m.loads if x['ordinal']==imp['ordinal']),None);need(dep is not None);record['dependencyPath']=dep['path'];record['resolution']=resolve(*target(dep['path']),imp['name'])
    elif imp['ordinal']==0:record['resolution']=resolve('candidate',key,imp['name'])
    else:record['resolution']={'resolved':False,'cause':'flatOrMainNamespaceNeedsExplicitRuntimeScope','ordinal':imp['ordinal'],'symbol':imp['name']}
    rows.append(record)
  gaps=[x for x in rows if not x['resolution']['resolved']];missingLoads=[x for x in loads if x['required'] and x['targetKind']=='uncaptured'];hist=collections.Counter(x['resolution']['cause'] for x in gaps)
  nativeQueue=collections.deque(sorted({x['targetKey'] for x in loads if x['required'] and x['targetKind']=='native'}));nativeVisited=set();nativeLoads=[]
  while nativeQueue:
   nk=nativeQueue.popleft()
   if nk in nativeVisited:continue
   nativeVisited.add(nk)
   for dep in dependencies('native',nk):
    kind,tk=target(dep['path']);required=dep['command']!=0x80000018
    nativeLoads.append(dict(importer=nk,importerUUID=native[nk]['UUID'],ordinal=dep['ordinal'],actualPath=dep['path'],actualCommand=dep['command'],requiredByLoadCommand=required,weakImportRequirementNotCaptured=not required,targetKind=kind,targetKey=tk,actualHeaderCaptured=kind=='native',uncapturedIsEvidenceGapNotProvenAbsent=True))
    if required and kind=='native':nativeQueue.append(tk)
  nativeMissing=[x for x in nativeLoads if x['requiredByLoadCommand'] and x['targetKind']=='uncaptured']
  zeroLoads=[x for x in loads if x['required'] and x['strongImportCount']==0]
  report={'schema':'Independent27 exact candidate strong-import inventory v3','currentCacheUUID':index['currentCacheUUID'],'currentNativeImages':67,'selectedRoots':roots,'selectedCatalog':{k:catalog[k]['source'] for k in sorted(catalog)},'reachedCandidateImages':images,'actualLoadRows':loads,'actualStrongImportRows':rows,'unresolvedStrongImportRows':gaps,'requiredUncapturedOrUnselectedLoadRows':missingLoads,'requiredZeroStrongImportLoadRows':zeroLoads,'currentNativeTransitiveLoadRows':nativeLoads,'currentNativeRequiredLoadHeadersNotCaptured':nativeMissing,'candidateStrongDefinitionGraphClosed':not gaps and not missingLoads,'fullLoaderGraphClosed':not gaps and not missingLoads and not nativeMissing,'nativeLoadAbsenceProven':False,'zeroImportLoadDeletionOrRetargetSafetyProven':False,'summary':{'reachedCandidateImages':len(images),'strongImports':len(rows),'resolved':len(rows)-len(gaps),'unresolved':len(gaps),'requiredUncapturedOrUnselectedLoads':len(missingLoads),'unresolvedCauses':dict(hist),'requiredZeroStrongImportLoads':len(zeroLoads),'reachedCurrentNativeImages':len(nativeVisited),'nativeRequiredLoadHeadersNotCaptured':len(nativeMissing)},'oldCPURegistryProvidersRejected':rejected,'noAutomaticFrameworkVersionsAliases':True,'noAutomaticSystemSymbolNameSearch':True,'retargetingPerformed':False,'resolutionMode':mode,'proposedPlanAppliedOnlyToOfflineResolution':mode=='proposed','deviceOperations':0,'nativeOperations':0,'strongGraphClosed':not gaps and not missingLoads and not nativeMissing,'guestBoot':False,'sourcePins':[pin(x) for x in sorted(basis)]}
  return report
 actual=collect('actual');proposed=collect('proposed')
 report={'schema':'Independent27 runtime actual plus explicit proposed retarget graph v3','actual':actual,'proposed':proposed,'proposedLoadPathMap':loadMap,'actualSummary':actual['summary'],'proposedSummary':proposed['summary'],'retargetingPerformed':False,'deviceOperations':0,'nativeOperations':0,'guestBoot':False,'sourcePins':[pin(x) for x in sorted(basis)]}
 (D/'inventory.json').write_text(json.dumps(report,indent=2)+'\n');(D/'freeze.json').write_text(json.dumps({'inventory':pin(D/'inventory.json'),'pins':report['sourcePins']},indent=2)+'\n');print(json.dumps({'inventory':pin(D/'inventory.json'),'freeze':pin(D/'freeze.json'),'actualSummary':report['actualSummary'],'proposedSummary':report['proposedSummary'],'missingProposedLoadPaths':sorted(set(x['actualPath'] for x in proposed['requiredUncapturedOrUnselectedLoadRows']))}))
if __name__=='__main__':main()
