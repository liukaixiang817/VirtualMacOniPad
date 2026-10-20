#!/usr/bin/env python3
"""Root-executed HOST MD26 compile and one exact PGRemoteTask initializer port; no signing/device."""
import argparse,collections,hashlib,json,pathlib,runpy,struct,subprocess,sys,plistlib
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
PLAN=N/'owned-gpu-task-parent-source-v1-attempt2/source-plan.json'
PLAN_SHA='6db8f96ff690367b020f8d90f139512114d32ef122044fc28b3651239449007a'
BASELINE_SHA='aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
PRIOR=N/'owned-pvg-display-handshake-observation-source-port-v3-attempt1/candidate.json'
PRIOR_SHA='a1a3d13888889934cad11a01c79f91c7510caf2b5f4a4e3ea61e6f3a7b24ba37'
M=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))['MachO']
TARGET='/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'
GPU='gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc'
EXE='com.apple.gpusw.ParavirtualizedGraphicsGPUTask'
CONTRACT='ownedPGRemoteTaskParentTransportV1Contract'
OWN=('VM27LargeConsumerV2.dylib','VM27LargeRegistry.dylib','VM27OwnedAppStartupV3.dylib')
def need(v,why):
 if not v:raise ValueError(why)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(row):
 p=pathlib.Path(row['path']);need(pin(p)=={k:row[k]for k in('path','bytes','sha256')},'exact frozen input '+str(p));return p
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def semantics(m):return collections.Counter((r['ordinal'],r['weak'],r['name'],r['addend'])for r in m.imports)
NATIVE_INDEX=N/'current-native-header-export-index-v3/index.json'
NATIVE_INDEX_SHA='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
def native_equivalence(before,after):
 need(pin(NATIVE_INDEX)['sha256']==NATIVE_INDEX_SHA,'fixed actual native export index')
 native=json.loads(NATIVE_INDEX.read_bytes())['images'];captured={}
 def resolve(path,symbol,seen=()):
  key=(path,symbol);need(key not in seen and len(seen)<64,'finite actual native export/reexport route')
  if path not in native:raise LookupError('native image not captured '+path)
  record=native[path];sources=[record['actualCompleteExportSource']['rangePin'],record['actualCompleteCommands']]+[r['rangePin']for r in record.get('actualCommandSourceRanges',[])]
  for source in sources:exact(source);captured[source['path']]=source
  ex=record['definitions'].get(symbol);seen=seen+(key,)
  node=dict(provider=path,uuid=record['UUID'],symbol=symbol)
  if ex is not None:
   node['actualExport']=ex
   if ex['flags']&8:
    dep=next(d for d in record['dependencies']if d['ordinal']==ex['ordinal']);return [node]+resolve(dep['path'],ex.get('alias')or ex.get('importedName')or symbol,seen)
   need((ex['flags']&3)==0 and not(ex['flags']&16),'actual regular native strong definition');return [node]
  for dep in record['dependencies']:
   if dep['command']!=0x8000001f:continue
   try:return [dict(node,actualReexportLoad=dep)]+resolve(dep['path'],symbol,seen)
   except LookupError:pass
  raise LookupError('no actual native definition '+path+' '+symbol)
 def load(image,row):return next(x['path']for x in image.loads if x['ordinal']==row['ordinal'])
 proof=[]
 for old in before.imports:
  matches=[row for row in after.imports if all(old[k]==row[k]for k in('name','weak','addend'))]
  need(len(matches)==1,'exact old MD symbol/weak/addend retained once')
  new=matches[0];oldroute=resolve(load(before,old),old['name']);newroute=resolve(load(after,new),new['name'])
  need(oldroute[-1]==newroute[-1],'old/new actual native final provider UUID/export/address must match')
  proof.append(dict(originalImport=old,actualImport=new,originalRequiredLoad=load(before,old),actualRequiredLoad=load(after,new),originalResolution=oldroute,actualResolution=newroute,sameActualNativeDefinition=True))
 return dict(schema='Actual old MD native import terminal-definition equivalence v1',rows=proof,allOldImportNamesWeakAndAddendsPreserved=True,allActualTerminalNativeDefinitionsSame=True,nativeIndex=pin(NATIVE_INDEX),actualNativeSourcePins=list(captured.values()),rawOrdinalEqualityNotAssumed=True,deviceOperations=0)

def patch_pg(old,destination,selected):
 b=old.read_bytes();m=M(b)
 need(m.uuid=='9e6a667aa77532de8dd56872ef6a53d9' and len(m.imports)==287 and len(m.loads)==10,'actual R86 PG with all existing typed routes')
 need(m.loads[9]['path']=='@loader_path/MD' and m.loads[9]['cmd']==12,'existing required MD ordinal10')
 sig=next(c for c in m.commands if c['cmd']==0x1d);cs,sz=struct.unpack_from('<II',sig['raw'],8)
 need(cs+sz==len(b),'terminal current PG signature')
 fix=next(c for c in m.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',fix['raw'],8)
 raw=b[fo:fo+fs];v,st,io,so,count,fmt,sfmt=struct.unpack_from('<7I',raw)
 need(v==0 and count==287 and fmt==1 and sfmt==0 and io+4*count<=so,'actual PG import format')
 names=[r['symbol'].encode()+b'\0'for r in selected]
 entries=b''.join(struct.pack('<I',((len(raw)-so+sum(map(len,names[:i])))<<9)|10)for i in range(len(selected)))
 fx=bytearray(raw[:io+4*count]+entries+raw[io+4*count:]+b''.join(names))
 struct.pack_into('<I',fx,12,so+4*len(selected));struct.pack_into('<I',fx,16,count+len(selected))
 out=bytearray(b[:cs]);changes=[]
 for r in selected:
  slot=r['authSlotRVA'];row=next(q for q in m.binds if q['fileoff']==slot)
  need(row['va']-m.base==slot and row['index']==144 and row['name']=='_objc_msgSend' and
       row['auth']==1 and row['key']==0 and row['addrdiv']==1 and row['diversity']==0 and row['pointerFormat']==9,'exact typed display observation auth slot')
  oldword=struct.unpack_from('<Q',out,slot)[0];newword=(oldword&~65535)|r['newImportIndex']
  struct.pack_into('<Q',out,slot,newword);changes.append(dict(**r,slot=slot,oldWord=oldword,newWord=newword,newIndex=r['newImportIndex']))
 align=lambda x:(x+7)&~7
 out.extend(b'\0'*(align(len(out))-len(out)));newoff=len(out);out.extend(fx)
 sym=next(c for c in m.commands if c['cmd']==2);sy,ns,strs,strsz=struct.unpack_from('<4I',sym['raw'],8)
 tab=b[sy:sy+16*ns];strings=b[strs:strs+strsz]
 ds=next(c for c in m.commands if c['cmd']==11);fields=list(struct.unpack('<20I',ds['raw']))
 need(fields[6]+fields[7]==ns,'terminal existing undefined nlist rows')
 out.extend(b'\0'*(align(len(out))-len(out)));newsym=len(out);out.extend(tab)
 for i in range(len(selected)):out.extend(struct.pack('<IBBHQ',len(strings)+sum(map(len,names[:i])),1,0,10<<8,0))
 newstrings=len(out);out.extend(strings+b''.join(names));commands=[]
 for c in m.commands:
  if c['cmd']==0x1d:continue
  x=bytearray(c['raw'])
  if c['cmd']==0x80000034:struct.pack_into('<II',x,8,newoff,len(fx))
  if c['cmd']==2:struct.pack_into('<4I',x,8,newsym,ns+len(selected),newstrings,len(strings)+sum(map(len,names)))
  if c['cmd']==11:struct.pack_into('<I',x,28,fields[7]+len(selected))
  if c['cmd']==0x19 and x[8:24].rstrip(b'\0')==b'__LINKEDIT':
   off=struct.unpack_from('<Q',x,40)[0];extent=len(out)-off
   struct.pack_into('<Q',x,32,(extent+16383)&~16383);struct.pack_into('<Q',x,48,extent)
  commands.append(bytes(x))
 header=b''.join(commands);need(len(header)<=m.sizeofcmds,'no added PG load commands')
 out[32:32+m.sizeofcmds]=header+b'\0'*(m.sizeofcmds-len(header));struct.pack_into('<II',out,16,len(commands),len(header))
 q=M(out);need(q.uuid==m.uuid and q.exports==m.exports,'original PG UUID and exports')
 need([(x['path'],x['cmd'])for x in q.loads]==[(x['path'],x['cmd'])for x in m.loads],'all PG required loads whole')
 need(len(q.imports)==288,'one new strong MD import')
 for x,y in zip(m.imports,q.imports[:287],strict=True):
  need(all(x[k]==y[k]for k in ['index','ordinal','weak','name','addend']),'all287 original PG import semantics')
 for r in selected:
  z=q.imports[r['newImportIndex']];need(z['name']==r['symbol'] and z['ordinal']==10 and not z['weak'] and not z['addend'],'exact new owned MD import')
 slots={r['authSlotRVA']for r in selected}
 for s in m.sections:
  lo=s['fileoff'];hi=lo+s['size']
  if not lo or not s['size']:continue
  expected=bytearray(b[lo:hi])
  for r in changes:
   if lo<=r['slot']<hi:struct.pack_into('<Q',expected,r['slot']-lo,r['newWord'])
  need(out[lo:hi]==expected,'PG section changed beyond the finite selected auth slots: '+s['name'])
 need([(r['fileoff'],r['word'])for r in m.binds if r['fileoff']not in slots]==
      [(r['fileoff'],r['word'])for r in q.binds if r['fileoff']not in slots],'all other PG bindings including all existing depth24 and BOOL slots whole')
 destination.write_bytes(out)
 return dict(original=pin(old),patched=pin(destination),selectedAuthSlots=changes,newSymbols=[r['symbol']for r in selected],newOrdinals=[10]*len(selected),
  all287OldImportSemanticsWhole=True,allOriginalTextAndCodeWholeUnchanged=True,allOldSectionsWholeExceptSelectedAuthSlots=True,
  allOtherAuthWordsWholeUnchanged=True,originalUUIDAndExportsUnchanged=True,allOriginalRequiredLoadsWholeUnchanged=True,
  oldNlistRowsWhole=True,appendedUndefinedSymbols=len(selected),newRequiredLoadsAdded=0,codeSignedByProductSigner=False,deviceOperations=0)

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--gpu-task-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path)
 a=ap.parse_args();out=a.output.resolve();bp=a.baseline_runtime_candidate.resolve();gp=a.gpu_task_candidate.resolve()
 need(out.parent==N and not out.exists(),'fresh owned HOST source-port output')
 need(pin(PLAN)['sha256']==PLAN_SHA and pin(bp)['sha256']==BASELINE_SHA and pin(PRIOR)['sha256']==PRIOR_SHA,'final reviewed source/actual R86/template pins')
 plan=json.loads(PLAN.read_bytes());prior=json.loads(PRIOR.read_bytes());old=json.loads(bp.read_bytes());gpu=json.loads(gp.read_bytes())
 need(plan['baselineRuntimeCandidate']==pin(bp) and gpu['schema']=='NativeGPUTaskOwnedEntryProductV1' and gpu['actualIOSCompileStrictLinkDyldAndSigningPassed']is True,'actual signed native GPU source product')
 gf=json.loads((gp.parent/'freeze.json').read_bytes());frozen={r['path']:r for r in gf['files']}
 for row in [gpu[k]for k in('task','compat','taskInfo','outerBundleInfo','taskCodeResources','defaultMetallib','sourcePlan','actualImportClosure')]:
  exact(row);need(frozen.get(row['path'])==row,'GPU product actually frozen')
 closure=json.loads(exact(gpu['actualImportClosure']).read_bytes());need(closure['unresolved']==[],'actual native task186 and shim closure')
 signed=next(r for r in gpu['signedFiles']if r['actualSignedFile']==gpu['task'])
 need(signed['allPrimaryPagesAndSpecialSlotsVerified']is True and signed['uuid']=='c29e911993f13c18a9257293d5168597','actual signed native task UUID/pages/slots')
 rt=pathlib.Path(old['runtimeRoot']);manifest=plistlib.loads(exact(old['manifest']).read_bytes());rows={r['id']:r for r in manifest['files']}
 oldmd=rt/rows['child:MD']['path'];oldpg=exact(plan['actualOriginalPG']);child=rt/rows[manifest['childEntryContract']['childID']]['path']
 need(pin(oldpg)['sha256']==rows['child:ParavirtualizedGraphics27.dylib']['sha256'],'exact actual child PG')
 for row in plan['sourceFiles']+[plan['inheritedMD25Root'],plan['sourceDiff']]+plan['existingOwnAPISourceProofs']:exact(row)
 for row in prior['actualIOSObjects']:exact(row)
 compiler=json.loads(exact(prior['actualIOSCompile']).read_bytes());linker=json.loads(exact(prior['actualIOSLink']).read_bytes())
 need(compiler['exit']==linker['exit']==0 and len(prior['actualIOSObjects'])==3,'actual current three-object compile/link template')
 selected=dict(plan['selectedAuthSlot']);selected['symbol']=selected['newExport'];selected['requiredOrdinal']=10
 need(selected['newImportIndex']==287 and selected['authSlotRVA']==0x6c850 and selected['callerReturnRVA']==0x36398 and selected['uniqueCallRVA']==0x36394,'one original remote initializer caller')
 raw=oldpg.read_bytes();need(struct.unpack_from('<Q',raw,0x6c850)[0]==selected['oldWord'] and raw[0x36394:0x36398].hex()==selected['actualOriginalBLHex'],'actual original authword and unique BL')
 for row in gpu['frozenReuseProviders']:
  exact(row);relative=PathRelative(row['path'],rt);r=next(r for r in rows.values()if r['path']==relative);need((r['bytes'],r['sha256'])==(row['bytes'],row['sha256']),'GPU reused provider same actual R86')
 out.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  argv=list(map(str,argv));z=subprocess.run(argv,capture_output=True,timeout=90);(out/(label+'.stdout')).write_bytes(z.stdout);(out/(label+'.stderr')).write_bytes(z.stderr)
  row=dict(command=argv,exit=z.returncode);dump(out/(label+'.json'),row);commands.append(dict(label=label,**row));need(z.returncode==0,label+': '+z.stderr.decode(errors='replace'))
 profile=out/'vm27_owned_gpu_task_parent_generated_v1.h'
 vals=[TARGET+'/gpu-task-flat',TARGET+'/gpu-task-flat/GPUTask.bundle',TARGET+'/'+GPU+'/Contents/MacOS/'+EXE,gpu['task']['sha256'],signed['cdhash'],signed['uuid']]
 profile.write_text('/* Actual signed GPU child identity; generated before parent compile. */\nconst VM27OwnedGPUTaskParentProfileV1 VM27OwnedGPUTaskPinnedParentProfileV1={1,501,'+','.join(json.dumps(v)for v in vals)+'};\n')
 source=exact(plan['sourceFiles'][0]);obj=out/'modern_metal_device_array_v26.o';md=out/'MD';pg=out/'ParavirtualizedGraphics27.dylib'
 argv=list(compiler['command']);oldsource=prior['source']['path'];oldobj=prior['actualIOSObjects'][0]['path']
 need(argv.count(oldsource)==argv.count(oldobj)==1,'one inherited root compile')
 argv[argv.index(oldsource)]=str(source);argv[argv.index(oldobj)]=str(obj);argv+=['-I',str(S),'-DVM27_OWNED_GPU_PARENT_PROFILE_HEADER='+json.dumps(str(profile))];run('compile',argv)
 argv=list(linker['command']);need([x for x in argv if x.endswith('.o')]==[r['path']for r in prior['actualIOSObjects']],'whole original three-object link order')
 argv[argv.index(oldobj)]=str(obj);argv[argv.index(prior['newProvider']['path'])]=str(md)
 exp=next(x for x in argv if x.startswith('-Wl,-exported_symbols_list,'));oldexports=pathlib.Path(exp.split(',',2)[2]);names=oldexports.read_text().splitlines();need(selected['symbol']not in names,'new unique initializer export')
 exports=out/'exports.txt';exports.write_text('\n'.join(names+[selected['symbol']])+'\n');argv[argv.index(exp)]='-Wl,-exported_symbols_list,'+str(exports)
 # Preserve the actual six old loads in order: Foundation, Metal reexport, libc++, libSystem, CoreFoundation, libobjc; then append three own dependencies.
 at=argv.index('-o');providers=[rt/rows['child:'+name]['path']for name in OWN]
 argv[at:at]=['-lc++','-lSystem','-framework','CoreFoundation','-lobjc','-Wl,-headerpad_max_install_names','-Wl,-undefined,error',*map(str,providers)];run('link',argv)
 for dep in M(md.read_bytes()).loads:
  if dep['path'].startswith('@rpath/')and pathlib.PurePosixPath(dep['path']).name in OWN:run('normalize-'+str(dep['ordinal']),['/usr/bin/install_name_tool','-change',dep['path'],'@loader_path/'+pathlib.PurePosixPath(dep['path']).name,md])
 before=M(oldmd.read_bytes());after=M(md.read_bytes())
 need(set(after.exports)==set(before.exports)|{selected['symbol']} and all(after.exports[k]['flags']==before.exports[k]['flags']for k in before.exports),'all original MD exports plus one genuine transport export')
 equivalence=native_equivalence(before,after);dump(out/'old-md-import-definition-equivalence.json',equivalence)
 need([(r['ordinal'],r['cmd'],r['path'])for r in after.loads[:len(before.loads)]]==[(r['ordinal'],r['cmd'],r['path'])for r in before.loads],'all six actual old MD load ordinals retained')
 need([pathlib.PurePosixPath(r['path']).name for r in after.loads[len(before.loads):]]==list(OWN),'only three actual existing own provider loads added')
 recipe=patch_pg(oldpg,pg,[selected]);dump(out/'recipe.json',recipe)
 for f,label in((md,'md-validate'),(pg,'pvg-validate')):run(label,['xcrun','dyld_info','-validate_only',f])
 record=dict(schema='Actual HOST R86 owned GPU parent MD26 and PG exact initializer source port v2',baselineRuntimeCandidate=pin(bp),gpuTaskCandidate=pin(gp),sourcePlan=pin(PLAN),providerKey='MD',roles=['child'],source=pin(source),sourceFiles=plan['sourceFiles'],builder=pin(__file__),originalProvider=pin(oldmd),newProvider=pin(md),originalChildPG=pin(oldpg),patchedChildPG=pin(pg),originalChild=pin(child),actualIOSObjects=[pin(obj),*prior['actualIOSObjects'][1:]],actualIOSCompile=pin(out/'compile.json'),actualIOSLink=pin(out/'link.json'),actualMDValidate=pin(out/'md-validate.json'),actualPGValidate=pin(out/'pvg-validate.json'),recipe=pin(out/'recipe.json'),generatedParentProfile=pin(profile),existingMDImportDefinitionEquivalence=pin(out/'old-md-import-definition-equivalence.json'),selectedSlots=[selected],addedExports=[selected['symbol']],actualProviderNativeImportCount=len(after.imports),actualProviderLoads=after.loads,actualProviderImports=after.imports,providerUUID=after.uuid,all287OldPGImportSemanticsWhole=True,allOtherPGAuthSlotsWhole=True,allOriginalMDExportsPreserved=True,allOriginalMDImportNamesWeakAndAddendsPreserved=True,allExistingMDImportsResolveSameNativeDefinitions=True,allSixOriginalMDLoadSemanticsPreserved=True,originalVTAndExceptionObjectsWhole=True,parentMDAndPGWholeUnchangedRequired=True,all29CPUObjectsAndBothCPUProvidersWholeR86=True,originalChildBodyAnd14EntitlementsWholeRequired=True,compileLinkAndBothValidateExit=[0,0,0,0],newRequiredLoadsAdded=3,globalAppleClassMutation=False,contractKey=CONTRACT,commands=commands,codeSigningOperations=0,deviceOperations=0)
 record[CONTRACT]=plan[CONTRACT];dump(out/'candidate.json',record)
 files=[pin(f)for f in out.rglob('*')if f.is_file()]+[pin(__file__),pin(PLAN),pin(bp),pin(gp),pin(gp.parent/'freeze.json'),pin(PRIOR),pin(oldmd),pin(oldpg),pin(child),pin(oldexports),*plan['sourceFiles'],plan['inheritedMD25Root'],plan['sourceDiff'],*plan['existingOwnAPISourceProofs'],*prior['actualIOSObjects'],prior['actualIOSCompile'],prior['actualIOSLink'],*[pin(p)for p in providers],equivalence['nativeIndex'],*equivalence['actualNativeSourcePins'],*[gpu[k]for k in('task','compat','taskInfo','outerBundleInfo','taskCodeResources','defaultMetallib','sourcePlan','actualImportClosure')]]
 dump(out/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0,codeSigningOperations=0));print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'))))
def PathRelative(p,root):return str(pathlib.Path(p).relative_to(root))
if __name__=='__main__':main()
