#!/usr/bin/env python3
"""HOST-only flags-only O2 build of current Life65, Engine6 and Production10.

Root alone executes this builder, signs, and operates the device. The three
sources and dependencies remain frozen. Other26 objects and the exact link are
inherited. Actual import changes are reported, and any additions are resolved
from retained current-device native command/export captures.
"""
import argparse,difflib,hashlib,importlib.util,json,pathlib,re,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('borrowed_host_input_primitives',BASE)
base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
OLD=N/'cpu-production-owned-stack-fast-source-local-v2-attempt1/candidate.json'
OLD_SHA='a2ee1f3e7b6af8975e6ec67227af1f213c4e9c57fb40bb8f21e3ecf29512a58b'
UNITS=(
 ('ios-Life65-O2',N/'cpu-guest-msgbuf-source-local-v7-attempt1/commands.json','ios-Life65','modern_cpu_kernel_lifecycle_v65.c','modern_cpu_kernel_lifecycle_v65.o','modern_cpu_kernel_lifecycle_v65.o'),
 ('ios-Engine6-O2',N/'cpu-vmapple-msi-type-source-local-v1-attempt1/commands.json','ios-Engine6','modern_gic_v3_engine_v6.c','modern_gic_v3_engine_v6.o','modern_gic_v3_engine_v6.o'),
 ('ios-nativeops10-O2',N/'cpu-production-owned-stack-fast-source-local-v2-attempt1/commands.json','ios-nativeops10','modern_cpu_production_native_ops_v10.c','modern_cpu_production_native_ops_v10.o','modern_cpu_production_native_ops_v10.o'),
)
FLAGS=('-O2','-fno-strict-aliasing')
NATIVE_INDEX=N/'current-native-header-export-index-v3/index.json'
NATIVE_INDEX_SHA='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'

def need(v,w):
 if not v:raise ValueError(w)
def pin(p):
 p=pathlib.Path(p).resolve();raw=base.regular_bytes(p);return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def exact(row):
 p=pathlib.Path(row['path']);need(p.resolve().is_relative_to(R) and pin(p)==row,'exact owned source/object/proof '+str(p));return p

def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def resolve_added_native_imports(image,added):
 if not added:return dict(addedImports=[],allAddedStrongImportsResolved=True,baselineNativeDefinitionClosureInherited=True,primaryCapturesReparsed=0),[]
 need(pin(NATIVE_INDEX)['sha256']==NATIVE_INDEX_SHA,'fixed actual current-device native index')
 nf=base.frozen_rows(NATIVE_INDEX.parent/'freeze.json');base.actual_frozen(pin(NATIVE_INDEX),nf,'frozen actual native index')
 records=json.loads(base.regular_bytes(NATIVE_INDEX))['images'];captured={};parsed={}
 for path in (NATIVE_INDEX,NATIVE_INDEX.parent/'freeze.json'):captured[str(path)]=pin(path)
 def native(path):
  if path in parsed:return parsed[path]
  if path not in records:raise LookupError('native image not captured '+path)
  row=records[path];commandPin=row['actualCompleteCommands'];exportPin=row['actualCompleteExportSource']['rangePin']
  for source in (commandPin,exportPin):
   need(pin(source['path'])==source,'exact actual native primary source');captured[source['path']]=source
  raw=base.regular_bytes(commandPin['path']);need(len(raw)>=32 and struct.unpack_from('<I',raw)[0]==0xfeedfacf,'actual native MachO64 header')
  count,size=struct.unpack_from('<II',raw,16);need(len(raw)==32+size,'actual complete native load commands')
  pos=32;deps=[];uuid=None
  for unused in range(count):
   cmd,n=struct.unpack_from('<II',raw,pos);need(n>=8 and pos+n<=len(raw),'bounded actual native command')
   if cmd in(0xc,0x18,0x80000018,0x8000001f,0x20,0x80000023):
    off=struct.unpack_from('<I',raw,pos+8)[0];need(24<=off<n,'actual dylib path offset');end=raw.find(b'\0',pos+off,pos+n);need(end>=0,'terminated actual dylib load path')
    deps.append(dict(ordinal=len(deps)+1,command=cmd,path=raw[pos+off:end].decode()))
   if cmd==0x1b:need(n==24,'actual UUID command');uuid=raw[pos+8:pos+24].hex()
   pos+=n
  need(pos==len(raw)and uuid==row['UUID']and deps==row['dependencies'],'actual native UUID and dependency commands reparsed')
  exports,_=base.m.trie(base.regular_bytes(exportPin['path']));parsed[path]=(uuid,deps,exports)
  return parsed[path]
 def resolve(path,symbol,seen):
  if (path,symbol)in seen:raise LookupError('cyclic native route')
  need(len(seen)<64,'bounded native definition route');seen=seen|{(path,symbol)}
  uuid,deps,exports=native(path);definition=exports.get(symbol);node=dict(provider=path,uuid=uuid,symbol=symbol)
  if definition is not None:
   node['actualExport']=definition
   if definition['flags']&8:
    dep=next((d for d in deps if d['ordinal']==definition['ordinal']),None);need(dep is not None,'actual export reexport ordinal')
    return [node]+resolve(dep['path'],definition.get('alias')or definition.get('name')or symbol,seen)
   need((definition['flags']&3)==0 and not(definition['flags']&16),'actual regular native definition')
   return [node]
  for dep in deps:
   if dep['command']!=0x8000001f:continue
   try:return [node|dict(actualReexportLoad=dep)]+resolve(dep['path'],symbol,seen)
   except LookupError:continue
  raise LookupError('unresolved actual native symbol '+path+' '+symbol)
 rows=[]
 for imp in added:
  need(imp['weak']==0 and imp['ordinal']>0 and imp['addend']==0,'new compiler helper is a strong ordinary native import')
  dep=next((row for row in image.loads if row['ordinal']==imp['ordinal']),None);need(dep is not None and dep['path'].startswith('/'),'new helper actual native load ordinal')
  rows.append(dict(actualImport=imp,resolved=True,route=resolve(dep['path'],imp['name'],set())))
 return dict(addedImports=rows,allAddedStrongImportsResolved=True,currentNativeIndex=pin(NATIVE_INDEX),actualPrimarySourcePins=list(captured.values()),primaryCapturesReparsed=len(parsed)),list(captured.values())

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-plan',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh own actual source build output')
 planpath=a.source_plan.resolve();need(planpath.is_relative_to(R),'owned source plan');plan=json.loads(base.regular_bytes(planpath));planpin=pin(planpath)
 need(plan['contractKey']=='cpuHotObjectsOptimizationV1Contract' and isinstance(plan['contract'],dict),'actual flags-only three hot object contract')
 need(plan['baselineCPU']==pin(OLD),'actual current Factory12 source baseline plan binding')
 sources=plan['sourceFiles'];need(sources and len({r['path']for r in sources})==len(sources),'unique actual source files')
 for row in sources:exact(row)
 need(all(str(S/unit[3])in{r['path']for r in sources}for unit in UNITS),'all three unchanged compiler sources are pinned')
 proofs=plan.get('proofs',{});extra=plan.get('additionalContracts',{})
 for row in proofs.values():exact(row)
 need(all(k.endswith('Contract')and isinstance(v,dict)for k,v in extra.items()),'only named source-owner additional contracts')
 need(pin(OLD)['sha256']==OLD_SHA,'actual successful Factory11 CPU source baseline');old=json.loads(base.regular_bytes(OLD));exact(old['provider'])
 for row in old['sourceFiles']+old['actualChangedObjects']+old['inheritedWholeObjects']:exact(row)
 prior=json.loads(base.regular_bytes(OLD.parent/'commands.json'));previous_link=list(next(c['argv']for c in prior if c['label']=='link-whole-guest-msgbuf'))
 oldobjects=[pin(x)for x in previous_link if x.endswith('.o')];need(len(oldobjects)==29,'actual29 baseline linked objects')
 old_by_name={pathlib.Path(r['path']).name:r for r in oldobjects};need(len(old_by_name)==29,'unique actual baseline object names')
 replaced=[old_by_name[unit[5]]for unit in UNITS];inherited=[r for r in oldobjects if r not in replaced]
 need(len(replaced)==3 and len(inherited)==26 and all(any(pathlib.Path(r['path']).name==name for r in inherited)for name in ('modern_cpu_native_public_factory_startup_failure_v12.o','vm27_hv_public_vm_bootstrap_v28.o')),'actual three flags-only replacements and26 whole including Factory12/Bootstrap28')
 o.mkdir(mode=0o700);commands=[];deps=[];changed=[];compiler_proofs=[];compile_changes=[];expected_dependencies={}
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);so=o/(label+'.stdout');se=o/(label+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr)
  commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se)));save(o/'commands.json',commands)
  need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-3500:]);return p

 for label,commandpath,oldlabel,source_name,object_name,old_object_name in UNITS:
  compiler_proofs.append(pin(commandpath));records=json.loads(base.regular_bytes(commandpath));record=next(c for c in records if c['label']==oldlabel);need(record['exit']==0,'actual successful prior compiler template')
  argv=list(record['argv']);original=list(argv);source=S/source_name;obj=o/object_name;dep=o/(pathlib.Path(object_name).stem+'.d')
  need(argv[argv.index('-c')+1]==str(source) and not any(re.fullmatch(r'-O(?:[0-3szg]|fast)',arg)for arg in argv),'exact unchanged source and original implicit-O0 compiler template')
  need(not any(arg in('-flto','-ffast-math','-fstrict-aliasing')for arg in argv),'no preexisting LTO/fastmath/strict-alias override')
  expected=next(row for row in plan['compilerInputs']if row['label']==label)
  need(expected['commandFile']==pin(commandpath)and expected['originalLabel']==oldlabel and expected['originalArgv']==original,'exact frozen compiler command proof')
  for row in [expected['dependencyFile']]+expected['dependencyFiles']:need(pin(row['path'])==row,'whole frozen original source/dependency input')
  expected_dependencies[label]={row['path']:row for row in expected['dependencyFiles']}
  argv[argv.index('-o')+1]=str(obj);argv[argv.index('-MF')+1]=str(dep);argv+=list(FLAGS)
  need([arg for arg in argv if arg.startswith('-O')]==['-O2'] and argv[-2:]==list(FLAGS),'only effective O2 and conservative aliasing flags added')
  run(label,argv);changed.append(pin(obj));deps.append(dep)
  actual_dependencies={str(pathlib.Path(x).resolve()):pin(x)for x in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split()if pathlib.Path(x).is_file()}
  need(actual_dependencies==expected_dependencies[label],'all actual compiler sources/dependencies whole unchanged under O2')
  compile_changes.append(dict(label=label,originalCommand=expected['commandFile'],originalLabel=oldlabel,originalArgv=original,actualArgv=argv,onlyAddedCompilerFlags=list(FLAGS),source=pin(source),sourceAndDependenciesWholeUnchanged=True,dependencyInputs=list(actual_dependencies.values())))
 provider=o/'VM27HVVMProductionHotObjectsO2V1.unsigned.dylib';replacements={r['path']:changed[i]['path']for i,r in enumerate(replaced)}
 link=[replacements.get(arg,arg)for arg in previous_link];need(all(previous_link.count(r['path'])==1 for r in replaced),'exact three whole-object link substitutions')
 link[link.index('-o')+1]=str(provider);link=[arg.replace('@rpath/'+pathlib.Path(old['provider']['path']).name,'@rpath/'+provider.name)for arg in link]
 run('link-whole-guest-msgbuf',link);run('validate-whole-gic-vm-serialized-actions',['xcrun','dyld_info','-validate_only',str(provider)])
 image=base.image_profile(base.regular_bytes(provider),'VM27HVVMProduction.dylib');previous=base.image_profile(base.regular_bytes(old['provider']['path']),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in r.items()if k not in('at','index')}for r in rows],key=lambda r:json.dumps(r,sort_keys=True))
 oldImportRows=imports(previous.imports);newImportRows=imports(image.imports)
 retainedImports=[row for row in newImportRows if row in oldImportRows]
 addedImports=[row for row in newImportRows if row not in oldImportRows]
 removedImports=[row for row in oldImportRows if row not in newImportRows]
 save(o/'actual-native-import-delta.json',dict(baselineImports=len(previous.imports),actualImports=len(image.imports),retainedSemantics=retainedImports,addedSemantics=addedImports,removedSemantics=removedImports,allNativeImportSemanticsSubsetOfBaseline=not addedImports,noNativeImportsAdded=not addedImports))
 nativeClosure,nativeSources=resolve_added_native_imports(image,addedImports)
 save(o/'added-native-import-primary-closure.json',nativeClosure)
 need([{k:v for k,v in r.items()if k!='at'}for r in image.loads]==[{k:v for k,v in r.items()if k!='at'}for r in previous.loads]and len(image.loads)==4,'all4 actual load semantics unchanged')
 need(set(image.exports)==set(previous.exports)and len(image.exports)==155 and all(image.exports[k]['flags']==previous.exports[k]['flags']for k in previous.exports),'all155 actual public export names and kinds unchanged')
 for row in inherited:exact(row)
 asm=run('disassemble-own-wake-callback',['xcrun','llvm-objdump','--disassemble','--disassemble-symbols=_VM27RunWakeFiredV34','--arch-name=aarch64',str(provider)]).stdout.decode();target=image.exports['_hv_vcpus_exit']['address'];target=int(target,0)if isinstance(target,str)else target;calls=[]
 for line in asm.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(bl|b|b\.[a-z]+)\s+0x([0-9a-f]+)',line)
  if not m:continue
  at=int(m.group(1),16);word=int(m.group(2),16);kind=m.group(3);dest=int(m.group(4),16)
  if kind in('b','bl'):
   displacement=word&0x3ffffff;displacement=displacement-(1<<26)if displacement&(1<<25)else displacement
   need(word&0xfc000000==(0x94000000 if kind=='bl'else 0x14000000),'actual B/BL machine opcode')
  else:
   displacement=(word>>5)&0x7ffff;displacement=displacement-(1<<19)if displacement&(1<<18)else displacement
   need(word&0xff000010==0x54000000,'actual conditional-B machine opcode')
  need(at+(displacement<<2)==dest,'actual decoded callback branch immediate')
  if dest==target:calls.append(dict(callRVA=at,instructionWord=word,targetRVA=dest,instructionKind=kind,disassembly=line.strip()))
 need(len(calls)==1 and not any('_hv_vcpus_exit'==str(v)for r in image.imports for v in r.values()),'exact one same-image hv_vcpus_exit callback branch and no external import')
 binding=dict(ownExportRVA=target,actualDirectBL=calls[0],actualDirectBranch=calls[0],actualInstructionIsBL=calls[0]['instructionKind']=='bl',externalVCPUsExitImportPresent=False,callbackAssembly=pin(o/'disassemble-own-wake-callback.stdout'))
 delta=''
 for left,right in plan.get('sourceDiffPairs',[]):
  left=pathlib.Path(left);right=pathlib.Path(right);need(left.resolve().is_relative_to(R)and right.resolve().is_relative_to(R),'owned actual source diff inputs')
  delta+=''.join(difflib.unified_diff(base.regular_bytes(left).decode().splitlines(True),base.regular_bytes(right).decode().splitlines(True),fromfile=str(left),tofile=str(right)))
 for source in plan.get('addedSourceFiles',[]):
  source=pathlib.Path(source);need(source.resolve().is_relative_to(R)and pin(source)in sources,'added owned source must be in exact source pins')
  delta+=''.join(difflib.unified_diff([],base.regular_bytes(source).decode().splitlines(True),fromfile='/dev/null',tofile=str(source)))
 (o/'source-delta.diff').write_text(delta)
 save(o/'actual-compiler-flag-delta.json',dict(units=compile_changes,actualChangedObjectCount=3,inheritedWholeObjectCount=26,sourceEdits=0,onlyAddedCompilerFlags=list(FLAGS),linkArgumentsUnchangedExceptObjectAndOutputPaths=True))
 result=dict(schema='Actual flags-only O2 Life65 Engine6 Production10 source product V1',provider=pin(provider),baselineCPU=pin(OLD),cpuHotObjectsOptimizationV1Contract=plan['contract'],sourcePlan=planpin,actualSameImageVCPUsExitBinding=binding,sourceFiles=sources,actualChangedObjects=changed,inheritedWholeObjects=inherited,allOther26ObjectsWholeUnchanged=True,allSourcesAndDependenciesWholeUnchanged=True,actualCompilerFlagsDelta=pin(o/'actual-compiler-flag-delta.json'),actualCompilerUnits=compile_changes,actualIOSCompileStrictLinkAndDyldValidatePassed=True,all155ExistingExportNamesAndKindsSame=True,allNativeImportSemanticsSubsetOfBaseline=not addedImports,noNativeImportsAdded=not addedImports,actualImportDelta=pin(o/'actual-native-import-delta.json'),addedNativeImportPrimaryClosure=pin(o/'added-native-import-primary-closure.json'),allAddedNativeImportsResolvedFromActualPrimaryCaptures=True,newNativeImportNames=[row['name']for row in addedImports],actualRemovedNativeImports=removedImports,all4LoadSemanticsSame=True,actualExports=155,actualImports=len(image.imports),actualNativeImports=len(image.imports),actualLoads=4,actualUUID=image.uuid,hvVMConfigCreateActualRVA=image.exports['_hv_vm_config_create']['address'],dupActualRVA=image.exports['_dup']['address'],readableSourceDiff=pin(o/'source-delta.diff'),deviceOperations=0,codeSigned=False)

 need(not(set(result)&set(proofs))and not(set(result)&set(extra))and not(set(proofs)&set(extra)),'source proofs and extra contracts cannot override actual build evidence');result.update(proofs);result.update(extra);save(o/'candidate.json',result)
 depfiles=[]
 for dep in deps:
  depfiles += [pin(x)for x in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split()if pathlib.Path(x).is_file()]
 files=[pin(x)for x in o.iterdir()if x.is_file()]+sources+depfiles+inherited+replaced+compiler_proofs+nativeSources+[row for unit in plan['compilerInputs']for row in [unit['dependencyFile']]+unit['dependencyFiles']]+[pin(__file__),pin(BASE),pin(OLD),pin(OLD.parent/'freeze.json'),old['provider'],planpin]+list(proofs.values())
 for left,right in plan.get('sourceDiffPairs',[]):files += [pin(left),pin(right)]
 files += [pin(source)for source in plan.get('addedSourceFiles',[])]
 rows={r['path']:r for r in files}
 for row in rows.values():need(pin(row['path'])==row,'all current direct frozen input/output pins')
 save(o/'freeze.json',dict(files=list(rows.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=image.uuid,binding=binding)))
if __name__=='__main__':main()
