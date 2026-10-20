#!/usr/bin/env python3
"""HOST-only one-object Life61 bounded guest msgbuf read build; never signs or runs iOS code.

The source owner supplies the frozen source plan and actual semantic contracts.
This builder inherits the exact successful Factory12 CPU29 link and compiler arguments;28 objects remain whole.
It supplies no activation evidence; Root decides whether the actual Factory11 result warrants execution.
"""
import argparse,difflib,hashlib,importlib.util,json,pathlib,re,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('borrowed_host_input_primitives',BASE)
base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
OLD=N/'cpu-guest-msgbuf-source-local-v5-attempt1/candidate.json'
OLD_SHA='bfb99b38b5af683ff298d8ce1b626ab9a2b9cefa9b1ed659c95d25fb0d3bd7e4'
UNITS=(('ios-Life64',N/'cpu-guest-msgbuf-source-local-v5-attempt1/commands.json','ios-Life63','modern_cpu_kernel_lifecycle_v64.c','modern_cpu_kernel_lifecycle_v64.o','modern_cpu_kernel_lifecycle_v63.o'),)

def need(v,w):
 if not v:raise ValueError(w)
def pin(p):
 p=pathlib.Path(p).resolve();raw=base.regular_bytes(p);return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def exact(row):
 p=pathlib.Path(row['path']);need(p.resolve().is_relative_to(R) and pin(p)==row,'exact owned source/object/proof '+str(p));return p

def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source-plan',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh own actual source build output')
 planpath=a.source_plan.resolve();need(planpath.is_relative_to(R),'owned source plan');plan=json.loads(base.regular_bytes(planpath));planpin=pin(planpath)
 need(plan['contractKey']=='cpuGuestMsgbufReadV1Contract' and isinstance(plan['contract'],dict),'actual source-owner published-GIC serialization contract')
 need(plan['baselineCPU']==pin(OLD),'actual current Factory12 source baseline plan binding')
 sources=plan['sourceFiles'];need(sources and len({r['path']for r in sources})==len(sources),'unique actual source files')
 for row in sources:exact(row)
 need(all(str(S/unit[3])in{r['path']for r in sources}for unit in UNITS),'actual one changed compiler unit is pinned')
 proofs=plan.get('proofs',{});extra=plan.get('additionalContracts',{})
 for row in proofs.values():exact(row)
 need(all(k.endswith('Contract')and isinstance(v,dict)for k,v in extra.items()),'only named source-owner additional contracts')
 need(pin(OLD)['sha256']==OLD_SHA,'actual successful Factory11 CPU source baseline');old=json.loads(base.regular_bytes(OLD));exact(old['provider'])
 for row in old['sourceFiles']+old['actualChangedObjects']+old['inheritedWholeObjects']:exact(row)
 prior=json.loads(base.regular_bytes(OLD.parent/'commands.json'));previous_link=list(next(c['argv']for c in prior if c['label']=='link-whole-guest-msgbuf'))
 oldobjects=[pin(x)for x in previous_link if x.endswith('.o')];need(len(oldobjects)==29,'actual29 baseline linked objects')
 old_by_name={pathlib.Path(r['path']).name:r for r in oldobjects};need(len(old_by_name)==29,'unique actual baseline object names')
 replaced=[old_by_name[unit[5]]for unit in UNITS];inherited=[r for r in oldobjects if r not in replaced]
 need(len(replaced)==1 and len(inherited)==28 and any(pathlib.Path(r['path']).name=='modern_cpu_native_public_factory_startup_failure_v12.o'for r in inherited),'actual Life61-only substitution and28 whole including Factory12/Engine6/Bootstrap28/Production8/Mandatory4')
 o.mkdir(mode=0o700);commands=[];deps=[];changed=[];compiler_proofs=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);so=o/(label+'.stdout');se=o/(label+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr)
  commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se)));save(o/'commands.json',commands)
  need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-3500:]);return p

 for label,commandpath,oldlabel,source_name,object_name,old_object_name in UNITS:
  compiler_proofs.append(pin(commandpath));records=json.loads(base.regular_bytes(commandpath));record=next(c for c in records if c['label']==oldlabel);need(record['exit']==0,'actual successful prior compiler template')
  argv=list(record['argv']);source=S/source_name;obj=o/object_name;dep=o/(pathlib.Path(object_name).stem+'.d')
  argv[argv.index('-c')+1]=str(source);argv[argv.index('-o')+1]=str(obj)
  if '-MF'in argv:argv[argv.index('-MF')+1]=str(dep)
  else:argv+=['-MMD','-MF',str(dep)]
  run(label,argv);changed.append(pin(obj));deps.append(dep)
 provider=o/'VM27HVVMProductionGuestMsgbufReadV6.unsigned.dylib';replacements={r['path']:changed[i]['path']for i,r in enumerate(replaced)}
 link=[replacements.get(arg,arg)for arg in previous_link];need(all(previous_link.count(r['path'])==1 for r in replaced),'exact one whole-object link substitution')
 link[link.index('-o')+1]=str(provider);link=[arg.replace('@rpath/'+pathlib.Path(old['provider']['path']).name,'@rpath/'+provider.name)for arg in link]
 run('link-whole-guest-msgbuf',link);run('validate-whole-gic-vm-serialized-actions',['xcrun','dyld_info','-validate_only',str(provider)])
 image=base.image_profile(base.regular_bytes(provider),'VM27HVVMProduction.dylib');previous=base.image_profile(base.regular_bytes(old['provider']['path']),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in r.items()if k not in('at','index')}for r in rows],key=lambda r:json.dumps(r,sort_keys=True))
 need(imports(image.imports)==imports(previous.imports)and len(image.imports)==94 and len(previous.imports)==94,'all94 actual native imports including existing cond_wait unchanged')
 need([{k:v for k,v in r.items()if k!='at'}for r in image.loads]==[{k:v for k,v in r.items()if k!='at'}for r in previous.loads]and len(image.loads)==4,'all4 actual load semantics unchanged')
 need(set(image.exports)==set(previous.exports)and len(image.exports)==155 and all(image.exports[k]['flags']==previous.exports[k]['flags']for k in previous.exports),'all155 actual public export names and kinds unchanged')
 for row in inherited:exact(row)
 asm=run('disassemble-own-wake-callback',['xcrun','llvm-objdump','--disassemble','--disassemble-symbols=_VM27RunWakeFiredV34','--arch-name=aarch64',str(provider)]).stdout.decode();target=image.exports['_hv_vcpus_exit']['address'];target=int(target,0)if isinstance(target,str)else target;calls=[]
 for line in asm.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+bl\s+0x([0-9a-f]+)',line)
  if m:
   at,word,dest=(int(v,16)for v in m.groups());delta=word&0x3ffffff;delta=delta-(1<<26)if delta&(1<<25)else delta;need(word>>26==0x25 and at+(delta<<2)==dest,'actual callback BL immediate')
   if dest==target:calls.append(dict(callRVA=at,instructionWord=word,targetRVA=dest,disassembly=line.strip()))
 need(len(calls)==1 and not any('_hv_vcpus_exit'==str(v)for r in image.imports for v in r.values()),'exact one own hv_vcpus_exit direct callback and no external import')
 binding=dict(ownExportRVA=target,actualDirectBL=calls[0],externalVCPUsExitImportPresent=False,callbackAssembly=pin(o/'disassemble-own-wake-callback.stdout'))
 delta=''
 for left,right in plan.get('sourceDiffPairs',[]):
  left=pathlib.Path(left);right=pathlib.Path(right);need(left.resolve().is_relative_to(R)and right.resolve().is_relative_to(R),'owned actual source diff inputs')
  delta+=''.join(difflib.unified_diff(base.regular_bytes(left).decode().splitlines(True),base.regular_bytes(right).decode().splitlines(True),fromfile=str(left),tofile=str(right)))
 for source in plan.get('addedSourceFiles',[]):
  source=pathlib.Path(source);need(source.resolve().is_relative_to(R)and pin(source)in sources,'added owned source must be in exact source pins')
  delta+=''.join(difflib.unified_diff([],base.regular_bytes(source).decode().splitlines(True),fromfile='/dev/null',tofile=str(source)))
 (o/'source-delta.diff').write_text(delta)
 result=dict(schema='Actual Life61 bounded one-shot guest msgbuf source product V1',provider=pin(provider),baselineCPU=pin(OLD),cpuGuestMsgbufReadV1Contract=plan['contract'],sourcePlan=planpin,actualSameImageVCPUsExitBinding=binding,sourceFiles=sources,actualChangedObjects=changed,inheritedWholeObjects=inherited,allOther28ObjectsWholeUnchanged=True,actualIOSCompileStrictLinkAndDyldValidatePassed=True,all155ExistingExportNamesAndKindsSame=True,all94NativeImportSemanticsSame=True,all4LoadSemanticsSame=True,actualExports=155,actualNativeImports=94,actualLoads=4,actualUUID=image.uuid,hvVMConfigCreateActualRVA=image.exports['_hv_vm_config_create']['address'],dupActualRVA=image.exports['_dup']['address'],readableSourceDiff=pin(o/'source-delta.diff'),deviceOperations=0,codeSigned=False)
 need(not(set(result)&set(proofs))and not(set(result)&set(extra))and not(set(proofs)&set(extra)),'source proofs and extra contracts cannot override actual build evidence');result.update(proofs);result.update(extra);save(o/'candidate.json',result)
 depfiles=[]
 for dep in deps:
  depfiles += [pin(x)for x in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split()if pathlib.Path(x).is_file()]
 files=[pin(x)for x in o.iterdir()if x.is_file()]+sources+depfiles+inherited+replaced+compiler_proofs+[pin(__file__),pin(BASE),pin(OLD),pin(OLD.parent/'freeze.json'),old['provider'],planpin]+list(proofs.values())
 for left,right in plan.get('sourceDiffPairs',[]):files += [pin(left),pin(right)]
 files += [pin(source)for source in plan.get('addedSourceFiles',[])]
 rows={r['path']:r for r in files}
 for row in rows.values():need(pin(row['path'])==row,'all current direct frozen input/output pins')
 save(o/'freeze.json',dict(files=list(rows.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=image.uuid,binding=binding)))
if __name__=='__main__':main()
