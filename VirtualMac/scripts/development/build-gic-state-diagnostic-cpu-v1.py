"""CPU95: genuine pointer-free software GIC state export and import."""
import pathlib,json,hashlib,subprocess,shlex
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'cpu-gic-state-diagnostic-v95-attempt1'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 O.mkdir(mode=0o700,exist_ok=True);commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
 prior=N/'cpu-gic-wake-subset-v93-attempt1/candidate.json';old=json.loads(prior.read_bytes());objects=old['changedCPUObjects']+old['inheritedCPUObjects']
 for row in objects:assert pin(row['path'])==row
 run('compile-state-test',['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread','-I',S,S/'test-modern-gic-state-v1.c','-o',O/'test-state'])
 run('test-state',[O/'test-state'])
 recipe=json.loads((prior.parent/'commands.json').read_bytes())
 factoryRecipe=json.loads((N/'cpu-production-observation-source-local-v88-attempt2/commands.json').read_bytes())
 bootRecipe=json.loads((N/'cpu-caller-frame-source-local-v70-attempt1/commands.json').read_bytes())
 gic=next(x['argv'][:]for x in recipe if x['label']=='compile-gic18')
 boot=next(x['argv'][:]for x in bootRecipe if x['label']=='ios-Bootstrap29')
 factory=next(x['argv'][:]for x in factoryRecipe if x['label']=='ios-Factory16OwnedMapping')
 factoryPrior=pathlib.Path(factory[factory.index('-c')+1]);factorySource=O/'Factory.gic-state.c';factorySource.write_text(factoryPrior.read_text()+'\n'+(S/'modern_cpu_factory_gic_state_v1.inc').read_text().replace('bool','_Bool').replace('true','1').replace('false','0').replace('NULL','((void*)0)'))
 changes=[('gic19',gic,S/'modern_gic_v3_engine_v19_state.c'),('bootstrap30',boot,S/'vm27_hv_public_vm_bootstrap_v31_state_diagnostic.m'),('factory-state',factory,factorySource)]
 replacements={};sources={str(factoryPrior):pin(factoryPrior)}
 for label,args,source in changes:
  oldobj=args[args.index('-o')+1];obj=O/(label+'.o');dep=O/(label+'.d');args[args.index('-c')+1]=str(source);args[args.index('-o')+1]=str(obj);args[args.index('-MF')+1]=str(dep);run('compile-'+label,args);replacements[oldobj]=str(obj)
  for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
   p=pathlib.Path(name).resolve()
   if p.is_relative_to(R):sources[str(p)]=pin(p)
 link=next(x['argv'][:]for x in recipe if x['label']=='link-cpu');cpu=O/'VM27HVVMProduction.dylib'
 for a,b in replacements.items():assert link.count(a)==1;link[link.index(a)]=b
 link[link.index('-o')+1]=str(cpu);run('link-cpu',link);run('validate-cpu',['xcrun','dyld_info','-validate_only',cpu])
 import importlib.util
 spec=importlib.util.spec_from_file_location('primitives',pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'));base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
 before=base.image_profile(pathlib.Path(old['cpu']['path']).read_bytes(),'cpu');after=base.image_profile(cpu.read_bytes(),'cpu')
 assert set(before.exports)==set(after.exports)
 assert sorted((x['name'],x['weak'])for x in before.imports)==sorted((x['name'],x['weak'])for x in after.imports)
 result=dict(schema='CPU95 actual versioned GIC capture/import, no native CPU or interrupt fabrication',baseline=pin(prior),cpu=pin(cpu),changedCPUObjects=[pin(p)for p in replacements.values()],inheritedCPUObjects=[x for x in objects if x['path']not in replacements],sources=list(sources.values()),comparisons=[dict(provider='VM27HVVMProduction.dylib',actualExports=after.exports,actualImports=after.imports,actualLoads=after.loads,addedImports=[])],deviceOperations=0,actualExportsAndImportsUnchanged=True,localGICStateRoundTripPassed=True)
 (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
