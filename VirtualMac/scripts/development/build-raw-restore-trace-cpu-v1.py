"""CPU97: bounded diagnostic for existing owned VMM raw trap calls."""
import pathlib,json,hashlib,subprocess,importlib.util,shlex
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'cpu-raw-restore-trace-v97-attempt2'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 O.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
 prior=N/'cpu-gic-state-input-v96-attempt1/candidate.json';old=json.loads(prior.read_bytes());objects=old['changedCPUObjects']+old['inheritedCPUObjects']
 for r in objects:assert pin(r['path'])==r
 original=next(r for r in objects if r['path'].endswith('/modern_cpu_optional_abi_v1.o'))
 recipe=json.loads((pathlib.Path(original['path']).parent/'commands.json').read_bytes());args=next(r['argv'][:]for r in recipe if r['argv'].count(original['path']) and '-c'in r['argv']);obj=O/'raw-trace.o';dep=O/'raw-trace.d';args[args.index('-c')+1]=str(S/'modern_cpu_raw_restore_trace_v1.c');args[args.index('-o')+1]=str(obj)
 if '-MF'in args:args[args.index('-MF')+1]=str(dep)
 else:args+=['-MMD','-MF',str(dep)]
 run('compile-raw-trace',args);asm=O/'raw-pass.o';run('compile-exact-trap',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-c',S/'modern_cpu_raw_restore_trace_v1.S','-o',asm])
 link=next(r['argv'][:]for r in json.loads((prior.parent/'commands.json').read_bytes())if r['label']=='link-cpu');assert link.count(original['path'])==1;link[link.index(original['path'])]=str(obj);link+=[str(asm)];cpu=O/'VM27HVVMProduction.dylib';link[link.index('-o')+1]=str(cpu);run('link-cpu',link);run('validate-cpu',['xcrun','dyld_info','-validate_only',cpu])
 sp=importlib.util.spec_from_file_location('x',pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'));base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base);before=base.image_profile(pathlib.Path(old['cpu']['path']).read_bytes(),'cpu');after=base.image_profile(cpu.read_bytes(),'cpu');assert set(before.exports)==set(after.exports)
 added=sorted({r['name']for r in after.imports}-{r['name']for r in before.imports});assert not added,added
 sources=[pin(S/'modern_cpu_raw_restore_trace_v1.c'),pin(S/'modern_cpu_raw_restore_trace_v1.S')]
 for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  p=pathlib.Path(name).resolve()
  if p.is_relative_to(R):sources.append(pin(p))
 result=dict(schema='CPU97 existing raw-HV pass-through diagnostic; exact GIC/CPU state objects whole',baseline=pin(prior),cpu=pin(cpu),changedCPUObjects=[pin(obj),pin(asm)],inheritedCPUObjects=[r for r in objects if r!=original],sources=sources,comparisons=[dict(provider='VM27HVVMProduction.dylib',actualExports=after.exports,actualImports=after.imports,actualLoads=after.loads,addedImports=[])],deviceOperations=0,actualExportsAndImportsUnchanged=True,actualTrapForwarding='original mov x16,-5; svc80; ret; one call; packet content not read')
 (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
