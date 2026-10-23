#!/usr/bin/env python3
"""GIC17: replace one object in the actual portable CPU provider."""
import json,importlib.util,subprocess,shlex
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';O=N/'cpu-gic-single-pass-v92-attempt1'
spec=importlib.util.spec_from_file_location('cpu_primitives',B/'build-independent27-signed-runtime-product-v10.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);pin=base.pin

def main():
 O.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));base.save(O/'commands.json',commands);assert p.returncode==0,p.stderr.decode();return p
 # Differential coverage plus actual concurrent owner and deadline fixtures.
 for name in ['test-modern-gic-single-pass-v17.c','test-modern-gic-icc-local-generations-v16.c','test-modern-gic-timer-generations-v16.c']:
  source=S/name
  if name.endswith('v16.c'):
   text=source.read_text();assert text.count('modern_gic_v3_engine_v16_local_icc_generations.c')==1
   source=O/name;source.write_text(text.replace('modern_gic_v3_engine_v16_local_icc_generations.c','modern_gic_v3_engine_v17_single_pass.c'))
  exe=O/(Path(name).stem+'-test');run('compile-'+name,['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread','-I',S,source,'-o',exe]);run('run-'+name,[exe])
 oldpath=N/'portable-host-components-v2-attempt1/candidate.json';old=json.loads(oldpath.read_text());objects=old['changedCPUObjects']+old['inheritedCPUObjects'];assert len(objects)==29
 for row in objects:assert pin(row['path'])==row
 recipe=json.loads((N/'cpu-gic-local-generations-source-local-v89-attempt1/commands.json').read_text());cmd=next(x['argv'][:] for x in recipe if x['label']=='ios-GIC16LocalGenerations');oldobj=cmd[cmd.index('-o')+1];obj=O/'modern_gic_v3_engine_v17_single_pass.o';dep=O/'GIC17.d';cmd[cmd.index('-c')+1]=str(S/'modern_gic_v3_engine_v17_single_pass.c');cmd[cmd.index('-o')+1]=str(obj);cmd[cmd.index('-MF')+1]=str(dep);cmd=[x.replace('-miphoneos-version-min=16.1','-miphoneos-version-min=15.0') for x in cmd];run('compile-gic17',cmd)
 recipe=json.loads((oldpath.parent/'commands.json').read_text());cmd=next(x['argv'][:] for x in recipe if x['label']=='link-cpu');assert cmd.count(oldobj)==1;cmd[cmd.index(oldobj)]=str(obj);cpu=O/'VM27HVVMProduction.dylib';cmd[cmd.index('-o')+1]=str(cpu);cmd=[x.replace('-miphoneos-version-min=16.1','-miphoneos-version-min=15.0') for x in cmd];run('link-cpu',cmd);run('validate-cpu',['xcrun','dyld_info','-validate_only',cpu])
 a=base.image_profile(cpu.read_bytes(),'cpu');b=base.image_profile(Path(old['cpu']['path']).read_bytes(),'cpu');assert set(a.exports)==set(b.exports);assert all(a.exports[k]['flags']==b.exports[k]['flags'] for k in a.exports)
 semantics=lambda rows:[{k:v for k,v in x.items() if k not in('at','index')} for x in rows]
 assert semantics(a.loads)==semantics(b.loads);assert sorted((x['name'],x['weak']) for x in a.imports)==sorted((x['name'],x['weak']) for x in b.imports)
 sources=[]
 for text in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  p=Path(text).resolve()
  if p.is_relative_to(R):sources.append(pin(p))
 comparison=dict(provider='VM27HVVMProduction.dylib',actualExports=a.exports,actualImports=a.imports,actualLoads=a.loads,addedImports=[])
 result=dict(schema='Actual CPU92 portable provider with one GIC17 single-pass arbitration object',baseline=pin(oldpath),cpu=pin(cpu),changedCPUObjects=[pin(obj)],inheritedCPUObjects=[x for x in objects if x['path']!=oldobj],sources=sources,comparisons=[comparison],actualExportsAndImportsUnchanged=True,localDifferentialQueries=240000,concurrentOwnerAndTimerTestsPassed=True,deviceOperations=0)
 assert len(result['inheritedCPUObjects'])==28;base.save(O/'candidate.json',result);base.save(O/'freeze.json',dict(files=[pin(p) for p in O.rglob('*') if p.is_file()]+[pin(__file__),pin(oldpath),*sources],deviceOperations=0));print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
