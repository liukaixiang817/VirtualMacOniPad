#!/usr/bin/env python3
"""Recompile the GPU parent profile for the actual newly signed iOS15 GPU task."""
import json,hashlib,plistlib,subprocess,shlex,importlib.util
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'portable-gpu-parent-v1-attempt1'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 O.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
 prior=N/'independent27-signed-runtime-portable-host-v157-attempt1/candidate.json';r=json.loads(prior.read_text());m=plistlib.loads(Path(r['manifest']['path']).read_bytes());rows={x['id']:x for x in m['files']};g=rows['gpu-task:main'];runtime=Path(r['runtimeRoot']);assert pin(runtime/g['path'])['sha256']==g['sha256']
 old=Path(r['linearPitchParentProfile']['path']);text=old.read_text();text=text.replace('89f8cb59fcfc0f5624133c6fe90b276486c2801cdb361855c3006ad5113cb143',g['sha256']).replace('38f5488dee00dbab805eb878de49bd090b1a8ea1',g['cdhash']);assert g['sha256'] in text and g['cdhash'] in text
 profile=O/'vm27_owned_gpu_task_parent_generated_v2.h';profile.write_text(text);obj=O/'MD.o';binary=O/'MD';dep=O/'MD.d'
 recipe=json.loads((N/'owned-pg-display-refresh-source-v2-attempt1/commands.json').read_text());compile=next(x['argv'][:] for x in recipe if x['label']=='compile');oldobj=compile[compile.index('-o')+1]
 compile=[x.replace('-miphoneos-version-min=16.1','-miphoneos-version-min=15.0').replace(str(old),str(profile)) for x in compile];compile[compile.index('-o')+1]=str(obj);compile[compile.index('-MF')+1]=str(dep);run('compile',compile)
 link=next(x['argv'][:] for x in recipe if x['label']=='link');link=[str(obj) if x==oldobj else x.replace('-miphoneos-version-min=16.1','-miphoneos-version-min=15.0') for x in link];link[link.index('-o')+1]=str(binary);run('link',link)
 norm=next(x['argv'][:] for x in recipe if x['label']=='normalize-owned-loads');norm[-1]=str(binary);run('normalize',norm);run('validate',['xcrun','dyld_info','-validate_only',binary])
 sp=importlib.util.spec_from_file_location('mdreader',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'));base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base);a=base.image_profile(binary.read_bytes(),'MD');b=base.image_profile((runtime/rows['child:MD']['path']).read_bytes(),'MD');assert set(a.exports)==set(b.exports);assert {(r['name'],r['weak']) for r in a.imports}=={(r['name'],r['weak']) for r in b.imports}
 sources=[]
 for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  p=Path(name).resolve()
  if p.is_relative_to(R):sources.append(pin(p))
 result=dict(schema='Actual signed GPU task profile refresh',baseline=pin(prior),md=pin(binary),sources=sources,generatedProfile=pin(profile),actualGPUHash=g['sha256'],actualGPUCDHash=g['cdhash'],comparisons=[dict(provider='child:MD',actualExports=a.exports,actualImports=a.imports,actualLoads=a.loads,codeIdentityChecksPreserved=True)],deviceOperations=0)
 (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
