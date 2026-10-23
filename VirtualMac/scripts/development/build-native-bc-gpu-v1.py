#!/usr/bin/env python3
"""Build the independent GPU task BC frontend, preserving native GPU22 code."""
import json,plistlib,subprocess,importlib.util,shutil,tempfile,shlex
from pathlib import Path
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host';B=R/'VirtualMac/scripts/development';O=N/'native-bc-gpu-v23-attempt1'
spec=importlib.util.spec_from_file_location('gpu_primitives',B/'build-independent27-signed-runtime-product-v10.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);pin=base.pin

def main():
 O.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));base.save(O/'commands.json',commands);assert p.returncode==0,p.stderr.decode()
 oldpath=N/'independent27-signed-runtime-native-gpu-caps-v160-attempt1/candidate.json';old=json.loads(oldpath.read_text());m=plistlib.loads(Path(old['manifest']['path']).read_bytes());rows={x['id']:x for x in m['files']};original=Path(old['runtimeRoot']);runtime=O/'runtime'
 for row in rows.values():
  if row['role']=='gpu-task':
   assert pin(original/row['path'])['sha256']==row['sha256'];base.copy_regular(original/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 recipe=json.loads((N/'owned-gpu-task-linear-pitch-source-port-v20-attempt1/commands.json').read_text());compile=next(x['argv'] for x in recipe if x['label']=='compile-2');oldobj=compile[compile.index('-o')+1];objs=[]
 for filename in ['vm27_owned_gpu_task_metal_v16.m','native_bc_texture_support.m','vm27_owned_native_bc_v1.m']:
  cmd=compile[:];cmd[cmd.index('-target')+1]='arm64e-apple-ios15.0';cmd[cmd.index('-c')+1]=str(S/filename);obj=O/(filename+'.o');cmd[cmd.index('-o')+1]=str(obj)
  if filename!='vm27_owned_gpu_task_metal_v16.m':cmd+=['-fvisibility=hidden']
  run('compile-'+filename,cmd);objs.append(obj)
 compat=runtime/rows['gpu-task:compat']['path'];cmd=next(x['argv'][:] for x in recipe if x['label']=='link-compat');cmd[cmd.index('-target')+1]='arm64e-apple-ios15.0';cmd[cmd.index(oldobj):cmd.index(oldobj)+1]=list(map(str,objs));cmd[cmd.index('-o')+1]=str(compat);run('link',cmd)
 for entry in recipe:
  if entry['label'].startswith('compat-path-'):
   cmd=entry['argv'][:];cmd[-1]=str(compat);run(entry['label'],cmd)
 run('validate-compat',['xcrun','dyld_info','-validate_only',compat])
 task=runtime/rows['gpu-task:main']['path'];xpc=task.parent.parent.parent
 proof=json.loads(Path(old['signatureVerification']['path']).read_text());proofs={x['relativePath']:x for x in proof['actualSignedFiles']};ent=O/'gpu.entitlements.plist';ent.write_bytes(plistlib.dumps(proofs[rows['gpu-task:main']['path']]['embeddedEntitlements']))
 with tempfile.TemporaryDirectory(prefix='vm27-bc-sign-',dir='/private/tmp') as t:
  bundle=Path(t)/xpc.name;shutil.copytree(xpc,bundle);run('xattrs',['xattr','-cr',bundle]);bc=bundle/compat.relative_to(xpc)
  run('sign-compat',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.gputask.compat',bc])
  run('sign-task',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','com.apple.gpusw.ParavirtualizedGraphicsGPUTask','--entitlements',ent,'--generate-entitlement-der',bundle]);run('verify-task',['codesign','--verify','--strict',bundle])
  for key in ['gpu-task:main','gpu-task:compat','gpu-task-coderesources']:
   p=runtime/rows[key]['path'];shutil.copyfile(bundle/p.relative_to(xpc),p)
 a=base.image_profile(task.read_bytes(),'gpu');b=base.image_profile((original/rows['gpu-task:main']['path']).read_bytes(),'gpu');assert a.uuid==b.uuid and a.imports==b.imports and a.loads==b.loads and a.exports==b.exports
 for sec in b.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):assert a.data[at:at+z]==b.data[at:at+z]
 gp=base.signature(task.read_bytes(),a.uuid,{1:(runtime/rows['gpu-task-info']['path']).read_bytes(),3:(runtime/rows['gpu-task-coderesources']['path']).read_bytes()});assert gp['embeddedEntitlements']==proofs[rows['gpu-task:main']['path']]['embeddedEntitlements']
 oldprofile=Path(old['generatedGPUParentProfile']['path']);text=oldprofile.read_text();assert rows['gpu-task:main']['sha256'] in text and rows['gpu-task:main']['cdhash'] in text
 profile=O/'vm27_owned_gpu_task_parent_generated_v3.h';profile.write_text(text.replace(rows['gpu-task:main']['sha256'],pin(task)['sha256']).replace(rows['gpu-task:main']['cdhash'],gp['cdhash']))
 mdrecipe=json.loads((N/'portable-gpu-parent-v1-attempt1/commands.json').read_text());cmd=next(x['argv'][:] for x in mdrecipe if x['label']=='compile');oldmdobj=cmd[cmd.index('-o')+1];obj=O/'MD.o';dep=O/'MD.d';cmd=[x.replace(str(oldprofile),str(profile)) for x in cmd];cmd[cmd.index('-o')+1]=str(obj);cmd[cmd.index('-MF')+1]=str(dep);run('compile-md',cmd)
 md=O/'MD';cmd=next(x['argv'][:] for x in mdrecipe if x['label']=='link');cmd=[str(obj) if x==oldmdobj else x for x in cmd];cmd[cmd.index('-o')+1]=str(md);run('link-md',cmd);cmd=next(x['argv'][:] for x in mdrecipe if x['label']=='normalize');cmd[-1]=str(md);run('normalize-md',cmd);run('validate-md',['xcrun','dyld_info','-validate_only',md])
 comparisons=[]
 for ident,p in [('gpu-task:compat',compat),('child:MD',md)]:
  new=base.image_profile(p.read_bytes(),ident);previous=base.image_profile((original/rows[ident]['path']).read_bytes(),ident);assert set(new.exports)==set(previous.exports)
  imports={(x['name'],x['weak']) for x in new.imports};before={(x['name'],x['weak']) for x in previous.imports};delta=imports-before
  # All BC additions use existing Foundation/Objective-C, dyld and LibSystem APIs.
  comparisons.append(dict(provider=ident,actualExports=new.exports,actualImports=new.imports,actualLoads=new.loads,addedImports=sorted(delta)))
 sources=[pin(S/f) for f in ['vm27_owned_gpu_task_metal_v16.m','vm27_owned_native_bc_v1.m','native_bc_texture_support.m','native_bc_texture_support.h']]
 for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  p=Path(name).resolve()
  if p.is_relative_to(R):sources.append(pin(p))
 result=dict(schema='Independent GPU23 native BC frontend and AGX records, native task code whole',baseline=pin(oldpath),md=pin(md),generatedProfile=pin(profile),sources=sources,comparisons=comparisons,replacements={k:pin(runtime/rows[k]['path']) for k in ['gpu-task:main','gpu-task:compat','gpu-task-coderesources']},actualGPUCDHash=gp['cdhash'],nativeTaskCodeWhole=True,deviceOperations=0)
 base.save(O/'candidate.json',result);print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
