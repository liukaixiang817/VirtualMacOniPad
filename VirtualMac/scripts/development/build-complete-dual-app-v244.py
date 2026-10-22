#!/usr/bin/env python3
"""Recompile App244 for iOS15, add scoped crash export and portable Runtime157."""
import copy,hashlib,json,pathlib,plistlib,shlex,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 previous=N/'complete-dual-actual-app-v243-attempt2/candidate.json';old=json.loads(previous.read_bytes())
 for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+old['appFiles']:assert pin(row['path'])==row,row['path']
 o=N/'complete-dual-actual-app-v244-attempt3';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(pathlib.Path(old['binary']['path']).parent,app);binary=app/'VirtualMacIndependent27'
 sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);commands=[];includes={}
 link=copy.deepcopy(next(c['argv'] for c in old['commands'] if c['label']=='link-app' and not c['exit']))
 def run(label,args):
  args=[str(x).replace('arm64e-apple-ios16.1','arm64e-apple-ios15.0').replace('arm64e-apple-ios16.0','arm64e-apple-ios15.0').replace('-miphoneos-version-min=16.1','-miphoneos-version-min=15.0') for x in args]
  p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
 changes={0:S/'VirtualMacApp_complete_dual_v69_portable.m',4:S/'VZDiagnostics_v2_portable.m',32:S/'portable_host_v2/vm27_independent_app_runtime_v5.m',34:N/'independent27-signed-runtime-portable-host-v157-attempt1/vm27_independent_runtime_product_anchor_v1.c'}
 changes.update({int(k):pathlib.Path(v) for k,v in json.loads((S/'portable_app_v1/source-map.json').read_text()).items()})
 for index,row in enumerate(sources):
  source=changes.get(index,pathlib.Path(row['path']));obj=o/(str(index)+'-'+source.stem+'.o');dep=o/(str(index)+'.d')
  if index==35:
   args=json.loads((N/'native-network-upstream-v1/compile-network-v2.json').read_text())['argv']
  else:
   cp=pathlib.Path(objects[index]['path']).parent/'commands.json'
   if not cp.exists():cp=cp.parent.parent/'commands.json'
   args=copy.deepcopy(next(c['argv'] for c in json.loads(cp.read_bytes()) if row['path'] in c.get('argv',[]) and '-c' in c['argv'] and not c['exit']))
  args[args.index('-c')+1]=str(source);args[args.index('-o')+1]=str(obj)
  if '-MF' in args:args[args.index('-MF')+1]=str(dep)
  else:args+=['-MMD','-MF',str(dep)]
  args+=['-I',str(S/'portable_app_v1/host'),'-Werror=unguarded-availability-new']
  run('compile-'+str(index),args);link[link.index(objects[index]['path'])]=str(obj);sources[index]=pin(source);objects[index]=pin(obj)
  for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
   path=pathlib.Path(name).resolve()
   if str(path).startswith(str(R)+'/'):includes[str(path)]=pin(path)
 link[link.index(old['binary']['path'])]=str(binary);run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
 info=app/'Info.plist';p=plistlib.loads(info.read_bytes());p['MinimumOSVersion']='15.0';info.write_bytes(plistlib.dumps(p,sort_keys=False))
 d=copy.deepcopy(old);d.update(schema='App244 Beta4 experimental portable hosts and scoped diagnostics',builder=pin(__file__),inheritedCompiledAppCandidate=pin(previous),sourceFiles=sources,objects=objects,actualIncludeClosure=list(includes.values()),binary=pin(binary),appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],commands=commands,actualChangedAppObjectIndices=list(range(len(objects))),actualUnchangedCompiledObjects=0,actualNewAppCompilations=len(objects),experimentalHostAdmission=True,crashReportsScopedToOwnedProcesses=True,minimumOS='15.0',crossOSRuntimeAcceptancePending=True,cursorWakeSourcePreserved=True)
 (o/'candidate.json').write_text(json.dumps(d,indent=2)+'\n');(o/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in o.rglob('*') if p.is_file()]+[pin(__file__),*sources,*objects,*includes.values()],deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),binary=pin(binary),compilations=len(objects))))
if __name__=='__main__':main()
