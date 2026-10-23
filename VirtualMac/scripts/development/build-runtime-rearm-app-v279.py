"""Retain shipped Beta5 link graph and network; replace main, loader and anchor."""
import copy,json,hashlib,shlex,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'complete-dual-actual-app-v279-attempt1'
def pin(p):
 p=Path(p).resolve();d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def main():
 prior=N/'complete-dual-actual-app-v276-attempt1/candidate.json';old=json.loads(prior.read_bytes());rtp=N/'independent27-signed-runtime-rearm-v179-attempt1/candidate.json';rt=json.loads(rtp.read_bytes())
 for record in old['sourceFiles']+old['objects']+old['actualIncludeClosure']:assert pin(record['path'])==record,record['path']
 release=N/'release-2.0.0beta5-candidate-v3';resources=release/'stage/var/jb/Applications/VirtualMacIndependent27.app';root=release/'network-source-and-relink-v5'
 O.mkdir(mode=0o700);app=O/'VirtualMacIndependent27.app';shutil.copytree(resources,app)
 sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
 link=[v.replace('@ROOT@',str(root)).replace('@SDK@',sdk).replace('@APP@',str(app)) for v in json.loads((root/'link-argv.json').read_bytes())]
 sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);includes={x['path']:x for x in old['actualIncludeClosure']};commands=[]
 def run(label,args):
  p=subprocess.run(args,capture_output=True,timeout=90);(O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
 for i,source in {0:S/'portable_app_v1/host/VirtualMacApp_complete_dual_v89_runtime_rearm.m',32:S/'portable_host_v2/vm27_independent_app_runtime_v6_rearm.m'}.items():
  obj=O/(str(i)+'-'+source.stem+'.o');dep=O/(str(i)+'.d')
  recipe=next(x['argv'][:] for x in json.loads((Path(old['objects'][i]['path']).parent/'commands.json').read_bytes()) if x['label']=='compile-'+str(i) and not x['exit'])
  recipe[recipe.index(old['sourceFiles'][i]['path'])]=str(source);recipe[recipe.index(old['objects'][i]['path'])]=str(obj);recipe[recipe.index('-MF')+1]=str(dep)
  run('compile-'+str(i),recipe)
  for value in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
   path=Path(value).resolve()
   if path.is_relative_to(R):includes[str(path)]=pin(path)
  previous=str(root/'objects'/(str(i)+'.o'));assert previous in link;link[link.index(previous)]=str(obj);sources[i]=pin(source);objects[i]=pin(obj)
 link[link.index(str(root/'objects/34.o'))]=rt['anchorIOSObject']['path'];sources[34]=rt['anchorSource'];objects[34]=rt['anchorIOSObject']
 run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',str(app/'VirtualMacIndependent27')])
 result=copy.deepcopy(old);result.update(schema='App279 safe stopped-guest unbind and dead bootstrap rearm; device acceptance pending',builder=pin(__file__),inheritedCompiledAppCandidate=pin(prior),sourceFiles=sources,objects=objects,actualIncludeClosure=list(includes.values()),binary=pin(app/'VirtualMacIndependent27'),appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],commands=commands,actualRuntimeCandidate=pin(rtp),actualChangedAppObjectIndices=[0,32,34],actualUnchangedCompiledObjects=len(objects)-3,actualNewAppCompilations=2,actualMainSourceChanged=True,codeSigned=False,deviceOperations=0,trustCacheOperations=0)
 (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
