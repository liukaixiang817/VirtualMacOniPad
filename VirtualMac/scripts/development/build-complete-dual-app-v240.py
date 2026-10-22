#!/usr/bin/env python3
"""Incremental App240: accept only the same canonical genuine framework image for either complete backend."""
import copy,hashlib,json,pathlib,shlex,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 previous=N/'complete-dual-actual-app-v239-attempt1/candidate.json';old=json.loads(previous.read_bytes())
 for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+old['appFiles']:assert pin(row['path'])==row,row['path']
 tests=N/'ssh-control-reconnect-local-v1-attempt1/commands.json';assert all(r['exit']==0 for r in json.loads(tests.read_bytes()))
 o=N/'complete-dual-actual-app-v240-attempt1';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(pathlib.Path(old['binary']['path']).parent,app);binary=app/'VirtualMacIndependent27'
 sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);commands=[];includes={r['path']:r for r in old['actualIncludeClosure']}
 link=copy.deepcopy(next(c['argv'] for c in old['commands'] if c['label']=='link-app' and not c['exit']))
 def run(label,args):
  p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
 for index,name in [(28,'vm27_genuine_vz_ssh_bridge_v4_canonical_image.m')]:
  source=R/'VirtualMac/vz/host'/name;obj=o/(str(index)+'-'+source.stem+'.o');dep=o/(str(index)+'.d')
  commandpath=pathlib.Path(objects[index]['path']).parent/'commands.json'
  if not commandpath.exists():commandpath=commandpath.parent.parent/'commands.json'
  args=copy.deepcopy(next(c['argv'] for c in json.loads(commandpath.read_bytes()) if c['label']=='compile-'+str(index) and c['exit']==0))
  args[args.index(sources[index]['path'])]=str(source);args[args.index(objects[index]['path'])]=str(obj)
  if '-MF' in args:args[args.index('-MF')+1]=str(dep)
  else:args+=['-MMD','-MF',str(dep)]
  run('compile-'+str(index),args)
  link[link.index(objects[index]['path'])]=str(obj)
  sources[index]=pin(source);objects[index]=pin(obj)
  for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
   path=pathlib.Path(name).resolve()
   if str(path).startswith(str(R)+'/'):includes[str(path)]=pin(path)
 link[link.index(old['binary']['path'])]=str(binary)
 run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
 d=copy.deepcopy(old);d.update(schema='App240 resolves actual and expected VZ image aliases to the same existing canonical image; App239 native Resume SSH refresh retained',builder=pin(__file__),inheritedCompiledAppCandidate=pin(previous),sourceFiles=sources,objects=objects,actualIncludeClosure=list(includes.values()),binary=pin(binary),appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],commands=commands,actualChangedAppObjectIndices=[28],actualUnchangedCompiledObjects=len(objects)-1,actualNewAppCompilations=1,reconnectSocketTests=pin(tests),realDefaultLockPauseHumanAccepted=True,realManualResumeVerifiedNativeState=True,realSSHReconnectDeviceAcceptancePending=True)
 (o/'candidate.json').write_text(json.dumps(d,indent=2)+'\n');(o/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in o.rglob('*') if p.is_file()]+[pin(__file__),*sources,*objects,*includes.values()],deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),binary=pin(binary),compilations=1)))
if __name__=='__main__':main()
