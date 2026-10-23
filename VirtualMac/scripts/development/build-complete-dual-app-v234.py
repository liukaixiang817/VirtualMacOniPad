#!/usr/bin/env python3
"""Incremental App234: preserve App233 and reconnect its owned SSH listener."""
import copy,hashlib,json,pathlib,shlex,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 previous=N/'complete-dual-actual-app-v233-attempt1/candidate.json';old=json.loads(previous.read_bytes())
 for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+old['appFiles']:assert pin(row['path'])==row,row['path']
 tests=N/'ssh-control-reconnect-local-v1-attempt1/commands.json';assert all(r['exit']==0 for r in json.loads(tests.read_bytes()))
 o=N/'complete-dual-actual-app-v234-attempt2';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(pathlib.Path(old['binary']['path']).parent,app);binary=app/'VirtualMacIndependent27'
 index=29;source=R/'VirtualMac/vz/host/vm27_host_vsock_ssh_owner_v2_reconnect.c';obj=o/(str(index)+'-'+source.stem+'.o');dep=o/'29.d';sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects'])
 commandpath=pathlib.Path(objects[index]['path']).parent/'commands.json'
 if not commandpath.exists():commandpath=commandpath.parent.parent/'commands.json'
 args=copy.deepcopy(next(c['argv'] for c in json.loads(commandpath.read_bytes()) if c['label']=='compile-'+str(index) and c['exit']==0))
 args[args.index(sources[index]['path'])]=str(source);args[args.index(objects[index]['path'])]=str(obj)
 if '-MF' in args:args[args.index('-MF')+1]=str(dep)
 else:args+=['-MMD','-MF',str(dep)]
 commands=[]
 def run(label,args):
  p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
 run('compile-29',args)
 link=copy.deepcopy(next(c['argv'] for c in old['commands'] if c['label']=='link-app' and not c['exit']));link[link.index(objects[index]['path'])]=str(obj);link[link.index(old['binary']['path'])]=str(binary)
 run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
 sources[index]=pin(source);objects[index]=pin(obj);includes={r['path']:r for r in old['actualIncludeClosure']}
 for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  path=pathlib.Path(name).resolve()
  if str(path).startswith(str(R)+'/'):includes[str(path)]=pin(path)
 d=copy.deepcopy(old);d.update(schema='App234 own SSH control reconnect preserving App233 complete backend graph and real lock pause',builder=pin(__file__),inheritedCompiledAppCandidate=pin(previous),sourceFiles=sources,objects=objects,actualIncludeClosure=list(includes.values()),binary=pin(binary),appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],commands=commands,actualChangedAppObjectIndices=[29],actualUnchangedCompiledObjects=len(objects)-1,actualNewAppCompilations=1,reconnectSocketTests=pin(tests),realDefaultLockPauseHumanAccepted=True,realManualResumeVerifiedNativeState=True,realSSHReconnectDeviceAcceptancePending=True)
 (o/'candidate.json').write_text(json.dumps(d,indent=2)+'\n');(o/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in o.rglob('*') if p.is_file()]+[pin(__file__),*sources,*objects,*includes.values()],deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),binary=pin(binary),compilations=1)))
if __name__=='__main__':main()
