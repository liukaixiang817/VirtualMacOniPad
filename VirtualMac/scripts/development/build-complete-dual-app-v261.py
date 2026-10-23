"""App261: inspect real native Hibernate configuration without changing VM state."""
import copy,json,pathlib,shlex,shutil,subprocess,hashlib
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    prior=N/'complete-dual-actual-app-v260-attempt1/candidate.json';old=json.loads(prior.read_bytes())
    signed=json.loads((N/'complete-dual-signed-app-v260-attempt1/candidate.json').read_bytes())
    for r in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+signed['appFiles']:assert pin(r['path'])==r,r['path']
    o=N/'complete-dual-actual-app-v261-attempt1';o.mkdir(mode=0o700)
    app=o/'VirtualMacIndependent27.app';shutil.copytree(signed['app'],app);binary=app/'VirtualMacIndependent27'
    source=R/'VirtualMac/vz/host/portable_app_v1/host/VirtualMacApp_complete_dual_v75_hibernate_admission.m'
    sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);includes={r['path']:r for r in old['actualIncludeClosure']}
    obj=o/'0-VirtualMacApp_complete_dual_v75_hibernate_admission.o';dep=o/'0.d'
    recipe=pathlib.Path(objects[0]['path']).parent/'commands.json'
    args=next(r['argv'][:] for r in json.loads(recipe.read_bytes()) if r['label']=='compile-0' and not r['exit'])
    args[args.index(sources[0]['path'])]=str(source);args[args.index(objects[0]['path'])]=str(obj)
    args[args.index('-MF')+1]=str(dep)
    commands=[]
    def run(label,args):
        p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        assert not p.returncode,p.stderr.decode()
    run('compile-0',args)
    for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
        p=pathlib.Path(name).resolve()
        if p.is_relative_to(R):includes[str(p)]=pin(p)
    args=next(r['argv'][:] for r in old['commands'] if r['label']=='link-app' and not r['exit'])
    args[args.index(objects[0]['path'])]=str(obj);args[args.index('-o')+1]=str(binary)
    sources[0]=pin(source);objects[0]=pin(obj)
    run('link-app',args);run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
    result=copy.deepcopy(old);result.update(schema='App261 actual Hibernate native configuration admission; no save claimed',builder=pin(__file__),
        inheritedCompiledAppCandidate=pin(prior),sourceFiles=sources,objects=objects,actualIncludeClosure=list(includes.values()),
        binary=pin(binary),appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],commands=commands,
        actualChangedAppObjectIndices=[0],actualUnchangedCompiledObjects=len(objects)-1,actualNewAppCompilations=1,
        actualOnlyMainObjectChanged=True,actualMainSourceChanged=True,codeSigned=False,deviceOperations=0,trustCacheOperations=0)
    (o/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(pin(o/'candidate.json')))
if __name__=='__main__':main()
