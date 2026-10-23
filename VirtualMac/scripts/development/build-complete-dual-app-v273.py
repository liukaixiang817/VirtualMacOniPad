"""App273: persistent Hibernate background save, relaunch and library controls."""
import copy,json,pathlib,shlex,shutil,subprocess,hashlib
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    prior=N/'complete-dual-actual-app-v272-attempt1/candidate.json';old=json.loads(prior.read_bytes())
    signed=json.loads((N/'complete-dual-signed-app-v272-attempt1/candidate.json').read_bytes())
    for r in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+signed['appFiles']:assert pin(r['path'])==r,r['path']
    o=N/'complete-dual-actual-app-v273-attempt2';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(signed['app'],app);binary=app/'VirtualMacIndependent27'
    sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);includes={r['path']:r for r in old['actualIncludeClosure']};commands=[]
    def run(label,args):
        p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert not p.returncode,p.stderr.decode()
    changes={0:'VirtualMacApp_complete_dual_v85_background_hibernate.m',14:'VZVMLibraryViewController_v10_hibernate.m'}
    link=next(r['argv'][:]for r in old['commands']if r['label']=='link-app' and not r['exit'])
    for i,name in changes.items():
        source=R/'VirtualMac/vz/host/portable_app_v1/host'/name;obj=o/(str(i)+'-'+source.stem+'.o');dep=o/(str(i)+'.d')
        args=next(r['argv'][:]for r in json.loads((pathlib.Path(objects[i]['path']).parent/'commands.json').read_bytes())if r['label']=='compile-'+str(i) and not r['exit'])
        args[args.index(sources[i]['path'])]=str(source);args[args.index(objects[i]['path'])]=str(obj);args[args.index('-MF')+1]=str(dep)
        run('compile-'+str(i),args)
        for path in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
            p=pathlib.Path(path).resolve()
            if p.is_relative_to(R):includes[str(p)]=pin(p)
        link[link.index(objects[i]['path'])]=str(obj);sources[i]=pin(source);objects[i]=pin(obj)
    link[link.index('-o')+1]=str(binary);run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
    resources=[]
    for lang in ['en','zh_CN']:
        source=R/'VirtualMac/resources/Localizations'/(lang+'.lproj')/'Localizable.strings'
        target=app/(lang+'.lproj')/'Localizable.strings';assert target.is_file();shutil.copyfile(source,target);resources.append(pin(source))
    result=copy.deepcopy(old);result.update(schema='App273 persistent Hibernate background save, directory flush, relaunch and library controls; execution acceptance pending',builder=pin(__file__),inheritedCompiledAppCandidate=pin(prior),sourceFiles=sources,objects=objects,actualIncludeClosure=list(includes.values()),binary=pin(binary),appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],commands=commands,changedLocalizationSources=resources,actualChangedAppObjectIndices=[0,14],actualUnchangedCompiledObjects=len(objects)-2,actualNewAppCompilations=2,actualOnlyMainObjectChanged=False,actualMainSourceChanged=True,codeSigned=False,deviceOperations=0,trustCacheOperations=0)
    (o/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(o/'candidate.json')))
if __name__=='__main__':main()
