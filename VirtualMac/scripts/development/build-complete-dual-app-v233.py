#!/usr/bin/env python3
"""Build whole13/whole27 selector and native lock pause; no device mutation."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import shlex
import shutil
import subprocess

R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'

def pin(path):
    path=pathlib.Path(path).resolve();data=path.read_bytes()
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def exact(row):
    assert pin(row['path'])==row,row['path']

def main():
    previous=N/'independent27-actual-app-lock-pause-v228-attempt1/candidate.json'
    signedpath=N/'independent27-signed-app-lock-pause-v228-attempt1/candidate.json'
    old=json.loads(previous.read_bytes());signed=json.loads(signedpath.read_bytes())
    for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+signed['appFiles']:exact(row)
    full13=N/'complete13-owned-runtime-release-v2-attempt1'
    host=full13/'host/VZHostCompat.dylib'
    assert pin(host)['sha256']=='685496d826ade98aae68ec794c2597e670f87a57690f8f8635b17d4399c1860a'
    out=N/'complete-dual-actual-app-v233-attempt1';out.mkdir(mode=0o700)
    app=out/'VirtualMacIndependent27.app';shutil.copytree(signed['app'],app)
    shutil.copyfile(host,app/'VZHostCompat.dylib')
    binary=app/'VirtualMacIndependent27'
    sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects'])
    commands=[];dependencies=[]
    def run(label,args):
        args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=90)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=args,exit=result.returncode))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        assert result.returncode==0,result.stderr.decode()
    def original_compile(index):
        path=pathlib.Path(old['objects'][index]['path']).parent/'commands.json'
        if not path.exists():path=path.parent.parent/'commands.json'
        return copy.deepcopy(next(c['argv'] for c in json.loads(path.read_bytes()) if c['label']=='compile-'+str(index) and c['exit']==0))
    link=copy.deepcopy(next(c['argv'] for c in old['commands'] if c['label']=='link-app' and c['exit']==0))
    changed=[(0,S/'VirtualMacApp_complete_dual_v63.m'),(1,S/'VZBackendSelection_complete_dual_v5.m'),
             (12,S/'VZSettingsViewController_v4_complete_dual.m'),(14,S/'VZVMLibraryViewController_v6_owned_dual.m')]
    for index,source in changed:
        obj=out/(str(index)+'-'+source.stem+'.o');dep=out/(str(index)+'.d');dependencies.append(dep)
        args=original_compile(index)
        args[args.index(old['sourceFiles'][index]['path'])]=str(source)
        args[args.index(old['objects'][index]['path'])]=str(obj)
        if '-MF' in args:args[args.index('-MF')+1]=str(dep)
        else:args+=['-MMD','-MF',str(dep)]
        run('compile-'+str(index),args)
        link[link.index(objects[index]['path'])]=str(obj)
        sources[index]=pin(source);objects[index]=pin(obj)
    for source in [S/'vm13_owned_runtime_v1.m',full13/'vm13_runtime_anchor_v1.c']:
        index=len(sources);obj=out/(str(index)+'-'+source.stem+'.o');dep=out/(str(index)+'.d');dependencies.append(dep)
        args=original_compile(1)
        args[args.index(old['sourceFiles'][1]['path'])]=str(source)
        args[args.index(old['objects'][1]['path'])]=str(obj)
        args+=['-MMD','-MF',str(dep)]
        run('compile-'+str(index),args);sources.append(pin(source));objects.append(pin(obj))
        link.insert(link.index('-o'),str(obj))
    link[link.index(old['binary']['path'])]=str(binary)
    run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',binary])
    spec=importlib.util.spec_from_file_location('dual_app_macho',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py')
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    before=reader.MachO(pathlib.Path(old['binary']['path']).read_bytes());after=reader.MachO(binary.read_bytes())
    assert before.loads==after.loads
    newimports={r['name'] for r in after.imports if not r['weak']}-{r['name'] for r in before.imports if not r['weak']}
    assert newimports<={'_readlinkat','_CC_SHA256_Init','_CC_SHA256_Update','_CC_SHA256_Final','_mkdtemp'},newimports
    includes={row['path']:row for row in old['actualIncludeClosure']}
    for dep in dependencies:
        for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
            path=pathlib.Path(name).resolve()
            if str(path).startswith(str(R)+'/'):includes[str(path)]=pin(path)
    localization=json.loads((S/'CompleteDual_localization_v2.json').read_bytes())
    for lang in ['en','zh_CN','zh_TW']:
        path=app/(lang+'.lproj/Localizable.strings');raw=path.read_bytes();value=plistlib.loads(raw)
        for key,translations in localization.items():value[key]=translations[lang]
        path.write_bytes(plistlib.dumps(value,fmt=plistlib.FMT_BINARY if raw.startswith(b'bplist') else plistlib.FMT_XML,sort_keys=False))
        run('validate-localization-'+lang,['plutil','-lint',path])
    for lang,translation in [('zh_CN','zh_CN'),('zh_TW','zh_TW'),('zh_HK','zh_TW')]:
        path=app/(lang+'.lproj/Backend.strings');raw=path.read_bytes();value=plistlib.loads(subprocess.check_output(['plutil','-convert','xml1','-o','-',str(path)]))
        for key,translations in localization.items():value[key]=translations[translation]
        path.write_bytes(plistlib.dumps(value,fmt=plistlib.FMT_BINARY if raw.startswith(b'bplist') else plistlib.FMT_XML,sort_keys=False))
        run('validate-backend-localization-'+lang,['plutil','-lint',path])
    result=copy.deepcopy(old)
    result.update(schema='App233 owned complete13 or independent27 whole graph; native lock pause both backends',
        builder=pin(__file__),inheritedCompiledAppCandidate=pin(previous),sourceFiles=sources,objects=objects,
        binary=pin(binary),appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],
        actualIncludeClosure=list(includes.values()),commands=commands,
        actualChangedAppObjectIndices=[0,1,12,14,39,40],actualUnchangedCompiledObjects=35,
        actualNewAppCompilations=6,actualMainSourceChanged=True,actualNewStrongImports=sorted(newimports),
        complete13SourceCandidate=pin(full13/'candidate.json'),whole13HostHook=pin(host),
        completeBackendChoices=['13.2.1','27'],complete13DeviceAcceptancePending=True,
        realLockUnlockAcceptancePending=True,applicationBinaryLinked=True,applicationPackaged=True,
        codeSigned=False,deviceOperations=0,trustCacheOperations=0)
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]+[pin(__file__),pin(S/'CompleteDual_localization_v2.json'),pin(previous),pin(signedpath),pin(host),*sources,*objects,*includes.values()]
    (out/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),compilations=6,newStrongImports=sorted(newimports),deviceAcceptancePending=True)))

if __name__=='__main__':main()
