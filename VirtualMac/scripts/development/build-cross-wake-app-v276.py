"""Relink the shipped Beta5 App with only Runtime176's manifest anchor changed."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'complete-dual-actual-app-v276-attempt1'

def pin(path):
    path=Path(path).resolve();data=path.read_bytes()
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def main():
    prior=N/'complete-dual-actual-app-v275-attempt1/candidate.json'
    old=json.loads(prior.read_bytes())
    runtime_path=N/'independent27-signed-runtime-cross-wake-v176-attempt1/candidate.json'
    runtime=json.loads(runtime_path.read_bytes())
    for record in old['sourceFiles']+old['objects']+old['actualIncludeClosure']:
        assert pin(record['path'])==record,record['path']
    release=N/'release-2.0.0beta5-candidate-v3'
    resources=release/'stage/var/jb/Applications/VirtualMacIndependent27.app'
    assert pin(resources/'VirtualMacIndependent27')['sha256']=='a5599a99956bc5cf7748c6c8dd9e71d33ab1a0adbd8c7220b654f2b89cde7525'
    O.mkdir(mode=0o700);app=O/'VirtualMacIndependent27.app';shutil.copytree(resources,app)
    root=release/'network-source-and-relink-v5'
    sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    argv=[v.replace('@ROOT@',str(root)).replace('@SDK@',sdk).replace('@APP@',str(app))
          for v in json.loads((root/'link-argv.json').read_bytes())]
    previous_anchor=str(root/'objects/34.o');assert argv.count(previous_anchor)==1
    assert pin(previous_anchor)['sha256']==old['objects'][34]['sha256']
    assert pin(runtime['anchorIOSObject']['path'])==runtime['anchorIOSObject']
    argv[argv.index(previous_anchor)]=runtime['anchorIOSObject']['path']
    commands=[]
    def run(label,args):
        p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode))
        (O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
    run('link-app',argv);run('validate-app',['xcrun','dyld_info','-validate_only',str(app/'VirtualMacIndependent27')])
    result=copy.deepcopy(old)
    result['sourceFiles'][34]=runtime['anchorSource'];result['objects'][34]=runtime['anchorIOSObject']
    result.update(schema='App276 development: shipped Beta5 App and network with Runtime176 anchor',
        builder=pin(__file__),inheritedCompiledAppCandidate=pin(prior),binary=pin(app/'VirtualMacIndependent27'),
        appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],commands=commands,
        actualRuntimeCandidate=pin(runtime_path),actualChangedAppObjectIndices=[34],
        actualUnchangedCompiledObjects=len(old['objects'])-1,actualNewAppCompilations=0,
        actualMainSourceChanged=False,codeSigned=False,deviceOperations=0,trustCacheOperations=0,
        shippedLinkRecipe=pin(root/'link-argv.json'))
    (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(O/'candidate.json')))

if __name__=='__main__':main()
