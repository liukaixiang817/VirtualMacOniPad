#!/usr/bin/env python3
"""Compile the new MRC App source and four real SSH units; no product anchor."""
import argparse, hashlib, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
    o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir();(o/'objects').mkdir()
    c=json.loads(a.source_candidate.read_bytes());src=pathlib.Path(c['source']['path'])
    assert pin(src)==c['source'] and c['trueSSHRegistrationAfterRuntimeBindBeforeStart']
    assert c['sshCleanupJoinsBeforeExistingInputDisplayAndVMRelease'] and not c['guestSSHAvailable']
    units=[src]+[pathlib.Path(f['path']) for f in c['newSSHBuildUnits']]
    assert [pin(f) for f in units[1:]]==c['newSSHBuildUnits']
    commands=[];closure={};objects=[]
    def run(label,args):
        cp=subprocess.run(list(map(str,args)),capture_output=True,timeout=90)
        (o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
        commands.append(dict(label=label,argv=list(map(str,args)),exit=cp.returncode))
        save(o/'commands.json',commands)
        assert cp.returncode==0,(label,cp.stderr.decode(errors='replace'));return cp
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
    base=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',S]
    for i,f in enumerate(units):
        flags=base+(['-fobjc-arc','-Wall','-Wextra','-Werror'] if i==1 else
            ['-std=c11','-Wall','-Wextra','-Werror'] if f.suffix=='.c' else [])
        obj=o/'objects'/(str(i)+'-'+f.stem+'.o')
        run('compile-'+str(i),flags+['-c',f,'-o',obj]);objects.append(obj)
        deps=run('deps-'+str(i),flags+['-MM',f]).stdout.decode().replace('\\\n',' ')
        for item in shlex.split(deps.split(':',1)[1]):
            q=pathlib.Path(item).resolve()
            if q.is_file():closure[str(q)]=pin(q)
    run('app-ir',base+['-S','-emit-llvm',src,'-o',o/'App10.actual.ios.ll'])
    # The linked SSH aggregate validates its real imports independently of the
    # still-unavailable final signed Runtime8 App anchor.
    aggregate=o/'VM27GenuineVZSSHBridgeV1.component.ios.dylib'
    run('link-ssh',base+['-dynamiclib']+objects[1:]+['-framework','Foundation',
        '-Wl,-undefined,error','-Wl,-no_adhoc_codesign',
        '-Wl,-install_name,@rpath/VM27GenuineVZSSHBridgeV1.component.ios.dylib','-o',aggregate])
    run('validate-ssh',['xcrun','dyld_info','-validate_only',aggregate])
    run('imports-ssh',['xcrun','dyld_info','-imports',aggregate])
    run('exports-ssh',['xcrun','dyld_info','-exports',aggregate])
    run('app-undefined',['xcrun','nm','-u',objects[0]])
    ir=(o/'App10.actual.ios.ll').read_text()
    assert '@VM27CreateGenuineVZSSHBridgeV1' in ir and 'copySnapshot:' in ir
    assert 'closeWithCompletion:' in ir and 'guest SSH unverified' in ir
    assert pin(src)==c['source'] and [pin(f)for f in units[1:]]==c['newSSHBuildUnits']
    record=dict(schema='App10 actual iOS component compile and real SSH strong link',
        sourceCandidate=pin(a.source_candidate),builder=pin(pathlib.Path(__file__)),
        sourceFiles=[pin(f)for f in units],actualIncludeClosure=list(closure.values()),
        objects=[pin(f)for f in objects],actualAppIR=pin(o/'App10.actual.ios.ll'),
        unsignedSSHAggregate=pin(aggregate),commands=commands,
        actualMRCAppCompiled=True,actualARCBridgeCompiled=True,actualIOSArm64eCompiled=True,
        trueSSHAggregateStrongLinkedAndValidated=True,finalAppStrongLinked=False,
        actualRuntime8AnchorRequiredForFinalLink=True,codeSigned=False,
        applicationPackaged=False,actualVMExecuted=False,actualVZCallbackExecuted=False,
        guestHelperInstalled=False,guestSSHVerified=False,deviceOperations=0,
        inheritedHostSocketModelsNotRepeated=True)
    save(o/'candidate.json',record)
    files=list(closure.keys())+[str(a.source_candidate.resolve()),str(pathlib.Path(__file__).resolve())]
    files += [str(f) for f in o.rglob('*')if f.is_file()]
    save(o/'freeze.json',dict(schema='App10 component exact source/include/output pins',
        files=[pin(pathlib.Path(f))for f in sorted(set(files))]))
    print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),objects=len(objects))))
if __name__=='__main__':main()
