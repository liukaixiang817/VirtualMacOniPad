"""Freeze and compare host-only public callback lifetime models.

The before source is the immutable prior repaired product, never an Apple image.
ASan probes intentionally fail there; the VM callback deadlock has a one-second
external deadline. All children are reaped. No native or device calls execute.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys

sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
H=R/'VirtualMac/vz/host'
BASE=N/'kernel-context-profiles-boundary-product-v2'
BASE_MANIFEST_SHA='5a19835ec06d39bae3216c797652515a8543b049b00ba7ec8a2ba6d00d044645'

def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())

def main():
    assert sys.flags.optimize==0
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
    manifest=BASE/'candidate.json';assert pin(manifest)['sha256']==BASE_MANIFEST_SHA
    baseline=json.loads(manifest.read_text())
    for row in baseline['sourceSnapshots']:
        assert pin(Path(row['path']))==row
    historical=baseline['historicalModelReceipt'];assert pin(Path(historical['path']))==historical
    legacy=json.loads(Path(historical['path']).read_text())
    legacy_models=[r for r in legacy['sourceFreeze'] if Path(r['path']).name in
                   {'lifecycle_mock_tests.c','initialization-tests.c','system-tests.c','system-golden.inc'}]
    assert len(legacy_models)==4
    for row in legacy_models:
        assert pin(R/row['path'])['sha256']==row['sha256']
    out=args.output.resolve();assert out.is_relative_to(N);out.mkdir(mode=0o700,exist_ok=False)
    (out/'runner-snapshot.py').write_bytes(Path(__file__).read_bytes())
    model=R/'VirtualMac/scripts/tests/test-modern-cpu-callback-lifetime-v3.c'
    old_model=R/'VirtualMac/scripts/tests/test-modern-cpu-initialization-boundary-v2.c'
    commands=[];legacy_results=[]
    def run(label,argv,timeout=30,expected=0,asan=False):
        env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        if asan:env['ASAN_OPTIONS']='detect_leaks=0:abort_on_error=0:exitcode=87'
        p=subprocess.Popen(list(map(str,argv)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        timed_out=False
        try:stdout,stderr=p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True;p.kill();stdout,stderr=p.communicate()
        (out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),exit=p.returncode,
                             directChildPID=p.pid,reaped=True,deadlineSeconds=timeout,timedOut=timed_out))
        if expected=='timeout':assert timed_out and b'VM destroy callback entered' in stdout
        else:
            assert not timed_out and p.returncode==expected,(label,p.returncode,stderr.decode(errors='replace'))
            if expected==87:assert b'AddressSanitizer: heap-use-after-free' in stderr and b'REENTRY destroy=0 free=0' in stdout
            else:assert not stderr,(label,stderr.decode(errors='replace'))
        return stdout
    sdk=run('macos-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip()
    inputs=[pin(model),pin(old_model),pin(Path(__file__))]
    inputs += [pin(R/row['path']) for row in legacy_models]
    names=[Path(row['path']).name for row in baseline['sourceSnapshots'] if Path(row['path']).name!=old_model.name]
    for variant in ('before','after'):
        source=out/variant;source.mkdir(mode=0o700)
        for name in names:
            p=BASE/'source'/name if variant=='before' else H/name
            (source/name).write_bytes(p.read_bytes());inputs.append(pin(p))
        for p in (model,old_model):(source/p.name).write_bytes(p.read_bytes())
        compiled=[source/name for name in ('modern_cpu_kernel_lifecycle_v2.c','modern_cpu_native_fields.c','modern_cpu_kernel_initialization_v2.c','modern_cpu_kernel_system_v2.c')]
        def compile_model(label,test,sanitized,isa=None):
            exe=out/label
            argv=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-pthread','-isysroot',sdk,'-I',source,source/test,*compiled,'-o',exe]
            if sanitized:argv+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            if isa is not None:argv+=['-DVM27_MODEL_NATIVE_ISA='+str(isa)]
            run(label+'-compile',argv);return exe
        if variant=='before':
            exe=compile_model('before-probe',model.name,True)
            for probe in ('init','sys','thread','destroy','version','create'):
                run('before-'+probe,[exe,'--probe',probe],expected=87,asan=True)
            run('before-vm-deadlock',[exe,'--probe','vm'],timeout=1,expected='timeout',asan=True)
        else:
            for sanitized in (False,True):
                label='after-model-sanitized' if sanitized else 'after-model'
                exe=compile_model(label,model.name,sanitized);run(label+'-run',[exe],asan=sanitized)
                label='existing-boundary-sanitized' if sanitized else 'existing-boundary'
                exe=compile_model(label,old_model.name,sanitized);run(label+'-run',[exe],asan=sanitized)
            for row in legacy_models:
                p=R/row['path'];(source/p.name).write_bytes(p.read_bytes())
            for isa in (1,2):
                for sanitized in (False,True):
                    for name in ('lifecycle_mock_tests.c','initialization-tests.c','system-tests.c'):
                        label='existing-'+Path(name).stem+'-isa'+str(isa)+('-sanitized' if sanitized else '')
                        exe=compile_model(label,name,sanitized,isa)
                        result=json.loads(run(label+'-run',[exe],asan=sanitized))
                        assert result.get('failed',0)==0 and result.get('result','PASS')=='PASS'
                        legacy_results.append(dict(model=name,nativeISA=isa,sanitized=sanitized,result=result))
    for row in inputs:assert pin(Path(row['path']))==row
    result=dict(schema='public-callback-lifetime-model-v3',baselineManifest=pin(manifest),sourceInputs=inputs,
                beforeASanUAFProbes=['initialization-Version','SYS-Version','currentThread','nativeDestroy','publicVersion','createPublication'],
                beforeVMNativeDestroyCallbackDeadlocked=True,beforeVMDeadlineSeconds=1,
                afterScenarios=48,afterOrdinaryAndASanPassed=True,existingBoundaryScenarios=222,
                existingBoundaryOrdinaryAndASanPassed=True,commands=commands,
                existingTypedProfileResults=legacy_results,
                nativeOperations=0,deviceOperations=0,AppleImageExecuted=False,syntheticContextOnly=True)
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]),indent=2)+'\n')
    print(json.dumps(dict(verification=pin(out/'verification.json'),freeze=pin(out/'freeze.json'),beforeUAFProbes=6,afterScenarios=48)))

if __name__=='__main__':main()
