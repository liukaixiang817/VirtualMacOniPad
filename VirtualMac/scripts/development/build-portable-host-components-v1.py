#!/usr/bin/env python3
"""Compile the multi-device 20B101 admission change without changing native ABI."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import struct
import subprocess

R=Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'portable-host-components-v1-attempt2'

def pin(p):
    p=Path(p).resolve(); data=p.read_bytes()
    return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def main():
    O.mkdir(mode=0o700)
    commands=[]; dependencies={}
    def run(label,args):
        args=list(map(str,args)); p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout)
        (O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode))
        (O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode: raise RuntimeError(label+': '+p.stderr.decode())
        return p
    def old_command(folder,label):
        return next(c['argv'][:] for c in json.loads((N/folder/'commands.json').read_text()) if c['label']==label and c['exit']==0)
    baseline=N/'cpu-exit-detail-snapshot-source-local-v91-attempt1/candidate.json'
    old=json.loads(baseline.read_text())
    objects=old['actualChangedObjects']+old['inheritedWholeObjects']
    for row in objects: assert pin(row['path'])==row
    replacements={}
    jobs=[('cpu-counter-fresh-source-local-v1-attempt1','ios-CounterReader22','modern_cpu_counter_domain_reader_v22.c'),
          ('cpu-mobile-capability-admission-source-v3-attempt3','ios-modern_cpu_config_capability_acquisition_v3','modern_cpu_config_capability_acquisition_v3.c'),
          ('cpu-exit-snapshot-source-local-v90-attempt1','ios-Production22ExitSnapshot','modern_cpu_production_native_ops_v22_exit_snapshot.c')]
    for index,(folder,label,name) in enumerate(jobs):
        argv=old_command(folder,label); prior=argv[argv.index('-o')+1]
        source=S/'portable_host_v1'/name; obj=O/(Path(name).stem+'.o'); dep=O/(str(index)+'.d')
        argv[argv.index('-c')+1]=str(source);argv[argv.index('-o')+1]=str(obj)
        if '-MF' in argv: argv[argv.index('-MF')+1]=str(dep)
        else: argv+=['-MMD','-MF',str(dep)]
        run(label,argv);replacements[prior]=str(obj)
        for item in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
            p=Path(item).resolve()
            if p.is_relative_to(R): dependencies[str(p)]=pin(p)
    cpu=O/'VM27HVVMProduction.dylib'
    argv=old_command(baseline.parent.name,'link-whole-guest-msgbuf')
    argv=[replacements.get(x,x) for x in argv];argv[argv.index('-o')+1]=str(cpu)
    run('link-cpu',argv);run('validate-cpu',['xcrun','dyld_info','-validate_only',cpu])
    ipa=O/'VM27IPALimit.dylib'
    argv=json.loads((N/'hv-ipa-native-provider-contract-v1/ios-compile.process.json').read_text())['argv']
    argv=[str(S/'portable_host_v1'/Path(x).name) if Path(x).name=='modern_vz_hypervisor_ipa_native_v1.c' else x for x in argv]
    argv+=['-I',str(S)];argv[argv.index('-o')+1]=str(ipa)
    run('link-ipa',argv)
    # Bind the existing provenance check to this new linker UUID; no instruction changes.
    data=bytearray(ipa.read_bytes()); at=32; uuid=None
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,at)
        if cmd==0x1b: uuid=bytes(data[at+8:at+24])
        at+=size
    marker=bytes.fromhex('565a4950415555494431a5276c8e1133')
    assert uuid and data.count(marker)==1
    pos=data.index(marker);data[pos:pos+16]=uuid;ipa.write_bytes(data)
    run('validate-ipa',['xcrun','dyld_info','-validate_only',ipa])
    module=R/'VirtualMac/scripts/development/build-independent27-signed-runtime-product-v10.py'
    spec=importlib.util.spec_from_file_location('host_profile_image_reader',module)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    runtime=json.loads((N/'independent27-signed-runtime-display-refresh-v155-attempt1/candidate.json').read_text())
    comparisons=[]
    for binary in (cpu,ipa):
        a=base.image_profile(binary.read_bytes(),binary.name)
        b=base.image_profile((Path(runtime['runtimeRoot'])/'parent-flat'/binary.name).read_bytes(),binary.name)
        assert set(a.exports)==set(b.exports)
        assert all(a.exports[k]['flags']==b.exports[k]['flags'] for k in a.exports)
        semantics=lambda rows:[{k:v for k,v in r.items() if k not in ('at','index')} for r in rows]
        assert semantics(a.loads)==semantics(b.loads)
        added=[x for x in a.imports if x['name'] not in {y['name'] for y in b.imports}]
        assert all(x['name'] in ('_getpagesize','_strlen') and not x['weak'] for x in added),added
        comparisons.append(dict(provider=binary.name,exports=len(a.exports),addedImports=added,
            originalLoadSemanticsPreserved=True,actualExports=a.exports,actualImports=a.imports,actualLoads=a.loads))
    test=O/'target-policy-test'
    run('compile-target-policy',['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror',S/'test-vm-host-target-policy-v1.c','-o',test])
    run('run-target-policy',[test])
    app=json.loads((N/'complete-dual-actual-app-v242-attempt1/candidate.json').read_text())
    obj=Path(app['objects'][32]['path']); folder=obj.parent
    if not (folder/'commands.json').exists(): folder=folder.parent
    argv=old_command(folder.name,'compile-32')
    argv[argv.index('-c')+1]=str(S/'portable_host_v1/vm27_independent_app_runtime_v5.m')
    argv[argv.index('-o')+1]=str(O/'app-runtime.o')
    if '-MF' in argv: argv[argv.index('-MF')+1]=str(O/'app-runtime.d')
    run('compile-app-runtime',argv)
    for p in (S/'portable_host_v1').iterdir(): dependencies[str(p.resolve())]=pin(p)
    for name in ('vm_host_target_policy_v1.h','vm_host_profile_read_v1.h','test-vm-host-target-policy-v1.c'):
        dependencies[str((S/name).resolve())]=pin(S/name)
    result=dict(schema='Portable host family admission v1; native 20B101 ABI only',
        baselineCPU=pin(baseline),cpu=pin(cpu),ipa=pin(ipa),appRuntimeObject=pin(O/'app-runtime.o'),
        changedCPUObjects=[pin(x) for x in replacements.values()],
        inheritedCPUObjects=[x for x in objects if x['path'] not in replacements],
        sources=list(dependencies.values()),comparisons=comparisons,
        compiledForIOS=True,localPolicyTestPassed=True,deviceOperations=0,
        newDeviceGuestBootVerified=False,OS15SupportImplemented=False,
        OS162To1631SupportImplemented=False)
    (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(O/'candidate.json'),cpu=pin(cpu),ipa=pin(ipa))))

if __name__=='__main__':main()
