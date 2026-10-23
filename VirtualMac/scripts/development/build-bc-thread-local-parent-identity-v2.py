#!/usr/bin/env python3
"""Compile the GPU24 parent using its actual signed child identity."""
import importlib.util
import json
import plistlib
import shlex
import subprocess
from pathlib import Path

R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B=Path(__file__).resolve().parent
O=N/'native-bc-gpu-parent-v25-attempt1'
spec=importlib.util.spec_from_file_location('runtime_primitives',B/'build-independent27-signed-runtime-product-v10.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
pin=base.pin

def main():
    O.mkdir(mode=0o700);commands=[]
    def run(label,argv):
        argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode));base.save(O/'commands.json',commands)
        assert not p.returncode,p.stderr.decode()
    oldpath=N/'independent27-signed-runtime-bc-thread-local-v164-attempt1/candidate.json'
    old=json.loads(oldpath.read_bytes());root=Path(old['runtimeRoot'])
    manifest=plistlib.loads(Path(old['manifest']['path']).read_bytes());rows={r['id']:r for r in manifest['files']}
    gpu=rows['gpu-task:main'];assert pin(root/gpu['path'])['sha256']==gpu['sha256']
    text=Path(old['generatedGPUParentProfile']['path']).read_text()
    assert gpu['sha256'] in text and gpu['cdhash'] in text
    profile=O/'vm27_owned_gpu_task_parent_generated_v4.h';profile.write_text(text)
    recipe=json.loads((N/'portable-gpu-parent-v1-attempt1/commands.json').read_bytes())
    argv=next(r['argv'][:] for r in recipe if r['label']=='compile')
    oldobj=argv[argv.index('-o')+1];obj=O/'MD.o';dep=O/'MD.d'
    macro=[i for i,s in enumerate(argv) if s.startswith('-DVM27_OWNED_GPU_PARENT_PROFILE_HEADER=')]
    assert len(macro)==1
    argv[macro[0]]='-DVM27_OWNED_GPU_PARENT_PROFILE_HEADER="'+str(profile)+'"'
    argv[argv.index('-o')+1]=str(obj);argv[argv.index('-MF')+1]=str(dep)
    run('compile-md',argv)
    includes=[Path(s).resolve() for s in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1])]
    assert profile in includes
    assert not any(p.name.startswith('vm27_owned_gpu_task_parent_generated_') and p!=profile for p in includes)
    md=O/'MD';argv=next(r['argv'][:] for r in recipe if r['label']=='link')
    argv=[str(obj) if s==oldobj else s for s in argv];argv[argv.index('-o')+1]=str(md)
    run('link-md',argv)
    argv=next(r['argv'][:] for r in recipe if r['label']=='normalize');argv[-1]=str(md);run('normalize-md',argv)
    run('validate-md',['xcrun','dyld_info','-validate_only',md])
    data=md.read_bytes()
    assert data.count(gpu['sha256'].encode()+b'\0')==1
    assert data.count(gpu['cdhash'].encode()+b'\0')==1
    new=base.image_profile(data,'MD');previous=base.image_profile((root/rows['child:MD']['path']).read_bytes(),'MD')
    assert new.exports.keys()==previous.exports.keys() and new.imports==previous.imports and new.loads==previous.loads
    sources=[pin(p) for p in includes if p.is_relative_to(R)]+[pin(profile)]
    result=dict(schema='GPU25 parent identity integration for unchanged GPU24 TLS provider',baseline=pin(oldpath),
        md=pin(md),generatedProfile=pin(profile),sources=sources,replacements={},
        comparisons=[dict(provider='child:MD',addedImports=[],actualImports=new.imports,actualLoads=new.loads,actualExports=new.exports)],
        actualGPUCDHash=gpu['cdhash'],actualGPUSHA256=gpu['sha256'],
        generatedHeaderActuallyCompiled=True,compiledBinaryIdentityStringsVerified=True,
        nativeTaskCodeWhole=True,deviceOperations=0)
    base.save(O/'candidate.json',result);print(json.dumps(pin(O/'candidate.json')))

if __name__=='__main__':main()
