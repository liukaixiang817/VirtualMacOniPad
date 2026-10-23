"""CPU99: retain CPU98, replace only production and wake-version readers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess

R=Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'cpu-cross-wake-v99-attempt3'

def pin(path):
    path=Path(path).resolve();data=path.read_bytes()
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def main():
    O.mkdir(mode=0o700);commands=[]
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode))
        (O/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
    previous=N/'cpu-gic-factory-input-v98-attempt1/candidate.json'
    old=json.loads(previous.read_bytes());objects=old['changedCPUObjects']+old['inheritedCPUObjects']
    for record in objects:assert pin(record['path'])==record
    production=next(r for r in objects if r['path'].endswith('/modern_cpu_production_native_ops_v22_exit_snapshot.o'))
    lifecycle=next(r for r in objects if r['path'].endswith('/modern_cpu_kernel_lifecycle_v78.o'))
    # The previous lifecycle's captured transitive inputs must still match.
    life_receipt=json.loads((Path(lifecycle['path']).parent/'candidate.json').read_bytes())
    for record in life_receipt['sourceFiles']:
        assert pin(record['path'])==record,record['path']
    products=[];sources=[]
    recipes=json.loads((Path(production['path']).parent/'commands.json').read_bytes())
    args=next(r['argv'][:] for r in recipes if r['label']=='ios-Production22ExitSnapshot')
    source=S/'modern_cpu_production_native_ops_v23_cross_wake.c'
    obj=O/'production-cross-wake.o';dep=O/'production-cross-wake.d'
    args[args.index('-c')+1]=str(source);args[args.index('-o')+1]=str(obj);args[args.index('-MF')+1]=str(dep)
    run('compile-production',args);products.append(pin(obj))
    for p in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
        if Path(p).resolve().is_relative_to(R):sources.append(pin(p))
    recipes=json.loads((Path(lifecycle['path']).parent/'commands.json').read_bytes())
    args=next(r['argv'][:] for r in recipes if r['label']=='ios-Life78ExitDetailSnapshot')
    pp=O/'lifecycle-before.c';preprocess=args[:]
    preprocess.remove('-MMD');at=preprocess.index('-MF');del preprocess[at:at+2]
    # Retain system-header line markers so the strict compile preserves the
    # original SDK warning scope instead of treating its inline helpers as ours.
    preprocess[preprocess.index('-c')]='-E'
    preprocess[preprocess.index('-o')+1]=str(pp);run('freeze-lifecycle',preprocess)
    before=pp.read_text()
    pattern=r'static VZKernelStatus WakeVersionV17\(VZKernelCPUWakeOwnerV17 \*o\) \{.*?\n\}'
    matches=list(re.finditer(pattern,before,re.S));assert len(matches)==1
    original=matches[0].group(0)
    assert original.count('WakeIdentityV17(o)')==2
    assert original.count('VM27CPUSelfOwnedMappedRangeV1')==1
    assert original.count('ops.readMemory')==1
    replacement=(S/'modern_cpu_kernel_wake_version_v33.inc').read_text()
    # The replacement enters a preprocessed unit: obtain both macro values
    # from that exact baseline function rather than a different SDK/profile.
    limit=re.search(r'nativeContext>([0-9]+UL) -0x4008',original).group(1)
    version=re.search(r'return version==(\([^?]+\))\?VZ_KERNEL_OK:',original).group(1)
    replacement=replacement.replace('UINTPTR_MAX',limit).replace('VZ_KERNEL_NATIVE_CONTEXT_VERSION',version)
    a,b=matches[0].span();after=before[:a]+replacement+before[b:]
    assert after[:a]==before[:a] and after[a+len(replacement):]==before[b:]
    source=O/'lifecycle-cross-wake.c';source.write_text(after)
    obj=O/'lifecycle-cross-wake.o';dep=O/'lifecycle-cross-wake.d'
    args[args.index('-c')+1]=str(source);args[args.index('-o')+1]=str(obj);args[args.index('-MF')+1]=str(dep)
    run('compile-lifecycle',args);products.append(pin(obj))
    sources.extend([pin(source),pin(S/'modern_cpu_kernel_wake_version_v33.inc')])
    link=next(r['argv'][:] for r in json.loads((previous.parent/'commands.json').read_bytes()) if r['label']=='link-cpu')
    for baseline,product in zip([production,lifecycle],products):
        assert link.count(baseline['path'])==1;link[link.index(baseline['path'])]=product['path']
    cpu=O/'VM27HVVMProduction.dylib';link[link.index('-o')+1]=str(cpu)
    run('link-cpu',link);run('validate-cpu',['xcrun','dyld_info','-validate_only',cpu])
    spec=importlib.util.spec_from_file_location('cpu99_image',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'))
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    prior_image=base.image_profile(Path(old['cpu']['path']).read_bytes(),'cpu')
    image=base.image_profile(cpu.read_bytes(),'cpu')
    assert set(image.exports)==set(prior_image.exports)
    assert image.imports==prior_image.imports and image.loads==prior_image.loads
    unchanged=[r for r in objects if r not in [production,lifecycle]]
    assert len(products)+len(unchanged)==len(objects)
    result=dict(schema='CPU99 retained-owner cross-CPU version read; device acceptance pending',
        baseline=pin(previous),builder=pin(__file__),cpu=pin(cpu),changedCPUObjects=products,
        inheritedCPUObjects=unchanged,sources=sources,deviceOperations=0,
        actualExportsAndImportsUnchanged=True,actualGenericWakeFallbackRetained=True,
        lifecycleOnlyOneFunctionChanged=True,baselineWakeFunctionSHA256=hashlib.sha256(original.encode()).hexdigest(),
        originalNative10AndIdentityChecksWhole=True,
        comparisons=[dict(provider='VM27HVVMProduction.dylib',actualExports=image.exports,
            actualImports=image.imports,actualLoads=image.loads,addedImports=[])])
    (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(pin(O/'candidate.json')))

if __name__=='__main__':main()
