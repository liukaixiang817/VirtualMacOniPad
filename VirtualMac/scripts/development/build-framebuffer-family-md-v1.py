#!/usr/bin/env python3
"""Build the Apple-family capability fix, or an explicit diagnostic negative control."""
import argparse, importlib.util, json, plistlib, shlex, subprocess
from pathlib import Path

R=Path(__file__).resolve().parents[3]; S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
spec=importlib.util.spec_from_file_location('runtime_primitives',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def main():
    p=argparse.ArgumentParser();p.add_argument('--negative-control',action='store_true');a=p.parse_args()
    variant='control' if a.negative_control else 'fixed'
    out=N/('native-framebuffer-family-md-'+variant+'-v1-attempt1');out.mkdir(mode=0o700)
    oldpath=N/'independent27-signed-runtime-rearm-v179-attempt1/candidate.json'
    old=json.loads(oldpath.read_bytes());root=Path(old['runtimeRoot'])
    rows={r['id']:r for r in plistlib.loads(Path(old['manifest']['path']).read_bytes())['files']}
    gpu=rows['gpu-task:main'];assert base.pin(root/gpu['path'])['sha256']==gpu['sha256']
    source=R/'VirtualMac/vz/development/probes/pvg-framebuffer-negative-control-v1.m' if a.negative_control else S/'modern_metal_device_array_v39_framebuffer_family.m'
    recipes=json.loads((N/'native-hibernate-fatal-md-v26-attempt1/commands.json').read_bytes())
    compile=next(r['argv'][:] for r in recipes if r['label']=='compile-md')
    compile[compile.index('-c')+1]=str(source);compile[compile.index('-o')+1]=str(out/'MD.o');compile[compile.index('-MF')+1]=str(out/'MD.d')
    commands=[]
    def run(label,args):
        args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=90)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        commands.append(dict(label=label,argv=args,exit=r.returncode));base.save(out/'commands.json',commands)
        if r.returncode:raise RuntimeError(label+': '+r.stderr.decode())
    run('compile-md',compile)
    recipes=json.loads((N/'native-vt-restore-md-v27-attempt3/commands.json').read_bytes())
    link=next(r['argv'][:] for r in recipes if r['label']=='link-md')
    inputs=[i for i,v in enumerate(link) if v.endswith('/MD.o')];assert len(inputs)==1
    link[inputs[0]]=str(out/'MD.o');link[link.index('-o')+1]=str(out/'MD');run('link-md',link)
    normalize=next(r['argv'][:] for r in recipes if r['label'].startswith('normalize'))
    normalize[-1]=str(out/'MD');run('normalize-md',normalize)
    run('validate-md',['xcrun','dyld_info','-validate_only',out/'MD'])
    data=(out/'MD').read_bytes();new=base.image_profile(data,'MD');before=base.image_profile((root/rows['child:MD']['path']).read_bytes(),'MD')
    semantics=lambda im:[tuple(row[k] for k in ['index','ordinal','weak','name','addend']) for row in im.imports]
    assert semantics(new)==semantics(before) and new.loads==before.loads and new.exports.keys()==before.exports.keys()
    assert data.count(gpu['sha256'].encode()+b'\0')==data.count(gpu['cdhash'].encode()+b'\0')==1
    includes=[Path(v).resolve() for v in shlex.split((out/'MD.d').read_text().replace('\\\n',' ').split(':',1)[1])]
    result=dict(schema='MD framebuffer-fetch native Apple2 minimum family query',negativeControlOnly=a.negative_control,
        baseline=base.pin(oldpath),md=base.pin(out/'MD'),sources=[base.pin(v) for v in includes if v.is_relative_to(R)],
        comparisons=[dict(provider='child:MD',importsUnchanged=True,loadsUnchanged=True,exportsUnchanged=True)],
        actualGPUCDHash=gpu['cdhash'],actualGPUSHA256=gpu['sha256'],deviceOperations=0)
    base.save(out/'candidate.json',result);print(json.dumps(base.pin(out/'candidate.json')))

if __name__=='__main__':main()
