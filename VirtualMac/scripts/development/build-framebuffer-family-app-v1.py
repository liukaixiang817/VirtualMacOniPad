#!/usr/bin/env python3
"""Relink the accepted App279 against the framebuffer-corrected manifest."""
import argparse, copy, hashlib, json, shutil, subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(path):
    path=Path(path).resolve();data=path.read_bytes();return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--negative-control',action='store_true');a=parser.parse_args()
    number=280 if a.negative_control else 281;runtime=180 if a.negative_control else 181
    out=N/('complete-dual-actual-app-v%d-attempt1'%number);out.mkdir(mode=0o700)
    prior=N/'complete-dual-actual-app-v279-attempt1/candidate.json';old=json.loads(prior.read_bytes())
    rp=N/('independent27-signed-runtime-framebuffer-v%d-attempt1/candidate.json'%runtime);rt=json.loads(rp.read_bytes())
    for record in old['sourceFiles']+old['objects']+old['actualIncludeClosure']:assert pin(record['path'])==record,record['path']
    source=Path(old['binary']['path']).parent;app=out/source.name;shutil.copytree(source,app)
    link=next(c['argv'][:] for c in json.loads((prior.parent/'commands.json').read_bytes()) if c['label']=='link-app' and not c['exit'])
    link[link.index('-o')+1]=str(app/'VirtualMacIndependent27')
    link[link.index(old['objects'][34]['path'])]=rt['anchorIOSObject']['path']
    commands=[]
    for label,argv in [('link-app',link),('validate-app',['xcrun','dyld_info','-validate_only',str(app/'VirtualMacIndependent27')])]:
        p=subprocess.run(argv,capture_output=True,timeout=90);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode:raise RuntimeError(p.stderr.decode())
    result=copy.deepcopy(old);result['sourceFiles'][34]=rt['anchorSource'];result['objects'][34]=rt['anchorIOSObject']
    result.update(schema='Framebuffer capability App%d; accepted App279 implementation unchanged'%number,negativeControlOnly=a.negative_control,
        builder=pin(__file__),inheritedCompiledAppCandidate=pin(prior),binary=pin(app/'VirtualMacIndependent27'),
        appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],commands=commands,actualRuntimeCandidate=pin(rp),
        actualChangedAppObjectIndices=[34],actualUnchangedCompiledObjects=len(old['objects'])-1,actualNewAppCompilations=0,
        actualMainSourceChanged=False,codeSigned=False,deviceOperations=0,trustCacheOperations=0)
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(pin(out/'candidate.json')))
if __name__=='__main__':main()
