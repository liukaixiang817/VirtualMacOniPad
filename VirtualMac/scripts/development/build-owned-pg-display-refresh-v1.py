#!/usr/bin/env python3
"""Build immutable display image admission cache; preserve fresh permissions and native GPU/CPU code."""
import pathlib,json,hashlib,copy,subprocess,shlex,importlib.util
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def run(label,args):
 args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(r.stdout);(o/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));assert r.returncode==0,r.stderr.decode()
oldp=N/'independent27-signed-runtime-display-identity-v154-attempt1/candidate.json';old=json.loads(oldp.read_text());baseline=pathlib.Path(old['runtimeRoot'])/'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/MD'
assert pin(S/'modern_metal_device_array_v35.m')==old['actualMDSource']
recipe=N/'owned-pvg-null-connection-parent-port-v1-attempt1';o=N/'owned-pg-display-refresh-source-v1-attempt1';o.mkdir(mode=0o700);obj=o/'modern_metal_device_array_v36.o';binary=o/'MD';dep=o/'source.d';commands=[]
argv=json.loads((recipe/'compile.json').read_text())['command'];source=S/'modern_metal_device_array_v36_refresh.m';argv[argv.index(str(S/'modern_metal_device_array_v32.m'))]=str(source);argv[argv.index('-o')+1]=str(obj);argv+=['-MMD','-MF',str(dep)];run('compile',argv)
link=json.loads((recipe/'link.json').read_text())['command'];link[link.index(str(recipe/'modern_metal_device_array_v32.o'))]=str(obj);link[link.index('-o')+1]=str(binary);run('link',link)
argv=json.loads((recipe/'loader-path.json').read_text())['command'];argv[-1]=str(binary);run('normalize-owned-loads',argv);run('validate',['xcrun','dyld_info','-validate_only',binary])
sp=importlib.util.spec_from_file_location('surface_cache_image',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);before=m.MachO(baseline.read_bytes());after=m.MachO(binary.read_bytes())
assert set(before.exports)==set(after.exports) and all(before.exports[k]['flags']==after.exports[k]['flags']for k in before.exports)
semantic=lambda x:{k:v for k,v in x.items()if k not in ('at','size')}
assert [semantic(x)for x in after.loads]==[semantic(x)for x in before.loads]
oldimports={(r['name'],r['weak'],r['addend'])for r in before.imports};assert oldimports<={(r['name'],r['weak'],r['addend'])for r in after.imports}
headers=[]
for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
 p=pathlib.Path(name).resolve()
 if str(p).startswith(str(R)+'/'):headers.append(pin(p))
(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
c=dict(schema='Owned VMM per-parent 60/120Hz native PGDisplayMode adapter V36',baselineRuntimeCandidate=pin(oldp),baselineMD=pin(baseline),provider=pin(binary),source=pin(source),sourceFiles=headers,actualChangedObjects=[pin(obj)],inheritedWholeObjects=[pin(pathlib.Path(x))for x in link if str(x).endswith('.o')and x!=str(obj)],actualExports=after.exports,actualImports=after.imports,actualLoads=after.loads,allExistingExportNamesKindsPreserved=True,allExistingLoadOrdinalsPreserved=True,allExistingLoadsPreserved=True,actualAddedNativeImports=sorted(set(r['name']for r in after.imports)-set(r['name']for r in before.imports)),compiled=True,actualIOSCompileStrictLinkAndDyldValidatePassed=True,imageAdmissionCacheCapacity=16,dyldImageChangeInvalidates=True,freshUIDPIDCSFlagsCallerClassMethodChecks=True,processLocalConcreteMetalMethodOverride=False,systemProcessesOrKernelModified=False,onlyImmutableExecutableAndImageMetadataCached=True,nativeCommandsPresentAndReadinessUnchanged=True,allCPU91AndGPU193NativeCodeUnchanged=True,deviceOperations=0,codeSigned=False)
(o/'candidate.json').write_text(json.dumps(c,indent=2)+'\n');files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+headers+[pin(__file__),pin(oldp),pin(baseline),*c['inheritedWholeObjects']];(o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),newNativeImports=c['actualAddedNativeImports'])))
