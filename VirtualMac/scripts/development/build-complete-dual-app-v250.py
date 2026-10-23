"""Relink App208 with Runtime159 manifest; all 38 non-anchor objects whole."""
import pathlib,json,hashlib,copy,subprocess,shutil
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])==r,r['path']
oldp=N/'complete-dual-actual-app-v249-attempt1/candidate.json';old=json.loads(oldp.read_text())
signed=json.loads((N/'complete-dual-signed-app-v249-attempt1/candidate.json').read_text())
for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+signed['appFiles']:exact(row)
rtp=N/'independent27-signed-runtime-native-microphone-v159-attempt1/candidate.json';rt=json.loads(rtp.read_text());exact(rt['anchorSource']);exact(rt['anchorIOSObject'])
o=N/'complete-dual-actual-app-v250-attempt1';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(signed['app'],app);binary=app/'VirtualMacIndependent27'
sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);sources[34]=rt['anchorSource'];objects[34]=rt['anchorIOSObject']
argv=list(next(c for c in old['commands']if c['label']=='link-app' and c['exit']==0)['argv']);assert argv.count(old['objects'][34]['path'])==1;argv[argv.index(old['objects'][34]['path'])]=objects[34]['path'];argv[argv.index(old['binary']['path'])]=str(binary)
commands=[]
for label,args in [('link-app',argv),('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])]:
 p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));assert p.returncode==0,p.stderr.decode()
(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
a=copy.deepcopy(old);a.update(schema='App250 Main50 Surface12 whole; Runtime159 CPU91 whole, native VMM microphone permission manifest anchor',builder=pin(__file__),inheritedCompiledAppCandidate=pin(oldp),sourceFiles=sources,objects=objects,binary=pin(binary),appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],commands=commands,actualChangedAppObjectIndices=[34],actualUnchangedCompiledObjects=len(objects)-1,actualNewAppCompilations=0,actualOnlyMainObjectChanged=False,actualMainSourceChanged=False,actualRuntimeCandidate=pin(rtp),actualRuntime134AndAnchorJoined=False,actualRuntime159AndAnchorJoined=True,codeSigned=False,applicationBinaryLinked=True,applicationPackaged=True,deviceOperations=0,trustCacheOperations=0)
(o/'candidate.json').write_text(json.dumps(a,indent=2)+'\n');files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+[pin(__file__),pin(oldp),*sources,*objects,*old['actualIncludeClosure']];(o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),onlyChangedObject=34)))
