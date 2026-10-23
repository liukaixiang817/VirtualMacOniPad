#!/usr/bin/env python3
"""App220: adjacent pan coalescing and bounded copied-pan A/B diagnostic; Runtime154 whole.

The real Magic Keyboard event route still needs physical device acceptance.
This builder does not create native UIEvents or claim hardware gestures passed.
"""
import pathlib,json,hashlib,copy,subprocess,shutil,shlex,importlib.util
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):assert pin(r['path'])==r,r['path']
def main():
 oldp=N/'independent27-actual-app-display-identity-v218-attempt1/candidate.json';old=json.loads(oldp.read_text())
 signedp=N/'independent27-signed-app-display-identity-v218-attempt1/candidate.json';signed=json.loads(signedp.read_text())
 for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+signed['appFiles']:exact(row)
 rt=old['actualRuntimeCandidate'];exact(rt)
 o=N/'independent27-actual-app-scroll-timing-v220-attempt1';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(signed['app'],app);binary=app/'VirtualMacIndependent27'
 sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);commands=[];deps=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));assert p.returncode==0,p.stderr.decode()
 link=copy.deepcopy(next(c['argv']for c in old['commands']if c['label']=='link-app'and c['exit']==0))
 for i,name in [(0,'VirtualMacApp_independent_scroll_timing_v53.m'),(17,'modern_uikit_input_surface_v16_scroll_cleanup.m'),(18,'modern_uikit_input_adapter_v6_scroll_diagnostic.m'),(23,'modern_input_packet_v5_scroll_coalescing.c')]:
  source=S/name;obj=o/(str(i)+'-'+source.stem+'.o');dep=o/(str(i)+'.d');deps.append(dep)
  commandFile=pathlib.Path(objects[i]['path']).parent/'commands.json'
  if not commandFile.exists():commandFile=commandFile.parent.parent/'commands.json'
  originalCommands=json.loads(commandFile.read_bytes());compileArgs=copy.deepcopy(next(c['argv']for c in originalCommands if c['label']=='compile-'+str(i)and c['exit']==0))
  compileArgs[compileArgs.index(sources[i]['path'])]=str(source);compileArgs[compileArgs.index(objects[i]['path'])]=str(obj);compileArgs[compileArgs.index('-MF')+1]=str(dep)
  if i in (17,18,23):compileArgs+=['-Wall','-Wextra','-Werror']
  run('compile-'+str(i),compileArgs);link[link.index(objects[i]['path'])]=str(obj);sources[i]=pin(source);objects[i]=pin(obj)
 link[link.index(old['binary']['path'])]=str(binary)
 run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',binary]);(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 sp=importlib.util.spec_from_file_location('trackpad_app_macho',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py');reader=importlib.util.module_from_spec(sp);sp.loader.exec_module(reader)
 before=reader.MachO(pathlib.Path(old['binary']['path']).read_bytes());after=reader.MachO(binary.read_bytes());assert before.loads==after.loads
 newImports={r['name']for r in after.imports if not r['weak']}-{r['name']for r in before.imports if not r['weak']};assert newImports<=set(),newImports
 includes={r['path']:r for r in old['actualIncludeClosure']}
 for dep in deps:
  for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
   p=pathlib.Path(name).resolve()
   if str(p).startswith(str(R)+'/'):includes[str(p)]=pin(p)
 a=copy.deepcopy(old);a.update(schema='App220 Main53 Surface16 Adapter6 Packet5 exact distance pan coalescing and bounded native scroll A/B; Runtime154 whole',builder=pin(__file__),inheritedCompiledAppCandidate=pin(oldp),sourceFiles=sources,objects=objects,binary=pin(binary),appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],actualIncludeClosure=list(includes.values()),commands=commands,actualChangedAppObjectIndices=[0,17,18,23],actualUnchangedCompiledObjects=len(objects)-4,actualNewAppCompilations=4,actualMainSourceChanged=True,actualOnlyMainObjectChanged=False,actualHardwareThreeFingerAcceptance=False,actualNewStrongImports=sorted(newImports),codeSigned=False,applicationBinaryLinked=True,applicationPackaged=True,deviceOperations=0,trustCacheOperations=0)
 a['inheritedPreviousProductContract']=a.pop(a['mainSourceContractKey']);a['mainSourceContractKey']='finiteCopiedPanScrollTimingV1Contract';a[a['mainSourceContractKey']]=dict(actualRuntime154=rt,allOtherObjectsWholeApp218=True,maxWindowsPerProcess=4,windowSeconds=12,capacity=2048,noPerFrameLog=True,noPixelCopyOrReadinessChange=True,physicalDisplayFPSNotClaimed=True)
 (o/'candidate.json').write_text(json.dumps(a,indent=2)+'\n');files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+[pin(__file__),pin(oldp),pin(signedp),*sources,*objects,*a['actualIncludeClosure']];(o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),changedObjects=[0,17,18,23],hardwareAcceptanceNotClaimed=True)))
if __name__=='__main__':main()
