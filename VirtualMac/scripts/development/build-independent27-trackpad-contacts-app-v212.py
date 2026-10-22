#!/usr/bin/env python3
"""App212: compile only input Surface13; Runtime150 and other38 objects whole.

The real Magic Keyboard event route still needs physical device acceptance.
This builder does not create native UIEvents or claim hardware gestures passed.
"""
import pathlib,json,hashlib,copy,subprocess,shutil,shlex,importlib.util
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):assert pin(r['path'])==r,r['path']
def main():
 oldp=N/'independent27-actual-app-bt-audio-unavailable-v211-attempt1/candidate.json';old=json.loads(oldp.read_text())
 signedp=N/'independent27-signed-app-bt-audio-unavailable-v211-attempt1/candidate.json';signed=json.loads(signedp.read_text())
 for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']+signed['appFiles']:exact(row)
 rt=old['actualRuntimeCandidate'];exact(rt)
 o=N/'independent27-actual-app-trackpad-contacts-v212-attempt1';o.mkdir(mode=0o700);app=o/'VirtualMacIndependent27.app';shutil.copytree(signed['app'],app);binary=app/'VirtualMacIndependent27'
 sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);source=S/'modern_uikit_input_surface_v13_trackpad_contacts.m';obj=o/'17-modern_uikit_input_surface_v13_trackpad_contacts.o';dep=o/'17.d'
 originalCommands=json.loads((pathlib.Path(objects[17]['path']).parent.parent/'commands.json').read_bytes());compileArgs=copy.deepcopy(next(c['argv']for c in originalCommands if c['label']=='compile-17'and c['exit']==0));compileArgs[compileArgs.index(sources[17]['path'])]=str(source);compileArgs[compileArgs.index(objects[17]['path'])]=str(obj);compileArgs[compileArgs.index('-MF')+1]=str(dep);compileArgs+=['-Wall','-Wextra','-Werror']
 commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));assert p.returncode==0,p.stderr.decode()
 run('compile-17',compileArgs);sources[17]=pin(source);objects[17]=pin(obj)
 link=copy.deepcopy(next(c['argv']for c in old['commands']if c['label']=='link-app'and c['exit']==0));link[link.index(old['objects'][17]['path'])]=str(obj);link[link.index(old['binary']['path'])]=str(binary)
 run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',binary]);(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 sp=importlib.util.spec_from_file_location('trackpad_app_macho',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py');reader=importlib.util.module_from_spec(sp);sp.loader.exec_module(reader)
 before=reader.MachO(pathlib.Path(old['binary']['path']).read_bytes());after=reader.MachO(binary.read_bytes());assert before.loads==after.loads
 assert {r['name']for r in after.imports if not r['weak']}<={r['name']for r in before.imports if not r['weak']},'no new strong imports'
 includes={r['path']:r for r in old['actualIncludeClosure']}
 for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  p=pathlib.Path(name).resolve()
  if str(p).startswith(str(R)+'/'):includes[str(p)]=pin(p)
 a=copy.deepcopy(old);a.update(schema='App212 Main50 whole; Surface13 real trackpad contact hint path; Runtime150 CPU91 whole',builder=pin(__file__),inheritedCompiledAppCandidate=pin(oldp),sourceFiles=sources,objects=objects,binary=pin(binary),appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],actualIncludeClosure=list(includes.values()),commands=commands,actualChangedAppObjectIndices=[17],actualUnchangedCompiledObjects=len(objects)-1,actualNewAppCompilations=1,actualMainSourceChanged=False,actualOnlyMainObjectChanged=False,actualHardwareThreeFingerAcceptance=False,actualNoNewStrongImports=True,codeSigned=False,applicationBinaryLinked=True,applicationPackaged=True,deviceOperations=0,trustCacheOperations=0)
 a['inheritedPreviousProductContract']=a.pop(a['mainSourceContractKey']);a['mainSourceContractKey']='trackpadContactsSurface13Contract';a[a['mainSourceContractKey']]=dict(actualRuntime150=rt,allOther38ObjectsWholeApp211=True,onlyActualOwnUIHoverEventScalarContactHints=True,noGlobalHIDMonitor=True,noSystemGestureMutation=True,realMagicKeyboardPacketDeliveryNotYetVerified=True)
 (o/'candidate.json').write_text(json.dumps(a,indent=2)+'\n');files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+[pin(__file__),pin(oldp),pin(signedp),*sources,*objects,*a['actualIncludeClosure']];(o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),onlyChangedObject=17,hardwareAcceptanceNotClaimed=True)))
if __name__=='__main__':main()
