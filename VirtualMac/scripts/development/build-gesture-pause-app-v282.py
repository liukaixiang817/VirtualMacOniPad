"""Compile App282 and the independent SpringBoard gesture companion."""
import copy,hashlib,json,shlex,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=Path(p).resolve();d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def main():
 prior=N/'complete-dual-actual-app-v281-attempt1/candidate.json';old=json.loads(prior.read_bytes())
 for row in old['sourceFiles']+old['objects']+old['actualIncludeClosure']:assert pin(row['path'])==row,row['path']
 o=N/'complete-dual-actual-app-v282-attempt1';o.mkdir(mode=0o700)
 app=o/'VirtualMacIndependent27.app';shutil.copytree(N/'release-2.0.0beta6-candidate-v2/stage/var/jb/Applications/VirtualMacIndependent27.app',app)
 source=S/'portable_app_v1/host/VirtualMacApp_complete_dual_v90_gesture_pause.m';obj=o/'0-main.o';dep=o/'0.d';commands=[]
 def run(label,args):
  p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=list(map(str,args)),exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
 recipe=next(c['argv'][:] for c in json.loads((Path(old['objects'][0]['path']).parent/'commands.json').read_bytes()) if c['label']=='compile-0' and not c['exit'])
 recipe[recipe.index(old['sourceFiles'][0]['path'])]=str(source);recipe[recipe.index(old['objects'][0]['path'])]=str(obj);recipe[recipe.index('-MF')+1]=str(dep)
 run('compile-0',recipe)
 includes={r['path']:r for r in old['actualIncludeClosure']}
 for v in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
  p=Path(v).resolve()
  if p.is_relative_to(R):includes[str(p)]=pin(p)
 link=next(c['argv'][:] for c in old['commands'] if c['label']=='link-app' and not c['exit'])
 link[link.index(old['objects'][0]['path'])]=str(obj);link[link.index('-o')+1]=str(app/'VirtualMacIndependent27')
 run('link-app',link);run('validate-app',['xcrun','dyld_info','-validate_only',app/'VirtualMacIndependent27'])
 for lang,values in [('en',['The virtual machine is paused. Resume when you are ready.','Resuming virtual machine…']),('zh_CN',['虚拟机已暂停，可随时继续。','正在继续虚拟机…'])]:
  p=app/(lang+'.lproj/Localizable.strings');text=p.read_text()
  for key,value in zip(['The virtual machine is paused. Resume when you are ready.','Resuming virtual machine…'],values):
   assert '"'+key+'" =' not in text;text+='\n"'+key+'" = "'+value+'";\n'
  p.write_text(text)
 sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
 tweak=R/'VirtualMac/vz/tweak/VM27GestureGuard_v1.m';dylib=o/'VM27GestureGuard.dylib'
 run('compile-gesture',['xcrun','clang','-arch','arm64e','-miphoneos-version-min=15.0','-isysroot',sdk,'-dynamiclib','-fblocks','-Wall','-Wextra','-framework','Foundation','-install_name','/var/jb/usr/lib/TweakInject/VM27GestureGuard.dylib',tweak,'-o',dylib])
 run('sign-gesture',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256',dylib]);run('verify-gesture',['codesign','--verify','--strict',dylib])
 run('describe-gesture',['codesign','-d','--verbose=4',dylib])
 r=copy.deepcopy(old);r['sourceFiles'][0]=pin(source);r['objects'][0]=pin(obj)
 r.update(schema='App282 full-screen pause and independent gesture ownership',builder=pin(__file__),inheritedCompiledAppCandidate=pin(prior),actualIncludeClosure=list(includes.values()),binary=pin(app/'VirtualMacIndependent27'),appFiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()],commands=commands,actualChangedAppObjectIndices=[0],actualUnchangedCompiledObjects=len(old['objects'])-1,actualNewAppCompilations=1,actualMainSourceChanged=True,codeSigned=False,deviceOperations=0,trustCacheOperations=0,gestureCompanion=pin(dylib),gestureSource=pin(tweak))
 (o/'candidate.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(pin(o/'candidate.json')))
if __name__=='__main__':main()
