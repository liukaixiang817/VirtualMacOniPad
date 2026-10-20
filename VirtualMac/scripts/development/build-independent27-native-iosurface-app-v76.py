#!/usr/bin/env python3
"""Root-only two-unit App124 successor; signed Runtime102 remains whole."""
import argparse,copy,hashlib,json,pathlib,shutil,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD=N/'independent27-actual-app-gui-diagnostic-v124-attempt1/candidate.json'
OLD_SHA='0409094dd6f3318e032f3d344916d6cf9fc30aab58d048de3f096f5b5a645ca7'
def need(v,s):
 if not v:raise ValueError(s)
def pin(p):
 p=pathlib.Path(p).resolve();need(p.is_file() and not p.is_symlink(),'regular file '+str(p));b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):need(pin(r['path'])==r,'whole pinned input '+r['path']);return pathlib.Path(r['path'])
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source-plan',required=True,type=pathlib.Path);ap.add_argument('--source-plan-sha256',required=True);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 out=a.output.resolve();pp=a.source_plan.resolve();need(out.parent==N and not out.exists(),'fresh owned output')
 need(pin(OLD)['sha256']==OLD_SHA and pin(pp)['sha256']==a.source_plan_sha256,'reviewed App124 and plan')
 old=json.loads(OLD.read_bytes());plan=json.loads(pp.read_bytes());units=plan['compileUnits']
 need([u['index'] for u in units]==[0,16] and plan['sourceFiles']==[units[0]['source']],'only Main35 NativeIOSurface9')
 need(plan['baselineCompiledAppCandidate']==pin(OLD) and plan['actualRuntimeCandidate']==old['actualRuntimeCandidate'],'same compiled baseline/runtime')
 ck=plan['contractKey'];need(ck.endswith('Contract') and isinstance(plan[ck],dict),'named Main contract')
 inherited=[*old['sourceFiles'],*old['objects'],*old['actualIncludeClosure'],*old.get('externalPrecompiledObjects',[]),*old['appFiles']]
 for r in inherited+plan['sourceFiles']+plan['extraSourceFiles']+[old['mainSourcePlan']]:exact(r)
 rt=json.loads(exact(old['actualRuntimeCandidate']).read_bytes())
 need(old['actualRuntimeCandidate']['sha256']=='aa255df657aff6b3855a1a217091b1a9a04e24ed958560dd233c70eaa00c2516' and rt['localCodeSigned'] and rt['actualProductPreflightPassed'] and old['objects'][34]==rt['anchorIOSObject'],'whole signed R102 and anchor')
 for u in units:exact(u['source']);exact(u['templateFile'])
 links=[c for c in old['commands'] if c['label']=='link-app' and c['exit']==0];need(len(links)==1,'actual App124 link')
 out.mkdir(mode=0o700);(out/'objects').mkdir(mode=0o700)
 orig=pathlib.Path(old['binary']['path']).parent;need(not any(p.is_symlink() for p in orig.rglob('*')),'ordinary original resources')
 app=out/'VirtualMacIndependent27.app';shutil.copytree(orig,app);binary=app/'VirtualMacIndependent27';commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True,timeout=90);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode));save(out/'commands.json',commands);need(p.returncode==0,label+': '+p.stderr.decode(errors='replace'))
 sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);dependencies=[]
 for u in units:
  i=u['index'];t=json.loads(exact(u['templateFile']).read_bytes());rows=t if isinstance(t,list) else [t]
  rows=[c for c in rows if c.get('label',u['templateLabel'])==u['templateLabel'] and c['exit']==0];need(len(rows)==1,'one actual successful compiler')
  argv=list(rows[0]['argv']);need(argv.count(u['templateSource'])==argv.count(u['templateObject'])==1,'actual source/output in compiler')
  target=out/'objects'/(str(i)+'-'+pathlib.Path(u['source']['path']).stem+'.o');dep=out/(str(i)+'.d')
  argv[argv.index(u['templateSource'])]=u['source']['path'];argv[argv.index(u['templateObject'])]=str(target)
  need('-MMD' not in argv and '-MF' not in argv,'no inherited dependency output')
  argv+=['-MMD','-MF',str(dep)];run('compile-'+str(i),argv);dependencies.append(dep);sources[i]=u['source'];objects[i]=pin(target)
 argv=list(links[0]['argv']);need(argv.count(old['binary']['path'])==1,'actual link output')
 for u in units:
  i=u['index'];need(argv.count(old['objects'][i]['path'])==1,'single old object');argv[argv.index(old['objects'][i]['path'])]=objects[i]['path']
 argv[argv.index(old['binary']['path'])]=str(binary);run('link-app',argv);need(binary.stat().st_size<=2097152,'same self-inspector limit')
 for label,flag in [('validate-app','-validate_only'),('imports-app','-imports'),('exports-app','-exports')]:run(label,['xcrun','dyld_info',flag,str(binary)])
 for i in range(35):
  if i not in (0,16):need(sources[i]==old['sourceFiles'][i] and objects[i]==old['objects'][i],'other33 objects whole')
 for r in inherited+sources+objects:exact(r)
 appfiles=[pin(p) for p in sorted(app.rglob('*')) if p.is_file()]
 for r in appfiles:
  rel=pathlib.Path(r['path']).relative_to(app)
  if str(rel)!='VirtualMacIndependent27':need((r['bytes'],r['sha256'])==(pin(orig/rel)['bytes'],pin(orig/rel)['sha256']),'all resources whole')
 closure={r['path']:r for r in old['actualIncludeClosure']}
 for dep in dependencies:
  for name in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split():
   p=pathlib.Path(name)
   if p.is_relative_to(R) and p.is_file():closure[str(p)]=pin(p)
 rec=copy.deepcopy(old);hist={}
 for k in list(rec):
  if k.startswith(('actualOther34','all34Other','actualSoftwareKeyboardAndQGANormalExitObjectsWholeApp')) or k in ('actualOnlyRelinkedRuntimeAnchor','actualMainAndOther33CompiledObjectsWholeUnchanged','actualChangedAppObjectIndices','actualUnchangedCompiledObjects','actualNewAppCompilations','actualOnlyMainObjectChanged','actualMainSourceChanged','mainSourcePlan','mainSourceContractKey','actualObserver3AndBitmap7ObjectsWholeUnchanged','actualMainSourcePlanAndContractWholeUnchanged'):
   hist[k]=rec.pop(k)
 oldck=old['mainSourceContractKey'];hist[oldck]=rec.pop(oldck)
 rec['historicalApp124BuildClaims']=hist
 rec.update(schema='Actual Main35 NativeIOSurface9 two-unit App125',builder=pin(__file__),sourceCandidate=pin(pp),mainSourcePlan=pin(pp),mainSourceContractKey=ck,sourceFiles=sources,objects=objects,commands=commands,binary=pin(binary),appFiles=appfiles,actualIncludeClosure=list(closure.values()),inheritedCompiledAppCandidate=pin(OLD),inheritedCompilationCommands=pin(OLD.parent/'commands.json'),actualChangedAppObjectIndices=[0,16],actualUnchangedCompiledObjects=33,actualNewAppCompilations=2,actualOnlyRelinkedRuntimeAnchor=False,actualOnlyMainObjectChanged=False,actualMainSourceChanged=True,actualRuntime102AndAnchorWholeUnchanged=True,allOriginalAppResourcesWholeUnchanged=True,codeSigned=False,deviceOperations=0,codeSigningOperations=0,trustCacheOperations=0,applicationBinaryLinked=True,applicationPackaged=True,actualGuestBoot=False,actualSSHVerified=False)
 rec[ck]=plan[ck];save(out/'candidate.json',rec)
 files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]+[pin(__file__),pin(OLD),pin(pp),old['actualRuntimeCandidate'],*sources,*objects,*closure.values(),*old.get('externalPrecompiledObjects',[])]+[u['templateFile'] for u in units]
 save(out/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0,codeSigningOperations=0));print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),changedObjects=[0,16],wholeObjects=33,runtimeWhole=True)))
if __name__=='__main__':main()
