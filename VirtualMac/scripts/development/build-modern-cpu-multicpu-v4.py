"""Separate V4 build and real-pthread mock verification. Never loads iOS output."""
from pathlib import Path
import argparse,difflib,hashlib,json,os,plistlib,re,subprocess,sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';H=R/'VirtualMac/vz/host'
BASE=N/'kernel-owned-pending-state-v3-local-v1/verified-build-v4'
BASESHA='4086d81d73b7c8007d9b896c11baf9685167ef983e6cef8f4d93f483c1df1170'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def body(source,name):
 match=re.search(r'\n(?:static )?(?:bool|void|VZKernelStatus) '+name+r'\([^;]+?\) \{',source,re.S);assert match,name
 start=match.start()+1;at=source.index('{',match.start());depth=1;end=at+1
 while depth:
  depth+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[start:end]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();out=args.output.resolve();assert out.is_relative_to(N);out.mkdir(exist_ok=False)
 source=out/'source';source.mkdir();inputs=[];commands=[];models=[]
 assert not sys.flags.optimize and pin(BASE/'freeze.json')['sha256']==BASESHA
 inputs.append(pin(BASE/'freeze.json'))
 for row in json.loads((BASE/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
 baseline=json.loads((BASE/'candidate.json').read_text());inputs.append(pin(BASE/'candidate.json'))
 priorPins={row['path']:row for row in baseline['sourceInputs']}
 for row in baseline['sourceSnapshots']:
  path=Path(row['path']);p=H/path.name
  if p.is_file():
   assert pin(p)['sha256']==row['sha256'];inputs.append(pin(p));(source/p.name).write_bytes(p.read_bytes())
 for name in ['modern_cpu_kernel_lifecycle_v4.c','modern_cpu_kernel_lifecycle_v4.h']:
  p=H/name;inputs.append(pin(p));(source/name).write_bytes(p.read_bytes())
 old=(source/'modern_cpu_kernel_lifecycle_v3.c').read_text();new=(source/'modern_cpu_kernel_lifecycle_v4.c').read_text()
 unchanged=['BeginOperation','EndOperation','BeginCPUOperation','Lock','Unlock','Finish','Start','CPUResult',
  'VZKernelNativeHVISAIsKnown','VZKernelConvertSerializedGuestISA','VZKernelTranslateVMOptions','Version','NativeFieldRead','ReadNativeFields',
  'InitializationRead','InitializationWrite','PendingValueStatusV3','PendingOutputDisjointV3','VZKernelCPUSetPendingInterruptV3']
 for name in unchanged:assert body(old,name)==body(new,name),name
 calls=lambda s:re.findall(r'(?:ops->nativeTrap|vm->ops\.nativeTrap)\([^;]+',s)
 assert calls(old)==calls(new) and len(calls(new))==4
 assert 'NativeCPUCreate args = {0, 0};' in new and 'activeCPU' not in new
 assert 'vm->generation = ++NextGeneration;' in new and 'cpu->generation = ++NextCPUGenerationV4;' in new
 block=new[new.index('// These two V3 APIs'):new.index('VZKernelStatus VZKernelCPUAccessSystemRegister')]
 assert 'nativeTrap(' not in block and 'readMemory' not in block and 'writeMemory' not in block
 (out/'source-delta-from-v3.diff').write_text(''.join(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='immutable-v3',tofile='alternative-v4')))
 tests=R/'VirtualMac/scripts/tests'
 for name in ['test-modern-cpu-multicpu-v4.c','test-modern-cpu-owned-pending-v3.c','test-modern-cpu-owned-pending-v3.cpp','test-modern-cpu-callback-lifetime-v3.c','test-modern-cpu-initialization-boundary-v2.c']:
  p=tests/name
  if name!='test-modern-cpu-multicpu-v4.c':assert priorPins[str(p.resolve())]==pin(p)
  inputs.append(pin(p));(source/name).write_bytes(p.read_bytes())
 oldtest=(source/'test-modern-cpu-owned-pending-v3.c').read_text()
 newtest=oldtest.replace('#include "modern_cpu_kernel_lifecycle_v3.c"','#include "modern_cpu_kernel_lifecycle_v4.c"').replace('VZKernelCPU *active=f.vm->activeCPU;f.vm->activeCPU=NULL;','VZKernelCPURegistryEntryV4 *active=f.vm->cpuRegistry;f.vm->cpuRegistry=NULL;').replace('f.vm->activeCPU=active;','f.vm->cpuRegistry=active;')
 assert oldtest!=newtest and 'activeCPU' not in newtest
 (source/'test-modern-cpu-owned-pending-v3-on-v4.c').write_text(newtest)
 (out/'pending-regression-fixture-delta.diff').write_text(''.join(difflib.unified_diff(oldtest.splitlines(keepends=True),newtest.splitlines(keepends=True),fromfile='immutable-v3-fixture',tofile='v4-registry-fixture')))
 oldtest=(source/'test-modern-cpu-callback-lifetime-v3.c').read_text()
 needle='''        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_OK);
        VZKernelCPU *other=(void *)1;CHECK(VZKernelCPUCreate(f.vm,&other,&r)==VZ_KERNEL_NOT_LIVE && !other);
        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_BUSY);
        CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_OK);++scenarios;'''
 replacement='''        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
        CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_BUSY);
        CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);f.cpu=NULL;
        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_OK);
        VZKernelCPU *other=(void *)1;CHECK(VZKernelCPUCreate(f.vm,&other,&r)==VZ_KERNEL_NOT_LIVE && !other);
        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_OK);++scenarios;'''
 assert oldtest.count(needle)==1;newtest=oldtest.replace(needle,replacement,1)
 (source/'test-modern-cpu-callback-lifetime-v3-on-v4.c').write_text(newtest)
 (out/'cleanup-drain-regression-fixture-delta.diff').write_text(''.join(difflib.unified_diff(oldtest.splitlines(keepends=True),newtest.splitlines(keepends=True),fromfile='immutable-v3-fixture',tofile='v4-drain-fixture')))
 legacy=N/'kernel-context-profiles-product-v2/source-freeze'
 for name in ['lifecycle_mock_tests.c','initialization-tests.c','system-tests.c','system-golden.inc']:
  p=legacy/name;assert priorPins[str(p.resolve())]==pin(p);inputs.append(pin(p));(source/name).write_bytes(p.read_bytes())
 inputs.append(pin(Path(__file__)));(out/'builder-snapshot.py').write_bytes(Path(__file__).read_bytes())
 def run(label,argv,san=False):
  argv=list(map(str,argv));env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  if san:env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0'
  child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
  try:stdout,stderr=child.communicate(timeout=30)
  except subprocess.TimeoutExpired:
   child.kill();stdout,stderr=child.communicate();(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr);raise
  (out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
  commands.append(dict(label=label,argv=argv,exit=child.returncode,directChildPID=child.pid,reaped=True))
  assert child.returncode==0,(label,stderr.decode(errors='replace'));return stdout,stderr
 sdk=run('macos-sdk',['xcrun','--sdk','macosx','--show-sdk-path'])[0].decode().strip()
 common=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-pthread','-isysroot',sdk,'-I',source]
 units=[source/name for name in ['modern_cpu_kernel_lifecycle_v4.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_native_fields.c','modern_cpu_kernel_initialization_v2.c','modern_cpu_kernel_system_v2.c']]
 for sanitized in [False,True]:
  suffix='-sanitized' if sanitized else '';san=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitized else []
  for name,macro in [('multicpu','VZ_MULTICPU_WHITEBOX'),('pending-regression','VZ_PENDING_WHITEBOX')]:
   test=source/('test-modern-cpu-multicpu-v4.c' if name=='multicpu' else 'test-modern-cpu-owned-pending-v3-on-v4.c')
   for white in [False,True]:
    label=name+('-whitebox' if white else '')+suffix;exe=out/label
    run(label+'-compile',common+(['-D'+macro] if white else [])+[test,*(units[1:] if white else units),'-o',exe]+san)
    stdout,stderr=run(label+'-run',[exe],sanitized);assert not stderr;j=json.loads(stdout)
    assert not j['full27Backend']
    if name=='multicpu':assert j['cases']==44 and j['checks']>1600 and not j['nativeMultiAllocationProved']
    else:assert j['checks']==(680 if white else 526) and j['scenarios']==(56 if white else 34)
    models.append(dict(model=label,result=j))
    if name=='multicpu':
     stdout,stderr=run(label+'-owner-exit',[exe,'--owner-exit'],sanitized);assert not stderr;j=json.loads(stdout);assert j['ownerExitCleanupTracked']
     models.append(dict(model=label+'-owner-exit',result=j))
  for name in ['test-modern-cpu-callback-lifetime-v3-on-v4.c','test-modern-cpu-initialization-boundary-v2.c']:
   label=Path(name).stem+suffix;exe=out/label;run(label+'-compile',common+[source/name,*units,'-o',exe]+san)
   stdout,stderr=run(label+'-run',[exe],sanitized);assert not stderr and stdout.endswith(b'PASS: 48 callback lifetime/release/failure/owner scenarios; local mocks only\n' if 'callback' in name else b'PASS: 4 stable, 48 final-callback rejection, 2 snapshot reentry, 168 read failures; local mocks only\n')
   models.append(dict(model=label,passed=True,scenarios=48 if 'callback' in name else 222,stdoutSHA256=hashlib.sha256(stdout).hexdigest()))
  for isa in [1,2]:
   for name in ['lifecycle_mock_tests.c','initialization-tests.c','system-tests.c']:
    label='legacy-'+Path(name).stem+'-isa'+str(isa)+suffix;exe=out/label
    run(label+'-compile',common+['-DVM27_MODEL_NATIVE_ISA='+str(isa),source/name,*units,'-o',exe]+san)
    stdout,stderr=run(label+'-run',[exe],sanitized);assert not stderr;j=json.loads(stdout);assert j.get('failed',0)==0 and j.get('result','PASS')=='PASS'
    models.append(dict(model=label,nativeISA=isa,sanitized=sanitized,result=j))
 macObjects=[]
 for unit in units:
  obj=out/(unit.stem+'-mac.o');run(unit.stem+'-mac-object',common+['-c',unit,'-o',obj]);macObjects.append(obj)
 cxx=out/'cxx-model';run('cxx-link',['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-pthread','-isysroot',sdk,'-I',source,source/'test-modern-cpu-owned-pending-v3.cpp',*macObjects,'-o',cxx]);run('cxx-run',[cxx])
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-pthread','-I',source];objects=[]
 for unit in units:
  obj=out/(unit.stem+'-ios.o');run(unit.stem+'-ios-object',ios+(['-fvisibility=hidden'] if 'pending_interrupt_values' in unit.name else [])+['-c',unit,'-o',obj]);objects.append(obj)
 candidate=out/'VM27KernelOwnedMultiCPUV4.dylib'
 run('ios-link',ios+['-dynamiclib',*objects,'-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-install_name,@rpath/VM27KernelOwnedMultiCPUV4.dylib','-Wl,-current_version,4.0','-Wl,-compatibility_version,4.0','-o',candidate])
 run('adhoc-sign',['codesign','--force','--sign','-',candidate]);run('strict-sign',['codesign','--verify','--strict',candidate]);sign=run('signature',['codesign','-d','--verbose=4',candidate])[1].decode()
 ents=run('entitlements',['codesign','-d','--entitlements',':-',candidate])[0];assert not ents or plistlib.loads(ents)=={}
 run('dyld-validate',['xcrun','dyld_info','-validate_only',candidate])
 symbols=lambda b:sorted(line.split()[-1] for line in b.decode().splitlines() if line.split())
 exports=symbols(run('exports',['xcrun','nm','-gU',candidate])[0]);assert exports==baseline['exports'] and len(exports)==21
 allSymbols=run('all-symbols',['xcrun','nm','-m',candidate])[0].decode()
 assert '_VZCPUPlanControl0EntryValueV1' not in allSymbols and '_VZCPUPlanControl0ReturnValueV1' not in allSymbols
 assert 'private external' in next(line for line in allSymbols.splitlines() if '_VZCPUSetPendingInterruptValueV1' in line)
 imports=symbols(run('undefined',['xcrun','nm','-u',candidate])[0]);oldImports=baseline['undefinedImports']
 added=sorted(set(imports)-set(oldImports));removed=sorted(set(oldImports)-set(imports));assert added==['_pthread_equal','_pthread_self'] and not removed,(added,removed)
 deps=run('dependencies',['otool','-L',candidate])[0].decode().splitlines()[1:];assert len(deps)==2 and any('/usr/lib/libSystem.B.dylib' in x for x in deps)
 assert '_VZCPU27KernelTrapRaw' not in exports+imports
 for row in inputs:assert pin(Path(row['path']))==row
 result=dict(schema='V4 own multi-CPU lifecycle local mock and strict iOS product v1',candidate=pin(candidate),sourceInputs=inputs,sourceSnapshots=[pin(p) for p in sorted(source.iterdir())],
  unchangedFunctionBodies=unchanged,nativeTrapCallExpressionsByteExactWithV3=True,nativeOp6RequestFixedZero=True,nativeOp7ArgumentNULL=True,
  actualPthreadSeal=True,privateRegistryVMStableEpochCPUGeneration=True,retainedDeadHandlesBlockVMDestroy=True,
  pendingRejectsAllPrivateAliases=True,pendingNativeCalls=0,pendingNativeReads=0,pendingNativeWrites=0,callbacksOutsideVMMutex=True,
  exports=exports,publicExportsUnchanged=True,undefinedImports=imports,addedImports=added,removedImports=removed,dependencies=deps,signingIdentity=sign,entitlements={},
  modelResults=models,commands=commands,CPlusPlusCLinkAndExecution=True,
  nativeMultiCPUAllocationProved=False,requestSlotExpansion=False,publicHVCPUIdsCreated=False,leaseAdded=False,USEROrVIEWConstructed=False,nativeRunAdded=False,runAllowedChanged=False,
  realNativeCalls=0,providerLoaded=False,deviceOperations=0,currentOriginalVMMIntegrated=False,kernelDefaultsUsed=False,full27Backend=False)
 (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
 (out/'freeze.json').write_text(json.dumps({'files':[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]},indent=2)+'\n')
 print(json.dumps({'candidate':pin(candidate),'manifest':pin(out/'candidate.json'),'freeze':pin(out/'freeze.json'),'models':len(models),'publicExports':len(exports)}))
if __name__=='__main__':main()
