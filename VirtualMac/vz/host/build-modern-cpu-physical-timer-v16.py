"""One real Root6 model fixture plus unsigned offline arm64e timer compilation."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
S=Path(__file__).resolve().parent;N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v12.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c',
 'modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c','vm27_hv_public_vm_bootstrap_v6.m']
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);a=ap.parse_args();D=Path(a.output).resolve()
 if D.parent!=N.resolve():raise ValueError('new diagnostic output required')
 D.mkdir(exist_ok=False);steps=[]
 baseline=N/'vm-hv-public-bootstrap-integration-local-v6/freeze.json';frozen=json.loads(baseline.read_text());before=pin(baseline)
 for expected in frozen['sourceInputs']:
  if pin(expected['path'])!=expected:raise ValueError('frozen Root6 source drift: '+expected['path'])
 wrapper=D/'timer-lifecycle-wrapper.c';wrapper.write_text('#include "modern_cpu_kernel_physical_timer_v16.h"\n#include "modern_cpu_kernel_lifecycle_v14.c"\n#include "modern_cpu_kernel_physical_timer_v16.inc"\n')
 def run(label,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  p=subprocess.run(list(map(str,args)),env=env,capture_output=True,timeout=30)
  (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,argv=list(map(str,args)),exit=p.returncode));(D/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
  if p.returncode:raise ValueError(label+' failed; preserve attempted build')
  return p.stdout
 try:
  results=[];common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror','-I',S,
   '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1','-DVM27_HV_VM_GUARD_LINKED=1']
  for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=D/label;run(label+'-compile',common+flags+[*[S/n for n in UNITS],wrapper,S/'test-modern-cpu-physical-timer-v16.m','-framework','CoreFoundation','-lobjc','-o',exe])
   results.append(json.loads(run(label+'-run',[exe]).splitlines()[-1]))
  if results[0]!=results[1]:raise ValueError('normal/sanitized results differ')
  obj=D/'ios-timer-lifecycle.o';dep=D/'ios-timer-lifecycle.d'
  run('ios-compile',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-fvisibility=hidden','-DVM27_HV_VM_GUARD_LINKED=1','-I',S,'-MMD','-MF',dep,'-c',wrapper,'-o',obj])
  run('ios-counter-assembly',['xcrun','llvm-objdump','--disassemble','--symbolize-operands',obj])
  if pin(baseline)!=before:raise ValueError('Root6 receipt changed')
  for expected in frozen['sourceInputs']:
   if pin(expected['path'])!=expected:raise ValueError('frozen Root6 source changed: '+expected['path'])
  inputs=sorted(set(Path(x).resolve() for x in dep.read_text().replace('\\\n',' ').split(':',1)[1].split()))
  result=dict(schema='private actual native physical timer owner V16 local candidate',root6FrozenReceipt=before,
   hostResults=results,strongVMGuardLinked=True,sourceInputs=[pin(p) for p in inputs],
   test=pin(S/'test-modern-cpu-physical-timer-v16.m'),builder=pin(__file__),iosObject=pin(obj),
   realNativeFields=['0x438 CNTP_CTL_EL02','0x3f0 CNTP_CVAL_EL02','0x748 dirty OR1'],
   actualPersistentV5Borrow=True,guestClockProfile='native CNTPCT with actual vtimer offset zero only',
   nativeCounterCompiledButDeviceAvailabilityUnproved=True,publicCNTPGICGateOpened=False,
   realGICRouterHookRequired=True,realDeadlineWakeHookRequired=True,quiescenceRequiredBeforeBorrowRelease=True,
   GICCallbacksInThisFixtureAreModels=True,fullGICImplemented=False,publicRunSYSEmulationImplemented=False,
   sourceOriginalCollection=pin(N/'cpu-physical-timer-boot-basis-v1/collection.json'),
   actualNativeCalls=0,deviceOperations=0,steps=steps)
  (D/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'candidate':pin(D/'candidate.json'),'tests':results}))
 except BaseException as e:
  (D/'failure.json').write_text(json.dumps(dict(error=str(e),steps=steps),indent=2)+'\n');raise
if __name__=='__main__':main()
