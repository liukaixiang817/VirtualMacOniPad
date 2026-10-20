"""Real retained registry wake owner tests, plus unsigned offline arm64e code."""
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
 D.mkdir(exist_ok=False);steps=[];base=N/'vm-hv-public-bootstrap-integration-local-v6/freeze.json'
 before=pin(base);frozen=json.loads(base.read_text())
 def frozenCheck():
  if pin(base)!=before:raise ValueError('Root6 frozen receipt drift')
  for x in frozen['sourceInputs']:
   if pin(x['path'])!=x:raise ValueError('Root6 frozen source drift: '+x['path'])
 frozenCheck();wrapper=D/'wake-lifecycle-wrapper.c'
 wrapper.write_text('#include "modern_cpu_kernel_wake_owner_v17.h"\n#include "modern_cpu_kernel_lifecycle_v14.c"\n#include "modern_cpu_kernel_wake_owner_v17.inc"\n')
 def run(label,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  p=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=30)
  (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,argv=list(map(str,args)),exit=p.returncode));(D/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
  if p.returncode:raise ValueError(label+' failed; preserve attempted build')
  return p.stdout
 try:
  common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror','-I',S,
   '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1','-DVM27_HV_VM_GUARD_LINKED=1'];results=[]
  for name,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=D/name;run(name+'-compile',common+flags+[*[S/n for n in UNITS],wrapper,S/'test-modern-cpu-wake-owner-v17.m','-framework','CoreFoundation','-lobjc','-o',exe])
   results.append(json.loads(run(name+'-run',[exe]).splitlines()[-1]))
  # Condition variables may wake spuriously, so the exact CHECK count can vary.
  if [{k:v for k,v in r.items() if k!='checks'} for r in results][0]!=[{k:v for k,v in r.items() if k!='checks'} for r in results][1]:raise ValueError('semantic results differ')
  obj=D/'ios-wake-lifecycle.o';dep=D/'ios-wake-lifecycle.d'
  run('ios-compile',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-fvisibility=hidden','-DVM27_HV_VM_GUARD_LINKED=1','-I',S,'-MMD','-MF',dep,'-c',wrapper,'-o',obj])
  asm=run('ios-counter-frequency-assembly',['xcrun','llvm-objdump','--disassemble','--symbolize-operands',obj])
  if b'CNTFRQ_EL0' not in asm:raise ValueError('actual counter frequency instruction absent')
  frozenCheck();inputs=sorted(set(Path(x).resolve() for x in dep.read_text().replace('\\\n',' ').split(':',1)[1].split()))
  c=dict(schema='retained native operation10 asynchronous wake owner V17 candidate',hostResults=results,
   sourceInputs=[pin(p) for p in inputs],test=pin(S/'test-modern-cpu-wake-owner-v17.m'),builder=pin(__file__),iosObject=pin(obj),
   root6FrozenReceipt=before,strongVMGuardLinked=True,actualV5BorrowHeld=True,CPUOperationGuardIntentionallyNotTakenForWake=True,
   exactActualRegistryIdentityAnd64BitNativeVersionChecked=True,arbitraryMasksRejected=True,
   signalGateDrainRequiredBeforeOwnerThreadBorrowRelease=True,counterFrequencyCompiledDeviceAccessUnproved=True,
   wakeDoesNotInjectIRQ=True,actualNativeCalls=0,deviceOperations=0,fullRun=False,steps=steps)
  (D/'candidate.json').write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(dict(candidate=pin(D/'candidate.json'),results=results)))
 except BaseException as e:
  (D/'failure.json').write_text(json.dumps(dict(error=str(e),steps=steps),indent=2)+'\n');raise
if __name__=='__main__':main()
