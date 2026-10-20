"""Build and test a new inert CPU candidate. Never sign, load or call iOS."""
from pathlib import Path
import argparse, hashlib, json, os, re, struct, subprocess, sys

R = Path(__file__).resolve().parents[3]
S = Path(__file__).resolve().parent
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS = ['modern_cpu_native_public_factory_v11.c', 'modern_cpu_kernel_lifecycle_v13.c',
 'modern_cpu_kernel_initialization_v3.c', 'modern_cpu_native_fields.c',
 'modern_cpu_pending_interrupt_values_v1.c', 'modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c', 'modern_cpu_config_os_object_v5.m',
 'modern_cpu_native_self_memory_v1.c', 'modern_vm_memory_packet.c', 'modern_cpu_native_capability_seed.c']
IOS_EXTRA = ['modern_cpu_config_capability_acquisition_v2.c', 'modern_cpu_tlbi_capability_values_v1.c',
 'modern_cpu_config_capability_query_v1.S']
FROZEN = [S / x for x in ['modern_cpu_native_public_factory_v8.c',
 'modern_cpu_native_public_factory_v9.c', 'modern_cpu_kernel_lifecycle_v11.c','modern_cpu_native_public_factory_v10.c','modern_cpu_kernel_lifecycle_v12.c','modern_cpu_native_public_factory_vtimer_v10.inc','modern_cpu_kernel_vtimer_v12.inc']]

def pin(path):
 p = Path(path).resolve(); b = p.read_bytes()
 return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def main():
 parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True)
 args = parser.parse_args(); d = Path(args.output).resolve()
 if d.parent != N.resolve(): raise ValueError('new local diagnostic folder required')
 d.mkdir(exist_ok=False)
 before = [pin(p) for p in FROZEN]; steps = []
 def need(condition, description):
  if not condition: raise ValueError(description)
 def run(label, argv):
  env = {k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1',
   PYTHONDONTWRITEBYTECODE='1')
  p = subprocess.run(list(map(str,argv)), capture_output=True, env=env, timeout=30)
  (d / (label+'.stdout')).write_bytes(p.stdout); (d / (label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label, args=list(map(str,argv)), exit=p.returncode,
   stdout=pin(d/(label+'.stdout')), stderr=pin(d/(label+'.stderr'))))
  (d/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
  need(p.returncode == 0, label+' failed; preserve this attempt and use a new output folder')
  return p.stdout
 try:
  common = ['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc',
   '-Wall','-Wextra','-Werror','-I',S,'-DVM27_CPU_CONFIG_TESTING=1']
  results = []
  for label, flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=d/label
   run(label+'-compile',common+flags+[S/x for x in UNITS]+[S/'test-modern-cpu-hv-debug-factory-v11.m',
    '-framework','CoreFoundation','-lobjc','-o',exe])
   result=json.loads(run(label+'-run',[exe]).splitlines()[-1]);results.append(result)
   need(result['CFcreated']==result['CFdestroyed']==12 and result['nativeCallsExecuted']==0,'actual vtimer fixture')
   old=d/(label+'-factory8-regression')
   run(label+'-factory8-compile',common+flags+[S/x for x in UNITS]+[S/'test-modern-cpu-hv-public-factory-v8.m',
    '-framework','CoreFoundation','-lobjc','-o',old])
   old_result=json.loads(run(label+'-factory8-run',[old]).splitlines()[-1])
   need(old_result['CFcreated']==old_result['CFdestroyed']==3,'original Factory8 regression')
   results.append(dict(originalFactory8=old_result))
   # Own fault fixture only: rename exactly the lifecycle release declaration
   # and body in this one object. Factory10 still calls the original symbol,
   # supplied by the fault fixture; the iOS production object is never renamed.
   objects=[]
   for name in UNITS:
    obj=d/(label+'-release-'+Path(name).stem+'.o');objects.append(obj)
    renamed=['-DVZKernelCPUReleaseBorrowV5=OwnRealCPUReleaseBorrow'] if name=='modern_cpu_kernel_lifecycle_v13.c' else []
    run(label+'-release-'+Path(name).stem,common+flags+renamed+['-c',S/name,'-o',obj])
   exe=d/(label+'-release-failure')
   run(label+'-release-compile',common+flags+['-DVM27_VTIMER_RELEASE_TEST=1',*objects,
    S/'test-modern-cpu-hv-debug-factory-v11.m','-framework','CoreFoundation','-lobjc','-o',exe])
   fault=json.loads(run(label+'-release-run',[exe]).splitlines()[-1]);results.append(dict(releaseFault=fault))
   need(fault['CFcreated']==fault['CFdestroyed']==15 and fault['releaseFaultInjected'],'actual release retention fixture')
  stub=d/'unused-acquisition.c'
  stub.write_text('#include "modern_cpu_config_capability_acquisition_v2.h"\n#include <stdlib.h>\n'
   'void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *p){(void)p;abort();}\n')
  exe=d/'legacy-regression'
  run('legacy-compile',common+[S/x for x in UNITS]+[S/'test-modern-cpu-native-run-producer-v3.m',stub,
   '-framework','CoreFoundation','-lobjc','-o',exe])
  legacy=json.loads(run('legacy-run',[exe]).splitlines()[-1]);need(legacy['created']==legacy['destroyed']==8,'legacy finite regression')
  caller=d/'typed-caller.c'
  caller.write_text('#include "modern_cpu_native_public_factory_v11.h"\n'
   '_Static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_return_t)==4 && sizeof(bool)==1,"public ABI");\n'
   'hv_return_t call_debug(hv_vcpu_t c,bool v){hv_return_t (*f1)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_exceptions;hv_return_t (*f2)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_reg_accesses;return (v?f1:f2)(c,v);}\n')
  run('mac-sdk-c-prototype',['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror','-I',S,'-c',caller,'-o',d/'mac-caller.o'])
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
   '-std=c11','-Wall','-Wextra','-Werror','-I',S]
  run('ios-c-prototype',ios+['-c',caller,'-o',d/'ios-caller.o'])
  cpp=d/'typed-caller.cpp'
  cpp.write_text('#include "modern_cpu_native_public_factory_v11.h"\n'
   'static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_return_t)==4 && sizeof(bool)==1,"public ABI");\n'
   'extern "C" hv_return_t call_debug_cpp(hv_vcpu_t c,bool v){hv_return_t (*f1)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_exceptions;hv_return_t (*f2)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_reg_accesses;return (v?f1:f2)(c,v);}\n')
  run('ios-cpp-prototype',['xcrun','--sdk','iphoneos','clang++','-arch','arm64e',
   '-miphoneos-version-min=16.1','-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-c',cpp,'-o',d/'ios-cpp-caller.o'])
  caller_symbols=run('ios-cpp-caller-symbols',['xcrun','nm','-u',d/'ios-cpp-caller.o'])
  need(sorted(line.split()[-1] for line in caller_symbols.splitlines() if line.split())==[b'_hv_vcpu_set_trap_debug_exceptions',b'_hv_vcpu_set_trap_debug_reg_accesses'],'two exact unmangled C symbols')
  objects=[]
  for name in UNITS+IOS_EXTRA:
   obj=d/('ios-'+Path(name).stem+'.o');objects.append(obj)
   exported=name in ['modern_cpu_native_public_factory_v11.c','modern_cpu_config_os_object_v5.m']
   run('ios-'+Path(name).stem,ios+([] if exported else ['-fvisibility=hidden'])+
    (['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
  headers=[S/('modern_cpu_native_public_factory_v'+str(v)+'.h') for v in range(2,12)]+[S/'modern_cpu_config_os_object_v3.h']
  own=sorted(set(name for h in headers for name in re.findall(r'(VM27CPU(?:Factory|Config)\w+)\(',h.read_text())))
  public=['hv_vcpu_config_create','hv_vcpu_create','hv_vcpu_destroy','hv_vcpu_set_reg','hv_vcpu_get_reg',
   'hv_vcpu_set_simd_fp_reg','hv_vcpu_get_simd_fp_reg','hv_vcpu_set_sys_reg','hv_vcpu_get_sys_reg',
   'hv_vcpu_config_get_feature_reg','hv_vcpu_run','hv_vcpu_set_vtimer_offset','hv_vcpu_set_trap_debug_exceptions','hv_vcpu_set_trap_debug_reg_accesses']
  exports=sorted(own+public); export_file=d/'exports.txt';export_file.write_text(''.join('_'+v+'\n' for v in exports))
  provider=d/'VM27CPUFactoryHVPublicV11.dylib'
  run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip',
   '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(export_file),
   '-Wl,-install_name,@rpath/VM27CPUFactoryHVPublicV11.dylib','-o',provider])
  run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
  symbols=run('ios-exports',['xcrun','nm','-gU',provider])
  imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider])
  need(sorted(x.split()[-1].decode() for x in symbols.splitlines() if x.split())==['_'+v for v in exports], 'exact own + public12 exports')
  need(not re.search(rb'_hv_|Hypervisor|Virtualization|VirtualMachineMonitor',imports),'no framework CPU or VMM imports')
  raw=provider.read_bytes();at=32
  for _ in range(struct.unpack_from('<I',raw,16)[0]):
   command,size=struct.unpack_from('<II',raw,at);need(command!=0x1d,'unsigned candidate');at+=size
  need([pin(p) for p in FROZEN]==before,'frozen Factory8/9/Lifecycle11 unchanged')
  inputs=[Path(__file__),S/'test-modern-cpu-hv-debug-factory-v11.m',S/'test-modern-cpu-hv-public-factory-v8.m',
   *[S/x for x in UNITS+IOS_EXTRA],*[S/x for x in ['modern_cpu_native_public_factory_v9.c',
    'modern_cpu_kernel_lifecycle_v11.c','modern_cpu_kernel_vtimer_v12.inc','modern_cpu_native_public_factory_vtimer_v10.inc',
    'modern_cpu_native_public_factory_ram_adopt_v9.inc','modern_cpu_native_public_factory_debug_v11.inc','modern_cpu_kernel_debug_v13.inc','modern_cpu_native_public_factory_v10.c','modern_cpu_kernel_lifecycle_v12.c']]]
  inputs+=list(S.glob('modern_cpu*.h'))+[S/'modern_cpu_kernel_system_fields.inc',S/'modern_vm_memory_packet.h']
  result=dict(schema='Factory11 Lifecycle13 modern bool debug traps on real old native CONTROL2 source v1',
   candidate=pin(provider),providerUnsigned=True,providerLoaded=False,providerSigned=False,
   exactPublicHVExports=public,exactOwnExports=own,hostResults=results,legacyResult=legacy,
   oldNativeContextVersion=hex(0x206879700000000e),nativeOffset=0x688,dirtyOffset=0x748,dirtyMask=4,
   exactFour64BitWrites=True,controlReadBeforeFirstWrite=True,extraControlSyncWrites=True,modernFalsePreservesFull64=True,
   native8InThisAPI=False,native9InThisAPI=False,realOwnerEpochGenerationIdentityGated=True,
   actualSelfTaskMachMappingChecksExecuted=True,partialWriteFailurePoisonsAndWithdrawsIdentity=True,
   failedReleaseRetainsBorrowInOwnerTLS=True,outputNativeContextAliasRejected=True,
   frozenInputsUnchanged=before,inputs=[pin(p) for p in sorted(set(inputs))],steps=steps,
   architecturalResetComplete=False,fullPublicRunEquivalent=False,fullModernClockCompensationEquivalent=False,
   originalVMMIntegrated=False,full27Backend=False,deviceOperations=0,nativeCPUCallsExecuted=0,
   genuineGuestBootObserved=False,remainingDebugPublicAPIsImplemented=True,
   scope='Modern full64 debug flags on real old CONTROL2 with exact original old synchronization, retains Factory10 timer implementation; guest exception execution unproved')
  (d/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(dict(candidate=pin(d/'candidate.json'),provider=pin(provider),public=len(public),own=len(own),hostResults=results)))
 except BaseException as e:
  (d/'failure.json').write_text(json.dumps(dict(error=str(e),frozenBefore=before,frozenAfter=[pin(p) for p in FROZEN],steps=steps),indent=2)+'\n')
  raise

if __name__ == '__main__': main()
