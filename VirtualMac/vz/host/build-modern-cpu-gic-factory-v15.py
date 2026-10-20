"""New actual-owner local integration, mocked native traps, never devices."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess
S=Path(__file__).resolve().parent;N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v15.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c',
 'modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c','modern_gic_v3_engine_v1.c']
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 a=argparse.ArgumentParser();a.add_argument('--output',required=True);args=a.parse_args();D=Path(args.output).resolve()
 if D.parent!=N.resolve():raise ValueError('new independent diagnostic folder required')
 D.mkdir(exist_ok=False);steps=[];before=pin(N/'vm-hv-public-bootstrap-integration-local-v8/freeze.json')
 frozen=json.loads(Path(before['path']).read_text())
 for expected in frozen['sourceInputs']:
  if pin(expected['path'])!=expected:raise ValueError('Root8 actual frozen source drift '+expected['path'])
 wrapper=D/'fixture-lifecycle.c';wrapper.write_text('#include "modern_cpu_kernel_lifecycle_v18.h"\n'
  '#include "modern_cpu_kernel_lifecycle_v16.c"\n#include "modern_cpu_kernel_physical_timer_v16.inc"\n'
  '#include "modern_cpu_kernel_wake_owner_v17.inc"\nextern bool FixturePhysicalCounterV18(void *,uint64_t *);\n'
  '#define VZKernelReadPhysicalCounterV16 FixturePhysicalCounterV18\n'
  '#include "modern_cpu_kernel_gic_owner_v18.inc"\n#undef VZKernelReadPhysicalCounterV16\n'
  '#include "modern_cpu_kernel_gic_run_v18.inc"\n'
  'VZKernelCPUGICOwnerV18 *FixtureActualGICOwnerV18(VZKernelCPU *cpu){return GICFindOwnerV18(cpu);}\n')
 def run(label,argv):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  p=subprocess.run(list(map(str,argv)),env=env,capture_output=True,timeout=45)
  (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,argv=list(map(str,argv)),exit=p.returncode,
   stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
  (D/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
  if p.returncode:raise ValueError(label+' failed; preserve this attempt')
  return p.stdout
 try:
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11',
   '-Wall','-Wextra','-Werror','-I',S]
  def closure(dep):
   dependencies=set()
   for line in dep.decode().replace('\\\n',' ').splitlines():
    for value in line.split(':',1)[1].split():dependencies.add(Path(value).resolve())
   for name in UNITS+['modern_cpu_kernel_lifecycle_v18.c','modern_cpu_config_capability_acquisition_v2.c',
    'modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']:
    dependencies.add(S/name)
   return [pin(p) for p in sorted(dependencies)]
  depArgs=ios+['-MM',S/'modern_cpu_native_public_factory_v15.c',S/'modern_cpu_kernel_lifecycle_v18.c',S/'modern_gic_v3_engine_v1.c']
  sourceBefore=closure(run('actual-production-dependencies-before',depArgs))
  host=[];common=['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror','-fno-objc-arc',
   '-I',S,'-DVM27_CPU_CONFIG_TESTING=1']
  for mode,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=D/mode;run(mode+'-compile',common+flags+[*[S/x for x in UNITS],wrapper,
    S/'test-modern-cpu-gic-factory-v15.m','-framework','CoreFoundation','-lobjc','-o',exe])
   host.append(json.loads(run(mode+'-run',[exe]).splitlines()[-1]))
  if host[0]!=host[1]:raise ValueError('normal/SAN actual owner results differ')
  objects=[]
  extra=['modern_cpu_kernel_lifecycle_v18.c','modern_cpu_config_capability_acquisition_v2.c',
   'modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']
  for name in UNITS+extra:
   obj=D/('ios-'+Path(name).stem+'.o');objects.append(obj)
   run('ios-'+Path(name).stem,ios+(['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
  dylib=D/'VM27CPUFactoryGICV15.dylib';run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation',
   '-lobjc','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-install_name,@rpath/VM27CPUFactoryGICV15.dylib','-o',dylib])
  run('ios-validate',['xcrun','dyld_info','-validate_only',dylib])
  imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',dylib])
  if re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports):raise ValueError('forbidden native framework dependency')
  inputs=closure(run('actual-production-dependencies-after',depArgs))
  if inputs!=sourceBefore:raise ValueError('actual production include closure changed during this build')
  if pin(before['path'])!=before:raise ValueError('Root8 receipt changed')
  for expected in frozen['sourceInputs']:
   if pin(expected['path'])!=expected:raise ValueError('Root8 source changed '+expected['path'])
  candidate=dict(schema='Factory15 Life18 true owned GIC physical timer post-token integration local v1',
   finiteLocalScopePassed=True,findings=[],hostResults=host,steps=steps,sourceInputs=inputs,
   actualProductionIncludeClosureBeforeAfterUnchanged=True,
   root8FrozenSourceAncestry=before,fixtureCounterBindingMockOnly=pin(wrapper),builder=pin(__file__),
   fixture=pin(S/'test-modern-cpu-gic-factory-v15.m'),iosProvider=pin(dylib),
   actualNativeCalls=0,deviceOperations=0,providerUnsigned=True,providerLoaded=False,
   publicRunHasNoFixedIterationLimit=True,privateBoundedRunFixtureOnly=True,
   actualPrivateGICInstanceRetainsFactoryKernelBorrows=True,truePostTokenNativeRegisterAndPCWrites=True,
   mpidrSemanticProof=pin(N/'mpidr-public-control-semantic-offline-v1/report.json'),
   trueCancelBeforeRunDoesNotInvokeNative9=True,cancelSeparateFromTimerWake=True,
   cancelWithoutGICAttachmentUnsupported=True,virtualTimerRaw0Unsupported=True,
   HVC16Private3fAndTLBIHandlersUnimplemented=True,strongRootOutputGuardLinked=False,
   publicGICSDKAdapterProvidedByRoot=False,fullPublicRunEquivalent=False,full27Backend=False)
  (D/'candidate.json').write_text(json.dumps(candidate,indent=2)+'\n')
  print(json.dumps(dict(candidate=pin(D/'candidate.json'),iosProvider=pin(dylib),hostResults=host)))
 except BaseException as e:
  (D/'failure.json').write_text(json.dumps(dict(error=str(e),steps=steps),indent=2)+'\n');raise
if __name__=='__main__':main()
