"""Compile true old-context mask port; actual native callbacks are mocked."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
S=Path(__file__).resolve().parent;N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v15.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c',
 'modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c','modern_gic_v3_engine_v1.c']
EXTRA=['modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c',
 'modern_cpu_config_capability_query_v1.S']
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 a=argparse.ArgumentParser();a.add_argument('--output',required=True);args=a.parse_args();D=Path(args.output).resolve()
 if D.parent!=N.resolve():raise ValueError('new diagnostic directory required')
 D.mkdir(exist_ok=False);steps=[]
 parent=pin(N/'cpu-gic-factory-integration-local-v8/candidate.json');p=json.loads(Path(parent['path']).read_text())
 for expected in p['sourceInputs']:
  if pin(expected['path'])!=expected:raise ValueError('parent actual production source drift '+expected['path'])
 fixture=D/'fixture-lifecycle-v20.c';production=D/'production-lifecycle-v20.c'
 fixture.write_text('#include "modern_cpu_kernel_lifecycle_v18.h"\n'
  '#include "modern_cpu_kernel_lifecycle_v16.c"\n#include "modern_cpu_kernel_physical_timer_v16.inc"\n'
  '#include "modern_cpu_kernel_wake_owner_v17.inc"\nextern bool FixturePhysicalCounterV18(void *,uint64_t *);\n'
  '#define VZKernelReadPhysicalCounterV16 FixturePhysicalCounterV18\n'
  '#include "modern_cpu_kernel_gic_owner_v18.inc"\n#undef VZKernelReadPhysicalCounterV16\n'
  '#include "modern_cpu_kernel_gic_run_v18.inc"\n'
  'VZKernelCPUGICOwnerV18 *FixtureActualGICOwnerV18(VZKernelCPU *cpu){return GICFindOwnerV18(cpu);}\n'
  '#include "modern_cpu_kernel_vtimer_mask_v20.h"\n#include "modern_cpu_kernel_vtimer_mask_v20.inc"\n')
 production.write_text('#include "modern_cpu_kernel_lifecycle_v18.c"\n'
  '#include "modern_cpu_kernel_vtimer_mask_v20.h"\n#include "modern_cpu_kernel_vtimer_mask_v20.inc"\n')
 def run(label,argv):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  r=subprocess.run(list(map(str,argv)),env=env,capture_output=True,timeout=45)
  (D/(label+'.stdout')).write_bytes(r.stdout);(D/(label+'.stderr')).write_bytes(r.stderr)
  steps.append(dict(label=label,argv=list(map(str,argv)),exit=r.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
  (D/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
  if r.returncode:raise ValueError(label+' failed; preserve failed attempt')
  return r.stdout
 try:
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-I',S]
  def closure(raw):
   values=set()
   for line in raw.decode().replace('\\\n',' ').splitlines():
    for item in line.split(':',1)[1].split():values.add(Path(item).resolve())
   values.update(S/name for name in UNITS+EXTRA)
   return [pin(x) for x in sorted(values)]
  depArgs=ios+['-MM',production,S/'modern_cpu_native_public_factory_v15.c',S/'modern_gic_v3_engine_v1.c']
  before=closure(run('actual-dependencies-before',depArgs));results=[]
  common=['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror','-fno-objc-arc','-I',S,'-DVM27_CPU_CONFIG_TESTING=1']
  for mode,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=D/mode;run(mode+'-compile',common+flags+[*[S/x for x in UNITS],fixture,S/'test-modern-cpu-vtimer-mask-v20.m','-framework','CoreFoundation','-lobjc','-o',exe])
   results.append(json.loads(run(mode+'-run',[exe]).splitlines()[-1]))
  if results[0]!=results[1]:raise ValueError('normal/SAN mismatch')
  objects=[]
  for source in [*[S/x for x in UNITS+EXTRA],production]:
   obj=D/('ios-'+source.stem+'.o');objects.append(obj)
   run('ios-'+source.stem,ios+(['-fno-objc-arc'] if source.suffix=='.m' else [])+['-c',source,'-o',obj])
  dylib=D/'VM27VtimerMaskV20.dylib';run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-install_name,@rpath/VM27VtimerMaskV20.dylib','-o',dylib])
  run('ios-validate',['xcrun','dyld_info','-validate_only',dylib])
  after=closure(run('actual-dependencies-after',depArgs))
  if before!=after:raise ValueError('actual production include closure changed')
  for expected in p['sourceInputs']:
   if pin(expected['path'])!=expected:raise ValueError('parent changed during local model')
  report=dict(schema='actual owned native6d8 mask port local v20',finiteLocalScopePassed=True,findings=[],
   parentActualOwnerCandidate=parent,sourceInputs=after,actualIncludeClosureBeforeAfterUnchanged=True,
   maskRawDispatchSemanticProof=pin(N/'vtimer-mask-raw-dispatch-semantic-offline-v1/report.json'),
   maskRawDispatchSemanticFreeze=pin(N/'vtimer-mask-raw-dispatch-semantic-offline-v1/freeze.json'),
   builder=pin(__file__),fixture=pin(S/'test-modern-cpu-vtimer-mask-v20.m'),hostResults=results,
   steps=steps,actualIOSProvider=pin(dylib),fixtureOnlyCounterBinding=pin(fixture),
   true6d8ReadModifyWrite=True,nativeDirtyAndReadyUnchanged=True,partialWritePoisonsActualOwner=True,
   native8Or9Or10InvokedByMaskPort=False,actualNativeCalls=0,deviceOperations=0,
   providerSigned=False,providerLoaded=False,publicMaskAPIIntegrated=False,rawExitClassified=False,
   fullTimerDelivery=False,fullPublicRunEquivalent=False,full27Backend=False)
  (D/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(dict(candidate=pin(D/'candidate.json'),provider=pin(dylib),hostResults=results)))
 except BaseException as e:
  (D/'failure.json').write_text(json.dumps(dict(error=str(e),steps=steps),indent=2)+'\n');raise
if __name__=='__main__':main()
