"""Bounded local C0 protocol fixtures and inert arm64e provider, never device."""
from pathlib import Path
import argparse,hashlib,json,os,re,struct,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v12.c','modern_cpu_kernel_lifecycle_v14.c',
 'modern_cpu_kernel_initialization_v3.c','modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c',
 'modern_cpu_kernel_system_v3.c','modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m',
 'modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c']
IOS_EXTRA=['modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']
FROZEN=[S/x for x in ['modern_cpu_native_public_factory_v8.c','modern_cpu_native_public_factory_v9.c',
 'modern_cpu_native_public_factory_v10.c','modern_cpu_native_public_factory_v11.c',
 'modern_cpu_kernel_lifecycle_v11.c','modern_cpu_kernel_lifecycle_v12.c','modern_cpu_kernel_lifecycle_v13.c',
 'modern_cpu_native_public_factory_vtimer_v10.inc','modern_cpu_kernel_vtimer_v12.inc',
 'modern_cpu_native_public_factory_debug_v11.inc','modern_cpu_kernel_debug_v13.inc']]
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);a=ap.parse_args();d=Path(a.output).resolve()
 if d.parent!=N.resolve():raise ValueError('new local diagnostic folder required')
 d.mkdir(exist_ok=False);before=[pin(p) for p in FROZEN];steps=[]
 def need(v,s):
  if not v:raise ValueError(s)
 def run(label,argv):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  p=subprocess.run(list(map(str,argv)),capture_output=True,env=env,timeout=30)
  (d/(label+'.stdout')).write_bytes(p.stdout);(d/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,argv=list(map(str,argv)),exit=p.returncode,
   stdout=pin(d/(label+'.stdout')),stderr=pin(d/(label+'.stderr'))))
  (d/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
  need(p.returncode==0,label+' failed; preserve this attempt');return p.stdout
 try:
  common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror',
   '-DVM27_CPU_CONFIG_TESTING=1','-I',S]
  host=[]
  for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=d/label;run(label+'-compile',common+flags+[S/x for x in UNITS]+[S/'test-modern-cpu-hv-pending-factory-v12.m',
    '-framework','CoreFoundation','-lobjc','-o',exe])
   receipt=json.loads(run(label+'-run',[exe]).splitlines()[-1]);host.append(dict(mode=label,receipt=receipt))
   need(receipt['CFcreated']==receipt['CFdestroyed']==39 and receipt['actualNativeCalls']==0,'finite true pending fixture')
   objects=[]
   for name in UNITS:
    obj=d/(label+'-fault-'+Path(name).stem+'.o');objects.append(obj)
    renamed=['-DVZKernelCPUReleaseBorrowV5=OwnRealCPUReleaseBorrow'] if name=='modern_cpu_kernel_lifecycle_v14.c' else []
    run(label+'-fault-'+Path(name).stem,common+flags+renamed+['-c',S/name,'-o',obj])
   fault=d/(label+'-release-failure')
   run(label+'-fault-link',common+flags+['-DVM27_PENDING_RELEASE_TEST=1',*objects,
    S/'test-modern-cpu-hv-pending-factory-v12.m','-framework','CoreFoundation','-lobjc','-o',fault])
   result=json.loads(run(label+'-fault-run',[fault]).splitlines()[-1]);host.append(dict(mode=label+'-release-failure',receipt=result))
   need(result['CFcreated']==result['CFdestroyed']==42 and result['releaseFaultInjected'],'real retained release failure')
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
   '-std=c11','-Wall','-Wextra','-Werror','-I',S]
  objects=[]
  for name in UNITS+IOS_EXTRA:
   obj=d/('ios-'+Path(name).stem+'.o');objects.append(obj)
   public=name in ['modern_cpu_native_public_factory_v12.c','modern_cpu_config_os_object_v5.m']
   run('ios-'+Path(name).stem,ios+([] if public else ['-fvisibility=hidden'])+
    (['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
  ancestor=N/'cpu-hv-debug-factory-local-v1/candidate.json';previous=json.loads(ancestor.read_text())
  own=sorted(previous['exactOwnExports']+['VM27CPUFactoryBorrowPendingInterruptV12'])
  public=sorted(previous['exactPublicHVExports']+['hv_vcpu_get_pending_interrupt','hv_vcpu_set_pending_interrupt'])
  exports=sorted(own+public);need(len(exports)==49,'actual public16 plus own33 symbols')
  exportfile=d/'exports.txt';exportfile.write_text(''.join('_'+x+'\n' for x in exports))
  provider=d/'VM27CPUFactoryHVPublicV12.dylib'
  run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip',
   '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exportfile),
   '-Wl,-install_name,@rpath/VM27CPUFactoryHVPublicV12.dylib','-o',provider])
  run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
  symbols=run('ios-exports',['xcrun','nm','-gU',provider]);imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider])
  need(sorted(x.split()[-1].decode() for x in symbols.splitlines() if x.split())==['_'+x for x in exports],'actual exact49 exports')
  need(not re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports),'independent framework imports')
  raw=provider.read_bytes();at=32
  for _ in range(struct.unpack_from('<I',raw,16)[0]):
   cmd,size=struct.unpack_from('<II',raw,at);need(cmd!=0x1d,'unsigned candidate');at+=size
  cpp=d/'typed-caller.cpp';cpp.write_text('#include "modern_cpu_native_public_factory_v12.h"\n'
   'static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_interrupt_type_t)==4 && sizeof(bool)==1,"SDK ABI");\n'
   'static_assert(HV_INTERRUPT_TYPE_IRQ==0 && HV_INTERRUPT_TYPE_FIQ==1,"SDK enum");\n'
   'extern "C" hv_return_t pending_caller(hv_vcpu_t cpu,hv_interrupt_type_t type,bool value,bool *out,unsigned action){\n'
   'hv_return_t (*get)(hv_vcpu_t,hv_interrupt_type_t,bool*)=hv_vcpu_get_pending_interrupt;\n'
   'hv_return_t (*set)(hv_vcpu_t,hv_interrupt_type_t,bool)=hv_vcpu_set_pending_interrupt;\n'
   'hv_return_t (*run)(hv_vcpu_t)=hv_vcpu_run;return action==0?get(cpu,type,out):action==1?set(cpu,type,value):run(cpu);}\n')
  for sdk in ['macosx','iphoneos']:
   obj=d/(sdk+'-typed-caller.o');flags=['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []
   run(sdk+'-cpp-caller',['xcrun','--sdk',sdk,'clang++','-std=c++17','-Wall','-Wextra','-Werror',*flags,'-I',S,'-c',cpp,'-o',obj])
   syms=run(sdk+'-cpp-symbols',['xcrun','nm','-u',obj])
   need(sorted(line.split()[-1] for line in syms.splitlines() if line.split())==
    [b'_hv_vcpu_get_pending_interrupt',b'_hv_vcpu_run',b'_hv_vcpu_set_pending_interrupt'],'true three unmangled SDK entries')
  need([pin(p) for p in FROZEN]==before,'frozen Factory and lifecycle source unchanged')
  inputs=[Path(__file__),S/'test-modern-cpu-hv-pending-factory-v12.m',S/'test-modern-cpu-hv-public-factory-v8.m',
   S/'modern_cpu_kernel_pending_run_v14.inc',S/'modern_cpu_native_public_factory_pending_v12.inc',
   *[S/x for x in UNITS+IOS_EXTRA],*FROZEN]+list(S.glob('modern_cpu*.h'))
  result=dict(schema='Factory12 Life14 real old C0 pending protocol plus true SDK pending accessors v1',
   candidate=pin(provider),ancestor=pin(ancestor),exactPublicHVExports=public,exactOwnExports=own,
   originalPendingContract=pin(N/'native-pending-control-return-contract-v1/contract.json'),
   publicPendingABI='get(hv_vcpu_t,hv_interrupt_type_t,bool*); set(hv_vcpu_t,hv_interrupt_type_t,bool)',
   pendingIRQMask='0x80',pendingFIQMask='0x40',realOwnPendingState=True,entryControlWrites=[0x670,0x678,0x670,0x748],
   returnControlWrites=[0x670,0x678,0x670,0x748],cleanupReloadsRealPostReturnControl0=True,
   cleanupRunsOnNonzeroNative9Status=True,returnClearsBothPendingBeforeControlRead=True,
   native9PerRun=1,native8AddedToPendingProtocol=False,automaticRetry=False,initialCancellationImplemented=False,
   zeroPendingSkipsControlSlices=True,realOwnerBorrowEpochGenerationVersionGated=True,
   nativeMappingPermissionChecks=True,partialWriteFailurePoisonsAndWithdrawsBothRegistries=True,
   failedCleanupPoisonsAndRetainsNativeCPU=True,failedReleaseRetainsActualBorrowInOwnerTLS=True,
   publicGetterStagesUntilSuccessfulBorrowRelease=True,hostResults=host,steps=steps,
   providerUnsigned=True,providerSigned=False,providerLoaded=False,strongRootOutputGuardLinked=False,
   inheritedTimerAndDebugSourceUnchanged=True,fullPublicRunEquivalent=False,fullTimerGICAndVIEW=False,
   architecturalResetComplete=False,originalVMMIntegrated=False,full27Backend=False,
   actualNativeCalls=0,deviceOperations=0,guestInstructions=0,frozenInputsUnchanged=before,
   inputs=[pin(p) for p in sorted(set(inputs))])
  (d/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(dict(candidate=pin(d/'candidate.json'),provider=pin(provider),exports=len(exports),hostResults=host)))
 except BaseException as error:
  (d/'failure.json').write_text(json.dumps(dict(error=str(error),steps=steps,frozenBefore=before,
   frozenAfter=[pin(p) for p in FROZEN]),indent=2)+'\n');raise
if __name__=='__main__':main()
