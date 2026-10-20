"""Minimal RootBoot7 integration fixture and inert iOS build; no signing/device."""
from pathlib import Path
import argparse,hashlib,json,os,struct,re,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v13.c','modern_cpu_kernel_lifecycle_v15.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c',
 'modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c','vm27_hv_public_vm_bootstrap_v7.m']
IOS_EXTRA=['modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']
FROZEN=[S/x for x in ['vm27_hv_public_vm_bootstrap_v4.h','vm27_hv_public_vm_bootstrap_v4.m',
 'modern_cpu_native_public_factory_v9.c','modern_cpu_native_public_factory_v10.c','modern_cpu_native_public_factory_v11.c',
 'modern_cpu_kernel_lifecycle_v11.c','modern_cpu_kernel_lifecycle_v12.c','modern_cpu_kernel_lifecycle_v13.c',
 'modern_cpu_kernel_vtimer_v12.inc','modern_cpu_native_public_factory_vtimer_v10.inc',
 'modern_cpu_kernel_debug_v13.inc','modern_cpu_native_public_factory_debug_v11.inc',
 'modern_cpu_kernel_lifecycle_v14.h','modern_cpu_kernel_lifecycle_v14.c',
 'modern_cpu_native_public_factory_v12.h','modern_cpu_native_public_factory_v12.c',
 'modern_cpu_kernel_pending_run_v14.inc','modern_cpu_native_public_factory_pending_v12.inc',
 'vm27_hv_public_vm_bootstrap_v6.h','vm27_hv_public_vm_bootstrap_v6.m',
 'vm27_hv_public_vm_bootstrap_v5.h','vm27_hv_public_vm_bootstrap_v5.m']]
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
 d=Path(args.output).resolve()
 if d.parent!=N.resolve():raise ValueError('new local output required')
 d.mkdir(exist_ok=False);before=[pin(p) for p in FROZEN];steps=[]
 def need(v,s):
  if not v:raise ValueError(s)
 def run(label,argv):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  p=subprocess.run(list(map(str,argv)),capture_output=True,env=env,timeout=30)
  (d/(label+'.stdout')).write_bytes(p.stdout);(d/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,argv=list(map(str,argv)),exit=p.returncode,stdout=pin(d/(label+'.stdout')),stderr=pin(d/(label+'.stderr'))))
  (d/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n');need(p.returncode==0,label+' failed; preserve attempt')
  return p.stdout
 try:
  common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror','-I',S,
   '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1','-DVM27_HV_VM_GUARD_LINKED=1']
  host=[]
  for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=d/label;run(label+'-compile',common+flags+[S/x for x in UNITS]+[S/'test-vm27-hv-public-vm-bootstrap-v7.m',
    '-framework','CoreFoundation','-lobjc','-o',exe])
   receipt=json.loads(run(label+'-run',[exe]).splitlines()[-1]);host.append(receipt)
   need(receipt['combinedStrongGuard'] and receipt['sameOwnerAndVMEpoch'] and receipt['writerReentries']==28 and receipt['physicalClaimSameRootOwnerVMRAM'] and receipt['native9']==2 and receipt['pendingCleanupOnNativeError'] and receipt['native7FailureRetainsVMRAM'] and
    receipt['VMConfigCreated']==receipt['VMConfigDestroyed']==receipt['CPUConfigCreated']==receipt['CPUConfigDestroyed']==1 and
    receipt['nativeCallsExecuted']==0,'actual minimal RootBoot7 fixture')
  need(host[0]==host[1],'normal and sanitizer evidence agree')
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11',
   '-Wall','-Wextra','-Werror','-DVM27_HV_VM_GUARD_LINKED=1','-I',S]
  objects=[];include_closure=set()
  for name in UNITS+IOS_EXTRA:
   obj=d/(Path(name).stem+'.o');objects.append(obj);dep=d/(Path(name).stem+'.d')
   exported=name in ['modern_cpu_native_public_factory_v13.c','modern_cpu_config_os_object_v5.m','vm27_hv_public_vm_bootstrap_v7.m']
   run(Path(name).stem+'-ios-compile',ios+([] if exported else ['-fvisibility=hidden'])+
    (['-fno-objc-arc'] if name.endswith('.m') else [])+['-MMD','-MF',dep,'-c',S/name,'-o',obj])
   for token in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
    path=Path(token).resolve()
    if path.is_relative_to(S):include_closure.add(path)
  root4=N/'vm-hv-public-bootstrap-integration-local-v4/candidate.json'
  cpu12=N/'cpu-hv-pending-factory-local-v4/candidate.json'
  max_basis=N/'hv-framework-max-vcpu-contract-v1/original-body-audit.json'
  parent=json.loads(root4.read_text());cpu=json.loads(cpu12.read_text());max_audit=json.loads(max_basis.read_text())
  original=max_audit['original27ExactCacheWindows'][0]
  need(original['name']=='maximum-vCPU' and original['startRVA']=='0x2d00' and original['endRVA']=='0x2d10' and
   original['rawAndOriginalCacheByteEqual'] and original['instructions'][1]['operands']=='w8, [x0]', 'complete genuine16B four-byte output basis')
  own=cpu['exactOwnExports']+['VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13'];public=cpu['exactPublicHVExports'];
  root_names=[x for x in parent['exactExports'] if x not in own and x not in public]
  exports=sorted(set(own+public+root_names+['hv_vm_get_max_vcpu_count']))
  need(len(exports)==68,'real combined68 exports')
  export_file=d/'exports.txt';export_file.write_text(''.join('_'+x+'\n' for x in exports))
  provider=d/'VM27HVVMCPUCombinedV7.dylib'
  run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error',
   '-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(export_file),'-Wl,-install_name,@rpath/VM27HVVMCPUCombinedV7.dylib','-o',provider])
  run('ios-validate',['xcrun','dyld_info','-validate_only',provider]);symbols=run('ios-exports',['xcrun','nm','-gU',provider])
  imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider])
  need(sorted(x.split()[-1].decode() for x in symbols.splitlines() if x.split())==['_'+x for x in exports],'actual exact67 export set')
  need(not re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports),'no genuine HV/VMM import')
  raw=provider.read_bytes();at=32
  for _ in range(struct.unpack_from('<I',raw,16)[0]):
   command,size=struct.unpack_from('<II',raw,at);need(command!=0x1d,'unsigned candidate');at+=size
  cpp=d/'typed-root7-caller.cpp';cpp.write_text('#include "vm27_hv_public_vm_bootstrap_v7.h"\n'
   'static_assert(sizeof(hv_return_t)==4 && sizeof(bool)==1,"actual SDK ABI");\n'
   'extern "C" hv_return_t call_root7(hv_vcpu_t c,uint64_t offset,bool value,uint32_t *n,unsigned action){\n'
   ' hv_return_t (*timer)(hv_vcpu_t,uint64_t)=hv_vcpu_set_vtimer_offset;\n'
   ' hv_return_t (*exceptions)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_exceptions;\n'
   ' hv_return_t (*registers)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_reg_accesses;\n'
   ' hv_return_t (*maximum)(uint32_t *)=hv_vm_get_max_vcpu_count;\n'
   ' hv_return_t (*get)(hv_vcpu_t,hv_interrupt_type_t,bool*)=hv_vcpu_get_pending_interrupt;\n'
   ' hv_return_t (*set)(hv_vcpu_t,hv_interrupt_type_t,bool)=hv_vcpu_set_pending_interrupt;\n'
   ' hv_return_t (*run)(hv_vcpu_t)=hv_vcpu_run;bool pending=false;\n'
   ' static_assert(sizeof(hv_interrupt_type_t)==4,"actual enum");\n'
   ' VM27CPUFactoryMachStatusV2 (*claim)(VM27CPUFactoryBorrowV2 *,VZKernelDebugClaimActionV15,uint64_t,uint64_t *,VZKernelDebugClaimReceiptV15 *,VM27CPUFactoryDiagnosticV2 *)=VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13;\n'
   ' if(action==7){VZKernelDebugClaimReceiptV15 receipt={};uint64_t out=0;return claim(nullptr,VZ_KERNEL_DEBUG_CLAIM_READ_V15,0,&out,&receipt,nullptr); }\n'
   ' switch(action){case 0:return timer(c,offset);case 1:return exceptions(c,value);case 2:return registers(c,value);case 3:return get(c,HV_INTERRUPT_TYPE_IRQ,&pending);case 4:return set(c,HV_INTERRUPT_TYPE_FIQ,value);case 5:return run(c);default:return maximum(n);}}\n')
  for sdk in ['macosx','iphoneos']:
   obj=d/(sdk+'-typed-caller.o');flags=['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []
   run(sdk+'-typed-caller',['xcrun','--sdk',sdk,'clang++','-std=c++17','-Wall','-Wextra','-Werror',*flags,'-I',S,'-c',cpp,'-o',obj])
   syms=run(sdk+'-typed-symbols',['xcrun','nm','-u',obj])
   need(sorted(line.split()[-1] for line in syms.splitlines() if line.split())==sorted([b'_hv_vcpu_set_vtimer_offset',
    b'_hv_vcpu_set_trap_debug_exceptions',b'_hv_vcpu_set_trap_debug_reg_accesses',b'_hv_vm_get_max_vcpu_count',
    b'_hv_vcpu_get_pending_interrupt',b'_hv_vcpu_set_pending_interrupt',b'_hv_vcpu_run',b'_VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13']),'eight actual unmangled SDK symbols')
  need([pin(p) for p in FROZEN]==before,'Root4 and all completed CPU source unchanged')
  inputs=sorted(include_closure|{Path(__file__).resolve(),S/'test-vm27-hv-public-vm-bootstrap-v7.m',*FROZEN})
  inherited=N/'vm-hv-public-bootstrap-integration-local-v5/inherited-strong-proof-v2.json'
  inherited_proof=json.loads(inherited.read_text())
  result=dict(schema='RootBoot7 ISA2 RAM Factory13 Life15 private claim and pending C0 true timer/debug/maxVCPU integration v1',
   candidate=pin(provider),exactExports=exports,normalChecks=host[0]['checks'],sanitizedChecks=host[1]['checks'],
   root4=pin(root4),root5=pin(N/'vm-hv-public-bootstrap-integration-local-v5/candidate.json'),cpu12=pin(cpu12),root6=pin(N/'vm-hv-public-bootstrap-integration-local-v6/candidate.json'),
   physicalClaimFactory=pin(N/'cpu-hv-physical-debug-claim-factory-local-v1/finalization.json'),
   physicalClaimLower=pin(N/'cpu-physical-debug-claim-local-v1/source-finalization.json'),
   physicalClaimPrivateRawEightBitPort=True,physicalClaimPublicSYSSetClearEmulation=False,
   inheritsRoot6PendingAndActual16HVPublicExports=True,
   inheritedActual42StrongProof=pin(inherited),actualIncludeClosure=[pin(x) for x in sorted(include_closure)],maxVCPUOriginal16ByteBasis=pin(max_basis),
   maxVCPUCountABI='hv_return_t(uint32_t*)',maxVCPUFrameworkUpperBound=64,maxVCPUOutputBytes=4,
   maxVCPUIsNotMeasuredNativeCapacity=True,strongRootOutputGuardLinked=True,sameActualOwnerEpochAndRegistry=True,
   timerDebugAndPendingBorrowBlockVMAndRAMChanges=True,
   pendingCleanupOnNonzeroNativeStatus=True,oneNative9PerActualRun=True,noPendingNative8=True,
   realPostReturnControlReload=True,partialPendingWriteWithdrawsBothRegistries=True,
   failedNative7RetainsActualCPUAndSameVMAndRAM=True,callbackReentryVMMapDestroyRunsNoNativeChange=True,
   partialCPUWritePoisonsAndRetainsVMRAMAndBackingUntilBorrowDrain=True,
   failedNative3And4RetainCallerBacking=True,failedNative2RetainsOwnedVMForRetry=True,
   sharedOneNativeCapabilityAcquisitionSource=True,inheritsRoot4TrueISA2AndRAMWithoutEditing=True,
   inheritsCPU12ActualHostModelTestsWithoutRepeating=True,currentStrongImportEvidenceInherited=True,
   originalVMMIntegrated=False,fullPublicRAMEquivalent=False,fullPublicRunEquivalent=False,
   fullModernClockCompensationEquivalent=False,providerSigned=False,providerLoaded=False,readyWritten=False,
   nativeVMCallsExecuted=0,nativeCPUCallsExecuted=0,deviceOperations=0,guestInstructions=0,full27Backend=False,
   hostResults=host,steps=steps,frozenInputsUnchanged=before,inputs=[pin(p) for p in sorted(set(inputs))])
  (d/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(dict(candidate=pin(d/'candidate.json'),provider=pin(provider),exports=len(exports),hostResults=host)))
 except BaseException as error:
  (d/'failure.json').write_text(json.dumps(dict(error=str(error),steps=steps,frozenBefore=before,
   frozenAfter=[pin(p) for p in FROZEN]),indent=2)+'\n');raise
if __name__=='__main__':main()
