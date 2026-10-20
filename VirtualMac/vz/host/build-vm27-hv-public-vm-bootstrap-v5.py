"""Minimal RootBoot5 integration fixture and inert iOS build; no signing/device."""
from pathlib import Path
import argparse,hashlib,json,os,struct,re,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v11.c','modern_cpu_kernel_lifecycle_v13.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c',
 'modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c','vm27_hv_public_vm_bootstrap_v5.m']
IOS_EXTRA=['modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']
FROZEN=[S/x for x in ['vm27_hv_public_vm_bootstrap_v4.h','vm27_hv_public_vm_bootstrap_v4.m',
 'modern_cpu_native_public_factory_v9.c','modern_cpu_native_public_factory_v10.c','modern_cpu_native_public_factory_v11.c',
 'modern_cpu_kernel_lifecycle_v11.c','modern_cpu_kernel_lifecycle_v12.c','modern_cpu_kernel_lifecycle_v13.c',
 'modern_cpu_kernel_vtimer_v12.inc','modern_cpu_native_public_factory_vtimer_v10.inc',
 'modern_cpu_kernel_debug_v13.inc','modern_cpu_native_public_factory_debug_v11.inc']]
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
   exe=d/label;run(label+'-compile',common+flags+[S/x for x in UNITS]+[S/'test-vm27-hv-public-vm-bootstrap-v5.m',
    '-framework','CoreFoundation','-lobjc','-o',exe])
   receipt=json.loads(run(label+'-run',[exe]).splitlines()[-1]);host.append(receipt)
   need(receipt['combinedStrongGuard'] and receipt['sameOwnerAndVMEpoch'] and receipt['writerReentries']==10 and
    receipt['VMConfigCreated']==receipt['VMConfigDestroyed']==receipt['CPUConfigCreated']==receipt['CPUConfigDestroyed']==1 and
    receipt['nativeCallsExecuted']==0,'actual minimal RootBoot5 fixture')
  need(host[0]==host[1],'normal and sanitizer evidence agree')
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11',
   '-Wall','-Wextra','-Werror','-DVM27_HV_VM_GUARD_LINKED=1','-I',S]
  objects=[]
  for name in UNITS+IOS_EXTRA:
   obj=d/(Path(name).stem+'.o');objects.append(obj)
   exported=name in ['modern_cpu_native_public_factory_v11.c','modern_cpu_config_os_object_v5.m','vm27_hv_public_vm_bootstrap_v5.m']
   run(Path(name).stem+'-ios-compile',ios+([] if exported else ['-fvisibility=hidden'])+
    (['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
  root4=N/'vm-hv-public-bootstrap-integration-local-v4/candidate.json'
  cpu11=N/'cpu-hv-debug-factory-local-v1/candidate.json'
  max_basis=N/'hv-framework-max-vcpu-contract-v1/original-body-audit.json'
  parent=json.loads(root4.read_text());cpu=json.loads(cpu11.read_text());max_audit=json.loads(max_basis.read_text())
  original=max_audit['original27ExactCacheWindows'][0]
  need(original['name']=='maximum-vCPU' and original['startRVA']=='0x2d00' and original['endRVA']=='0x2d10' and
   original['rawAndOriginalCacheByteEqual'] and original['instructions'][1]['operands']=='w8, [x0]', 'complete genuine16B four-byte output basis')
  own=cpu['exactOwnExports'];public=cpu['exactPublicHVExports'];
  root_names=[x for x in parent['exactExports'] if x not in own and x not in public]
  exports=sorted(set(own+public+root_names+['hv_vm_get_max_vcpu_count']))
  need(len(exports)==64,'real combined64 exports')
  export_file=d/'exports.txt';export_file.write_text(''.join('_'+x+'\n' for x in exports))
  provider=d/'VM27HVVMCPUCombinedV5.dylib'
  run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error',
   '-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(export_file),'-Wl,-install_name,@rpath/VM27HVVMCPUCombinedV5.dylib','-o',provider])
  run('ios-validate',['xcrun','dyld_info','-validate_only',provider]);symbols=run('ios-exports',['xcrun','nm','-gU',provider])
  imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider])
  need(sorted(x.split()[-1].decode() for x in symbols.splitlines() if x.split())==['_'+x for x in exports],'actual exact64 export set')
  need(not re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports),'no genuine HV/VMM import')
  raw=provider.read_bytes();at=32
  for _ in range(struct.unpack_from('<I',raw,16)[0]):
   command,size=struct.unpack_from('<II',raw,at);need(command!=0x1d,'unsigned candidate');at+=size
  cpp=d/'typed-root5-caller.cpp';cpp.write_text('#include "vm27_hv_public_vm_bootstrap_v5.h"\n'
   'static_assert(sizeof(hv_return_t)==4 && sizeof(bool)==1,"actual SDK ABI");\n'
   'extern "C" hv_return_t call_root5(hv_vcpu_t c,uint64_t offset,bool value,uint32_t *n,unsigned action){\n'
   ' hv_return_t (*timer)(hv_vcpu_t,uint64_t)=hv_vcpu_set_vtimer_offset;\n'
   ' hv_return_t (*exceptions)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_exceptions;\n'
   ' hv_return_t (*registers)(hv_vcpu_t,bool)=hv_vcpu_set_trap_debug_reg_accesses;\n'
   ' hv_return_t (*maximum)(uint32_t *)=hv_vm_get_max_vcpu_count;\n'
   ' switch(action){case 0:return timer(c,offset);case 1:return exceptions(c,value);case 2:return registers(c,value);default:return maximum(n);}}\n')
  for sdk in ['macosx','iphoneos']:
   obj=d/(sdk+'-typed-caller.o');flags=['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []
   run(sdk+'-typed-caller',['xcrun','--sdk',sdk,'clang++','-std=c++17','-Wall','-Wextra','-Werror',*flags,'-I',S,'-c',cpp,'-o',obj])
   syms=run(sdk+'-typed-symbols',['xcrun','nm','-u',obj])
   need(sorted(line.split()[-1] for line in syms.splitlines() if line.split())==sorted([b'_hv_vcpu_set_vtimer_offset',
    b'_hv_vcpu_set_trap_debug_exceptions',b'_hv_vcpu_set_trap_debug_reg_accesses',b'_hv_vm_get_max_vcpu_count']),'four actual unmangled SDK symbols')
  need([pin(p) for p in FROZEN]==before,'Root4 and all completed CPU source unchanged')
  inputs=[Path(__file__),S/'test-vm27-hv-public-vm-bootstrap-v5.m',S/'vm27_hv_public_vm_bootstrap_v5.h',
   *[S/x for x in UNITS+IOS_EXTRA],*FROZEN,S/'modern_cpu_native_public_factory_ram_adopt_v9.inc',
   S/'modern_cpu_kernel_system_fields.inc',S/'modern_vm_memory_packet.h']+list(S.glob('modern_cpu*.h'))
  result=dict(schema='RootBoot5 ISA2 RAM Factory11 Life13 true timer/debug/maxVCPU integration v1',
   candidate=pin(provider),exactExports=exports,normalChecks=host[0]['checks'],sanitizedChecks=host[1]['checks'],
   root4=pin(root4),cpu11=pin(cpu11),maxVCPUOriginal16ByteBasis=pin(max_basis),
   maxVCPUCountABI='hv_return_t(uint32_t*)',maxVCPUFrameworkUpperBound=64,maxVCPUOutputBytes=4,
   maxVCPUIsNotMeasuredNativeCapacity=True,strongRootOutputGuardLinked=True,sameActualOwnerEpochAndRegistry=True,
   timerAndDebugBorrowBlockVMAndRAMChanges=True,callbackReentryVMMapDestroyRunsNoNativeChange=True,
   partialCPUWritePoisonsAndRetainsVMRAMAndBackingUntilBorrowDrain=True,
   failedNative3And4RetainCallerBacking=True,failedNative2RetainsOwnedVMForRetry=True,
   sharedOneNativeCapabilityAcquisitionSource=True,inheritsRoot4TrueISA2AndRAMWithoutEditing=True,
   inheritsCPU11ActualHostModelTestsWithoutRepeating=True,currentStrongImportEvidenceInherited=True,
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
