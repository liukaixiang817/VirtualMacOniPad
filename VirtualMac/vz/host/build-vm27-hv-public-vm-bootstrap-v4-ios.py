"""Create inert unsigned VM+CPU source candidate; no device or ready flag."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/vm-hv-public-bootstrap-integration-local-v4'
def pin(path):
 p=Path(path).absolute();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 if (D/'candidate.json').exists():raise ValueError('completed candidate already exists')
 host=json.loads((D/'host-results.json').read_bytes());steps=[]
 if len(host['selected'])!=2 or any(x['checks']!=234 or x['VMConfigCreated']!=2 or x['VMConfigDestroyed']!=2 for x in host['selected']):raise ValueError('actual host receipts')
 def run(label,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  p=subprocess.run(list(map(str,args)),capture_output=True,timeout=30,env=env)
  (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,args=list(map(str,args)),exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
  (D/'ios-steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
  if p.returncode:raise ValueError(label+' failed')
  return p.stdout
 units=['modern_cpu_native_public_factory_v9.c','modern_cpu_kernel_lifecycle_v11.c','modern_cpu_kernel_initialization_v3.c',
  'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c','modern_cpu_native_exit_reducer_v1.c',
  'modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c',
  'modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S',
  'vm27_hv_public_vm_bootstrap_v4.m']
 common=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror',
  '-DVM27_HV_VM_GUARD_LINKED=1','-I',S]
 objects=[]
 for name in units:
  obj=D/(Path(name).stem+'.o');objects.append(obj)
  public=name in ['modern_cpu_native_public_factory_v9.c','modern_cpu_config_os_object_v5.m','vm27_hv_public_vm_bootstrap_v4.m']
  run(Path(name).stem+'-ios-compile',common+([] if public else ['-fvisibility=hidden'])+(['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
 previous=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-hv-public-run-cluster-integration-local-v1/candidate.json'
 parent=json.loads(previous.read_bytes());exports=sorted(parent['exactOwnExports']+parent['exactPublicHVExports']+[
  'hv_vm_config_create','hv_vm_config_get_max_ipa_size','hv_vm_config_get_default_ipa_size','hv_vm_config_set_ipa_size','hv_vm_config_get_ipa_size',
  'hv_vm_config_set_ipa_granule','hv_vm_config_set_el2_enabled','_hv_vm_config_set_isa','_hv_vm_config_set_vhe_enabled','hv_vm_create','hv_vm_destroy',
  'VM27HVVMInstallNativeOpsV1','VM27HVVMUninstallNativeOpsV1','VM27HVVMGetOwnedVMV1','VM27CPUFactoryRAMAdoptHostV9','hv_vm_map','hv_vm_protect','hv_vm_unmap'])
 export=D/'exports.txt';export.write_text(''.join('_'+n+'\n' for n in exports))
 provider=D/'VM27HVVMCPUCombinedV4.dylib'
 run('ios-link',common+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error',
  '-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(export),'-Wl,-install_name,@rpath/VM27HVVMCPUCombinedV4.dylib','-o',provider])
 run('ios-validate',['xcrun','dyld_info','-validate_only',provider]);nm=run('ios-exports',['xcrun','nm','-gU',provider])
 imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider]);run('ios-disassembly',['xcrun','llvm-objdump','--macho','--disassemble',provider])
 if sorted(x.split()[-1].decode() for x in nm.splitlines() if x.split())!=['_'+n for n in exports]:raise ValueError('exports')
 if re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports):raise ValueError('foreign HV dependency')
 b=provider.read_bytes();at=32
 for _ in range(struct.unpack_from('<I',b,16)[0]):
  cmd,size=struct.unpack_from('<II',b,at)
  if cmd==0x1d:raise ValueError('must stay unsigned')
  at+=size
 row=dict(schema='Public VM bootstrap and true Factory7 reciprocal guard source candidate v1',finiteLocalScopePassed=True,
  candidate=pin(provider),parent=pin(previous),normalChecks=234,sanitizedChecks=234,actualVMConfigCFCreateDestroyEach=2,
  exactExports=exports,sharedCPUAndVMRegistry=True,sharedSingleNativeCapabilityAcquisitionSource=True,
  rawIPAHighHalvesAndMinimumValidated=True,nativeVMOwnerLifecycleFailureRetentionMocked=True,
  nativeVMCPUCallbacksAllMocked=True,initialCPUConfigAliasFailureSaved=True,reciprocalCPUConfigOutputGuardFixed=True,
  nativeCallsExecuted=0,deviceOperations=0,originalVMMIntegrated=False,publicWholeRangeRAMSourceImplemented=True,publicOneStepRunSourceImplemented=True,fullPublicRAMEquivalent=False,fullPublicRunEquivalent=False,
  fullPublicVMConfigEquivalent=False,providerSigned=False,providerLoaded=False,readyWritten=False,guestInstructions=0,full27Backend=False,
  hostReceipts=host,iosSteps=steps,inputs=[pin(S/u) for u in units]+[pin(S/'vm27_hv_public_vm_bootstrap_v4.h'),pin(S/'modern_cpu_native_public_factory_v9.h'),pin(S/'modern_cpu_native_public_factory_ram_adopt_v9.inc'),pin(S/'modern_cpu_kernel_lifecycle_v11.h'),pin(S/'test-vm27-hv-public-vm-bootstrap-v4.m'),pin(Path(__file__)),pin(S/'build-vm27-hv-public-vm-bootstrap-v4.py')])
 with (D/'candidate.json').open('x') as f:json.dump(row,f,indent=2);f.write('\n')
 print(json.dumps(dict(candidate=pin(D/'candidate.json'),provider=pin(provider),exports=len(exports),nativeCalls=0)))
if __name__=='__main__':main()
