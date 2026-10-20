"""Build only an unsigned inert BRK diagnostic. No signing, TC or device I/O."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess,shlex

S=Path(__file__).resolve().parent
R=S.parents[2]
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-owned-brk-device-unsigned-local-v6'
UNITS=['modern_cpu_native_public_factory_v9.c','modern_cpu_kernel_lifecycle_v11.c',
 'modern_cpu_kernel_initialization_v3.c','modern_cpu_native_fields.c',
 'modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m',
 'modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c',
 'modern_cpu_native_capability_seed.c','modern_cpu_config_capability_acquisition_v2.c',
 'modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S',
 'vm27_hv_public_vm_bootstrap_v4.m','cpu_owned_brk_device_fixture_v5.c',
 'cpu_owned_brk_device_native_v1.S']

def pin(path):
 p=Path(path).absolute();data=p.read_bytes()
 return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def save(path,value):
 with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
def main():
 if D.exists():raise ValueError('use a fresh output version; completed/failed results are retained')
 D.mkdir()
 inputs=[]
 steps=[]
 def run(label,args):
  env={key:value for key,value in os.environ.items() if not key.startswith('DYLD_')}
  proc=subprocess.run(list(map(str,args)),capture_output=True,timeout=45,env=env)
  (D/(label+'.stdout')).write_bytes(proc.stdout);(D/(label+'.stderr')).write_bytes(proc.stderr)
  row=dict(label=label,args=list(map(str,args)),exit=proc.returncode,
   stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr')))
  steps.append(row)
  (D/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
  if proc.returncode:raise ValueError(label+' failed')
  return proc.stdout
 flags=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
  '-std=c11','-Wall','-Wextra','-Werror','-fvisibility=hidden','-DVM27_HV_VM_GUARD_LINKED=1',
  '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1','-I',S]
 objects=[]
 try:
  # Use the compiler's actual local include graph; unrelated evolving headers
  # are not inputs to this diagnostic. -MM excludes SDK/system headers.
  closure={S/name for name in UNITS}
  for name in UNITS:
   dependencies=run(Path(name).stem+'-dependencies',flags+
    (['-fno-objc-arc'] if name.endswith('.m') else [])+['-MM',S/name]).decode()
   if ':' not in dependencies:raise ValueError('missing dependency rule '+name)
   body=dependencies.split(':',1)[1].replace('\\\n',' ')
   for token in shlex.split(body):
    path=Path(token).resolve()
    if not path.is_relative_to(S):raise ValueError('unexpected local input '+str(path))
    closure.add(path)
  inputs=[pin(path) for path in sorted(closure)]+[pin(Path(__file__))]
  for name in UNITS:
   obj=D/(Path(name).stem+'.o');objects.append(obj)
   run(Path(name).stem+'-compile',flags+(['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
  binary=D/'cpu-owned-brk-v6'
  run('link',flags+objects+['-framework','CoreFoundation','-lobjc','-Wl,-dead_strip',
   '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',binary])
  run('validate',['xcrun','dyld_info','-validate_only',binary])
  imports=run('imports',['xcrun','dyld_info','-dependents','-imports',binary])
  run('symbols',['xcrun','nm','-m',binary])
  run('disassembly',['xcrun','llvm-objdump','--macho','--disassemble',binary])
  if re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports):
   raise ValueError('foreign framework/API dependency')
  data=binary.read_bytes();offset=32;unsigned=True
  for _ in range(struct.unpack_from('<I',data,16)[0]):
   command,size=struct.unpack_from('<II',data,offset)
   if command==0x1d:unsigned=False
   offset+=size
  if not unsigned:raise ValueError('must remain unsigned')
  for row in inputs:
   if pin(row['path'])!=row:raise ValueError('input changed during compile')
  save(D/'candidate.json',dict(schema='Owned one-step BRK native diagnostic unsigned source candidate v6',
   binary=pin(binary),inputs=inputs,steps=steps,finiteIOSCompileLinkValidatePassed=True,actualCompilerLocalIncludeClosure=True,
   providerSigned=False,providerLoaded=False,deviceOperations=0,nativeOperationsExecuted=0,
   nativeISADiagnostic=2,requestedNativeCallbackSequence=[1,3,6,8,9,7,4,2],
   native8Conditional=True,native9Maximum=1,native0CapabilityQueryMaximum=1,
   staleNative8BRKRejectedBeforeNative9=True,freshSyndromeRecheckedInsideNative9Wrapper=True,native345PacketsDefaultSpaceOnly=True,
   callerOwnedSingle16KiBGuestBacking=True,wholePageBRK0=True,requiresExternal20SecondWatchdog=True,
   requiredCPULimitInfinity=True,requiresActualDebugTrapControl2=True,requiredCoreLimit=0,fullPublicRunEquivalent=False,
   architecturalResetComplete=False,guestInstructionOracle=False,guestBooted=False,full27Backend=False))
  print(json.dumps(dict(candidate=pin(D/'candidate.json'),binary=pin(binary),nativeOperationsExecuted=0)))
 except Exception as error:
  save(D/'failure.json',dict(error=str(error),steps=steps,inputs=inputs,
   nativeOperationsExecuted=0,deviceOperations=0))
  raise
if __name__=='__main__':main()
