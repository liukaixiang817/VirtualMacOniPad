"""Mac normal/SAN source execution with only injected native/capability mocks."""
from pathlib import Path
import hashlib,json,os,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-owned-brk-device-host-faults-v1'
UNITS=['modern_cpu_native_public_factory_v9.c','modern_cpu_kernel_lifecycle_v11.c',
 'modern_cpu_kernel_initialization_v3.c','modern_cpu_native_fields.c',
 'modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m',
 'modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c',
 'modern_cpu_native_capability_seed.c','vm27_hv_public_vm_bootstrap_v4.m',
 'cpu_owned_brk_device_fixture_v1.c','cpu_owned_brk_host_fault_native_v1.c']
MODES=['brk','raw11','unknown','wrong-syndrome','map-failure','version-failure',
 'sync-failure','run-failure','cpu-destroy-failure','unmap-failure','vm-destroy-failure']
def pin(path):
 p=Path(path).absolute();data=p.read_bytes()
 return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def save(path,value):
 with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
def main():
 if D.exists():raise ValueError('fresh version required')
 D.mkdir();steps=[];receipts=[]
 inputs=[pin(S/name) for name in UNITS]+[pin(Path(__file__))]
 def run(label,args,envExtra=None):
  env={key:value for key,value in os.environ.items() if not key.startswith('DYLD_')}
  if envExtra:env.update(envExtra)
  p=subprocess.run(list(map(str,args)),capture_output=True,timeout=30,env=env)
  (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
  steps.append(dict(label=label,args=list(map(str,args)),exit=p.returncode,
   stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
  (D/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
  return p
 try:
  for kind,san in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   binary=D/(kind+'-mock')
   args=['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror',
    '-Wno-unused-command-line-argument','-fno-objc-arc','-DVM27_HV_VM_GUARD_LINKED=1',
    '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1','-DVM27_BRK_FIXTURE_HOST_FAULTS=1',
    '-I',S,*san,*[S/name for name in UNITS],'-framework','CoreFoundation','-lobjc','-o',binary]
   p=run(kind+'-compile',args)
   if p.returncode:raise ValueError('compile '+kind)
   for mode in MODES:
    p=run(kind+'-'+mode,[binary,'--owned-brk-one-step-v1'],
     {'VM27_BRK_HOST_MODE':mode,'ASAN_OPTIONS':'detect_leaks=0'})
    if p.returncode!=(0 if mode=='brk' else 74) or p.stderr:raise ValueError(kind+' '+mode+' status/stderr')
    rows=[json.loads(line) for line in p.stdout.splitlines()]
    result=next(row for row in rows if row['kind']=='result')
    calls=[row['operation'] for row in rows if row['kind']=='nativeBegin']
    if len(calls)!=len(set(calls)) or any(op not in [1,2,3,4,6,7,8,9] for op in calls):raise ValueError('retry/foreign operation')
    if result['passed']!=(mode=='brk') or result['instructionOracle']!=(mode in ['brk','cpu-destroy-failure','unmap-failure','vm-destroy-failure']):raise ValueError('truthful oracle')
    if result['native9']!=(0 if mode in ['map-failure','version-failure','sync-failure'] else 1):raise ValueError('native9 bounds')
    if mode in ['cpu-destroy-failure','unmap-failure'] and result['callerBackingReleased']:raise ValueError('uncertain mapping backing release')
    if mode=='cpu-destroy-failure' and (result['native4'] or result['native2']):raise ValueError('cleanup after failed7')
    if mode=='unmap-failure' and result['native2']:raise ValueError('cleanup after failed4')
    if mode in ['brk','raw11','unknown','wrong-syndrome','run-failure'] and not result['cleanupComplete']:raise ValueError('owner cleanup')
    if mode=='raw11':
     receipt=next(row for row in rows if row['kind']=='runReceipt')
     if receipt['rawReason']!=11 or receipt['returnBits']!=0xfae94002 or receipt['knownFields']!=1:raise ValueError('raw11 explicit failure')
    receipts.append(dict(kind=kind,mode=mode,result=result,callbackSequence=calls))
  for row in inputs:
   if pin(row['path'])!=row:raise ValueError('source drift')
  save(D/'host-results.json',dict(schema='Owned BRK source finite end-to-end fault models v1',
   finiteMockScopePassed=True,actualSelfMachReadWriteAndMappingUsed=True,
   nativeAndCapabilitiesAllMocked=True,normalModes=len(MODES),sanitizedModes=len(MODES),
   nativeCallsExecuted=0,deviceOperations=0,guestInstructions=0,guestBooted=False,full27Backend=False,
   inputs=inputs,steps=steps,receipts=receipts))
  print(json.dumps(dict(results=pin(D/'host-results.json'),normalModes=len(MODES),sanitizedModes=len(MODES),nativeCallsExecuted=0)))
 except Exception as error:
  save(D/'failure.json',dict(error=str(error),steps=steps,inputs=inputs,receipts=receipts))
  raise
if __name__=='__main__':main()
