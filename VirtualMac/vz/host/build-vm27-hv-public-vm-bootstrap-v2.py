"""Build and exercise source integration only; no device/sign/load action."""
from pathlib import Path
import hashlib,json,os,subprocess
S=Path(__file__).resolve().parent
R=S.parents[2]
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/vm-hv-public-bootstrap-integration-local-v2'
UNITS=['modern_cpu_native_public_factory_v9.c','modern_cpu_kernel_lifecycle_v11.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c','modern_cpu_native_exit_reducer_v1.c',
 'modern_cpu_config_os_object_v5.m','modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c','modern_cpu_native_capability_seed.c',
 'vm27_hv_public_vm_bootstrap_v2.m']
def pin(path):
 p=Path(path);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 if (D/'host-results.json').exists():raise ValueError('Do not overwrite completed receipt')
 D.mkdir(parents=True,exist_ok=True);steps=[];results=[]
 def run(name,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  q=subprocess.run(list(map(str,args)),capture_output=True,timeout=30,env=env)
  (D/(name+'.stdout')).write_bytes(q.stdout);(D/(name+'.stderr')).write_bytes(q.stderr)
  steps.append(dict(label=name,args=list(map(str,args)),exit=q.returncode,stdout=pin(D/(name+'.stdout')),stderr=pin(D/(name+'.stderr'))))
  (D/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
  if q.returncode:raise ValueError(name+' failed')
  return q.stdout
 common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror','-I',S,
  '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1','-DVM27_HV_VM_GUARD_LINKED=1']
 for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  exe=D/label
  run(label+'-compile',common+flags+[S/x for x in UNITS]+[S/'test-vm27-hv-public-vm-bootstrap-v2.m','-framework','CoreFoundation','-lobjc','-o',exe])
  results.append(json.loads(run(label+'-run',[exe]).splitlines()[-1]))
 with (D/'host-results.json').open('x') as f:json.dump(dict(selected=results,steps=steps),f,indent=2);f.write('\n')
 print(json.dumps(results))
if __name__=='__main__':main()
