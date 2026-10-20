from pathlib import Path
import json,os,re,struct,hashlib,subprocess
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-hv-public-cluster-integration-local-v2';steps=[]
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def run(label,args):
 env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0';env['UBSAN_OPTIONS']='halt_on_error=1'
 p=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=30)
 (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
 steps.append(dict(label=label,args=list(map(str,args)),exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
 (D/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
 if p.returncode:raise ValueError(label+' failed')
 return p.stdout
units=['modern_cpu_native_public_factory_v6.c','modern_cpu_kernel_lifecycle_v10.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c','modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v4.m','modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c']
common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror','-I',S,'-DVM27_CPU_CONFIG_TESTING=1']
results=[]
for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
 exe=D/label;run(label+'-compile',common+flags+[*[S/x for x in units],S/'test-modern-cpu-hv-public-factory-v6.m','-framework','CoreFoundation','-lobjc','-o',exe])
 result=json.loads(run(label+'-run',[exe]).splitlines()[-1]);assert result['CFcreated']==result['CFdestroyed']==3 and result['nativeCallsExecuted']==0
 results.append(result)
# A new alternative source must retain the prior own API behavior. This is the
# existing finite regression linked against V8/Factory4; its trap9 remains mock.
exe=D/'legacy-regression';run('legacy-regression-compile',common+[*[S/x for x in units],S/'test-modern-cpu-native-run-producer-v3.m','-framework','CoreFoundation','-lobjc','-o',exe])
legacy=json.loads(run('legacy-regression-run',[exe]).splitlines()[-1]);assert legacy['created']==legacy['destroyed']==8 and legacy['nativeCalls']==0
(D/'host-results.json').write_text(json.dumps(dict(selected=results,legacy=legacy),indent=2)+'\n')
print(json.dumps(dict(selected=results,legacy=legacy)))
