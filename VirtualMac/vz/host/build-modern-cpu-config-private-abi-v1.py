#!/usr/bin/env python3
"""New OS6 private setters, linked into one frozen Root12 registry; no device."""
import argparse,hashlib,importlib.util,json,os,pathlib,subprocess,sys
sys.dont_write_bytecode=True
S=pathlib.Path(__file__).resolve().parent;N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=pathlib.Path,required=True);out=a.parse_args().out.resolve()
 if out.parent!=N.resolve():raise ValueError('Fresh diagnostics required')
 out.mkdir(exist_ok=False);commands=[];D=N/'vm-hv-public-bootstrap-integration-local-v12-attempt2'
 frozen=json.loads((D/'freeze.json').read_text())
 for row in frozen['files']:
  if pin(row['path'])!=row:raise ValueError('Frozen Root12 changed '+row['path'])
 spec=importlib.util.spec_from_file_location('root12',S/'build-vm27-hv-public-vm-bootstrap-v12.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
 def run(label,args):
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45,env={**os.environ,'ASAN_OPTIONS':'halt_on_error=1:detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1'})
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append(dict(label=label,argv=list(map(str,args)),returncode=r.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
  (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if r.returncode:raise RuntimeError(label+': '+r.stderr.decode(errors='replace'))
  return r.stdout
 common=['-std=c11','-Wall','-Wextra','-Werror','-I',S,'-DVM27_HV_VM_GUARD_LINKED=1']
 models={};reuse=[]
 for mode,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  inherited=[D/('scalar-'+mode+'-'+pathlib.Path(n).stem+'.o') for n in b.UNITS if n!='modern_cpu_config_os_object_v5.m']
  inherited.append(D/('scalar-'+mode+'-test-vm27-counter-hooks-v12.o'));reuse.extend(inherited)
  exe=out/mode
  run(mode+'-link',['xcrun','--sdk','macosx','clang',*common,*extra,'-fno-objc-arc','-DVM27_CPU_CONFIG_TESTING=1',
   *inherited,S/'modern_cpu_config_os_object_v6.m',S/'modern_cpu_config_capability_acquisition_v2.c',
   S/'modern_cpu_tlbi_capability_values_v1.c',S/'test-modern-cpu-config-private-abi-v1.m','-framework','CoreFoundation','-lobjc','-o',exe])
  models[mode]=json.loads(run(mode+'-run',[exe]).splitlines()[-1])
 if models['normal']!=models['san']:raise ValueError('Changed model disagreement')
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',*common]
 obj=out/'modern_cpu_config_os_object_v6.o'
 run('ios-os6',[*ios,'-fno-objc-arc','-c',S/'modern_cpu_config_os_object_v6.m','-o',obj])
 c=json.loads((D/'candidate.json').read_text());exports=set(c['exactExports'])|{'_hv_vcpu_config_set_tlbi_workaround_enabled','_hv_vcpu_config_set_fgt_enabled'}
 exportfile=out/'exports.txt';exportfile.write_text(''.join('_'+n+'\n' for n in sorted(exports)))
 objects=[D/(pathlib.Path(n).stem+'.o') for n in b.UNITS+b.EXTRA if n!='modern_cpu_config_os_object_v5.m'];reuse.extend(objects)
 provider=out/'VM27HVVMCPUConfigPrivateV1.unsigned.dylib'
 run('ios-link',[*ios,'-dynamiclib',*objects,obj,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exportfile),'-Wl,-install_name,@rpath/VM27HVVMCPUConfigPrivateV1.unsigned.dylib','-o',provider])
 run('ios-dyld-validate',['xcrun','dyld_info','-validate_only',provider])
 actual=run('ios-symbols',['xcrun','nm','-gU',provider]);actual={line.split()[-1].decode() for line in actual.splitlines()}
 if actual!={'_'+x for x in exports}:raise ValueError('Actual export mismatch')
 cpp=out/'typed-caller.cpp';cpp.write_text('#include "modern_cpu_config_private_abi_v1.h"\n#include <type_traits>\nstatic_assert(std::is_same_v<decltype(&_hv_vcpu_config_set_tlbi_workaround_enabled),hv_return_t(*)(hv_vcpu_config_t,bool)>);\nextern "C" hv_return_t V1(hv_vcpu_config_t c,bool b){return _hv_vcpu_config_set_tlbi_workaround_enabled(c,b)|_hv_vcpu_config_set_fgt_enabled(c,b);}\n')
 run('ios-cxx',['xcrun','--sdk','iphoneos','clang++','-arch','arm64e','-miphoneos-version-min=16.1','-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-c',cpp,'-o',out/'typed.o'])
 undefined=run('ios-cxx-undefined',['xcrun','nm','-u',out/'typed.o'])
 if b'__hv_vcpu_config_set_tlbi_workaround_enabled' not in undefined or b'__hv_vcpu_config_set_fgt_enabled' not in undefined:raise ValueError('Private C ABI mangled')
 sources=[S/'modern_cpu_config_private_abi_v1.h',S/'modern_cpu_config_os_object_v6.m',S/'test-modern-cpu-config-private-abi-v1.m',pathlib.Path(__file__).resolve()]
 basis=N/'modern27-hvc-private-tlbi-semantic-offline-v1'
 report=dict(schema='true OS6 private config aliases local v1',provider=pin(provider),models=models,exactExports=sorted(exports),registryCount=1,root12SourcesUnmodified=True,sourcePins=[pin(x) for x in sources],inheritedRoot12=pin(D/'freeze.json'),reusedObjectPins=[pin(x) for x in sorted(set(reuse))],trueOriginalTLBIBasis=pin(basis/'report.json'),TLBIFalseQueryFree=True,TLBITrueUsesExistingActualCapability=True,FGTStateActuallyWritten=True,runRejectsFGTAndTLBI=True,actualTypedCppUnmangled=True,deviceOperations=0,nativeOperations=0,providerLoaded=False,guestBoot=False)
 (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
 files=sources+[out/'candidate.json',provider,D/'freeze.json',basis/'report.json',basis/'freeze.json',out/'commands.json',cpp,out/'typed.o',exportfile]
 (out/'freeze.json').write_text(json.dumps(dict(schema='OS6 private config freeze v1',files=[pin(x) for x in files]),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),provider=pin(provider),freeze=pin(out/'freeze.json'),models=models)))
if __name__=='__main__':main()
