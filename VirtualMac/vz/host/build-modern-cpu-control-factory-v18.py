#!/usr/bin/env python3
"""Finite Control2/7/8 Life22+Factory18 integration; frozen Root12 unchanged."""
import argparse,hashlib,importlib.util,json,os,pathlib,struct,subprocess,sys
sys.dont_write_bytecode=True
S=pathlib.Path(__file__).resolve().parent;N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();v=p.read_bytes();return dict(path=str(p),bytes=len(v),sha256=hashlib.sha256(v).hexdigest())
def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=pathlib.Path,required=True);out=a.parse_args().out.resolve()
 if out.parent!=N.resolve():raise ValueError('Fresh diagnostics required')
 out.mkdir(exist_ok=False);D=N/'vm-hv-public-bootstrap-integration-local-v12-attempt2'
 for row in json.loads((D/'freeze.json').read_text())['files']:
  if pin(row['path'])!=row:raise ValueError('Frozen Root12 changed '+row['path'])
 spec=importlib.util.spec_from_file_location('root12',S/'build-vm27-hv-public-vm-bootstrap-v12.py');root=importlib.util.module_from_spec(spec);spec.loader.exec_module(root)
 sys.path.insert(0,str(N/'modern27-remaining-context-fields-independent-readonly-v1'));from independent_macho import MachO
 raw=S.parents[2]/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw'
 hv=MachO((raw/'Hypervisor').read_bytes());vmm=MachO((raw/'VirtualMachine.arm64e').read_bytes())
 table=struct.unpack_from('<18Q',hv.data,hv.file(hv.base+0x87680))
 if table!=(0,16,24,32,0,40,8,112,120,128,0,56,64,72,80,88,96,208):raise ValueError('Actual modern table')
 checks=[(hv,0x5830,0x7100443f),(hv,0x5838,0x529f7de9),(hv,0x583c,0x72a00069),
  (hv,0x585c,0xf8696949),(hv,0x5878,0xb900010a),(hv,0x58dc,0xf8286922),
  (vmm,0x289de8,0x528000e1),(vmm,0x289e04,0x52800101),(vmm,0x28cb4c,0x528000e1),(vmm,0x28cb5c,0x52800101)]
 for m,rva,word in checks:
  if struct.unpack_from('<I',m.data,m.file(m.base+rva))[0]!=word:raise ValueError('Actual control caller '+hex(rva))
 oldpath=N/'old13-observer-baseline-v1/Hypervisor';old=MachO(oldpath.read_bytes())
 captures=[]
 for name,m,lo,hi in [('modern-control-resolver',hv,0x5830,0x5908),('modern-private-public-wrappers',hv,0x84e88,0x84f30),('old-control-getter-setter',old,0x56c4,0x58ac)]:
  p=out/(name+'.bin');p.write_bytes(m.data[m.file(m.base+lo):m.file(m.base+lo)+hi-lo]);captures.append(dict(range=[hex(lo),hex(hi)],pin=pin(p)))
 commands=[];models={};reuse=[]
 def run(label,args):
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45,env={**os.environ,'ASAN_OPTIONS':'halt_on_error=1:detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1'})
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append(dict(label=label,argv=list(map(str,args)),returncode=r.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
  (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if r.returncode:raise RuntimeError(label+': '+r.stderr.decode(errors='replace'))
  return r.stdout
 common=['-std=c11','-Wall','-Wextra','-Werror','-I',S,'-DVM27_HV_VM_GUARD_LINKED=1']
 changed=['modern_cpu_native_public_factory_v18.c','modern_cpu_kernel_lifecycle_v22.c','modern_cpu_config_os_object_v6.m']
 replaced={'modern_cpu_native_public_factory_v17.c','modern_cpu_kernel_lifecycle_v21.c','modern_cpu_config_os_object_v5.m'}
 for mode,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  inherited=[D/('scalar-'+mode+'-'+pathlib.Path(n).stem+'.o') for n in root.UNITS if n not in replaced]
  inherited.append(D/('scalar-'+mode+'-test-vm27-counter-hooks-v12.o'));reuse.extend(inherited);objects=[]
  for n in changed:
   obj=out/(mode+'-'+pathlib.Path(n).stem+'.o');objects.append(obj)
   run(mode+'-'+pathlib.Path(n).stem,['xcrun','--sdk','macosx','clang',*common,*extra,'-DVM27_CPU_CONFIG_TESTING=1',
    *(['-fno-objc-arc'] if n.endswith('.m') else []),
    *(['-DVZKernelCPUReleaseBorrowV5=ControlActualReleaseV18'] if n=='modern_cpu_kernel_lifecycle_v22.c' else []),'-c',S/n,'-o',obj])
  exe=out/mode;run(mode+'-link',['xcrun','--sdk','macosx','clang',*common,*extra,'-DVM27_HV_VM_TESTING=1','-fno-objc-arc',*inherited,*objects,
   S/'test-modern-cpu-control-factory-v18.m','-framework','CoreFoundation','-lobjc','-o',exe])
  models[mode]=json.loads(run(mode+'-run',[exe]).splitlines()[-1])
 if models['normal']!=models['san']:raise ValueError('Changed model disagreement')
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',*common];objects=[]
 for n in changed:
  obj=out/(pathlib.Path(n).stem+'.o');objects.append(obj)
  run('ios-'+pathlib.Path(n).stem,[*ios,*(['-fvisibility=hidden'] if n=='modern_cpu_kernel_lifecycle_v22.c' else []),
   *(['-fno-objc-arc'] if n.endswith('.m') else []),'-c',S/n,'-o',obj])
 inherited=[D/(pathlib.Path(n).stem+'.o') for n in root.UNITS+root.EXTRA if n not in replaced];reuse.extend(inherited)
 exports=set(json.loads((D/'candidate.json').read_text())['exactExports'])|{
  '_hv_vcpu_config_set_tlbi_workaround_enabled','_hv_vcpu_config_set_fgt_enabled',
  '_hv_vcpu_get_control_field','_hv_vcpu_set_control_field','VM27CPUFactoryBorrowAccessControlV18'}
 exportfile=out/'exports.txt';exportfile.write_text(''.join('_'+x+'\n' for x in sorted(exports)))
 provider=out/'VM27HVVMCPUControlV18.unsigned.dylib'
 run('ios-link',[*ios,'-dynamiclib',*inherited,*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error',
  '-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exportfile),'-Wl,-install_name,@rpath/VM27HVVMCPUControlV18.unsigned.dylib','-o',provider])
 run('ios-validate',['xcrun','dyld_info','-validate_only',provider]);m=MachO(provider.read_bytes())
 if set(m.exports)!={'_'+x for x in exports} or len(m.exports)!=127:raise ValueError('Actual 127 exports')
 if any(x['flags'] for x in m.exports.values()):raise ValueError('Export alias')
 orig=MachO(pathlib.Path(json.loads((D/'candidate.json').read_text())['provider']['path']).read_bytes())
 def imports(i):return sorted((i.loads[x['ordinal']-1]['path'],x['name'],x['weak'],x['addend']) for x in i.imports)
 if imports(m)!=imports(orig):raise ValueError('Actual native imports changed')
 cpp=out/'typed-caller.cpp';cpp.write_text('#include "modern_cpu_native_public_factory_v18.h"\n#include <type_traits>\nstatic_assert(std::is_same_v<decltype(&_hv_vcpu_get_control_field),hv_return_t(*)(hv_vcpu_t,uint32_t,uint64_t*)>);\nstatic_assert(std::is_same_v<decltype(&_hv_vcpu_set_control_field),hv_return_t(*)(hv_vcpu_t,uint32_t,uint64_t)>);\nextern "C" hv_return_t C(hv_vcpu_t c,uint32_t f,uint64_t *v){return _hv_vcpu_get_control_field(c,f,v)|_hv_vcpu_set_control_field(c,f,*v);}\n')
 run('ios-cxx',['xcrun','--sdk','iphoneos','clang++','-arch','arm64e','-miphoneos-version-min=16.1','-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-c',cpp,'-o',out/'typed.o'])
 undef=run('ios-cxx-undefined',['xcrun','nm','-u',out/'typed.o'])
 if b'__hv_vcpu_get_control_field' not in undef or b'__hv_vcpu_set_control_field' not in undef:raise ValueError('C ABI not joined')
 files=[S/x for x in changed+['modern_cpu_kernel_lifecycle_v22.h','modern_cpu_kernel_control_v22.inc','modern_cpu_native_public_factory_v18.h',
  'modern_cpu_native_public_factory_control_v18.inc','test-modern-cpu-control-factory-v18.m','modern_cpu_config_private_abi_v1.h']]+[pathlib.Path(__file__).resolve()]
 report=dict(schema='true Life22 Factory18 control2_7_8 local v1',provider=pin(provider),models=models,exactExports=sorted(exports),
  singleCPURegistry=True,actualNativeImportsUnchanged=len(m.imports),sourcePins=[pin(x) for x in files],reusedObjectPins=[pin(x) for x in sorted(set(reuse))],
  inheritedRoot12=pin(D/'freeze.json'),basisInputs=[pin(raw/'Hypervisor'),pin(raw/'VirtualMachine.arm64e'),pin(oldpath)],
  actualModernTable=list(table),actualClosedSelectors=[2,7,8],actualOldOffsets=[0x688,0x6e0,0x6e8],basisCaptures=captures,
  counterReader21Unchanged=True,typedCppUnmangled=True,otherControlSelectorsImplemented=False,deviceOperations=0,nativeOperations=0,providerLoaded=False,guestBoot=False)
 (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
 files+=[out/'candidate.json',provider,D/'freeze.json',out/'commands.json',cpp,out/'typed.o',exportfile]+[pathlib.Path(x['pin']['path']) for x in captures]
 (out/'freeze.json').write_text(json.dumps(dict(schema='Life22 Factory18 control source freeze v1',files=[pin(x) for x in files]),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),provider=pin(provider),freeze=pin(out/'freeze.json'),models=models)))
if __name__=='__main__':main()
