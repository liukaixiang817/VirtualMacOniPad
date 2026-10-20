#!/usr/bin/env python3
"""Own architectural profile + genuine single CPU registry; no device I/O."""
import argparse,hashlib,importlib.util,json,os,pathlib,struct,subprocess,sys
sys.dont_write_bytecode=True
S=pathlib.Path(__file__).resolve().parent
N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=pathlib.Path,required=True);out=a.parse_args().out.resolve()
 if out.parent!=N.resolve():raise ValueError('Fresh diagnostics required')
 out.mkdir(exist_ok=False)
 D=N/'vm-hv-public-bootstrap-integration-local-v15-attempt1'
 inheritedFreeze=json.loads((D/'freeze.json').read_text())
 for row in inheritedFreeze['pins']+[inheritedFreeze['candidate'],inheritedFreeze['finalization']]:
  if pin(row['path'])!=row:raise ValueError('Frozen Root15 changed '+row['path'])
 spec=importlib.util.spec_from_file_location('root12',S/'build-vm27-hv-public-vm-bootstrap-v12.py')
 root=importlib.util.module_from_spec(spec);spec.loader.exec_module(root)
 sys.path.insert(0,str(N/'modern27-remaining-context-fields-independent-readonly-v1'));from independent_macho import MachO
 raw=S.parents[2]/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw'
 vmm=MachO((raw/'VirtualMachine.arm64e').read_bytes())
 origin=N/'ordinary-cpu-config-capability-device-v1/03-cpu-config-execute/stdout'
 observation=next(json.loads(line) for line in origin.read_text().splitlines() if line.startswith('{') and json.loads(line).get('kind')=='nativeContext')
 response=bytes.fromhex(observation['hex'])
 if len(response)!=352 or int.from_bytes(response[0x140:0x148],'little')!=0x21:raise ValueError('Actual previously observed Native0')
 nativeInclude=out/'native0-observed-v20.inc';nativeInclude.write_text(','.join(str(x)for x in response)+'\n')
 order=[11,0,1,2,3,14,4,5,6,16,17,7,8,15,12,13]
 calls=[0x2b646c+0x20*i for i in range(16)]
 for call,selector in zip(calls,order):
  w=struct.unpack_from('<I',vmm.data,vmm.file(vmm.base+call-4))[0]
  if w!=(0x52800001|(selector<<5)):raise ValueError('Actual ctor selector '+hex(call))
  w=struct.unpack_from('<I',vmm.data,vmm.file(vmm.base+call))[0]
  if w!=(0x94000000|(((0x412d34-call)//4)&0x3ffffff)):raise ValueError('Actual ctor strong caller')
  nextw=struct.unpack_from('<I',vmm.data,vmm.file(vmm.base+call+4))[0]
  if nextw&0xff00001f!=0x35000000:raise ValueError('Actual ctor fail path')
 anchors={0x2b65f8:0xf9005668,0x2327c:0x9101c2e0,0x23280:0x9100c261,0x23284:0x52802022,
  0x2e9c50:0xa903e274,0x2e9d04:0x3d81a280,0x2ebe90:0xf9434295,0x2ec024:0xa93657b9,
  0x2ec070:0x3dc00100,0x2ec074:0x3c808000,0xb235c:0xf9400a74,0xb23b8:0xf9401297,
  0xb2434:0xa9026017,0xb2438:0x52800088,0xb243c:0xb9003008,
  0x288970:0x3943af48,0x288974:0x72000d1f,0x288978:0x54002920,
  0x28b5a8:0x3943af88,0x28b5ac:0x72000d1f,0x28b5b0:0x54002220}
 for rva,w in anchors.items():
  if struct.unpack_from('<I',vmm.data,vmm.file(vmm.base+rva))[0]!=w:raise ValueError('Actual feature pointer anchor '+hex(rva))
 captures=[]
 for name,lo,hi in [('actual-feature-ctor',0x2b63d4,0x2b6824),('actual-feature-vm-copy',0x2316c,0x232a4),
  ('actual-feature-config-copy',0x307c60,0x307ca0),('actual-feature-output-copy',0x30e638,0x30e654),
  ('actual-feature-moving-copy',0x3b6a0,0x3b6f0),('actual-feature-context-pointer',0x2e9b24,0x2e9d20),
  ('actual-feature-job-pointer',0x2ebe90,0x2ec080),('actual-feature-cpu-pointer',0xb2310,0xb2440),
  ('actual-feature-save-sme-gate',0x288968,0x28897c),('actual-feature-restore-sme-gate',0x28b5a8,0x28b5b4)]:
  b=vmm.data[vmm.file(vmm.base+lo):vmm.file(vmm.base+lo)+hi-lo]
  p=out/(name+'.bin');p.write_bytes(b);captures.append(dict(range=[hex(lo),hex(hi)],pin=pin(p)))
 commands=[];models={};reused=[];closure=set()
 def run(label,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45,env=env)
  for suffix,b in [('stdout',r.stdout),('stderr',r.stderr)]: (out/(label+'.'+suffix)).write_bytes(b)
  commands.append(dict(label=label,argv=list(map(str,args)),returncode=r.returncode,
   stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
  (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if r.returncode:raise RuntimeError(label+': '+r.stderr.decode(errors='replace'))
  return r.stdout
 common=['-std=c11','-Wall','-Wextra','-Werror','-I',S,'-I',out,'-DVM27_HV_VM_GUARD_LINKED=1']
 changed=['modern_cpu_native_public_factory_v20.c','modern_cpu_kernel_system_v4.c','modern_cpu_own_feature_profile_v1.c']
 local=changed+['modern_cpu_kernel_lifecycle_v22.c','modern_cpu_config_os_object_v6.m','modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c']
 replaced={'modern_cpu_native_public_factory_v17.c','modern_cpu_kernel_lifecycle_v21.c','modern_cpu_config_os_object_v5.m','modern_cpu_kernel_system_v3.c'}
 R12=N/'vm-hv-public-bootstrap-integration-local-v12-attempt2'
 Optional=N/'cpu-optional-abi-owner-refusal-local-v1-attempt3'
 for mode,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  objects=[R12/('scalar-'+mode+'-'+pathlib.Path(n).stem+'.o') for n in root.UNITS if n not in replaced]
  objects+=[R12/('scalar-'+mode+'-test-vm27-counter-hooks-v12.o'),Optional/(mode+'-modern_cpu_optional_abi_v1.o')]
  reused+=objects
  for name in local:
   obj=out/(mode+'-'+pathlib.Path(name).stem+'.o');objects.append(obj)
   flags=['-DVM27_CPU_CAPABILITY_TESTING=1'] if name=='modern_cpu_config_capability_acquisition_v2.c' else []
   if name=='modern_cpu_config_os_object_v6.m':flags+=['-DVM27CPUConfigReleaseBorrowV3=VM27CPUProfileActualConfigReleaseV20','-fno-objc-arc']
   run(mode+'-'+pathlib.Path(name).stem,['xcrun','--sdk','macosx','clang',*common,*extra,'-DVM27_CPU_CONFIG_TESTING=1',*flags,'-c',S/name,'-o',obj])
  exe=out/mode;run(mode+'-link',['xcrun','--sdk','macosx','clang',*common,*extra,'-DVM27_HV_VM_TESTING=1','-fno-objc-arc',
   *objects,S/'test-modern-cpu-own-feature-profile-v1.m','-framework','CoreFoundation','-lobjc','-o',exe])
  models[mode]=json.loads(run(mode+'-run',[exe]).splitlines()[-1])
 if models['normal']!=models['san']:raise ValueError('Changed model disagreement')
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',*common];objects=[]
 for name in changed:
  dep=run(pathlib.Path(name).stem+'-closure',[*ios,'-MM',S/name]).decode()
  for token in dep.replace('\\\n',' ').split(':',1)[1].split():
   p=pathlib.Path(token).resolve()
   if p.is_relative_to(S):closure.add(p)
  obj=out/(pathlib.Path(name).stem+'.o');objects.append(obj)
  run('ios-'+pathlib.Path(name).stem,[*ios,*(['-fvisibility=hidden'] if name!='modern_cpu_native_public_factory_v20.c' else []),'-c',S/name,'-o',obj])
 oldLink=next(row['argv'] for row in json.loads((D/'commands.json').read_text()) if row['label']=='ios-link')
 inherited=[pathlib.Path(x) for x in oldLink if x.endswith('.o') and pathlib.Path(x).name not in {'modern_cpu_native_public_factory_v19.o','modern_cpu_kernel_system_v3.o'}]
 reused+=inherited;provider=out/'VM27HVVMOwnFeatureProfileV1.unsigned.dylib'
 run('ios-link',[*ios,'-dynamiclib',*inherited,*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error',
  '-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(D/'exports.txt'),'-Wl,-install_name,@rpath/VM27HVVMOwnFeatureProfileV1.unsigned.dylib','-o',provider])
 run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
 now=MachO(provider.read_bytes());old=MachO(pathlib.Path(json.loads((D/'candidate.json').read_text())['provider']['path']).read_bytes())
 def imports(m):return sorted((m.loads[x['ordinal']-1]['path'],x['name'],x['weak'],x['addend']) for x in m.imports)
 if set(now.exports)!=set(old.exports) or len(now.exports)!=150 or any(x['flags'] for x in now.exports.values()):raise ValueError('Actual exports')
 if imports(now)!=imports(old):raise ValueError('Actual native imports changed')
 cpp=out/'typed-caller.cpp';cpp.write_text('#include "modern_cpu_native_public_factory_v20.h"\n#include <type_traits>\nstatic_assert(sizeof(hv_feature_reg_t)==4);\nstatic_assert(std::is_same_v<decltype(&hv_vcpu_config_get_feature_reg),hv_return_t(*)(hv_vcpu_config_t,hv_feature_reg_t,uint64_t*)>);\n#if __has_include(<Hypervisor/hv_vcpu_config.h>)\nstatic_assert(HV_FEATURE_REG_ID_AA64SMFR0_EL1==12 && HV_FEATURE_REG_ID_AA64ZFR0_EL1==13 && HV_FEATURE_REG_ID_AA64ISAR2_EL1==14 && HV_FEATURE_REG_ID_AA64PFR2_EL1==15 && HV_FEATURE_REG_ID_AA64MMFR3_EL1==16 && HV_FEATURE_REG_ID_AA64MMFR4_EL1==17);\n#endif\nextern "C" hv_return_t C(hv_vcpu_config_t c,hv_feature_reg_t r,uint64_t*p){return hv_vcpu_config_get_feature_reg(c,r,p);}\nextern "C" VZKernelStatus P(const VZKernelCapabilitySeed*s,uint64_t*p){return VM27CPUOwnProfileGetFeatureV1(s,17,p);}\n')
 for sdk,flags in [('iphoneos',['-arch','arm64e','-miphoneos-version-min=16.1']),('macosx',[])]:
  obj=out/('typed-'+sdk+'.o');run(sdk+'-cxx',['xcrun','--sdk',sdk,'clang++',*flags,'-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-c',cpp,'-o',obj])
  undefined=run(sdk+'-cxx-undefined',['xcrun','nm','-u',obj])
  if b'_hv_vcpu_config_get_feature_reg' not in undefined or b'_VM27CPUOwnProfileGetFeatureV1' not in undefined:raise ValueError('Actual C ABI')
 primary=[dict(url='https://documentation-service.arm.com/static/6526e1bd9e189a266cef8412',claim='SMFR0/ZFR0 absent extensions have no advertised SME/SVE capabilities.'),
  dict(url='https://documentation-service.arm.com/static/69aac74fe79f9a1d642aa91f?token=',page=140,claim='MMFR4.E2H0 is RES0 without AA64EL2.'),
  dict(url='https://documentation-service.arm.com/static/665741bb876c8d213b78610b',claim='Zero ISAR2/MMFR3 fields do not advertise their optional architecture extensions.'),
  dict(url='https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/tools/sysreg',claim='Primary register encoding definitions: PFR0.SVE, PFR1.SME, PFR2 and MMFR4 conditional fields.')]
 sdk=pathlib.Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/System/Library/Frameworks/Hypervisor.framework/Headers/hv_vcpu_config.h')
 report=dict(schema='Own coherent EL2-off CPU feature profile local v1',provider=pin(provider),models=models,
  exactExports=sorted(now.exports),actualNativeImportsUnchanged=len(now.imports),singleCPURegistry=True,constructorSelectors=order,
  sourcePins=[pin(p) for p in sorted(closure)],reusedObjectPins=[pin(p)for p in sorted(set(reused))],
  originalInputs=[pin(raw/'VirtualMachine.arm64e'),pin(origin),pin(sdk)],basisCaptures=captures,primarySources=primary,
  nativeSeedWords='0..11 remain Native0-derived; own policy withholds EL2/EL3/SVE, SME, VH and NV',
  extensionWords='12..17 own architectural unimplemented-extension values; not bytes reported by Native0',
  freshSMEGate=dict(PFR1Response=0x21,originalSeedMask=0xf0,PFR1OwnValue=0x20,
   configPFR1Offset='a8',mainVMFeatureCopy=['2327c dest mainVM+70','23280 source temporaryFeature+30','23284 0x101 bytes','23288 memcpy'],
   mainVMPFR1Offset='e8',actualCPUFeaturesPointer=['2e9c50 embeddedContext+20=mainVM','2e9d04 mainVM680=embeddedContext',
    '2ebe90→2ec024→2ec070/74 actual job10=embeddedContext','b235c job10','b23b8 context20','b2434 CPU20=mainVM'],
   SMEByte='mainVM.eb=PFR1 bits31..24; low nibble bits27..24 SME',saveGate=['288970','288974','288978→288e9c'],restoreGate=['28b5a8','28b5ac','28b5b0→28b9f4'],
   originalMachineGatesPreserved=True,arbitrarySerializedRestoreClaimed=False),
  typedCppUnmangled=True,publicAndBorrowedSYSRejectConflictingIDs=True,deviceOperations=0,nativeOperations=0,
  providerLoaded=False,guestBoot=False,validGetContextReturnsView=False)
 (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
 files=sorted(closure|{S/x for x in changed+['modern_cpu_native_public_factory_v20.h','modern_cpu_native_public_factory_features_v20.inc','modern_cpu_own_feature_profile_v1.h','test-modern-cpu-own-feature-profile-v1.m']}|{pathlib.Path(__file__).resolve()})
 files+=[out/'candidate.json',out/'commands.json',provider,cpp,nativeInclude,D/'freeze.json',out/'typed-iphoneos.o',out/'typed-macosx.o']+[pathlib.Path(r['pin']['path']) for r in captures]
 (out/'freeze.json').write_text(json.dumps(dict(schema='Own feature profile freeze v1',files=[pin(p)for p in files]),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),provider=pin(provider),freeze=pin(out/'freeze.json'),models=models)))
if __name__=='__main__':main()
