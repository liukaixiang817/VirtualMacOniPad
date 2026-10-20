#!/usr/bin/env python3
"""Validate scalar private methods against real Root11 owners, never a device."""
from pathlib import Path
import argparse,hashlib,json,os,runpy,subprocess,struct,sys
sys.dont_write_bytecode=True
S=Path(__file__).resolve().parent;N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);out=p.parse_args().out.resolve()
 if out.parent!=N.resolve() or out.exists():raise ValueError('Fresh diagnostic output required')
 out.mkdir(mode=0o700);commands=[];models={};closure=set()
 root=N/'vm-hv-public-bootstrap-integration-local-v11-attempt2';rootCandidate=json.loads((root/'candidate.json').read_bytes())
 rootFreeze=json.loads((root/'freeze.json').read_bytes())
 def inherited():
  for row in rootFreeze['files']:
   if pin(row['path'])!=row:raise ValueError('Frozen Root11 input drift: '+row['path'])
 inherited();rootBuilder=S/'build-vm27-hv-public-vm-bootstrap-v11.py';b=runpy.run_path(str(rootBuilder))
 def run(label,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
  env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45,env=env)
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append(dict(label=label,args=list(map(str,args)),returncode=r.returncode))
  (out/'commands-in-progress.json').write_text(json.dumps(commands,indent=2)+'\n')
  if r.returncode:raise RuntimeError(label+': '+r.stderr.decode(errors='replace'))
  return r.stdout
 common=['-Wall','-Wextra','-Werror','-I',S,'-DVM27_HV_VM_GUARD_LINKED=1']
 source=S/'modern_vmm_private_cpu_scalar_v1.c';fixture=S/'test-modern-vmm-private-cpu-scalar-v1.m';cpp=S/'test-modern-vmm-private-cpu-scalar-v1.cpp'
 try:
  for mode,flags in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   objects=[]
   for unit in [S/n for n in b['UNITS']]+[source,fixture]:
    obj=out/(mode+'-'+unit.stem+'.o');objects.append(obj)
    run(mode+'-'+unit.stem,['xcrun','--sdk','macosx','clang','-std=c11',*common,
     '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1',*flags,
     *(['-fno-objc-arc'] if unit.suffix=='.m' else []),'-fexceptions','-c',unit,'-o',obj])
   exe=out/mode
   run(mode+'-link',['xcrun','--sdk','macosx','clang++','-std=c++17',*common,*flags,
    *objects,cpp,'-framework','CoreFoundation','-lobjc','-o',exe])
   models[mode]=json.loads(run(mode+'-run',[exe]).splitlines()[-1])
  if models['normal']!=models['san'] or not models['normal']['actual53NativeFieldPairs']:raise RuntimeError('Actual model mismatch')
  ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11',*common]
  obj=out/'scalar-ios.o';dep=out/'scalar-ios.d'
  run('scalar-ios',[*ios,'-fexceptions','-MMD','-MF',dep,'-c',source,'-o',obj])
  for token in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
   path=Path(token).resolve()
   if path.is_relative_to(S):closure.add(path)
  exports=['VM27VMMReadCPUScalarV1','VM27VMMWriteCPUScalarV1','VM27VMMUpdateACTLRBit1V1']
  exportFile=out/'exports.txt';exportFile.write_text(''.join('_'+n+'\n' for n in sorted(exports)))
  provider=out/'VM27VMMPrivateCPUScalarMethodsV1.unsigned.dylib'
  run('scalar-ios-link',[*ios,'-dynamiclib',obj,rootCandidate['provider']['path'],
   '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exportFile),
   '-Wl,-install_name,@rpath/VM27VMMPrivateCPUScalarMethodsV1.dylib','-o',provider])
  run('scalar-validate',['xcrun','dyld_info','-validate_only',provider])
  actual=sorted(line.split()[-1].decode() for line in run('scalar-exports',['xcrun','nm','-gU',provider]).splitlines() if line.split())
  if actual!=['_'+n for n in sorted(exports)]:raise RuntimeError('Actual exports mismatch')
  parserPath=N/'cpu-config-capability-query-current-definitions-readonly-v1/audit.py';parser=runpy.run_path(str(parserPath))
  data=provider.read_bytes();header=parser['header'](data);imports=parser['imports'](data,header)
  expected={'_VM27VMMGetMandatoryFieldV2','_VM27VMMSetMandatoryFieldV2','_hv_vcpu_get_sys_reg','_hv_vcpu_set_sys_reg'}
  if {row['symbol'] for row in imports}!=expected or len(imports)!=4:raise RuntimeError('Actual true owner API imports mismatch')
  rootDefs={'_'+n for n in rootCandidate['exactExports']}
  if any(row['weak'] or row['path']!='@rpath/VM27HVVMCPUCombinedV11.dylib' or row['symbol'] not in rootDefs for row in imports):raise RuntimeError('Scalar provider actual Root11 definition join')
  at=32
  for _ in range(struct.unpack_from('<I',data,16)[0]):
   command,size=struct.unpack_from('<II',data,at)
   if command==0x1d:raise RuntimeError('Unexpected code signature')
   at+=size
  typed=out/'typed-scalar.cpp'
  typed.write_text('#include "modern_vmm_private_cpu_scalar_v1.h"\n'
   'static_assert(sizeof(hv_vcpu_t)==8 && sizeof(uint32_t)==4,"original scalar ABI");\n'
   'extern "C" uint64_t typed(hv_vcpu_t cpu,uint32_t s,uint64_t v,VM27VMMScalarFailureV1 f){\n'
   ' uint64_t(*r)(hv_vcpu_t,uint32_t,VM27VMMScalarFailureV1)=VM27VMMReadCPUScalarV1;\n'
   ' void(*w)(hv_vcpu_t,uint32_t,uint64_t,VM27VMMScalarFailureV1)=VM27VMMWriteCPUScalarV1;\n'
   ' void(*u)(hv_vcpu_t,uint32_t,VM27VMMScalarFailureV1)=VM27VMMUpdateACTLRBit1V1;\n'
   ' if(s==1){w(cpu,s,v,f);return 0;}if(s==2){u(cpu,s,f);return 0;}return r(cpu,s,f);}\n')
  typedRows={}
  for sdk in ['macosx','iphoneos']:
   obj=out/(sdk+'-typed.o')
   run(sdk+'-typed',['xcrun','--sdk',sdk,'clang++','-std=c++17',*common,
    *(['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []),'-c',typed,'-o',obj])
   symbols=sorted(line.split()[-1].decode() for line in run(sdk+'-typed-symbols',['xcrun','nm','-u',obj]).splitlines() if line.split())
   if symbols!=actual:raise RuntimeError('Actual unmangled scalar C++ ABI mismatch')
   typedRows[sdk]=symbols
  inherited()
  report=dict(schema='genuine original VMM private scalar source adapter with true Root11 owners v1',
   models=models,provider=pin(provider),actualExports=actual,actualOwnerImports=imports,actualOwnerProvider=rootCandidate['provider'],
   inheritedRoot11=pin(root/'candidate.json'),inheritedRoot11Freeze=pin(root/'freeze.json'),
   originalSelectorWhitelistCount=53,actualNativeContextProjected=False,sourceOperationNeverReturnsSuccessOnError=True,
   errorCallbackReceivesActualPublicStatus=True,actualScalarCppCallerABI=typedRows,
   actualSourceClosure=[pin(p) for p in sorted(closure)],sourceSigned=False,sourceLoaded=False,
   originalVMMExecuted=False,nativeCallsExecuted=0,deviceOperations=0,fullIndependent27GuestBoot=False,commands=commands)
  (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
  paths=[Path(__file__),source,fixture,cpp,rootBuilder,parserPath,root/'candidate.json',root/'freeze.json']+sorted(closure)+[p for p in out.iterdir() if p.is_file()]
  (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in paths],nativeCallsExecuted=0,deviceOperations=0),indent=2)+'\n')
  print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),models=models,provider=pin(provider))))
 except BaseException as error:
  (out/'failure.json').write_text(json.dumps(dict(error=str(error),commands=commands),indent=2)+'\n');raise
if __name__=='__main__':main()
