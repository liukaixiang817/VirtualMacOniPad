#!/usr/bin/env python3
"""Build one CPU registry with own DTR bank; no device/sign/native execution."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys,importlib.util,re
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,m):
 if not v:raise ValueError(m)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);out=ap.parse_args().out.resolve();need(out.parent==N and not out.exists(),'fresh host diagnostic output');out.mkdir()
 base=N/'cpu-own-feature-profile-local-v1-attempt2';candidate=base/'candidate.json';old=json.loads(candidate.read_text());freeze=base/'freeze.json';f=json.loads(freeze.read_text())
 for q in f['files']:need(pin(q['path'])==q,'frozen F20 pin '+q['path'])
 oldCommands=json.loads((base/'commands.json').read_text());commands=[];reused=set();models={}
 def run(label,argv):
  argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,timeout=60);stdout=out/(label+'.stdout');stderr=out/(label+'.stderr');stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
  commands.append(dict(label=label,argv=argv,returncode=p.returncode,stdout=pin(stdout),stderr=pin(stderr)));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  need(not p.returncode,label+': '+p.stderr.decode(errors='replace'));return p.stdout
 sources=['modern_cpu_native_public_factory_v21','modern_cpu_kernel_lifecycle_v23','modern_vmm_dtr_v1']
 for mode in ['normal','san','ios']:
  template=next(q['argv']for q in oldCommands if q['label']==mode+'-modern_cpu_native_public_factory_v20')
  for src in sources:
   argv=template.copy();argv[argv.index('-c')+1]=S/(src+'.c');name=(mode+'-'if mode!='ios'else'')+src+'.o';argv[-1]=out/name
   if src=='modern_cpu_kernel_lifecycle_v23':
    argv.insert(argv.index('-c'),'-fvisibility=hidden')
    if mode!='ios':argv.insert(argv.index('-c'),'-DVZKernelCPUReleaseBorrowV5=DTRActualReleaseV21')
   run(mode+'-'+src,argv)
  argv=next(q['argv']for q in oldCommands if q['label']==mode+'-link').copy()
  for i,x in enumerate(argv):
   if x.endswith(('normal-modern_cpu_native_public_factory_v20.o','san-modern_cpu_native_public_factory_v20.o','/modern_cpu_native_public_factory_v20.o')):argv[i]=str(out/((mode+'-'if mode!='ios'else'')+'modern_cpu_native_public_factory_v21.o'))
   elif x.endswith(('normal-modern_cpu_kernel_lifecycle_v22.o','san-modern_cpu_kernel_lifecycle_v22.o','/modern_cpu_kernel_lifecycle_v22.o')):argv[i]=str(out/((mode+'-'if mode!='ios'else'')+'modern_cpu_kernel_lifecycle_v23.o'))
   elif x.endswith('/test-modern-cpu-own-feature-profile-v1.m'):argv[i]=str(S/'test-modern-cpu-dtr-factory-v21.m')
  argv.insert(argv.index('-framework'),str(out/((mode+'-'if mode!='ios'else'')+'modern_vmm_dtr_v1.o')))
  if mode=='ios':
   exports=out/'exports.txt';exports.write_text('\n'.join(sorted(old['exactExports']+['_VM27CPUFactoryAccessDTRV21','_VM27VMMReadDTRV1','_VM27VMMWriteDTRV1']))+'\n')
   for i,x in enumerate(argv):
    if x.startswith('-Wl,-exported_symbols_list,'):argv[i]='-Wl,-exported_symbols_list,'+str(exports)
    if x.startswith('-Wl,-install_name,'):argv[i]='-Wl,-install_name,@rpath/VM27HVVMDTRV21.unsigned.dylib'
   argv[-1]=str(out/'VM27HVVMDTRV21.unsigned.dylib')
  else:argv[-1]=str(out/mode)
  for x in argv:
   if isinstance(x,str) and x.endswith('.o') and Path(x).parent!=out:reused.add(Path(x))
  run(mode+'-link',argv)
  if mode!='ios':models[mode]=json.loads(run(mode+'-run',[out/mode]));need(models[mode]['checks']==689 and models[mode]['nativeOperations']==0,'bounded model result')
 provider=out/'VM27HVVMDTRV21.unsigned.dylib';run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
 parser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';spec=importlib.util.spec_from_file_location('dtrmacho',parser);lib=importlib.util.module_from_spec(spec);spec.loader.exec_module(lib)
 m=lib.MachO(provider.read_bytes());o=lib.MachO(Path(old['provider']['path']).read_bytes());need(set(m.exports)==set(old['exactExports'])|{'_VM27CPUFactoryAccessDTRV21','_VM27VMMReadDTRV1','_VM27VMMWriteDTRV1'},'153 exact exports');need(m.imports==o.imports,'71 exact current imports retained');need(len(m.imports)==71,'71 actual imports')
 # Compile and strong link C++ caller against actual iOS SDK and new 153 exports.
 typed=out/'typed-dtr.cpp';typed.write_text('#include "modern_vmm_dtr_v1.h"\nextern "C" uint64_t typed_dtr(hv_vcpu_t id,VM27VMMScalarFailureV1 fail){uint64_t v=0;VM27CPUFactoryAccessDTRV21(id,VZ_KERNEL_DTR_READ_RX_V23,0,&v);VM27VMMWriteDTRV1(id,0x9820,v,fail);return VM27VMMReadDTRV1(id,0x9828,fail);}\n')
 run('typed-cpp-ios',['xcrun','--sdk','iphoneos','clang++','-arch','arm64e','-miphoneos-version-min=16.1','-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-dynamiclib',typed,provider,'-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',out/'typed-dtr.unsigned.dylib'])
 primary=[S/(x+'.c')for x in sources]+[S/'modern_cpu_kernel_lifecycle_v23.h',S/'modern_cpu_kernel_dtr_v23.inc',S/'modern_cpu_native_public_factory_v21.h',S/'modern_cpu_native_public_factory_dtr_v21.inc',S/'modern_vmm_dtr_v1.h',S/'test-modern-cpu-dtr-factory-v21.m'];seen=set()
 def include(p):
  p=Path(p).resolve()
  if p in seen:return
  seen.add(p)
  for name in re.findall(r'^\s*#include\s+"([^"]+)"',p.read_text(errors='replace'),re.M):
   child=p.parent/name
   if child.is_file():include(child)
 for p in primary:include(p)
 life=(S/'modern_cpu_kernel_lifecycle_v23.c').read_text();need(life.count('static pthread_mutex_t RegistryMutex')==1,'one lower registry');need(life.count('static VZKernelVM *RegisteredVM')==1,'one lower owner');need('#include "modern_cpu_kernel_lifecycle_v21.c"' not in life,'single flat lower base');factory=(S/'modern_cpu_native_public_factory_v21.c').read_text();need(factory.count('#include "modern_cpu_native_public_factory_v20.c"')==1,'one inherited factory')
 record=dict(schema='Own per-CPU software DTR bank and genuine typed VMM wrapper source v21',builder=pin(__file__),provider=pin(provider),inheritedCandidate=pin(candidate),inheritedFreeze=pin(freeze),models=models,exactExports=sorted(m.exports),newExports={k:v for k,v in m.exports.items()if k not in o.exports},actualNativeImportsUnchanged=71,singleCPURegistry=True,ownSoftwareResetZeroPolicy=True,hardwareDebuggerRXProducerImplemented=False,combinedSetterActualTwoWritesToTX=True,realOwnerEpochGenerationVersionGuards=True,partialWriteWithdraws=True,failedPublicReleaseRetainsActualBorrow=True,publicSDKHostDTRSYSImplementationClaim=False,originalVMMMethodsPatched=False,sourcePins=[pin(p)for p in sorted(seen)],primarySources=[pin(p)for p in primary],reusedObjectPins=[pin(p)for p in sorted(reused)],deviceOperations=0,nativeOperations=0,codeSigned=False,providerLoadedOnDevice=False,guestBoot=False)
 (out/'candidate.json').write_text(json.dumps(record,indent=2)+'\n');paths=seen|reused|{Path(__file__).resolve(),candidate,freeze,base/'commands.json',parser,Path(old['provider']['path'])}|set(out.iterdir());(out/'freeze.json').write_text(json.dumps(dict(schema='Own DTR source and actual unsigned single-registry provider frozen v21',files=[pin(p)for p in sorted(paths)if p.is_file()],deviceOperations=0,nativeOperations=0),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),provider=pin(provider),models=models,actualExports=len(m.exports),actualImports=len(m.imports))))
if __name__=='__main__':main()
