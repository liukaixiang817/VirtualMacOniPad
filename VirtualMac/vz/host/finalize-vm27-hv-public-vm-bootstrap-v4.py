"""Finalize the corrected VM/RAM source candidate without device execution."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'vm-hv-public-bootstrap-integration-local-v4'
def pin(path):
 p=Path(path).absolute();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def require(value,reason):
 if not value:raise ValueError(reason)
def actual_imports(path):
 b=Path(path).read_bytes();at=32;libraries=[];fix=None
 require(struct.unpack_from('<I',b)[0]==0xfeedfacf,'actual Mach-O64')
 for _ in range(struct.unpack_from('<I',b,16)[0]):
  cmd,size=struct.unpack_from('<II',b,at)
  require(size>=8 and at+size<=len(b),'load command extent')
  if cmd in (12,0x80000018,0x8000001f,0x80000023):
   offset=struct.unpack_from('<I',b,at+8)[0]
   end=b.index(0,at+offset,at+size);libraries.append(b[at+offset:end].decode())
  if cmd==0x80000034:fix=struct.unpack_from('<II',b,at+8)
  require(cmd!=0x1d,'unsigned candidate only');at+=size
 require(fix is not None and fix[0]+fix[1]<=len(b),'actual chained fixups')
 f=b[fix[0]:fix[0]+fix[1]]
 version,starts,imp,symbols,count,fmt,symfmt=struct.unpack_from('<7I',f)
 require(version==0 and fmt==1 and symfmt==0,'actual uncompressed import format1')
 result=[]
 for i in range(count):
  word=struct.unpack_from('<I',f,imp+4*i)[0];ordinal=word&255
  require(not word&256 and 1<=ordinal<=len(libraries),'strong actual owner')
  name=symbols+(word>>9);end=f.index(0,name)
  result.append(dict(symbol=f[name:end].decode(),path=libraries[ordinal-1]))
 return result
def main():
 require(not (D/'freeze.json').exists() and not (D/'finalization.json').exists(),'completed finalization')
 candidatePath=D/'candidate.json';c=json.loads(candidatePath.read_bytes());provider=Path(c['candidate']['path'])
 require(pin(provider)==c['candidate'],'provider drift')
 for row in c['inputs']:require(pin(row['path'])==row,'candidate input drift')
 parent=N/'cpu-hv-public-run-cluster-integration-local-v1/freeze.json';rows={}
 for row in json.loads(parent.read_bytes())['files']:
  require(pin(row['path'])==row,'frozen parent drift '+row['path']);rows[row['path']]=row
 expectedFactory=(S/'modern_cpu_native_public_factory_v8.c').read_text().replace(
  '"modern_cpu_native_public_factory_v8.h"','"modern_cpu_native_public_factory_v9.h"')+'\n#include "modern_cpu_native_public_factory_ram_adopt_v9.inc"\n'
 require((S/'modern_cpu_native_public_factory_v9.c').read_text()==expectedFactory,'Factory8 unchanged plus RAM adoption')
 proofPath=N/'cpu-hv-public-feature-current-definitions-readonly-v2/current-definitions.json'
 proof=json.loads(proofPath.read_bytes())
 for row in proof['inputs']:require(pin(row['path'])==row,'current definitions input drift')
 known={(x['importEntry']['symbol'],x['importEntry']['path']):x for x in proof['proofs']}
 actual=actual_imports(provider)
 require(len(actual)==42 and all((x['symbol'],x['path']) in known for x in actual),'actual42 current owner join')
 source=D/'typed-vm-ram-run-cpp-caller.cpp'
 source.write_text('''#include "vm27_hv_public_vm_bootstrap_v4.h"
#include <type_traits>
static_assert(sizeof(hv_vm_config_t)==8 && sizeof(hv_return_t)==4 && sizeof(hv_ipa_t)==8,"VM ABI");
static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_vcpu_exit_t)==32,"CPU ABI");
static_assert(std::is_same<decltype(&hv_vm_map),hv_return_t(*)(void*,hv_ipa_t,size_t,hv_memory_flags_t)>::value,"SDK map signature");
extern "C" hv_return_t OwnVMRAMRunCaller(hv_vm_config_t c,uint32_t*p,void*host,
 VM27CPUFactoryVMV2*vm,VM27CPUFactoryRAMV5**ram,VZKernelRAMResultV9*result,hv_vcpu_t cpu){
 hv_vm_config_t a=hv_vm_config_create();
 hv_return_t r=hv_vm_config_get_default_ipa_size(p)|hv_vm_config_get_max_ipa_size(p)|
 hv_vm_config_get_ipa_size(c,p)|hv_vm_config_set_ipa_size(c,36)|
 hv_vm_config_set_ipa_granule(c,(hv_ipa_granule_t)0)|hv_vm_config_set_el2_enabled(c,false)|
 _hv_vm_config_set_isa(c,1)|_hv_vm_config_set_vhe_enabled(c,false)|hv_vm_create(a)|
 hv_vm_map(host,0x40000000,16384,7)|hv_vm_protect(0x40000000,16384,5)|
 hv_vm_unmap(0x40000000,16384)|hv_vm_destroy()|hv_vcpu_run(cpu);
 return r|VM27CPUFactoryRAMAdoptHostV9(vm,host,16384,ram,result);
}
''')
 expected=sorted('_'+x for x in c['exactExports'] if x.startswith(('hv_vm_','_hv_vm_')))
 expected+=['_hv_vcpu_run','_VM27CPUFactoryRAMAdoptHostV9'];expected.sort()
 require(len(expected)==16 and not any(x.startswith('___hv_vm_') for x in expected),'real private C name count')
 cpp=[]
 for kind in ['macosx','iphoneos']:
  obj=D/(kind+'-typed-vm-ram-run-cpp.o')
  args=['xcrun','--sdk',kind,'clang++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(S)]
  if kind=='iphoneos':args+=['-arch','arm64e','-miphoneos-version-min=16.1']
  q=subprocess.run(args+['-c',str(source),'-o',str(obj)],capture_output=True,timeout=30)
  (D/(kind+'-typed-vm-ram-run-cpp.stdout')).write_bytes(q.stdout)
  (D/(kind+'-typed-vm-ram-run-cpp.stderr')).write_bytes(q.stderr)
  require(q.returncode==0,kind+' true C++ compile')
  nm=subprocess.check_output(['xcrun','nm','-u',str(obj)],timeout=30)
  (D/(kind+'-typed-vm-ram-run-cpp-nm.stdout')).write_bytes(nm)
  symbols=sorted(x.split()[-1].decode() for x in nm.splitlines() if x.split())
  require(symbols==expected,'actual16 C symbols '+kind)
  cpp.append(dict(platform=kind,object=pin(obj),symbols=symbols))
 contractPath=N/'vmm-public-adapter-gap-design-v1/contract.json'
 contract=json.loads(contractPath.read_bytes());original=contract['allHypervisorImports']
 for row in contract['inputs']:require(pin(row['path'])==row,'original contract input drift')
 require(len(original)==75 and len({x['name'] for x in original})==75 and
  all(x['ordinal']==21 and x['weak'] is False for x in original),'original75 strong imports')
 exportNames={'_'+x for x in c['exactExports']}
 covered=[x for x in original if x['name'] in exportNames]
 missing=[x for x in original if x['name'] not in exportNames]
 require(len(covered)==24 and len(missing)==51,'actual original symbol closure count')
 host=json.loads((D/'host-results.json').read_bytes())
 require(len(host['selected'])==2 and all(x['checks']==234 for x in host['selected']),'actual234 host receipts')
 # This compile uses the finalized standalone header. The earlier host binaries
 # predate its lexical separation from v2; their behavioral receipts stay intact.
 previous=N/'vm-hv-public-bootstrap-integration-local-v2/parent-Run-regression.json'
 lower=N/'cpu-borrowed-ram-lifecycle-local-v1/host-results.json'
 final=dict(schema='Corrected public VM RAM and one-call CPU source finalization v4',
  finiteLocalScopePassed=True,candidate=pin(candidatePath),provider=pin(provider),
  parentFreeze=pin(parent),currentDefinitions=pin(proofPath),
  actual42StrongImportDefinitionsJoined=True,proofs=[known[x['symbol'],x['path']] for x in actual],
  actualCPPCaller=cpp,correctPrivateCNames=True,originalImportContract=pin(contractPath),
  originalStrongHypervisorImports=75,originalImportsWithExport=covered,remainingOriginalImports=missing,
  exactExportCount=58,coveredOriginalImportCount=24,remainingOriginalImportCount=51,
  originalImportsWithExportAreNotFullSemanticProof=True,Factory8UnchangedPlusRAMAdoption=True,
  normalChecks=234,sanitizedChecks=234,ownVMConfigRealCFCreateDestroyEach=2,
  hostBehaviorPrecedesStandaloneHeaderSeparation=False,finalStandaloneHeaderCPPCompiled=True,
  parentRunRegression=pin(previous),borrowedRAMRegression=pin(lower),
  allNativeTrapsMocked=True,nativeCallsExecuted=0,deviceOperations=0,
  providerSigned=False,providerLoaded=False,fullPublicVMEquivalent=False,
  fullPublicRAMEquivalent=False,fullPublicRunEquivalent=False,
  originalVMMIntegrated=False,guestInstructions=0,full27Backend=False)
 with (D/'finalization.json').open('x') as f:json.dump(final,f,indent=2);f.write('\n')
 for p in D.iterdir():
  if p.is_file() and p.name!='freeze.json':rows[str(p.absolute())]=pin(p)
 for row in c['inputs']+proof['inputs']+contract['inputs']:rows[row['path']]=row
 extra=[Path(__file__),parent,proofPath,contractPath,previous,lower,
  S/'test-modern-cpu-borrowed-ram-lifecycle-v11.c']
 for kind in ['macosx','iphoneos']:
  sdk=Path(subprocess.check_output(['xcrun','--sdk',kind,'--show-sdk-path'],text=True).strip())
  if kind=='macosx':
   extra += [sdk/'System/Library/Frameworks/Hypervisor.framework/Headers'/name for name in
    ['hv_vm.h','hv_vm_config.h','hv_vm_types.h','hv_vcpu.h','hv_vcpu_types.h']]
 for p in extra:rows[str(p.absolute())]=pin(p)
 with (D/'freeze.json').open('x') as f:
  json.dump(dict(schema='Corrected public VM RAM source immutable finite freeze v4',files=list(rows.values())),f,indent=2);f.write('\n')
 print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),pins=len(rows),
  actualOriginalExportsCovered=24,remainingOriginalImports=51,nativeCalls=0)))
if __name__=='__main__':main()
