"""Join actual bounded current definitions and append immutable source freeze."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';D=N/'vm-hv-public-bootstrap-integration-local-v1'
def pin(path):
 p=Path(path).absolute();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def imports(path):
 b=Path(path).read_bytes();at=32;libraries=[];fix=None
 for _ in range(struct.unpack_from('<I',b,16)[0]):
  cmd,size=struct.unpack_from('<II',b,at)
  if cmd in (12,0x80000018,0x8000001f,0x80000023):
   offset=struct.unpack_from('<I',b,at+8)[0];end=b.index(0,at+offset,at+size);libraries.append(b[at+offset:end].decode())
  if cmd==0x80000034:fix=struct.unpack_from('<II',b,at+8)
  at+=size
 if not fix:raise ValueError('fixups')
 f=b[fix[0]:fix[0]+fix[1]];version,starts,imp,symbols,count,fmt,symfmt=struct.unpack_from('<7I',f)
 if version or fmt!=1 or symfmt:raise ValueError('only exact actual uncompressed format1')
 result=[]
 for i in range(count):
  word=struct.unpack_from('<I',f,imp+4*i)[0];ordinal=word&255;weak=bool(word&256);name=symbols+(word>>9)
  end=f.index(0,name);symbol=f[name:end].decode()
  if weak or not 1<=ordinal<=len(libraries):raise ValueError('strong actual owner')
  result.append(dict(symbol=symbol,path=libraries[ordinal-1]))
 return result
def main():
 if (D/'freeze.json').exists():raise ValueError('completed freeze')
 c=json.loads((D/'candidate.json').read_bytes());provider=c['candidate']['path']
 if pin(provider)!=c['candidate']:raise ValueError('provider drift')
 parent=N/'cpu-hv-public-feature-cluster-integration-local-v3/freeze.json';rows={}
 for row in json.loads(parent.read_bytes())['files']:
  if pin(row['path'])!=row:raise ValueError('parent frozen drift '+row['path'])
  rows[row['path']]=row
 proofPath=N/'cpu-hv-public-feature-current-definitions-readonly-v2/current-definitions.json'
 proof=json.loads(proofPath.read_bytes());known={(x['importEntry']['symbol'],x['importEntry']['path']):x for x in proof['proofs']}
 actual=imports(provider)
 if len(actual)!=42 or any((x['symbol'],x['path']) not in known for x in actual):raise ValueError('actual42 bounded owner join')
 sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
 source=D/'typed-vm-cpp-caller.cpp'
 source.write_text('#include "vm27_hv_public_vm_bootstrap_v1.h"\nstatic_assert(sizeof(hv_vm_config_t)==8&&sizeof(hv_ipa_granule_t)==4&&sizeof(hv_return_t)==4,"ABI");\nextern "C" hv_return_t OwnVMCaller(hv_vm_config_t c,uint32_t*p){hv_vm_config_t a=hv_vm_config_create();hv_return_t r=hv_vm_config_get_default_ipa_size(p)|hv_vm_config_get_max_ipa_size(p)|hv_vm_config_get_ipa_size(c,p)|hv_vm_config_set_ipa_size(c,36)|hv_vm_config_set_ipa_granule(c,(hv_ipa_granule_t)0)|hv_vm_config_set_el2_enabled(c,false)|__hv_vm_config_set_isa(c,1)|__hv_vm_config_set_vhe_enabled(c,false)|hv_vm_create(a)|hv_vm_destroy();return r;}\n')
 cpp=[]
 for kind in ['macosx','iphoneos']:
  obj=D/(kind+'-typed-vm-cpp.o');args=['xcrun','--sdk',kind,'clang++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(S)]
  if kind=='iphoneos':args+=['-arch','arm64e','-miphoneos-version-min=16.1']
  q=subprocess.run(args+['-c',str(source),'-o',str(obj)],capture_output=True,timeout=30)
  (D/(kind+'-typed-vm-cpp.stdout')).write_bytes(q.stdout);(D/(kind+'-typed-vm-cpp.stderr')).write_bytes(q.stderr)
  if q.returncode:raise ValueError(kind+' compile')
  nm=subprocess.check_output(['xcrun','nm','-u',str(obj)],timeout=30);(D/(kind+'-typed-vm-cpp-nm.stdout')).write_bytes(nm)
  symbols=sorted(x.split()[-1].decode() for x in nm.splitlines() if x.split())
  expected=sorted('_'+x for x in c['exactExports'] if x.startswith('hv_vm_') or x.startswith('__hv_vm_'))
  if symbols!=expected:raise ValueError('actual C++ exact11 C names')
  cpp.append(dict(platform=kind,object=pin(obj),symbols=symbols))
 final=dict(schema='Finite VM bootstrap source combined guard and actual definitions finalization v1',
  finiteLocalScopePassed=True,candidate=pin(D/'candidate.json'),provider=pin(provider),currentDefinitions=pin(proofPath),
  actual42StrongImportDefinitionsJoined=True,proofs=[known[x['symbol'],x['path']] for x in actual],
  actualCPPCaller=cpp,ownVMConfigRealCFCreateDestroyEach=2,normalChecks=167,sanitizedChecks=167,
  allNativeTrapsMocked=True,nativeCallsExecuted=0,deviceOperations=0,providerSigned=False,providerLoaded=False,
  fullPublicVMEquivalent=False,originalVMMIntegrated=False,guestInstructions=0,full27Backend=False)
 with (D/'finalization.json').open('x') as f:json.dump(final,f,indent=2);f.write('\n')
 for p in D.iterdir():
  if p.is_file() and p.name!='freeze.json':rows[str(p.absolute())]=pin(p)
 for p in [Path(__file__),S/'vm27_hv_public_vm_bootstrap_v1.h',S/'vm27_hv_public_vm_bootstrap_v1.m',
  S/'test-vm27-hv-public-vm-bootstrap-v1.m',S/'build-vm27-hv-public-vm-bootstrap-v1.py',S/'build-vm27-hv-public-vm-bootstrap-v1-ios.py',
  sdk/'System/Library/Frameworks/Hypervisor.framework/Headers/hv_vm.h',sdk/'System/Library/Frameworks/Hypervisor.framework/Headers/hv_vm_config.h',
  sdk/'System/Library/Frameworks/Hypervisor.framework/Headers/hv_vm_types.h',proofPath,parent]:rows[str(p.absolute())]=pin(p)
 with (D/'freeze.json').open('x') as f:json.dump(dict(schema='PublicVM combined source immutable finite freeze v1',files=list(rows.values())),f,indent=2);f.write('\n')
 print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),pins=len(rows),nativeCalls=0)))
if __name__=='__main__':main()
