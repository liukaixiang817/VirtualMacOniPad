"""Relink the existing genuine C++ leaf source under a new identity; no HV or old CPU DSO."""
import pathlib,json,hashlib,subprocess,sys,importlib.util
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host';D=N/'independent27-cxx-stateless-leaf-local-v1'
SYMS=['_malloc_type_calloc','__ZNSt3__113__hash_memoryEPKvm','__ZNKSt3__119bad_expected_accessIvE4whatEv','__ZTINSt3__119bad_expected_accessIvEE','__ZNSt3__123__atomic_monitor_globalEPKv','__ZNSt3__126__atomic_wait_global_tableEPKvx','__ZNSt3__132__atomic_notify_all_global_tableEPKv','__ZNSt13exception_ptr31__from_native_exception_pointerEPv']
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 D.mkdir(exist_ok=False);source=S/'modern_cpu_runtime_compat.cpp';original=pin(source);commands=[]
 def run(label,args):
  args=list(map(str,args));z=subprocess.run(args,capture_output=True,timeout=60);(D/(label+'.stdout')).write_bytes(z.stdout);(D/(label+'.stderr')).write_bytes(z.stderr);commands.append(dict(label=label,argv=args,returncode=z.returncode));(D/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if z.returncode:raise RuntimeError(label+': '+z.stderr.decode()[-2000:])
  return z
 (D/'leaf-exports.txt').write_text('\n'.join(SYMS)+'\n');(D/'cp-reexports.txt').write_text('\n'.join(SYMS[1:])+'\n');(D/'empty.c').write_text('/* Exact original libc++ and genuine leaf reexports, no implementation. */\n')
 (D/'native-libcxx.tbd').write_text('--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64e-ios ]\ninstall-name: /usr/lib/libc++.1.dylib\n...\n')
 leaf=D/'VM27CxxStatelessLeafV1.unsigned.dylib';cp=D/'VM27CxxProviderV1.unsigned.dylib'
 flags=['-std=c++23','-O2','-fno-typed-cxx-new-delete','-D_LIBCPP_BUILDING_LIBRARY','-D_LIBCPP_DISABLE_AVAILABILITY','-fptrauth-abi-version=0','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-Wl,-no_adhoc_codesign']
 run('ios-leaf-link',['xcrun','--sdk','iphoneos','clang++','-target','arm64e-apple-ios16.1',*flags,'-dynamiclib','-install_name','@rpath/VM27CxxStatelessLeafV1.dylib','-Wl,-exported_symbols_list,'+str(D/'leaf-exports.txt'),source,'-o',leaf])
 run('ios-cp-link',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-fptrauth-abi-version=0','-Wl,-no_adhoc_codesign','-dynamiclib','-Wl,-reexport_library,'+str(D/'native-libcxx.tbd'),leaf,'-Wl,-reexported_symbols_list,'+str(D/'cp-reexports.txt'),'-Wl,-rpath,@loader_path','-install_name','@rpath/VM27CxxProvider.dylib',D/'empty.c','-o',cp])
 for name,p in [('leaf',leaf),('cp',cp)]:
  run(name+'-validate',['xcrun','dyld_info','-validate_only',p]);run(name+'-imports',['xcrun','dyld_info','-imports','-dependents',p]);run(name+'-exports',['xcrun','dyld_info','-exports',p]);run(name+'-locals',['xcrun','nm','-a',p])
 sp=importlib.util.spec_from_file_location('macho',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py');l=importlib.util.module_from_spec(sp);sp.loader.exec_module(l);lm=l.MachO(leaf.read_bytes());cm=l.MachO(cp.read_bytes());assert set(lm.exports)==set(SYMS) and set(cm.exports)==set(SYMS[1:])
 assert any(x['cmd']==0x8000001f and x['path']=='/usr/lib/libc++.1.dylib' for x in cm.loads)
 assert all(cm.exports[x]['flags']&8 for x in SYMS[1:]);assert not any('ModernCPU' in x['path'] or 'Hypervisor' in x['path'] or 'Virtualization' in x['path'] for m in [lm,cm] for x in m.loads)
 assert all(c['cmd']!=0x1d for m in [lm,cm] for c in m.commands)
 assert pin(source)==original
 nativeIndex=N/'current-native-header-export-index-v2/index.json';native=json.loads(nativeIndex.read_text())['images'];nativeRows=[]
 def resolve(path,name,seen=()):
  if (path,name) in seen:return None
  if path not in native:return None
  im=native[path];r=im['definitions'].get(name)
  if r is not None:
   if r['flags']&8:
    dep=next(x for x in im['dependencies'] if x['ordinal']==r['ordinal']);return resolve(dep['path'],r.get('alias') or name,seen+((path,name),))
   return dict(path=path,UUID=im['UUID'],symbol=name,definition=r)
  for dep in im['dependencies']:
   if dep['command']==0x8000001f:
    got=resolve(dep['path'],name,seen+((path,name),))
    if got:return got
  return None
 for q in lm.imports:
  dep=next((x for x in lm.loads if x['ordinal']==q['ordinal']),None)
  proof=resolve(dep['path'],q['name']) if dep else None
  namespaceCandidate=resolve('/usr/lib/libc++abi.dylib',q['name']) if q['ordinal']<0 else None
  nativeRows.append(dict(actualImport=q,dependency=dep,actualExactNativeDefinition=proof,explicitWeakCoalescingNativeCandidate=namespaceCandidate,runtimeCoalescingExecuted=False))
 assert all(x['actualExactNativeDefinition'] or x['explicitWeakCoalescingNativeCandidate'] for x in nativeRows)
 prior=N/'ordinary-cxx-cdhash-policy-device-result-v1/verdict.json';priorReview=N/'current-stock-cxx-leaves-independent-review-v1/review.json';basis=[source,pathlib.Path(__file__),nativeIndex,prior,priorReview,N/'vz-cxx-six-strong-data-v2/candidate.json',N/'cpu-runtime-leaf-v5-independent-review-v1/review.json']
 c=dict(schema='Independent27 genuine C++ leaf single-table new identity unsigned source relink v1',leaf=pin(leaf),leafUUID=lm.uuid,provider=pin(cp),providerUUID=cm.uuid,sourceWholeBytesUnchanged=original,exactLeafExports=sorted(lm.exports),exactProviderReexports=cm.exports,nativeImportDefinitionRows=nativeRows,singleAtomicWaitingTable=True,atomicTableIsOrdinaryUserspaceNotCPUOwnerRegistry=True,noHypervisorVirtualizationOrOldCPUBackendDependencies=True,originalLeafActualPriorExecutionReceipt=pin(prior),priorOrdinaryExecutionDoesNotProveNewProductExecution=True,newProductLoaded=False,finiteLocalScopePassed=True,findings=[],deviceOperations=0,nativeOperations=0,signingCalls=0,guestBoot=False,sourcePins=[pin(x) for x in basis],commands=commands)
 (D/'candidate.json').write_text(json.dumps(c,indent=2)+'\n');files=basis+[x for x in D.iterdir() if x.is_file() and x.name!='freeze.json'];(D/'freeze.json').write_text(json.dumps(dict(files=[pin(x) for x in files]),indent=2)+'\n');print(json.dumps(dict(candidate=pin(D/'candidate.json'),freeze=pin(D/'freeze.json'),leaf=pin(leaf),provider=pin(cp),nativeImports=len(lm.imports))))
if __name__=='__main__':main()
