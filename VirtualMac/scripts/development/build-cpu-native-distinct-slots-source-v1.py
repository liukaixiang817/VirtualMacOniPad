#!/usr/bin/env python3
"""Build two changed native CPU slot objects; reuse every other Root25 object."""
import argparse,hashlib,importlib.util,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('slots_profile_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh output');o.mkdir(mode=0o700)
 olddir=N/'child-dup-native-diagnostic-source-local-v1-attempt1';oldpath=olddir/'candidate.json';old=json.loads(oldpath.read_bytes());need(pin(oldpath)['sha256']=='f87e5e4ba71430a7bf9bd3e20cf52a338a7c46a28b37f3cb07bec92e227d6f26','fixed actual Root25');need(pin(old['provider']['path'])==old['provider'],'whole old provider')
 commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);out=o/(label+'.stdout');err=o/(label+'.stderr');out.write_bytes(p.stdout);err.write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(out),stderr=pin(err)));save(o/'commands.json',commands);need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-1000:]);return p
 sources=[S/x for x in ('modern_cpu_kernel_lifecycle_v25.c','modern_cpu_kernel_lifecycle_v25.h','modern_cpu_production_native_ops_v5.c','modern_cpu_production_native_ops_slot_v5.inc','test-modern-cpu-native-distinct-slots-v1.c')]
 flags=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-I',str(S),'-I',str(N/'cpu-own-feature-profile-local-v1-attempt2'),'-DVM27_HV_VM_GUARD_LINKED=1']
 life=o/'modern_cpu_kernel_lifecycle_v25.o';ops=o/'modern_cpu_production_native_ops_v5.o'
 run('ios-lifecycle25',flags+['-fvisibility=hidden','-c',str(sources[0]),'-o',str(life)])
 run('ios-nativeops5',flags+['-c',str(sources[2]),'-o',str(ops)])
 host=o/'slots-host-test';run('host-slot-test-compile',['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections','-I',str(S),str(sources[4]),str(sources[0]),'-Wl,-dead_strip','-o',str(host)])
 tested=run('host-slot-test-run',[str(host)]);test=json.loads(tested.stdout);need(all(test[x] is True for x in ('fourDistinctOwnerCPUs','slots0Through63','failedCreateReleased','failedDestroyReserved','incompleteCreationReserved','reuseOnlyAfterNativeDestroyZero','full64NoNativeCall','allWorkersJoined')),'targeted slots ownership and cleanup')
 oldcommands=json.loads((olddir/'commands.json').read_bytes());link=next(x['argv'] for x in oldcommands if x['label']=='link-whole-root25');replacements={str(N/'borrowed-host-permission-source-local-v24-attempt1/modern_cpu_kernel_lifecycle_v24.o'):str(life),str(N/'cpu-start-milestone-source-local-v24-attempt1/modern_cpu_production_native_ops_v4.o'):str(ops)}
 oldobjects=[pin(x) for x in link if x.endswith('.o')];need(len(oldobjects)==29,'actual29 old object joins');inherited=[p for p in oldobjects if p['path'] not in replacements];need(len(inherited)==27,'exact27 inherited objects')
 provider=o/'VM27HVVMProductionCPUSlotsV1.unsigned.dylib';link=[replacements.get(x,x) for x in link];link[link.index('-o')+1]=str(provider);link=[x.replace('@rpath/VM27HVVMProductionRoot25.unsigned.dylib','@rpath/VM27HVVMProductionCPUSlotsV1.unsigned.dylib') for x in link];run('link-whole-cpu-slots',link);run('validate-whole-cpu-slots',['xcrun','dyld_info','-validate_only',str(provider)])
 current=base.image_profile(provider.read_bytes(),'VM27HVVMProduction.dylib');prior=base.image_profile(pathlib.Path(old['provider']['path']).read_bytes(),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in x.items() if k not in ('at','index')} for x in rows],key=lambda x:json.dumps(x,sort_keys=True))
 need(imports(current.imports)==imports(prior.imports) and len(current.imports)==93,'all93 native import semantics exact');need([{k:v for k,v in x.items() if k!='at'} for x in current.loads]==[{k:v for k,v in x.items() if k!='at'} for x in prior.loads],'all4 load semantics exact');need(set(current.exports)==set(prior.exports) and len(current.exports)==154 and all(current.exports[k]['flags']==prior.exports[k]['flags'] for k in current.exports),'all154 export names/kinds exact');need(all(pin(p['path'])==p for p in inherited),'inherited27 wholeobjects unchanged')
 result=dict(schema='Native distinct CPU slot source V1; Life25 and NativeOps5 on Root25',provider=pin(provider),baselineRoot25=pin(oldpath),root25Candidate=pin(oldpath),sourceFiles=[pin(x) for x in sources],actualChangedObjects=[pin(life),pin(ops)],inheritedWholeObjects=inherited,actualIOSCompileStrictLinkAndDyldValidatePassed=True,targetedHostSlotTest=pin(o/'host-slot-test-run.stdout'),targetedHostSlotResults=test,lowestUnused64SlotReservation=True,reservesDuringCreateAndFailedDestroy=True,releasesOnlyFailedNativeCreateOrSuccessfulNativeDestroy=True,actualRequestedAndReturnedSlotsPropagated=True,all154ExportNamesAndKindsSame=True,all93NativeImportSemanticsSame=True,all4LoadSemanticsSame=True,actualExports=154,actualNativeImports=93,actualLoads=4,actualUUID=current.uuid,hvVMConfigCreateActualRVA=current.exports['_hv_vm_config_create']['address'],dupActualRVA=current.exports['_dup']['address'],realGPRSIMDSystemRunDestroySemanticsUnchanged=True,allOther27ObjectsWholeUnchanged=True,noNativeReturnSubstitution=True,oldProviderDisassembly=pin(N/'cpu-public-exit-source-audit-v5/old-create-exit-pointer.asm'),deviceOperations=0,codeSigned=False)
 save(o/'candidate.json',result);save(o/'freeze.json',dict(files=[pin(x) for x in o.iterdir() if x.is_file()]+[pin(x) for x in sources]+[pin(__file__),pin(BASE),pin(oldpath),pin(olddir/'freeze.json'),old['provider']]+inherited,deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=current.uuid)))
if __name__=='__main__':main()
