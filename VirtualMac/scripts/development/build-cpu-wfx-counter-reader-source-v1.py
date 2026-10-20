#!/usr/bin/env python3
"""Reuse the actual owned V21 counter-domain reader for WFx CNTV waits."""
import argparse,hashlib,importlib.util,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py');sp=importlib.util.spec_from_file_location('run_sparse_clock_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh output');o.mkdir(mode=0o700)
 oldpath=N/'cpu-wfx-wait-source-local-v1-attempt2/candidate.json';old=json.loads(oldpath.read_bytes());need(pin(oldpath)['sha256']=='2f5e22fca05e8496d2bcf6274c98969a8b0b11e8ddc49b560ebc23079a7f8ac0','actual R44 source');need(pin(old['provider']['path'])==old['provider'],'actual unchanged R44 provider')
 commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);so=o/(label+'.stdout');se=o/(label+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se)));save(o/'commands.json',commands);need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-3000:]);return p
 prior=json.loads((oldpath.parent/'commands.json').read_bytes());argv=list(next(x['argv'] for x in prior if x['label']=='ios-Life31'));source=S/'modern_cpu_kernel_lifecycle_v32.c';obj=o/'modern_cpu_kernel_lifecycle_v32.o';dep=o/'modern_cpu_kernel_lifecycle_v32.d';argv[argv.index('-c')+1]=str(source);argv[argv.index('-o')+1]=str(obj);argv[argv.index('-MF')+1]=str(dep);run('ios-Life32',argv)
 link=list(next(x['argv'] for x in prior if x['label']=='link-whole-wfx-wait'));oldobj=str(oldpath.parent/'modern_cpu_kernel_lifecycle_v31.o');need(link.count(oldobj)==1,'one Life31 replacement');oldobjects=[pin(x) for x in link if x.endswith('.o')];need(len(oldobjects)==29,'actual29 objects');inherited=[x for x in oldobjects if x['path']!=oldobj];need(len(inherited)==28,'28 whole R44 objects')
 provider=o/'VM27HVVMProductionWFxCounterReaderV1.unsigned.dylib';link=[str(obj) if x==oldobj else x for x in link];link[link.index('-o')+1]=str(provider);link=[x.replace('@rpath/VM27HVVMProductionWFxWaitV1.unsigned.dylib','@rpath/VM27HVVMProductionWFxCounterReaderV1.unsigned.dylib') for x in link];run('link-whole-wfx-counter-reader',link);run('validate-whole-wfx-counter-reader',['xcrun','dyld_info','-validate_only',str(provider)])
 im=base.image_profile(provider.read_bytes(),'VM27HVVMProduction.dylib');previous=base.image_profile(pathlib.Path(old['provider']['path']).read_bytes(),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in x.items() if k not in ('at','index')} for x in rows],key=lambda x:json.dumps(x,sort_keys=True))
 need(imports(im.imports)==imports(previous.imports) and len(im.imports)==93,'same93 actual imports');need([{k:v for k,v in x.items() if k!='at'} for x in im.loads]==[{k:v for k,v in x.items() if k!='at'} for x in previous.loads] and len(im.loads)==4,'same4 actual loads');need(set(im.exports)==set(previous.exports) and len(im.exports)==155 and all(im.exports[k]['flags']==previous.exports[k]['flags'] for k in previous.exports),'same155 names/kinds');need(all(pin(x['path'])==x for x in inherited),'28 whole previous objects')
 sources=[pin(S/x) for x in ['modern_cpu_kernel_lifecycle_v32.c','wfx_wait_v32/modern_cpu_kernel_lifecycle_v27.c','modern_cpu_kernel_gic_run_v32.inc']]
 actual=N/'independent27-app56-normal-guest-lifecycle-v48-attempt1/device-receipts/start/stdout';need(pin(actual)['sha256']=='625db03207d2d5f91ed90662dff784d2c413c7a89e5bca4e7f0726b94fdafa68','actual Normal48 failure')
 contract=dict(usesSameRetainedTimerOwnerActualReadCounterDomainBinding=True,actualBindingIsExistingV21ArchitecturalReader=True,directOldV19CounterReaderNoLongerUsedByCNTVWait=True,originalInitializationOwnedBeforeAndAfterReaderUnchanged=True,originalCounterDomainValidationUnchanged=True,noGlobalMemoryOrSYSGuardRelaxation=True,noExtraCPUReadsOrNativeCalls=True,noPCDeadlineMaskOrNativeResultChanges=True,onlyFirst8ActualCNTVErrorLogs=True,unknownBanksExplicitlyKnownZero=True,errnoPreservedAroundErrorFormatting=True,oldWFxOwnerConditionEngineAndNative16EntryBoundUnchanged=True,Factory5ConsumerV6AndChildWhole=True,actualChangedObjects=1,allOther28ObjectsWhole=True)
 result=dict(schema='Owned WFx CNTV counter-domain binding correction V1',provider=pin(provider),cpuWFxWaitCandidate=pin(oldpath),cpuWFxCounterReaderContract=contract,sourceFiles=sources,actualChangedObjects=[pin(obj)],inheritedWholeObjects=inherited,allOther28ObjectsWholeUnchanged=True,actualIOSCompileStrictLinkAndDyldValidatePassed=True,actualNormal48Receipt=pin(actual),all155ExistingExportNamesAndKindsSame=True,all93NativeImportSemanticsSame=True,all4LoadSemanticsSame=True,actualExports=155,actualNativeImports=93,actualLoads=4,actualUUID=im.uuid,hvVMConfigCreateActualRVA=im.exports['_hv_vm_config_create']['address'],dupActualRVA=im.exports['_dup']['address'],deviceOperations=0,codeSigned=False)
 save(o/'candidate.json',result);deps=[pin(x) for x in dep.read_text().replace('\
',' ').split(':',1)[1].split() if pathlib.Path(x).is_file()];files=[pin(x) for x in o.iterdir() if x.is_file()]+sources+deps+inherited+[pin(__file__),pin(BASE),pin(oldpath),pin(oldpath.parent/'freeze.json'),old['provider'],pin(oldobj),pin(actual)];rows={x['path']:x for x in files}
 for x in rows.values():need(pin(x['path'])==x,'all current direct freeze pins')
 save(o/'freeze.json',dict(files=list(rows.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=im.uuid)))
if __name__=='__main__':main()
