#!/usr/bin/env python3
"""Compile only two receipt-observation objects; preserve the actual R38 ABI and Child."""
import argparse, hashlib, importlib.util, json, pathlib, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py');sp=importlib.util.spec_from_file_location('run_result_primitives',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh output');o.mkdir(mode=0o700)
 oldpath=N/'cpu-AMX-availability-combined-source-local-v1-attempt2/candidate.json';old=json.loads(oldpath.read_bytes());need(pin(oldpath)['sha256']=='d5a6d82cb4eb8362fc72b8f4ed51b6da471831afd40c642d4ed204c541cafaf1','actual R38 combined source');need(pin(old['provider']['path'])==old['provider'],'previous actual provider pin')
 oldrows={x['path']:x for x in json.loads((oldpath.parent/'freeze.json').read_bytes())['files']};need(oldrows.get(str(oldpath))==pin(oldpath),'baseline frozen')
 commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);so=o/(label+'.stdout');se=o/(label+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se)));save(o/'commands.json',commands);need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-2400:]);return p
 helper=json.loads((N/'cpu-AMX-availability-helper-source-local-v1-attempt2/commands.json').read_bytes());objects=[];depfiles=[]
 for label,prior,new in [('ios-Life29','ios-Life28','modern_cpu_kernel_lifecycle_v29'),('ios-FactoryStartupFailureV3','ios-FactoryStartupFailureV2','modern_cpu_native_public_factory_startup_failure_v3')]:
  argv=list(next(x['argv'] for x in helper if x['label']==prior));argv[argv.index('-c')+1]=str(S/(new+'.c'));obj=o/(new+'.o');argv[argv.index('-o')+1]=str(obj);dep=o/(new+'.d');argv[argv.index('-MF')+1]=str(dep);run(label,argv);objects.append(pin(obj));depfiles.append(dep)
 link=list(next(x['argv'] for x in json.loads((oldpath.parent/'commands.json').read_bytes()) if x['label']=='link-whole-AMX-availability'));oldobjects=[pin(x) for x in link if x.endswith('.o')];need(len(oldobjects)==29,'29 actual R38 provider objects');changed=old['actualChangedObjects'];need(len(changed)==2,'exact existing helper delta');replacements={next(x['path'] for x in changed if 'lifecycle_v28' in x['path']):objects[0]['path'],next(x['path'] for x in changed if 'factory' in x['path']):objects[1]['path']};need(all(link.count(x)==1 for x in replacements),'two exact replacements');inherited=[x for x in oldobjects if x['path'] not in replacements];need(len(inherited)==27,'27 whole inherited objects')
 provider=o/'VM27HVVMProductionRunResultDiagnosticsV1.unsigned.dylib';link=[replacements.get(x,x) for x in link];link[link.index('-o')+1]=str(provider);link=[x.replace('@rpath/VM27HVVMProductionAMXAvailabilityV1.unsigned.dylib','@rpath/VM27HVVMProductionRunResultDiagnosticsV1.unsigned.dylib') for x in link];run('link-whole-run-result-diagnostics',link);run('validate-whole-run-result-diagnostics',['xcrun','dyld_info','-validate_only',str(provider)])
 im=base.image_profile(provider.read_bytes(),'VM27HVVMProduction.dylib');prior=base.image_profile(pathlib.Path(old['provider']['path']).read_bytes(),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in x.items() if k not in ('at','index')} for x in rows],key=lambda x:json.dumps(x,sort_keys=True))
 need(imports(im.imports)==imports(prior.imports) and len(im.imports)==93,'same93 native imports');need([{k:v for k,v in x.items() if k!='at'} for x in im.loads]==[{k:v for k,v in x.items() if k!='at'} for x in prior.loads] and len(im.loads)==4,'same4 load semantics');need(set(im.exports)==set(prior.exports) and len(im.exports)==155 and all(im.exports[k]['flags']==prior.exports[k]['flags'] for k in prior.exports),'same155 export names/kinds');need(all(pin(x['path'])==x for x in inherited),'whole27 original objects')
 sourcepaths=[S/'modern_cpu_kernel_lifecycle_v29.c',S/'modern_cpu_native_public_factory_startup_failure_v3.c',S/'modern_cpu_kernel_gic_run_diagnostics_v29.inc',S/'modern_cpu_run_receipt_diagnostic_v29.inc']+sorted((S/'run_diagnostics_v29').glob('*.c'));sources=[pin(x) for x in sourcepaths]
 deps=[]
 for d in depfiles:
  # This workspace and all dependency paths contain no spaces.
  text=d.read_text().replace('\\\n',' ');deps += [pin(x) for x in text.split(':',1)[1].split() if pathlib.Path(x).is_file()]
 contract=dict(firstSixteenExistingInternalRunReceiptsOnly=True,firstEightPublicRunReturnsOnly=True,observesOnlyAlreadyInitializedLocalReceipts=True,unknownNativeValuesExplicitlyMarked=True,noExtraNativeCalls=True,noExtraCPUOrContextReads=True,noGuestOrCPUStateWrites=True,noCallsFlagsArgumentsResultsOrOutputsChanged=True,originalReleaseBodyInlinedWithoutChangingOneActualBorrowRelease=True,retainsOriginalDeferredBorrowAndStatusPriority=True,recordsActualReleaseStatus=True,preservesErrnoAcrossFormatting=True,logsKnownRawESRVirtualAndPhysicalAddress=True,logsInternalResumePublicReasonIdentityAndPoison=True,logsFinalPublicRunReturnAndProducerStatus=True,ChildBodyWholeUnchanged=True)
 result=dict(schema='Bounded genuine public Run result receipt observations V1',provider=pin(provider),cpuAMXAvailabilityCombinedCandidate=pin(oldpath),publicRunResultDiagnosticsContract=contract,sourceFiles=sources,actualChangedObjects=objects,inheritedWholeObjects=inherited,allOther27ObjectsWholeUnchanged=True,actualIOSCompileStrictLinkAndDyldValidatePassed=True,all155ExistingExportNamesAndKindsSame=True,all93NativeImportSemanticsSame=True,all4LoadSemanticsSame=True,actualExports=155,actualNativeImports=93,actualLoads=4,actualUUID=im.uuid,hvVMConfigCreateActualRVA=im.exports['_hv_vm_config_create']['address'],dupActualRVA=im.exports['_dup']['address'],deviceOperations=0,codeSigned=False)
 save(o/'candidate.json',result);files=[pin(x) for x in o.iterdir() if x.is_file()]+sources+deps+objects+inherited+[pin(__file__),pin(BASE),pin(oldpath),pin(oldpath.parent/'freeze.json'),old['provider']];rows={x['path']:x for x in files}
 for x in rows.values():need(pin(x['path'])==x,'all frozen inputs exact')
 save(o/'freeze.json',dict(files=list(rows.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=im.uuid)))
if __name__=='__main__':main()
