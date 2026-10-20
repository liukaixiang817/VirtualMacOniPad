#!/usr/bin/env python3
"""Observe the actual 64 instruction bytes preceding the saved PC within the same diagnostic budget."""
import argparse,difflib,hashlib,importlib.util,json,pathlib,re,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py');spec=importlib.util.spec_from_file_location('post_wake_primitives',BASE);base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh output');o.mkdir(mode=0o700)
 oldpath=N/'cpu-el1-virtual-timer-pagewalk-source-local-v1-attempt2/candidate.json';old=json.loads(oldpath.read_bytes());need(pin(oldpath)['sha256']=='541ba7c9784f0cb7677efd52c34977a36e7b83b2bcdefbaec74d0d712621f7c8','actual R50 source');need(pin(old['provider']['path'])==old['provider'],'actual unchanged R50 provider')
 for row in old['sourceFiles']+old['actualChangedObjects']+old['inheritedWholeObjects']:need(pin(row['path'])==row,'exact actual R50 source/object baseline')
 commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);so=o/(label+'.stdout');se=o/(label+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se)));save(o/'commands.json',commands);need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-3500:]);return p
 prior=json.loads((oldpath.parent/'commands.json').read_bytes());argv=list(next(x['argv'] for x in prior if x['label']=='ios-Life37'));obj=o/'modern_cpu_kernel_lifecycle_v38.o';dep=o/'modern_cpu_kernel_lifecycle_v38.d';argv[argv.index('-c')+1]=str(S/'modern_cpu_kernel_lifecycle_v38.c');argv[argv.index('-o')+1]=str(obj);argv[argv.index('-MF')+1]=str(dep);run('ios-Life38',argv)
 link=list(next(x['argv'] for x in prior if x['label']=='link-whole-el1-virtual-timer-pagewalk'));oldobj=str(oldpath.parent/'modern_cpu_kernel_lifecycle_v37.o');need(link.count(oldobj)==1,'one Life37 replacement');oldobjects=[pin(x) for x in link if x.endswith('.o')];need(len(oldobjects)==29,'actual29 objects');inherited=[x for x in oldobjects if x['path']!=oldobj];need(len(inherited)==28 and any(pathlib.Path(x['path']).name=='modern_gic_v3_engine_v5.o' for x in inherited),'28 whole R50 objects including Engine5')
 provider=o/'VM27HVVMProductionPrecedingBootInstructionsV1.unsigned.dylib';link=[str(obj) if x==oldobj else x for x in link];link[link.index('-o')+1]=str(provider);link=[x.replace('@rpath/VM27HVVMProductionEL1VirtualTimerPagewalkV1.unsigned.dylib','@rpath/VM27HVVMProductionPrecedingBootInstructionsV1.unsigned.dylib') for x in link];run('link-whole-preceding-boot-instructions',link);run('validate-whole-preceding-boot-instructions',['xcrun','dyld_info','-validate_only',str(provider)])
 im=base.image_profile(provider.read_bytes(),'VM27HVVMProduction.dylib');previous=base.image_profile(pathlib.Path(old['provider']['path']).read_bytes(),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in x.items() if k not in ('at','index')} for x in rows],key=lambda x:json.dumps(x,sort_keys=True))
 need(imports(im.imports)==imports(previous.imports) and len(im.imports)==93,'same93 actual imports');need([{k:v for k,v in x.items() if k!='at'} for x in im.loads]==[{k:v for k,v in x.items() if k!='at'} for x in previous.loads] and len(im.loads)==4,'same4 actual loads');need(set(im.exports)==set(previous.exports) and len(im.exports)==155 and all(im.exports[k]['flags']==previous.exports[k]['flags'] for k in previous.exports),'same155 names/kinds');need(all(pin(x['path'])==x for x in inherited),'28 whole previous objects')
 sources=[pin(S/x) for x in ['modern_cpu_kernel_lifecycle_v38.c','wfx_wait_v38/modern_cpu_kernel_lifecycle_v27.c','modern_cpu_kernel_gic_run_v38.inc']]
 asm=run('disassemble-own-wake-callback',['xcrun','llvm-objdump','--disassemble','--disassemble-symbols=_VM27RunWakeFiredV34','--arch-name=aarch64',str(provider)]).stdout.decode();target=im.exports['_hv_vcpus_exit']['address'];target=int(target,0) if isinstance(target,str) else target;calls=[]
 for line in asm.splitlines():
  found=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+bl\s+0x([0-9a-f]+)',line)
  if found:
   at,word,dest=(int(v,16) for v in found.groups());delta=word&0x3ffffff;delta=delta-(1<<26) if delta&(1<<25) else delta;need((word>>26)==0x25 and at+(delta<<2)==dest,'actual BL target')
   if dest==target:calls.append(dict(callRVA=at,instructionWord=word,targetRVA=dest,disassembly=line.strip()))
 need(len(calls)==1,'single actual callback BL to own exported hv_vcpus_exit');need(not any('_hv_vcpus_exit'==str(v) for row in im.imports for v in row.values()),'no external public wake import')
 binding=dict(ownExportRVA=target,actualDirectBL=calls[0],externalVCPUsExitImportPresent=False,callbackAssembly=pin(o/'disassemble-own-wake-callback.stdout'))
 contract=dict(singleExisting10SecondWakeAndActualPostReturnSampleOnly=True,originalNative9ReceiptAndRunStatusPreserved=True,Life37RegisterSYSAndExactObservedTTBR0PagewalkGuardsWhole=True,Engine5RealEL1VirtualPPI27Whole=True,PCAtSavedPC64BytesAndImmediatelyPrecedingPC64BytesOnly=True,unknownOrPCUnderflowFailsClosed=True,LRRegisterStillObservedButLRCodeReadRemoved=True,maxCodeBytes=128,noAdditionalNativeCallOrGuestStateWrite=True,noPACOrHVCBehaviorOrGuardChange=True,allExistingVMOperationRegistryVMMutexUniqueRAMAndSelfMachCopyGuardsPreserved=True,MMUOnStillRequiresExistingExactObservedTCRTranslation=True,MMUOffStillRequiresActualKnownEL1SCTLRM0=True,allExistingDiagnosticUnknownAndErrnoPreserved=True,actualChangedObjects=1,allOther28ObjectsWhole=True)

 result=dict(schema='Actual one-shot saved-PC and preceding boot instruction snapshot V1',provider=pin(provider),cpuEL1VirtualTimerPagewalkCandidate=pin(oldpath),cpuPrecedingBootInstructionSnapshotContract=contract,actualSameImageVCPUsExitBinding=binding,sourceFiles=sources,actualChangedObjects=[pin(obj)],inheritedWholeObjects=inherited,allOther28ObjectsWholeUnchanged=True,actualIOSCompileStrictLinkAndDyldValidatePassed=True,all155ExistingExportNamesAndKindsSame=True,all93NativeImportSemanticsSame=True,all4LoadSemanticsSame=True,actualExports=155,actualNativeImports=93,actualLoads=4,actualUUID=im.uuid,hvVMConfigCreateActualRVA=im.exports['_hv_vm_config_create']['address'],dupActualRVA=im.exports['_dup']['address'],deviceOperations=0,codeSigned=False)
 pairs=[('modern_cpu_kernel_lifecycle_v37.c','modern_cpu_kernel_lifecycle_v38.c'),('wfx_wait_v37/modern_cpu_kernel_lifecycle_v27.c','wfx_wait_v38/modern_cpu_kernel_lifecycle_v27.c'),('modern_cpu_kernel_gic_run_v37.inc','modern_cpu_kernel_gic_run_v38.inc')];delta=''.join(''.join(difflib.unified_diff((S/left).read_text().splitlines(True),(S/right).read_text().splitlines(True),fromfile=left,tofile=right)) for left,right in pairs);(o/'life37-to-life38.diff').write_text(delta);result['readableSourceDiff']=pin(o/'life37-to-life38.diff');save(o/'candidate.json',result)
 deps=[pin(x) for x in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split() if pathlib.Path(x).is_file()];files=[pin(x) for x in o.iterdir() if x.is_file()]+sources+deps+inherited+[pin(__file__),pin(BASE),pin(oldpath),pin(oldpath.parent/'freeze.json'),old['provider'],pin(oldobj)];rows={x['path']:x for x in files}
 for x in rows.values():need(pin(x['path'])==x,'all current direct freeze pins')
 save(o/'freeze.json',dict(files=list(rows.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=im.uuid,binding=binding)))
if __name__=='__main__':main()
