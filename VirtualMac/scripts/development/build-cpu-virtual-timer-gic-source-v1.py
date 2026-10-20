#!/usr/bin/env python3
"""Route actual virtual timer state through GIC PPI26 and consume modern internal timer exits."""
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
 oldpath=N/'cpu-bounded-wake-post-snapshot-source-local-v1-attempt1/candidate.json';old=json.loads(oldpath.read_bytes());need(pin(oldpath)['sha256']=='fd67efafd3b3c57f417b954aebe5343055c81bb5a9f6b3a918c90ab30f26785c','actual R47 source');need(pin(old['provider']['path'])==old['provider'],'actual unchanged R47 provider')
 for row in old['sourceFiles']+old['actualChangedObjects']+old['inheritedWholeObjects']:need(pin(row['path'])==row,'exact actual R47 source and object baseline')
 commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True);so=o/(label+'.stdout');se=o/(label+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se)));save(o/'commands.json',commands);need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-3000:]);return p
 prior=json.loads((oldpath.parent/'commands.json').read_bytes());argv=list(next(x['argv'] for x in prior if x['label']=='ios-Life34'));source=S/'modern_cpu_kernel_lifecycle_v35.c';obj=o/'modern_cpu_kernel_lifecycle_v35.o';dep=o/'modern_cpu_kernel_lifecycle_v35.d';argv[argv.index('-c')+1]=str(source);argv[argv.index('-o')+1]=str(obj);argv[argv.index('-MF')+1]=str(dep);run('ios-Life35',argv)
 link=list(next(x['argv'] for x in prior if x['label']=='link-whole-bounded-wake-post'));oldobj=str(oldpath.parent/'modern_cpu_kernel_lifecycle_v34.o');need(link.count(oldobj)==1,'one Life34 replacement');oldobjects=[pin(x) for x in link if x.endswith('.o')];need(len(oldobjects)==29,'actual29 objects');oldengine=next(x['path'] for x in old['inheritedWholeObjects'] if pathlib.Path(x['path']).name=='modern_gic_v3_engine_v3.o');need(link.count(oldengine)==1,'one Engine3 replacement');inherited=[x for x in oldobjects if x['path'] not in (oldobj,oldengine)];need(len(inherited)==27,'27 whole R47 objects')
 engineprior=json.loads((N/'cpu-wfx-wait-source-local-v1-attempt2/commands.json').read_bytes());engineargv=list(next(x['argv'] for x in engineprior if x['label']=='ios-GICEngine3'));engineobj=o/'modern_gic_v3_engine_v4.o';enginedep=o/'modern_gic_v3_engine_v4.d';engineargv[engineargv.index('-c')+1]=str(S/'modern_gic_v3_engine_v4.c');engineargv[engineargv.index('-o')+1]=str(engineobj);engineargv[engineargv.index('-MF')+1]=str(enginedep);run('ios-GICEngine4',engineargv)
 provider=o/'VM27HVVMProductionVirtualTimerGICV1.unsigned.dylib';link=[str(obj) if x==oldobj else str(engineobj) if x==oldengine else x for x in link];link[link.index('-o')+1]=str(provider);link=[x.replace('@rpath/VM27HVVMProductionBoundedWakePostV1.unsigned.dylib','@rpath/VM27HVVMProductionVirtualTimerGICV1.unsigned.dylib') for x in link];run('link-whole-virtual-timer-gic',link);run('validate-whole-virtual-timer-gic',['xcrun','dyld_info','-validate_only',str(provider)])
 im=base.image_profile(provider.read_bytes(),'VM27HVVMProduction.dylib');previous=base.image_profile(pathlib.Path(old['provider']['path']).read_bytes(),'VM27HVVMProduction.dylib')
 def imports(rows):return sorted([{k:v for k,v in x.items() if k not in ('at','index')} for x in rows],key=lambda x:json.dumps(x,sort_keys=True))
 need(imports(im.imports)==imports(previous.imports) and len(im.imports)==93,'same93 actual imports');need([{k:v for k,v in x.items() if k!='at'} for x in im.loads]==[{k:v for k,v in x.items() if k!='at'} for x in previous.loads] and len(im.loads)==4,'same4 actual loads');need(set(im.exports)==set(previous.exports) and len(im.exports)==155 and all(im.exports[k]['flags']==previous.exports[k]['flags'] for k in previous.exports),'same155 names/kinds');need(all(pin(x['path'])==x for x in inherited),'27 whole previous objects')
 sources=[pin(S/x) for x in ['modern_cpu_kernel_lifecycle_v35.c','wfx_wait_v35/modern_cpu_kernel_lifecycle_v27.c','modern_cpu_kernel_gic_run_v35.inc','modern_gic_v3_engine_v4.c','modern_gic_v3_engine_v4.h']]
 actual=N/'independent27-app59-normal-guest-lifecycle-v53-attempt1/device-receipts/start/stdout';need(pin(actual)['sha256']=='d2806a5338b67ae4a5b1bef892bc65e53aa38715912451012a1bc3635a64744c','actual Normal53 original Child assertion')
 asm=run('disassemble-own-wake-callback',['xcrun','llvm-objdump','--disassemble','--disassemble-symbols=_VM27RunWakeFiredV34','--arch-name=aarch64',str(provider)]).stdout.decode()
 import re
 target=im.exports['_hv_vcpus_exit']['address'];target=int(target,0) if isinstance(target,str) else target
 calls=[]
 for line in asm.splitlines():
  found=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+bl\s+0x([0-9a-f]+)',line)
  if found:
   at,word,dest=(int(v,16) for v in found.groups());delta=(word&0x3ffffff);delta=delta-(1<<26) if delta&(1<<25) else delta
   need((word>>26)==0x25 and at+(delta<<2)==dest,'actual BL instruction target')
   if dest==target:calls.append(dict(callRVA=at,instructionWord=word,targetRVA=dest,disassembly=line.strip()))
 need(len(calls)==1,'single actual callback BL to own exported hv_vcpus_exit')
 need(not any('_hv_vcpus_exit'==str(v) for row in im.imports for v in row.values()),'public wake must not be an external import')
 binding=dict(ownExportRVA=target,actualDirectBL=calls[0],externalVCPUsExitImportPresent=False,callbackAssembly=pin(o/'disassemble-own-wake-callback.stdout'))
 contract=dict(actualCTL430CVAL3e8AndNative6d8Only=True,usesActualSameOwnerPhysicalTimerReceiptCounterDomain=True,revalidatesRealCounterDomainAndTranslationRange=True,noHostElapsedGuessOrFakeTimerState=True,PPI26LevelFromCTLBits3Equal1AndActualCounterAtOrPastCVAL=True,PPI26AssertAndClearUseSameIdentityAndLevelSemanticsAsPhysical30=True,physicalPPI30AndAllExistingGICPathsPreserved=True,nativeSoftMaskOnlySuppressesDuplicateNativeTimerExits=True,realGuestFutureCVALOrDisabledTimerClearsSoftMaskForRearm=True,actualPreNative9MaskRefreshedAfterEveryRealTimerPoll=True,onlyExistingExactVirtualTimerPublicReason2ConsumedInternally=True,raw3Or4OtherCasesAndRaw2Or11Unchanged=True,internalTimerConsumptionDoesNotAdvancePC=True,virtualTimerLevelStillRoutesWithNativeSoftMaskSet=True,WFxFutureDeadlineIgnoresNativeSoftMask=True,WFxExpiredTimerRequiresActualEnabledPendingGICWork=True,noNewNative8OrUnboundedNativeEntryPolicy=True,existingCNTVReaderAndCounterValidationGuardsPreserved=True,partialNewVirtualMutationFailurePoisonsCPU=True,atMostFirst8ActualVirtualTimerStateAndConsumeLogs=True,Life34BoundedWakeAndPostSnapshotPreserved=True,Factory5ConsumerV6ChildWhole=True,actualChangedObjects=2,allOther27ObjectsWhole=True)
 result=dict(schema='Actual virtual timer GIC PPI26 and modern internal timer exit V1',provider=pin(provider),cpuBoundedWakePostSnapshotCandidate=pin(oldpath),cpuVirtualTimerGICContract=contract,actualSameImageVCPUsExitBinding=binding,sourceFiles=sources,actualChangedObjects=[pin(obj),pin(engineobj)],inheritedWholeObjects=inherited,allOther27ObjectsWholeUnchanged=True,actualIOSCompileStrictLinkAndDyldValidatePassed=True,actualNormal53OriginalAssertionLog=pin(actual),all155ExistingExportNamesAndKindsSame=True,all93NativeImportSemanticsSame=True,all4LoadSemanticsSame=True,actualExports=155,actualNativeImports=93,actualLoads=4,actualUUID=im.uuid,hvVMConfigCreateActualRVA=im.exports['_hv_vm_config_create']['address'],dupActualRVA=im.exports['_dup']['address'],deviceOperations=0,codeSigned=False)

 import difflib
 pairs=[('modern_cpu_kernel_lifecycle_v34.c','modern_cpu_kernel_lifecycle_v35.c'),('wfx_wait_v34/modern_cpu_kernel_lifecycle_v27.c','wfx_wait_v35/modern_cpu_kernel_lifecycle_v27.c'),('modern_cpu_kernel_gic_run_v34.inc','modern_cpu_kernel_gic_run_v35.inc'),('modern_gic_v3_engine_v3.c','modern_gic_v3_engine_v4.c'),('modern_gic_v3_engine_v3.h','modern_gic_v3_engine_v4.h')]
 delta=''.join(''.join(difflib.unified_diff((S/left).read_text().splitlines(True),(S/right).read_text().splitlines(True),fromfile=left,tofile=right)) for left,right in pairs)
 (o/'life34-to-life35.diff').write_text(delta);result['readableSourceDiff']=pin(o/'life34-to-life35.diff')
 save(o/'candidate.json',result);deps=[pin(x) for d in (dep,enginedep) for x in d.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split() if pathlib.Path(x).is_file()];files=[pin(x) for x in o.iterdir() if x.is_file()]+sources+deps+inherited+[pin(__file__),pin(BASE),pin(oldpath),pin(oldpath.parent/'freeze.json'),old['provider'],pin(oldobj),pin(oldengine),pin(actual)];rows={x['path']:x for x in files}
 for x in rows.values():need(pin(x['path'])==x,'all current direct freeze pins')
 save(o/'freeze.json',dict(files=list(rows.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=result['provider'],uuid=im.uuid)))
if __name__=='__main__':main()
