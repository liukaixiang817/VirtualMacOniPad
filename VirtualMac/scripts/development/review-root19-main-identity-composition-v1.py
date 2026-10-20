#!/usr/bin/env python3
"""Read-only finite Root19 composition/source/tool review; no model reruns."""
import argparse,ast,difflib,hashlib,importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';B=R/'VirtualMac/scripts/development'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();assert o.parent==N and not o.exists();o.mkdir();checks=[];inputs={}
 def check(ok,label):
  checks.append(dict(check=label,passed=bool(ok)))
  if not ok:raise AssertionError(label)
 def frozen(folder):
  f=folder/'freeze.json';inputs[str(f)]=pin(f)
  for row in json.loads(f.read_bytes())['files']:
   check(pin(row['path'])==row,'exact frozen pin '+row['path']);inputs[row['path']]=row
 root=N/'vm-hv-production-root19-main-identity-local-v1-attempt1'
 base=N/'vm-hv-production-root18-mobile-capability-local-v1-attempt1'
 fix=N/'actual-executable-image-source-local-v1-attempt1'
 for folder in [root,base,fix]:frozen(folder)
 new=json.loads((root/'candidate.json').read_bytes());old=json.loads((base/'candidate.json').read_bytes())
 code=(S/'vm27_hv_public_vm_bootstrap_v14.m').read_text();updated=(S/'vm27_hv_public_vm_bootstrap_v19.m').read_text()
 replacement='''#include "vm27_actual_executable_image_v1.h"
static const struct mach_header *ActualMainImageV19(void) {
    VM27ActualExecutableImageV1 image = {0};
    return VM27ActualExecutableImageFindSelfV1(&image) == 0
        ? (const struct mach_header *)image.header : NULL;
}
#define MAIN_IMAGE_V14 ActualMainImageV19()'''
 check(updated==code.replace('#define MAIN_IMAGE_V14 _dyld_get_image_header(0)',replacement),'only production main selector replaced')
 check(updated.count('VM27ActualExecutableImageFindSelfV1')==1,'one actual shared finder production call')
 check(new['inheritedCandidate']==pin(base/'candidate.json') and new['mainIdentityCandidate']==pin(fix/'candidate.json'),'exact Root18 and frozen main source ancestry')
 previous=next(x['argv']for x in json.loads((base/'commands.json').read_bytes())if x['label']=='ios-link')
 current=next(x['argv']for x in json.loads((root/'commands.json').read_bytes())if x['label']=='link-whole-root19')
 oldobjects=[pathlib.Path(x)for x in previous if x.endswith('.o')]
 newobjects=[pathlib.Path(x)for x in current if x.endswith('.o')]
 replaced=pathlib.Path(new['replacedBootstrapObjects'][0]['path']);boot=pathlib.Path(new['actualNewObjects'][0]['path']);finder=pathlib.Path(new['actualNewObjects'][1]['path'])
 check(len(oldobjects)==27 and len(newobjects)==28,'27 prior objects to one replaced bootstrap plus one hidden finder')
 check(replaced in oldobjects and replaced not in newobjects and newobjects==[boot if x==replaced else x for x in oldobjects]+[finder],'actual link order preserves all 26 reused objects')
 for path in oldobjects:
  if path==replaced:continue
  check(pin(path) in new['reusedObjectPins'],'each unchanged object actual bytes retained '+path.name)
 check(len(new['reusedObjectPins'])==26,'no extra reused owner provider')
 check(sum(x.name=='modern_cpu_kernel_lifecycle_v23.o'for x in newobjects)==1 and sum(x.name=='modern_cpu_native_public_factory_v22.o'for x in newobjects)==1,'one genuine Lifecycle23 and Factory22 registry')
 check(sum(x.name=='modern_cpu_config_capability_acquisition_v3.ios.o'for x in newobjects)==1,'mobile capability and once-cache object retained exactly')
 reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
 spec=importlib.util.spec_from_file_location('main_identity_peer_reader',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 priorImage=m.MachO(pathlib.Path(old['provider']['path']).read_bytes());image=m.MachO(pathlib.Path(new['provider']['path']).read_bytes())
 check(set(image.exports)==set(priorImage.exports)==set(old['exactExports']) and len(image.exports)==153,'actual153 exports retain inherited ABI')
 check(len(image.imports)==89 and len(priorImage.imports)==82,'actual89 native imports vs prior82')
 check(not any('VM27ActualExecutableImage' in name for name in image.exports),'shared C APIs hidden from production exports')
 names=lambda i:{x['name']for x in i.imports}
 added=sorted(names(image)-names(priorImage));removed=sorted(names(priorImage)-names(image))
 check(not removed and len(added)==7,'only seven actual read-only main lookup native imports added')
 differences=[]
 for now,before in [('build-independent27-signed-runtime-product-v3.py','build-independent27-signed-runtime-product-v2.py'),('sign-independent27-actual-app-product-v2.py','sign-independent27-actual-app-product-v1.py')]:
  p=B/now;q=B/before;inputs[str(p)]=pin(p);inputs[str(q)]=pin(q)
  newtext=p.read_text();oldtext=q.read_text()
  if 'runtime' in now:
   expected=oldtext.replace("S/'vm27_independent_app_runtime_v3.m',anchor", "S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor")
   expected=expected.replace("schema='Actual signed independent27 Runtime3 product v1'", "schema='Actual signed independent27 Runtime4 main identity product v3'")
   expected=expected.replace("pin(S/'vm27_independent_app_runtime_v3.m'),", "pin(S/'vm27_independent_app_runtime_v4.m'),\n                pin(S/'vm27_actual_executable_image_v1.c'),pin(S/'vm27_actual_executable_image_v1.h'),")
  else:
   expected=oldtext.replace('vm27_independent_app_runtime_v3.m','vm27_independent_app_runtime_v4.m').replace('actual Runtime3 compiled into main','actual Runtime4 compiled into main').replace('Actual strong linked and signed independent27 App product v1','Actual strong linked and signed independent27 App main identity product v2')
  check(newtext==expected,'finite exact builder delta '+now)
  ast.parse(newtext);differences.append(dict(before=pin(q),after=pin(p),diff=''.join(difflib.unified_diff(oldtext.splitlines(True),newtext.splitlines(True)))))
 stage=N/'independent27-main-identity-stage-v7-attempt1';stage6=N/'independent27-firmware-stage-v6-attempt1'
 frozen(stage)
 st=json.loads((stage/'candidate.json').read_bytes());st6=json.loads((stage6/'candidate.json').read_bytes())
 rows={x['key']:x for x in st['stagedImages']};rows6={x['key']:x for x in st6['stagedImages']}
 check(set(rows)==set(rows6) and len(rows)==73,'same actual73 stage images')
 changed=[]
 for name in rows:
  a=pathlib.Path(rows[name]['staged']['path']).read_bytes();b=pathlib.Path(rows6[name]['staged']['path']).read_bytes()
  if a!=b:changed.append(name)
 check(sorted(changed)==['VM27HVVMProduction.dylib','VM27OwnedAppChildPreMainV3.dylib'],'only CPU and child preMain changed; other71 whole bytes exact')
 graph=N/'independent27-main-identity-definition-graph-v3-attempt1/verification.json'
 proof=json.loads(graph.read_bytes());inputs[str(graph)]=pin(graph)
 check(proof['remainingActualStrongSymbols']==0 and not proof['unresolvedStrongImportRows'] and
       proof['actualStrongImports']==5414 and not proof['requiredSelectedLoadGaps'],
       'actual5414 new stage strong definition graph zero gaps and load gaps')
 report=dict(schema='Root19 main identity composition and signing tools independent finite review v1',finiteLocalScopePassed=True,findings=[],
  rootCandidate=pin(root/'candidate.json'),rootFreeze=pin(root/'freeze.json'),sourceCandidate=pin(fix/'candidate.json'),
  checks=checks,checkCount=len(checks),reusedObjects=26,priorObjects=27,currentObjects=28,
  actualExports=len(image.exports),actualNativeImports=len(image.imports),addedActualNativeImports=added,removedActualNativeImports=removed,
  stageCandidate=pin(stage/'candidate.json'),actualChangedStageImages=changed,unchangedStageImages=71,actualDefinitionGraph=pin(graph),
  runtimeBuilderAndAppSignerDeltas=differences,nativeCPUModelsRepeated=False,deviceOperations=0,nativeOperations=0,guestBoot=False,
  scope=['Production selector uses true canonical executable identity; original BL/LR/callerRVA/UUID/permissions unchanged.',
   'This checks source, actual composition and signing tool delta; final signed leaves and deployment packet require their own final byte review.',
   'Current first visible guest boot has not yet been executed.'])
 save(o/'review.json',report)
 files=[pin(p)for p in o.rglob('*')if p.is_file()]+list(inputs.values())+[pin(__file__),pin(reader),pin(S/'vm27_hv_public_vm_bootstrap_v14.m'),pin(stage6/'candidate.json')]
 save(o/'freeze.json',dict(files=list({x['path']:x for x in files}.values())))
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),checks=len(checks),findings=[])))
if __name__=='__main__':main()
