"""Freeze finite source integration and raw actual definition join; no device."""
from pathlib import Path
import hashlib,json
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-system-factory-integration-local-v4';A=N/'cpu-system-factory-current-definitions-readonly-v2'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(x,s):
 if not x:raise ValueError(s)
need(not (D/'freeze.json').exists(),'fresh freeze')
c=json.loads((D/'candidate.json').read_text());a=json.loads((A/'current-definitions.json').read_text())
need(c['candidate']==a['provider'],'actual linked provider exact same bytes')
need(c['normalActualChecks']==c['ASanUBActualChecks']==601,'selected actual model count')
need(c['legacyV7Factory3ActualRegressionChecks']==640 and a['actualImportCount']==41,'legacy and raw imports')
old=N/'cpu-native-run-producer-integration-local-v2/freeze.json'
oldpins=json.loads(old.read_text())['files']
for i in oldpins:need(pin(i['path'])==i,'old frozen source/output drift')
refs=[old,N/'cpu-native-run-producer-current-definitions-readonly-v1/freeze.json',
 N/'native-op8-run-contract-v1/audit/contract.json',
 N/'cpu-owned-creation-actual-independent-review-v1/review.json']
f=dict(schema='Guarded actual SYS Factory4 Lifecycle8 source finalization v1',finiteLocalScopePassed=True,findings=[],
 candidate=pin(D/'candidate.json'),currentDefinitions=pin(A/'current-definitions.json'),
 normalAndASanActualChecksEach=601,legacyV7ActualChecks=640,oldFrozenPinsVerified=len(oldpins),
 alternatives=['modern_cpu_kernel_lifecycle_v8.c','modern_cpu_native_public_factory_v4.c','modern_cpu_kernel_system_v3.c'],
 newOwnExports=['VM27CPUFactoryBorrowAccessSystemV4'],actualNative8Expression='nativeTrap(cpu->vm->ops.context,8,NULL)',
 actualContextRequiredMinimumReadBytes=0x4108,kernelAllocationByteLengthProved=False,
 actualSelfTaskMappingChecked=True,actualFieldWriteProtectionCheckedBeforeInjectedWriter=True,
 readonlyMetadataAllowedWithWritableTarget=True,originalGetterDirtyOrReadyMaskSetterReadyOnly=True,
 successful8NoSecondReadyTest=True,privateV2LegacyReceiptBehaviorPreserved=True,
 actualCreationSourceAvailable=True,actualNative8ExecutionProven=False,current41StrongNamesClosed=True,
 ordinarySelfMachMemoryAPIsExecuted=True,genuineVMCPUTrapsOnlyMockedInThisBuild=True,
 architectureResetComplete=False,memoryBindingComplete=False,fullPublicRunEquivalent=False,
 originalApple25ClusterPublished=False,originalVMMIntegrated=False,full27Backend=False,
 nativeVMCallsExecuted=0,nativeCPUCallsExecuted=0,native8CallsExecuted=0,native9CallsExecuted=0,
 deviceOperations=0,iOSSigned=False,iOSLoaded=False,readyWritten=False,peerPending=True,
 references=[pin(p) for p in refs])
(D/'finalization.json').write_text(json.dumps(f,indent=2)+'\n')
files={}
for i in c['inputs']+a['inputs']:
 need(pin(i['path'])==i,'source or capture drift');files[i['path']]=i
for p in refs+[Path(__file__)]:files[str(p.resolve())]=pin(p)
for folder in [D,A]:
 for p in folder.rglob('*'):
  if p.is_file() and p.name!='freeze.json':files[str(p.resolve())]=pin(p)
freeze=dict(schema='Immutable finite SYS product and raw current definition pins v1',files=sorted(files.values(),key=lambda x:x['path']),
 deviceOperations=0,nativeCallsExecuted=0,full27Backend=False)
(D/'freeze.json').write_text(json.dumps(freeze,indent=2)+'\n')
print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),files=len(files))))
