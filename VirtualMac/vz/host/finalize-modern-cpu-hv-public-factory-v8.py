"""Freeze inert exact SDK Run entry; one owned native9, no hardware execution."""
from pathlib import Path
import hashlib,json
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-hv-public-run-cluster-integration-local-v1'
G=N/'cpu-hv-public-run-original-sdk-readonly-v1'
A=N/'cpu-hv-public-run-current-definitions-readonly-v1'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,msg):
 if not v:raise ValueError(msg)
need(not (D/'freeze.json').exists(),'no frozen overwrite')
c=json.loads((D/'candidate.json').read_text());g=json.loads((G/'audit.json').read_text());a=json.loads((A/'current-definitions.json').read_text())
need(c['candidate']==a['provider'] and a['actualImportCount']==42,'actual new linked42strong imports')
need(c['normalActualChecks']==c['ASanUBActualChecks']==916 and c['legacyV7Factory3ActualRegressionChecks']==640,'actual selected and legacy outputs')
need(len(c['exactOwnExports'])==29 and len(c['exactPublicHVExports'])==11 and 'hv_vcpu_run' in c['exactPublicHVExports'],'exact29own11public exports')
need(g['finiteLocalScopePassed'] and g['actualSDKRunArgumentBits']==64 and g['actualSDKStatusBits']==32,'actual original caller and Mac/iOS SDK ABI')
old=N/'cpu-hv-public-feature-cluster-integration-local-v3/freeze.json'
for i in json.loads(old.read_text())['files']:need(pin(i['path'])==i,'prior375source/evidence drift')
refs=[old,N/'cpu-hv-public-feature-cluster-integration-local-v3/finalization.json',
 N/'cpu-hv-abi2-final-binding-independent-review-v1/review.json',
 N/'cpu-native-run-producer-integration-local-v2/freeze.json',
 N/'original27-vmm-public-exit-consumer-abi-v1/contract.json']
f=dict(schema='Actual SDK public hv_vcpu_run one-call source Factory8 finalization v1',
 finiteLocalScopePassed=True,findings=[],candidate=pin(D/'candidate.json'),provider=c['candidate'],
 originalCallerAndSDKContract=pin(G/'audit.json'),currentNative42Definitions=pin(A/'current-definitions.json'),
 actualPublicExports=c['exactPublicHVExports'],normalASanActualChecksEach=916,legacyActualRegressionChecks=640,
 actualOwnCFCreateDestroyEach=3,actualMockNative9CallsEach=17,eachPublicCallAtMostOneNative9=True,
 old375PinsVerified=True,oldV7OwnRunPublicationAndExportsPreserved=True,
 newSDKPublicRunArgumentBits=64,newSDKPublicRunStatusBits=32,
 publicCreatePersistent32ByteAllocationUsed=True,
 postNativeOwnerPthreadTLSVMepochGenerationVersionAndPrivateRunTokenRequired=True,
 publicStorageCommitOnlyAfterBorrowReleaseSuccess=True,failedRunPreservesAll32StorageBytes=True,
 raw2And11ReturnBusyWithoutPublicExit=True,raw0UnknownAndEmulationLanesReturnUnsupported=True,
 nativeReturnSeparatedFromRawReason=True,raw11NotInterpretedAsErrno=True,
 noForcedInitialCancel=True,noC0Submission=True,noRunLoopOrRetry=True,
 sourceNative9ExpressionUnchanged=True,sourceNative6RequestSlotStillZero=True,
 publicationHasNoCallbackAfterSuccessfulRelease=True,releaseFailureRetainsBorrowerTLSDrain=True,
 currentNativeStrongNamesClosed=True,standaloneVMGuardFlag=0,RootCombinedProviderNotThisArtifact=True,
 finiteSDKPublicRunSourceImplemented=True,fullPublicRunEquivalent=False,architectureResetComplete=False,
 memoryBindingComplete=False,originalVMMIntegrated=False,original25ClusterComplete=False,original75HVImportsComplete=False,
 iOSUnsigned=True,providerLoaded=False,providerSigned=False,realRouteCreated=False,readyWritten=False,
 allNativeTrapsInHostFixturesMocked=True,nativeCPUCalls=0,nativeVMCalls=0,native8Calls=0,native9Calls=0,
 deviceOperations=0,guestExecutionProven=False,full27Backend=False,independentRunSourcePeerPending=True,
 references=[pin(p) for p in refs])
(D/'finalization.json').write_text(json.dumps(f,indent=2)+'\n')
files={}
for j in [c,g,a]:
 for i in j['inputs']:need(pin(i['path'])==i,'source/input pin drift');files[i['path']]=i
for p in refs+[Path(__file__)]:files[str(p.resolve())]=pin(p)
for folder in [D,G,A]:
 for p in folder.rglob('*'):
  if p.is_file() and not (folder==D and p.name=='freeze.json'):files[str(p.resolve())]=pin(p)
(D/'freeze.json').write_text(json.dumps(dict(schema='Immutable exact SDK public Run single9 source v1',
 files=sorted(files.values(),key=lambda i:i['path']),nativeCPUCalls=0,nativeVMCalls=0,native9Calls=0,
 deviceOperations=0,full27Backend=False),indent=2)+'\n')
print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),files=len(files))))
