"""Freeze same-VM owned RAM product; no genuine trap/device/route."""
from pathlib import Path
import hashlib,json,struct
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-owned-ram-integration-local-v3';A=N/'cpu-owned-ram-current-definitions-readonly-v3'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(x,s):
 if not x:raise ValueError(s)
need(not (D/'freeze.json').exists(),'fresh immutable freeze')
c=json.loads((D/'candidate.json').read_text());a=json.loads((A/'current-definitions.json').read_text())
need(c['candidate']==a['provider'],'linked provider actual bytes')
need(c['normalActualChecks']==c['ASanUBActualChecks']==231 and c['legacyV7Factory3ActualRegressionChecks']==640,'actual model counts')
old=N/'cpu-system-factory-integration-local-v4/freeze.json'
oldpins=json.loads(old.read_text())['files']
for i in oldpins:need(pin(i['path'])==i,'old frozen source/output drift')
original=N/'old13-observer-baseline-v1/Hypervisor';raw=original.read_bytes()
contract=N/'native-memory-map-probe-root-v1/audit/contract.json';j=json.loads(contract.read_text())
need(pin(original)=={k:j['input'][k] for k in ['path','bytes','sha256']},'actual old native whole source pin')
frameProof=[]
for name,frame in j['frames'].items():
 start,end=frame['startRVA'],frame['endRVA'];need(hashlib.sha256(raw[start:end]).hexdigest()==frame['SHA256'],'complete actual original frame bytes')
 for w in frame['instructions']:need(f'{struct.unpack_from("<I",raw,w["rva"])[0]:08x}'==w['machineWord'],'each genuine packet word')
 frameProof.append(dict(name=name,startRVA=start,endRVA=end,bytes=end-start,sha256=frame['SHA256']))
refs=[old,N/'cpu-system-factory-source-independent-review-v1/review.json',N/'cpu-native-sys-original-self-memory-independent-review-v1/review.json',
 contract,N/'native-memory-map-independent-review-v1/native-review.json',N/'kernel-memory-map-native-v1/result.json',
 N/'cpu-owned-creation-actual-independent-review-v1/review.json']
f=dict(schema='Actual same-VM owned RAM Factory5 Lifecycle9 source finalization v1',finiteLocalScopePassed=True,findings=[],
 candidate=pin(D/'candidate.json'),currentDefinitions=pin(A/'current-definitions.json'),
 alternatives=['modern_cpu_kernel_lifecycle_v9.c','modern_cpu_native_public_factory_v5.c'],
 addedOwnExports=[x for x in c['exactOwnExports'] if 'RAM' in x],
 normalAndASanActualChecksEach=231,legacy640Passed=True,oldSYS218PinsVerified=len(oldpins),genuineOriginalFrames=frameProof,
 nativePacketBytes=40,nativePacketWordOffsets=[0,8,16,24,32],nativeOperations=[3,5,4],
 VMAndCPUAndRAMUseSameRealRegistryAndNativeOps=True,VMOwnerActualPthreadAndThreadIDRequired=True,
 backingAllocationOwnedMmapWithPROT_NONEGuards=True,wholeBackingIncludingGuardsRejectedAsOutputs=True,
 atomicVMGuardAcquiredBeforeCallbacks=True,noCallbacksUnderVMMutex=True,
 RAMMutationsDeniedWithAnyCPUHandle=True,mappedRAMMayRemainAliveThroughCPUCreationAndDestruction=True,
 native3FailureMappingUncertain=True,native5FailureMappingUncertain=True,native4FailureRetainsBacking=True,
 ownerChangedAfterNativeSuccessCannotAuthorizeRelease=True,onlyOwnerVerifiedSuccessfulUnmapPermitsBackingFree=True,
 allRAMHandlesBlockVMDestroyAndFree=True,failedMapUnmapDoesNotBecomePublicSuccess=True,
 actualOwnCFCreateAndDestroyEach=1,current41StrongNamesClosed=True,
 originalMapEvidenceNativeISA=2,originalMapEvidenceFlags=[3,1,3],originalMapEvidenceGuestCPUCalls=0,
 newNativeISA1MapEXECProven=False,guestREADWRITEEXECEnforcementProven=False,cacheCoherencyForGuestExecutionProven=False,
 memoryLifecycleSourceImplemented=True,memoryBindingComplete=False,architectureResetComplete=False,
 originalApple25ClusterPublished=False,originalVMMIntegrated=False,fullPublicRunEquivalent=False,
 old13Forwarding=False,originalUSERVIEWCreated=False,defaultsOrC0ResetInvented=False,
 nativeVMCallsExecuted=0,nativeCPUCallsExecuted=0,nativeRAMCallsExecuted=0,native8CallsExecuted=0,native9CallsExecuted=0,
 actualMacOwnMmapAndSelfMachMemoryAPIsExecuted=True,iOSSigned=False,iOSLoaded=False,deviceOperations=0,readyWritten=False,
 full27Backend=False,peerPending=True,references=[pin(p) for p in refs])
(D/'finalization.json').write_text(json.dumps(f,indent=2)+'\n')
files={}
for i in c['inputs']+a['inputs']:
 need(pin(i['path'])==i,'source/capture drift');files[i['path']]=i
for p in refs+[original,Path(__file__)]:files[str(p.resolve())]=pin(p)
for folder in [D,A]:
 for p in folder.rglob('*'):
  if p.is_file() and p.name!='freeze.json':files[str(p.resolve())]=pin(p)
(D/'freeze.json').write_text(json.dumps(dict(schema='Immutable finite RAM product and exact current definition pins v1',
 files=sorted(files.values(),key=lambda x:x['path']),deviceOperations=0,nativeCallsExecuted=0,full27Backend=False),indent=2)+'\n')
print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),files=len(files))))
