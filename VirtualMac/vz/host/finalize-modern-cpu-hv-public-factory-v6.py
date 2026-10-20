"""Freeze actual nine public CPU entries; no route, device or native execution."""
from pathlib import Path
import hashlib,json
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-hv-public-cluster-integration-local-v2'
A=N/'cpu-hv-public-cluster-current-definitions-readonly-v1'
G=N/'cpu-hv-public-getter-original-sdk-readonly-v2'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,s):
 if not v:raise ValueError(s)
need(not (D/'freeze.json').exists(),'no frozen overwrite')
c=json.loads((D/'candidate.json').read_text());a=json.loads((A/'current-definitions.json').read_text());g=json.loads((G/'audit.json').read_text())
need(c['candidate']==a['provider'],'actual linked imports')
need(c['normalActualChecks']==c['ASanUBActualChecks']==354 and c['legacyV7Factory3ActualRegressionChecks']==640,'actual host results')
need(a['actualImportCount']==41 and len(c['exactOwnExports'])==29 and len(c['exactPublicHVExports'])==9,'actual finite interfaces')
need(g['finiteLocalScopePassed'] and len(g['publicCPU25UsedCoverage'])==25,'original getter and SDK closure')
old=N/'cpu-owned-ram-integration-local-v3/freeze.json';oldpins=json.loads(old.read_text())['files']
for i in oldpins:need(pin(i['path'])==i,'old frozen source/output drift')
refs=[old,N/'cpu-owned-ram-source-independent-review-v1/review.json',
 N/'cpu-system-factory-source-independent-review-v1/review.json',
 N/'cpu-native-sys-original-self-memory-independent-review-v1/review.json',
 N/'vmm-public-adapter-gap-design-v1/contract.json',
 N/'original27-vmm-public-exit-consumer-abi-v1/contract.json',
 N/'cpu-owned-creation-actual-independent-review-v1/review.json']
f=dict(schema='Actual nine public CPU ABI source finalization Factory6 Lifecycle10 v1',finiteLocalScopePassed=True,findings=[],
 candidate=pin(D/'candidate.json'),provider=c['candidate'],getterSDKContract=pin(G/'audit.json'),currentDefinitions=pin(A/'current-definitions.json'),
 alternatives=['modern_cpu_native_public_factory_v6.c','modern_cpu_kernel_lifecycle_v10.c'],actualPublicExports=c['exactPublicHVExports'],
 addedOwnExport='VM27CPUFactoryPublicDrainBorrowV6',normalASanActualChecksEach=354,legacyActualRegressionChecks=640,
 actualOwnCFObjectsCreatedAndDestroyedEach=3,oldRAM230PinsVerified=len(oldpins),current41StrongNamesClosed=True,
 actualSDKStatusBits=32,actualSDKCPUIdentifierBits=64,actualSDKScalarAndSIMDEnumBits=32,actualSDKSYSIdentifierBits=16,
 actualSIMDVectorBytes=16,actualSIMDVectorAlignment=16,persistentPublicExitBytes=32,
 persistentExitFieldOffsets=[0,8,16,24],CPUObjectOriginalVMMBytes=296,CPUObjectOriginalVMMIDOffset=0xd8,CPUObjectOriginalVMMExitPointerOffset=0xe0,
 publicConfigCreateIsSameProviderRealCFPlusOne=True,nonnullSDKAllocationFailureContainedByAbort=True,
 actualFactoryVMRegistryAndImmutableOpsRequired=True,publicCPUIdentifierNotNativeReturnedSlot=True,
 publicSettersUseOnlyBoundVMWriter=True,ownerThreadPthreadTLSVMepochAndCPUGenerationRequired=True,
 publicGetterFieldReadActualMappedRangeAndVersionChecked=True,publicGetterFailurePreservesCallerValue=True,
 originalScalarFPCRCPSRFPSRUInt32ReadsZeroExtendedToUInt64=True,wholePrivateRAMIncludingGuardsRejectedAsOutputs=True,
 acquireApplyReadReleaseUsesActualBorrowAndDrain=True,unexpectedReleaseFailureRetainedInBorrowerTLS=True,
 successfulPublicDestroyUnpublishesID=True,sequentialNewCreationHasDifferentOwnIDAndGeneration=True,
 partialWritePoisonUnpublishesIDAndRetainsActualOwnerCleanup=True,poisonedIDPublicDestroyRejectsAndOwnOwnerCleanupRequired=True,
 nativeOpsBindingNotInventedByPublicWrappers=True,nativeSlotRequestStillFixedZero=True,actualPublicVMCreateBootstrapImplemented=False,
 publicVMConfigAndMapAPIsImplemented=False,featureConfigGetterImplemented=False,publicRunExported=False,
 remaining16CPUImportsImplemented=False,original25ClusterComplete=False,original75HVImportsComplete=False,
 nativeContextVIEWExported=False,originalUSERTableRecreated=False,unsupportedSYSNeverShadowSuccess=True,
 unknownMandatorySYS=['CNTP_CTL_EL0/0xdf11','CNTP_CVAL_EL0/0xdf12','SCXTNUM_EL0/0xde87','SCXTNUM_EL1/0xc687'],
 nativeCallsExecuted=0,nativeVMCallsExecuted=0,nativeCPUCallsExecuted=0,native8CallsExecuted=0,native9CallsExecuted=0,
 actualMacOwnMmapAndSelfTaskMachMemoryAPIsExecuted=True,allNativeTrapCallbacksMocked=True,
 iOSProviderUnsigned=True,iOSProviderLoaded=False,deviceOperations=0,readyWritten=False,realRouteCreated=False,
 originalVMMIntegrated=False,fullPublicRunEquivalent=False,architectureResetComplete=False,memoryBindingComplete=False,
 guestExecutionProven=False,full27Backend=False,peerPending=True,references=[pin(p) for p in refs])
(D/'finalization.json').write_text(json.dumps(f,indent=2)+'\n')
files={}
for j in [c,a,g]:
 for i in j['inputs']:
  need(pin(i['path'])==i,'actual source/receipt pin drift');files[i['path']]=i
for p in refs+[Path(__file__)]:files[str(p.resolve())]=pin(p)
for folder in [D,A,G]:
 for p in folder.rglob('*'):
  if p.is_file() and p.name!='freeze.json':files[str(p.resolve())]=pin(p)
(D/'freeze.json').write_text(json.dumps(dict(schema='Immutable actual nine public CPU ABI source and genuine byte SDK contracts v1',
 files=sorted(files.values(),key=lambda x:x['path']),nativeCallsExecuted=0,deviceOperations=0,full27Backend=False),indent=2)+'\n')
print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),files=len(files))))
