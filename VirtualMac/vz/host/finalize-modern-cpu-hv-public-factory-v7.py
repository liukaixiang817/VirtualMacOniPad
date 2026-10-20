"""Freeze ten genuine CPU entry source and one bounded shared query; no iOS run."""
from pathlib import Path
import hashlib,json
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-hv-public-feature-cluster-integration-local-v3'
A=N/'cpu-hv-public-feature-current-definitions-readonly-v2'
G=N/'cpu-hv-public-feature-original-sdk-readonly-v2'
Q=N/'cpu-feature-capability-acquisition-local-v3'
C=N/'cpu-hv-abi2-cpp-linkage-independent-review-v1'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,s):
 if not v:raise ValueError(s)
need(not (D/'freeze.json').exists(),'no frozen overwrite')
c=json.loads((D/'candidate.json').read_text());a=json.loads((A/'current-definitions.json').read_text())
g=json.loads((G/'audit.json').read_text());q=json.loads((Q/'results.json').read_text())
need(c['candidate']==a['provider'],'actual selected linked import image')
need(c['normalActualChecks']==c['ASanUBActualChecks']==385 and c['legacyV7Factory3ActualRegressionChecks']==640,'actual source integration results')
need(a['actualImportCount']==42 and len(c['exactOwnExports'])==29 and len(c['exactPublicHVExports'])==10,'actual finite interfaces')
need(g['finiteLocalScopePassed'],'genuine query/SDK ABI source proof')
need((C/'review.json').is_file() and (C/'freeze.json').is_file(),'actual independent C++ linkage supplement')
cpp=json.loads((C/'review.json').read_text());need(cpp['finiteLocalScopePassed'],'new ABI2 C++ actual external names')
for p in [N/'cpu-hv-public-cluster-integration-local-v2/freeze.json',C/'freeze.json']:
 for i in json.loads(p.read_text())['files']:need(pin(i['path'])==i,'prior frozen evidence changed')
refs=[N/'cpu-hv-public-cluster-integration-local-v2/finalization.json',
 N/'cpu-hv-public-cluster-independent-review-v1/review.json',
 N/'cpu-owned-ram-integration-local-v3/freeze.json',
 N/'vmm-public-adapter-gap-design-v1/contract.json',
 N/'original27-vmm-public-exit-consumer-abi-v1/contract.json',
 C/'review.json',C/'freeze.json']
f=dict(schema='Actual ten public CPU ABI Factory7 OS5 shared AcqV2 finalization v1',
 finiteLocalScopePassed=True,findings=[],candidate=pin(D/'candidate.json'),provider=c['candidate'],
 featureGenuineABIContract=pin(G/'audit.json'),currentDefinitions=pin(A/'current-definitions.json'),
 actualSharedQueryModel=pin(Q/'results.json'),CPlusPlusLinkagePeer=pin(C/'review.json'),
 alternatives=['modern_cpu_native_public_factory_v7.c','modern_cpu_config_os_object_v5.m','modern_cpu_config_capability_acquisition_v2.c'],
 actualPublicExports=c['exactPublicHVExports'],normalASanActualChecksEach=385,legacyActualRegressionChecks=640,
 actualOwnCFObjectsCreatedAndDestroyedEach=3,current42StrongNamesClosed=True,
 actualFeatureSelectors=list(range(12)),unknownModernFeatureSelectors=list(range(12,18)),
 featureAndTLBIAndRawIPAPairShareOnePrivateProcessOnce=True,
 exactRawIPAOffsets=[0x149,0x151],IPAPairKnownIsNotSupported=True,
 trueDyldBuildVersionStructBytes=8,trueDyldBuildVersionAlignment=4,trueDyldBoolReturn=True,
 trueDyldVersionSetTokenBoundToValidatedIPadProfile=True,
 priorIOSFallbackCPlusPlusMangledFindingPreserved=True,newABI2FirstIncludeHasActualTenCSymbols=True,
 additionalVMGuardSourceStrongCompileSelected=True,standaloneVMGuardFlag=0,
 RootVMBootstrapInstallationAllowed=False,combinedGuard1NotThisStandaloneProduct=True,
 persistentPublicExitBytes=32,CPUObjectOriginalVMMBytes=296,CPUObjectOriginalVMMIDOffset=0xd8,CPUObjectOriginalVMMExitPointerOffset=0xe0,
 featureGetterUsesActualOwnCFBorrowAndRetainedDrain=True,unsupportedOrUnknownPreservesOutput=True,
 sourceDoesNotInstallAppleUSEROrModernVIEW=True,nativeSlotRequestStillFixedZero=True,
 nativeCallsExecuted=0,nativeVMCallsExecuted=0,nativeCPUCallsExecuted=0,native8CallsExecuted=0,native9CallsExecuted=0,
 actualMacOwnMmapAndSelfTaskMachMemoryAPIsExecuted=True,allNativeTrapCallbacksMocked=True,
 iOSProviderUnsigned=True,iOSProviderLoaded=False,deviceOperations=0,readyWritten=False,realRouteCreated=False,
 publicRunExported=False,remaining15CPUImportsImplemented=False,original25ClusterComplete=False,original75HVImportsComplete=False,
 originalVMMIntegrated=False,fullPublicRunEquivalent=False,architectureResetComplete=False,memoryBindingComplete=False,
 guestExecutionProven=False,full27Backend=False,featureRuntimeAcquisitionOnDeviceProven=False,
 unknownMandatorySYS=['CNTP_CTL_EL0/0xdf11','CNTP_CVAL_EL0/0xdf12','SCXTNUM_EL0/0xde87','SCXTNUM_EL1/0xc687'],
 references=[pin(p) for p in refs])
(D/'finalization.json').write_text(json.dumps(f,indent=2)+'\n')
files={}
for j in [c,a,g,q,cpp]:
 for i in j.get('inputs',[]):
  need(pin(i['path'])==i,'actual source/receipt pin drift');files[i['path']]=i
for p in refs+[Path(__file__)]:files[str(p.resolve())]=pin(p)
for folder in [D,A,G,Q,C]:
 for p in folder.rglob('*'):
  if p.is_file() and not (folder==D and p.name=='freeze.json'):files[str(p.resolve())]=pin(p)
(D/'freeze.json').write_text(json.dumps(dict(schema='Immutable actual ten public CPU ABI and shared query source v1',
 files=sorted(files.values(),key=lambda x:x['path']),nativeCallsExecuted=0,deviceOperations=0,full27Backend=False),indent=2)+'\n')
print(json.dumps(dict(finalization=pin(D/'finalization.json'),freeze=pin(D/'freeze.json'),files=len(files))))
