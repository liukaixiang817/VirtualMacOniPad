"""Freeze a passed, unsigned, offline Factory16/Life20 source integration."""
from pathlib import Path
import argparse,hashlib,json
S=Path(__file__).resolve().parent
N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(path):
 p=Path(path).resolve();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate-directory',required=True)
 args=ap.parse_args();D=Path(args.candidate_directory).resolve()
 if D.parent!=N.resolve() or (D/'finalization.json').exists() or (D/'freeze.json').exists():
  raise ValueError('new unsealed local candidate required')
 pins={}
 def remember(expected):
  actual=pin(expected['path'])
  if actual!=expected:raise ValueError('actual source/evidence drift '+expected['path'])
  if actual['path'] in pins and pins[actual['path']]!=actual:raise ValueError('inconsistent repeated pin')
  pins[actual['path']]=actual
 def scan(value):
  if isinstance(value,dict):
   if {'path','bytes','sha256'}<=value.keys():remember({k:value[k] for k in ('path','bytes','sha256')})
   else:
    for child in value.values():scan(child)
  elif isinstance(value,list):
   for child in value:scan(child)
 candidatePin=pin(D/'candidate.json');remember(candidatePin)
 candidate=json.loads(Path(candidatePin['path']).read_text());scan(candidate)
 if not candidate.get('finiteLocalScopePassed') or candidate.get('findings') or not candidate.get('actualProductionIncludeClosureBeforeAfterUnchanged'):
  raise ValueError('passed actual-source candidate required')
 if candidate['hostResults'][0]!=candidate['hostResults'][1]:raise ValueError('normal/SAN mismatch')
 parents=[]
 for key in ['root9FrozenSourceAncestry','timer19Frozen','mask20Frozen']:
  expected=candidate[key];remember(expected);parent=json.loads(Path(expected['path']).read_text());scan(parent)
  parents.append(dict(kind=key,freeze=expected,allCurrentPinsRevalidated=True))
 for stem in ['vtimer-mask-raw-dispatch-semantic-offline-v1','native-vtimer-fresh-bank-geometry-offline-v1',
  'modern27-hvc-private-tlbi-semantic-offline-v1']:
  expected=pin(N/stem/'freeze.json');remember(expected);scan(json.loads(Path(expected['path']).read_text()))
 hvcBasis=pin(N/'modern27-hvc-private-tlbi-semantic-offline-v1/report.json')
 remember(hvcBasis);hvc=json.loads(Path(hvcBasis['path']).read_text())
 if not hvc.get('finiteLocalScopePassed') or hvc.get('findings'):raise ValueError('passed exact modern HVC basis required')
 ancestryPin=pin(D/'source-ancestry.json');remember(ancestryPin);scan(json.loads(Path(ancestryPin['path']).read_text()))
 for typed in candidate['typedCXXCallers']:
  if not typed['joinedActualProvider']:raise ValueError('actual C++ provider join required')
 for path in sorted(D.iterdir()):
  if path.is_file():remember(pin(path))
 remember(pin(__file__))
 final=dict(schema='Factory16 Life20 true owned GIC Timer19 and virtual timer integration finalization v1',
  candidate=candidatePin,provider=candidate['iosProvider'],parents=parents,
  actualProductionIncludeClosureCount=len(candidate['sourceInputs']),
  normalAndSanitizerChecksEach=candidate['hostResults'][0]['checks'],
  trueSDKCXXCallersJoinedActualProvider=True,
  actualRegisteredVMAndCPUGenerationOwnsGIC=True,retainedFactoryAndKernelCPUAttachments=True,
  pendingControl0EntryAndReturnProtocolPreserved=True,native9ErrorsStillCleanPendingControl0=True,
  eachGICPostMutationUsesTrueRunToken=True,publicRunHasNoFixedIterationLimit=True,
  privateBoundedRunOnlyForFixtures=True,cancelUsesActualCPUFlagAndNative10Wake=True,
  canceledBeforeRunUsesNoNative9=True,physicalTimerAndCancelWakeSeparate=True,
  publicVtimerMaskGetSetUseActual6d8RMW=True,virtualTimerInitialMaskPreservedAcrossNativeRetries=True,
  raw0PublicCanceledAndRaw3Or4VtimerTruePredicate=True,
  native430Full64Equals5Required=True,actual4110ActiveBankAnd4100ReadyReads=True,
  native4100And4110NeverWritten=True,realAutoMaskOneWriteBeforePublicVtimerExit=True,
  nonzeroCounterDomainUsesFrozenTimer19SharedOwnedState=True,
  postDF01ReturnsSampledMachMinusActualVtimerOffset=True,
  postDF00ReturnsActualSampledFrequency=True,postCNTPCTLAndCVALUseActualCounterDomain=True,
  ordinaryHVCBasis=hvcBasis,exactFactory15BodyAncestry=ancestryPin,
  ordinaryEL1HVCUsesTruePostPSTATEAndX0=True,
  ordinaryHVCRequiresActualNativeRaw1Or6Or8AndCompleteExitFields=True,
  ordinaryHVCProducesIndependentPublicExceptionWithoutOldReducerFlags=True,
  ordinaryHVCKeepsPCAndRegisterStateForRealVMMDispatcher=True,
  privateImm0C6AndC3000006FamiliesAndEL0Unsupported=True,
  modernC1HasNoAdditionalX0BranchAfterActualNativeExit=True,
  failedPostWriteOrTokenBoundaryPoisonsAndRetainsTrueCPUVM=True,
  cleanupDrainsActualTimerAndWakeBeforeNative7=True,
  allNativeCallsMocked=True,deviceOperations=0,providerSigned=False,providerLoaded=False,
  strongRootOutputGuardLinked=False,publicGICSDKAdapterProvidedByRoot=False,
  cancelWithoutGICAttachmentUnsupported=True,deviceCounterDomainAndCNTPCTTrapUnproved=True,
  HVCWithoutGICAttachmentUsesFrozenPrivate14AndIsUnsupported=True,
  privateHVCAndTLBIEmulationUnimplemented=True,
  fullPublicRunEquivalent=False,full27Backend=False)
 finalPath=D/'finalization.json';finalPath.write_text(json.dumps(final,indent=2)+'\n');remember(pin(finalPath))
 for expected in pins.values():
  if pin(expected['path'])!=expected:raise ValueError('final source/evidence freeze race '+expected['path'])
 freeze=dict(schema='Factory16 Life20 complete actual bytes local freeze v1',
  files=[pins[path] for path in sorted(pins)],sourceInputs=candidate['sourceInputs'],
  nativeExecutionAuthorizedByThisRecord=False,deviceOperations=0,full27Backend=False)
 freezePath=D/'freeze.json';freezePath.write_text(json.dumps(freeze,indent=2)+'\n')
 print(json.dumps(dict(finalization=pin(finalPath),freeze=pin(freezePath),pins=len(pins))))
if __name__=='__main__':main()
