"""Freeze only an already successful local actual-owner integration.

This records no device authorization and does not compile, sign, or load code.
"""
from pathlib import Path
import argparse,hashlib,json
S=Path(__file__).resolve().parent
N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(path):
 p=Path(path).resolve();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--candidate-directory',required=True)
 parser.add_argument('--engine-candidate',required=True)
 parser.add_argument('--engine-independent-review',required=True)
 parser.add_argument('--engine-source-freeze',required=True)
 args=parser.parse_args();D=Path(args.candidate_directory).resolve()
 if D.parent!=N.resolve():raise ValueError('independent diagnostic folder required')
 if (D/'finalization.json').exists() or (D/'freeze.json').exists():raise ValueError('do not replace a frozen record')
 pins={}
 def remember(expected):
  actual=pin(expected['path'])
  if actual!=expected:raise ValueError('source/evidence drift '+expected['path'])
  if actual['path'] in pins and pins[actual['path']]!=actual:raise ValueError('inconsistent repeated pin')
  pins[actual['path']]=actual
 def scan(value):
  if isinstance(value,dict):
   if set(('path','bytes','sha256')).issubset(value):remember({k:value[k] for k in ('path','bytes','sha256')})
   else:
    for child in value.values():scan(child)
  elif isinstance(value,list):
   for child in value:scan(child)
 candidatePin=pin(D/'candidate.json');remember(candidatePin)
 candidate=json.loads(Path(candidatePin['path']).read_text());scan(candidate)
 if not candidate['finiteLocalScopePassed'] or candidate['findings'] or not candidate['actualProductionIncludeClosureBeforeAfterUnchanged']:
  raise ValueError('successful actual-source candidate required')
 if candidate['hostResults'][0]!=candidate['hostResults'][1]:raise ValueError('normal/SAN mismatch')
 rootPin=candidate['root8FrozenSourceAncestry'];root=json.loads(Path(rootPin['path']).read_text());scan(root)
 enginePin=pin(args.engine_candidate);reviewPin=pin(args.engine_independent_review)
 if not Path(enginePin['path']).is_relative_to(N) or not Path(reviewPin['path']).is_relative_to(N):
  raise ValueError('exact local engine evidence required')
 remember(enginePin);remember(reviewPin)
 engine=json.loads(Path(enginePin['path']).read_text());review=json.loads(Path(reviewPin['path']).read_text())
 scan(engine);scan(review)
 engineSourceFreezePin=pin(args.engine_source_freeze)
 if not Path(engineSourceFreezePin['path']).is_relative_to(N):raise ValueError('local actual engine source freeze required')
 remember(engineSourceFreezePin);scan(json.loads(Path(engineSourceFreezePin['path']).read_text()))
 if not engine.get('controllerModelPassed') or not review.get('finiteLocalScopePassed') or review.get('findings'):
  raise ValueError('engine candidate and independent review must pass')
 # Pin all newly produced actual compilation/model artifacts, including object
 # files and their command logs. The final record does not invent parent pins.
 for path in sorted(D.iterdir()):
  if path.is_file():remember(pin(path))
 remember(pin(__file__))
 final=dict(schema='Factory15 Life18 actual GIC owner integration finalization v1',
  candidate=candidatePin,provider=candidate['iosProvider'],root8Ancestry=rootPin,
  engineCandidate=enginePin,engineIndependentReview=reviewPin,engineActualSourceFreeze=engineSourceFreezePin,
  actualProductionIncludeClosureCount=len(candidate['sourceInputs']),
  actualProductionIncludeClosureBeforeAfterUnchanged=True,
  root8AllFrozenPinsRevalidated=True,normalAndSanitizerChecksEach=candidate['hostResults'][0]['checks'],
  actualRegisteredVMAndCPUGenerationOwnsGIC=True,retainedFactoryAndKernelCPUAttachments=True,
  realMPIDRControl3ReadbackSynchronizesAffinity=True,
  foreignDistributorAndSPIAllowed=True,foreignICCRejectedWithoutPoison=True,
  acknowledgedInterruptOutputFailureWithdrawsBothCPURegistries=True,
  acknowledgedInterruptLowerOutputFailurePoisoned=True,
  pendingControl0EntryAndReturnProtocolPreserved=True,native9ErrorsStillCleanPendingControl0=True,
  eachGICPostMutationUsesTrueRunToken=True,publicRunHasNoFixedIterationLimit=True,
  privateBoundedRunOnlyForFixtures=True,cancelUsesActualCPUFlagAndNative10Wake=True,
  canceledBeforeRunUsesNoNative9=True,physicalTimerAndCancelWakeSeparate=True,
  cleanupDrainsActualTimerAndWakeBeforeNative7=True,partialFailureRetainsCPUVMAndBorrow=True,
  allNativeCallsMocked=True,deviceOperations=0,providerSigned=False,providerLoaded=False,
  strongRootOutputGuardLinked=False,publicGICSDKAdapterProvidedByRoot=False,
  cancelWithoutGICAttachmentUnsupported=True,virtualTimerLaneImplemented=False,
  HVC16Private3fAndTLBIHandlersUnimplemented=True,fullPublicRunEquivalent=False,full27Backend=False)
 finalPath=D/'finalization.json';finalPath.write_text(json.dumps(final,indent=2)+'\n');remember(pin(finalPath))
 # Recheck every actual byte immediately before publishing the freeze.
 for expected in pins.values():
  if pin(expected['path'])!=expected:raise ValueError('final freeze race '+expected['path'])
 freeze=dict(schema='Factory15 Life18 complete actual bytes local freeze v1',
  files=[pins[path] for path in sorted(pins)],sourceInputs=candidate['sourceInputs'],
  nativeExecutionAuthorizedByThisRecord=False,deviceOperations=0,full27Backend=False)
 freezePath=D/'freeze.json';freezePath.write_text(json.dumps(freeze,indent=2)+'\n')
 print(json.dumps(dict(finalization=pin(finalPath),freeze=pin(freezePath),pins=len(pins))))

if __name__=='__main__':main()
