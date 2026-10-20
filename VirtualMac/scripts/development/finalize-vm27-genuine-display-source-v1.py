#!/usr/bin/env python3
"""Seal the finite source display bridge evidence, without a runtime claim."""
import argparse,hashlib,json,pathlib,re,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 build=N/'uikit-genuine-display-source-local-v1';actual=N/'uikit-genuine-display-actual-mac-surface-v1'
 evidence=N/'vz-framebuffer-owner-original-readonly-v16';candidate=json.loads((build/'candidate.json').read_bytes())
 pins={}
 def add(p):row=pin(p);pins[row['path']]=row;return row
 for row in candidate['sourceFiles']+[candidate['builder'],candidate['iosProvider']]:
  assert pin(pathlib.Path(row['path']))==row;add(pathlib.Path(row['path']))
 assert candidate['normal']['passed'] and candidate['normal']['checks']==24
 assert candidate['sanitized']['passed'] and candidate['sanitized']['checks']==24
 real=json.loads((actual/'result.json').read_bytes())
 assert len(real['results'])==2
 for row in real['results']:
  assert pin(pathlib.Path(row['binary']['path']))==row['binary']
  assert row['exit']==0 and row['result']['passed'] and row['result']['checks']==38
  assert row['result']['actualMacIOSurface'] and row['result']['deviceOperations']==0
  assert not row['result']['originalVZExecuted']
 for directory in (build,actual,evidence):
  for p in directory.iterdir():
   if p.is_file():add(p)
 for row in json.loads((evidence/'inputs.json').read_bytes()):
  assert pin(pathlib.Path(row['path']))==row;add(pathlib.Path(row['path']))
 # The production frontend port has changed branch encodings during uncache.
 # Bind the runtime function gate to its actual selected ported text bytes.
 vzManifest=N/'vz-own-uikit-notification-source-port-data-v1/candidate.json'
 vz=json.loads(vzManifest.read_bytes());vzPin=vz['frontendCandidate'];image=pathlib.Path(vzPin['path'])
 assert pin(image)==vzPin;raw=image.read_bytes();profiles=[]
 profile=S/'vm27_genuine_display_profile_v1.inc'
 for rva,count,items in re.findall(r'\{(0x[0-9a-f]+),(\d+),\{([^}]+)\}\}',profile.read_text()):
  expected=bytes(int(x.strip(),16)for x in items.split(','));assert len(expected)==32
  start=int(rva,16);size=int(count);actualHash=hashlib.sha256(raw[start:start+size]).digest()
  assert actualHash==expected
  profiles.append(dict(rva=start,bytes=size,sha256=expected.hex()))
 assert len(profiles)==5;add(vzManifest);add(image)
 # Preserve exact earlier audit revisions and parser failures, rather than
 # rewriting their results with the final source's corrected locations.
 history=[]
 for directory in sorted(N.glob('vz-framebuffer-owner-original-readonly-v*')):
  for p in directory.iterdir():
   if p.is_file():add(p)
  history.append(dict(directory=str(directory),files=[pin(p)for p in directory.iterdir()if p.is_file()]))
 final=dict(schema='Genuine VZ27 display observer and UIKit Metal source finalization v1',
  candidate=pin(build/'candidate.json'),actualLocalMacSurface=pin(actual/'result.json'),
  originalProfileEvidence=pin(evidence/'contract.json'),selectedPortedVZ=vzPin,
  actualRuntimeCodeProfiles=profiles,originalAuditHistory=history,
  localSourceCompileLinkAndFiniteModelsPassed=True,
  normalChecks=24,sanitizedChecks=24,actualMacSurfaceNormalChecks=38,actualMacSurfaceSanitizedChecks=38,
  sourceSharedPtrByValueABIAndQueueLocalExceptionCatchValidated=True,
  actualIOSurfaceUseCountAndDrainValidated=True,
  partialDetachFailureKeepsActualVMOwnerRetained=True,
  sourceMetalRenderedCompletionImplemented=True,sourceAppJoinStillInProgress=True,
  historicalLocalFailures=[
   'Sandboxed actual IOSurface creation returned NULL; default local fixture uses no surface.',
   'Initial actual-surface fixture used dispatch_main and timed out; final fixture uses the physical main CFRunLoop.',
   'Initial detach fault escaped a libdispatch execution block; final source catches exceptions inside each actual queue block before rethrowing on the owned bridge.'
  ],historicalFailureBinaryPinsAvailable=False,
  originalVZExecuted=False,actualUIKitMetalRendered=False,actualGuestSurfaceObserved=False,
  fullFramebufferEquivalenceClaimed=False,fullMacViewSemanticsClaimed=False,
  firstProfile='Nonplanar BGRA IOSurface, no HDR or cursor equivalence claim',
  deviceOperations=0,nativeHVCalls=0,codeSigned=False,readyForDeviceExecution=False,full27Backend=False)
 add(pathlib.Path(__file__));save(o/'finalization.json',final);add(o/'finalization.json')
 save(o/'freeze.json',dict(schema='Finite genuine display source evidence freeze v1',files=list(pins.values()),deviceOperations=0))
 print(json.dumps(dict(finalization=pin(o/'finalization.json'),freeze=pin(o/'freeze.json'),pins=len(pins))))
if __name__=='__main__':main()
