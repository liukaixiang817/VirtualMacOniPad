#!/usr/bin/env python3
"""Freeze real copied App4 sources and compiled components; no product anchor."""
import argparse,hashlib,json,pathlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 source=N/'independent27-app-display-source-candidate-v4-attempt2/candidate.json'
 components=N/'independent27-app-components-v4-attempt4/candidate.json'
 sj=json.loads(source.read_bytes());cj=json.loads(components.read_bytes())
 for key in ('source','backendSource','builder','runtimeInterface'):
  assert pin(pathlib.Path(sj[key]['path']))==sj[key]
 assert cj['sourceCandidate']==pin(source) and pin(pathlib.Path(cj['builder']['path']))==cj['builder']
 for row in cj['sourceFiles']+cj['actualIncludeClosure']+cj['objects']:assert pin(pathlib.Path(row['path']))==row
 assert len(cj['objects'])==29 and all(c['exit']==0 for c in cj['commands'])
 runtime=[r for r in cj['sourceFiles'] if pathlib.Path(r['path']).name.startswith('vm27_independent_app_runtime_')]
 assert len(runtime)==1 and pathlib.Path(runtime[0]['path']).name=='vm27_independent_app_runtime_v3.m'
 parents=[N/'independent27-runtime-source-local-v3-attempt1/freeze.json',
  N/'uikit-genuine-display-source-finalization-v1/freeze.json',
  N/'actual-vm-main-input-queue-source-v3-attempt1/freeze.json',
  N/'independent27-app-source-finalization-v3/freeze.json',
  N/'independent27-runtime-v3-independent-source-review-v1/freeze.json']
 seen=set();verified=[]
 def verify(p):
  p=p.resolve()
  if p in seen:return
  seen.add(p);j=json.loads(p.read_bytes());verified.append(pin(p))
  for row in j['files']:
   q=pathlib.Path(row['path']);assert pin(q)==row,(str(q),'parent drift')
  for row in j['files']:
   q=pathlib.Path(row['path'])
   if q.name=='freeze.json':verify(q)
 for p in parents:verify(p)
 files={}
 def add(p):files[str(p.resolve())]=pin(p)
 for parent in (source.parent,components.parent):
  for p in parent.rglob('*'):
   if p.is_file():add(p)
 for row in cj['sourceFiles']+cj['actualIncludeClosure']:add(pathlib.Path(row['path']))
 add(pathlib.Path(sj['builder']['path']));add(pathlib.Path(cj['builder']['path']));add(pathlib.Path(__file__))
 for p in parents:add(p)
 final=dict(schema='Copied App4 actual UIKit source and Runtime3 components finalization',sourceCandidate=pin(source),components=pin(components),
  parentFreezes=[pin(p)for p in parents],recursivelyVerifiedParentFreezes=verified,actualCompiledUnits=29,
  soleActualRuntimeSource=runtime[0],actualIndependentBackendRootCanonicalized=True,
  actualOriginalVMQueueBindBeforeInputDisplayAndStart=True,actualGuestStartedRequiresChildFactoryAndVZRunning=True,
  actualUIInputAndIOSurfaceDisplaySources=True,oldVenturaCPUVZFallbackExcludedFromSelected27Route=True,
  sourceAndComponentCompilationPassed=True,productAnchorGenerated=False,fixtureAnchorUsed=False,
  actualProductMainBinaryLinked=False,actualApplicationPackaged=False,actualSignedAppMainBytes=None,
  actualParentSelfInspectorMaxBytes=2097152,finalSignedMainSizeVerificationRequired=True,
  currentNICDefault='NAT; networking requires a separately real provider or explicit NIC0 experiment before first display',
  nativeCPUCalls=0,deviceOperations=0,actualVZRuntimeExecuted=False,guestBoot=False,
  boundary='Frozen actual App4 source and true 29-unit iOS component compile only. Strong final main link/package waits for real product manifest anchor; original VMM/XPC/VZ/input/display and guest device execution remain required.')
 save(o/'finalization.json',final);add(o/'finalization.json')
 save(o/'freeze.json',dict(schema='Copied App4 true source and components freeze v1',files=list(files.values()),parentFreezes=[pin(p)for p in parents]))
 print(json.dumps(dict(finalization=pin(o/'finalization.json'),freeze=pin(o/'freeze.json'),pins=len(files))))
if __name__=='__main__':main()
