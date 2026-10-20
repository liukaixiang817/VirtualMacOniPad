#!/usr/bin/env python3
"""HOST-only single-TU CPU bitmap display provenance and genuine iOS compile."""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')};return pathlib.Path(r['path'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();assert o.parent==N and not o.exists()
 source=S/'vm27_uikit_guest_display_v4.mm';assert pin(source)['sha256']=='d510c5ef9f440b6890f7bf306d53659bdf0ec0317c7bf0538bc57a2e7bb709b0'
 cp=N/'independent27-actual-app-metal-stage-diagnostic-v14-attempt1/candidate.json';old=json.loads(cp.read_bytes());prior=exact(old['sourceFiles'][16]);text=source.read_text();prior_text=prior.read_text()
 prefix=prior_text[:prior_text.index('@interface VM27UIKitMetalDisplayV1')];assert text.startswith(prefix)
 assert 'MTLCreateSystemDefaultDevice(' not in text and 'newCommandQueue' not in text
 assert 'kCAGravityResize;' in text and 'dispatch_sync(' not in text
 o.mkdir(mode=0o700);commands=[]
 def run(label,args):
  r=subprocess.run(args,capture_output=True);(o/(label+'.stdout')).write_bytes(r.stdout);(o/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));assert r.returncode==0,(label,r.stderr.decode());return r.stdout.decode()
 argv=next(x['argv'].copy()for x in old['commands']if x['label']=='compile-16');argv=[str(source)if x==str(prior)else x for x in argv];argv[argv.index('-o')+1]=str(o/'DisplayV4.o');argv+=['-Wall','-Wextra','-Werror'];run('actual-ios-arm64e-arc',argv)
 newnm=run('new-undefined',['xcrun','nm','-u',str(o/'DisplayV4.o')]);oldnm=run('old-undefined',['xcrun','nm','-u',str(exact(old['objects'][16]))]);added=sorted(set(newnm.splitlines())-set(oldnm.splitlines()));removed=sorted(set(oldnm.splitlines())-set(newnm.splitlines()))
 indexpath=N/'current-native-header-export-index-v3/index.json';index=json.loads(indexpath.read_bytes());assert len(index['images'])==67
 routes=[];local=[]
 for name in added:
  if name.startswith('_objc_msgSend$'):local.append(dict(name=name,kind='linker Objective-C selector stub'));continue
  definitions=[(path,image,image['definitions'][name])for path,image in index['images'].items()if name in image['definitions'] and not image['definitions'][name]['flags']&8]
  assert len(definitions)==1,(name,'added object symbol needs exactly one captured native defining image');path,image,definition=definitions[0]
  routes.append(dict(name=name,actualDefiningNativePath=path,nativeImageUUID=image['UUID'],definition=definition,actualExportSource=image['actualCompleteExportSource']))
 routepath=o/'added-native-symbol-definitions.json';routepath.write_text(json.dumps(dict(actualObjectUndefinedAdded=added,actualObjectUndefinedRemoved=removed,addedDirectNativeDefinitions=routes,linkerSelectorStubs=local,originalNative67Index=pin(indexpath),actualFinalAppOrdinalProofStillRequired=True,deviceOperations=0),indent=2)+'\n')
 diff=o/'display-v3-to-v4.diff';diff.write_text(''.join(difflib.unified_diff(prior_text.splitlines(True),text.splitlines(True),fromfile=str(prior),tofile=str(source))))
 sdk=pathlib.Path(argv[argv.index('-isysroot')+1]);contracts=[sdk/'System/Library/Frameworks'/f for f in ('IOSurface.framework/Headers/IOSurfaceRef.h','CoreGraphics.framework/Headers/CGImage.h','CoreGraphics.framework/Headers/CGDataProvider.h','QuartzCore.framework/Headers/CATransaction.h')]
 record=dict(schema='HOST genuine IOSurface CPU bitmap display single-source candidate V4',source=pin(source),builder=pin(__file__),priorSource=pin(prior),priorActualApp14Candidate=pin(cp),actualIOSObject=pin(o/'DisplayV4.o'),actualCompileCommands=commands,sourceDiff=pin(diff),actualAddedNativeDefinitions=pin(routepath),actualSDKTraitContracts=[pin(p)for p in contracts],actualMain13SourceUnchanged=old['sourceFiles'][0],genuineObserverSource=pin(S/'vm27_genuine_display_observer_v1.mm'),publicV1HeaderUnchanged=pin(S/'vm27_uikit_guest_display_v1.h'),factory2AttestationPrefixWholeUnchanged=True,publicDisplayABIUnchanged=True,rendererRequiresMetalDevice=False,genuineOriginalFrameAndIOSurfaceProducerUnchanged=True,actualLockReadOnlyAndCopyAndUnlock=True,acceptedPixelFormat='BGRA/4-byte/nonplanar opaque alpha ignored',maximumCopiedBytes=67108864,maximumDimension=8192,oneCopyInFlightAndOneLatestRetained=True,copyCoalescingDelayMilliseconds=100,fullBoundsContentsGravity='kCAGravityResize',aspectFitAndInputViewportCalibrationImplemented=False,seedChangedDropsWithoutPublishAndWaitsForNewActualFrame=True,unlockFailureRetainsActualSurfaceAndViewAndReportsCloseError=True,mainToCopyToMainAllAsynchronous=True,groupDrainDoesNotWaitForCATransactionCompletion=True,lateCATransactionCompletionClosedGateSuppressesAccounting=True,completedFrameMarker='[Independent27Display] completed actual IOSurface bitmap frame=%llu size=%zux%zu backend=cpu-bitmap',completedFrameMeaning='Actual copied CGImage assigned to CALayer; actual CATransaction completion observed after commit returned. Physical visibility and GPU completion not established.',failureMarkerPrefix='[Independent27DisplayV4] failed=',allPrintedFailureMarkersFatal=True,closeFailureReportsErrorAndRetainsOwner=True,seedDropIsFatal=False,requestedActualChangedAppObjectIndices=[16],actualApplicationLinked=False,codeSigningOperations=0,deviceOperations=0,actualIOSurfaceGuestFramesExecuted=False,actualCPUStarted=False,actualPhysicalScreenVisible=False,actualGuestInputCalibrated=False)
 candidate=o/'candidate.json';candidate.write_text(json.dumps(record,indent=2)+'\n');rows=[pin(p)for p in o.iterdir()if p.is_file()]+[pin(__file__),pin(source),pin(prior),pin(cp),pin(cp.parent/'freeze.json'),old['sourceFiles'][0],old['objects'][16],record['genuineObserverSource'],record['publicV1HeaderUnchanged'],pin(S/'vm27_uikit_vm_attestation_v2.h'),pin(S/'vm27_genuine_display_observer_v1.h'),pin(indexpath)]+record['actualSDKTraitContracts']
 def append_pins(value):
  if isinstance(value,dict):
   if all(k in value for k in ('path','bytes','sha256')):rows.append(value)
   else:
    for child in value.values():append_pins(child)
  elif isinstance(value,list):
   for child in value:append_pins(child)
 for route in routes:append_pins(route['actualExportSource'])
 freeze=o/'freeze.json';freeze.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),codeSigningOperations=0,deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(candidate),freeze=pin(freeze),source=pin(source))))
if __name__=='__main__':main()
