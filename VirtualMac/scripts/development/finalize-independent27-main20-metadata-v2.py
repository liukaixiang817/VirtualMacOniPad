#!/usr/bin/env python3
"""Freeze truthful Main20 source/object metadata without recompiling machine code."""
import copy,hashlib,json,pathlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def exact(row):
 assert pin(row['path'])=={k:row[k]for k in('path','bytes','sha256')};return row
A=N/'independent27-app-url-display-ssh-deferred-source-v20-attempt1';B=N/'independent27-main20-compiled-object-v1-attempt1'
s=json.loads((A/'candidate.json').read_bytes());o=json.loads((B/'candidate.json').read_bytes())
assert pin(A/'candidate.json')['sha256']=='f48792d215f5e2f9caa2a8a06f4acaec88ae184ec144af74dff8494b670c40e2'
assert pin(B/'candidate.json')['sha256']=='16f97bb359200b0697e89f46e0279c96f64158de15c6132772e614643385e64e'
for row in(s['source'],s['sourceDiff'],s['actualIOSSyntax'],o['object'],o['actualCompile']):exact(row)
P=N/'independent27-app-url-display-ssh-deferred-source-v20-attempt2';Q=N/'independent27-main20-compiled-object-v1-attempt2'
assert not P.exists()and not Q.exists();P.mkdir(mode=0o700);Q.mkdir(mode=0o700)
keys=('source','sourceDiff','baselineMain19','baselineMain19Source','actualIOSSyntax','actualIOSSyntaxExit','urlDisplayPresentationContract','bridgeSourceCandidate','requiredBridgeImplementation','requiredBridgeHeader','publicBridgeV1ABIStillUsed','ownedSSHService','futureGuestHelper')
x={k:copy.deepcopy(s[k])for k in keys}
x.update(schema='Actual Main20 source: valid URL exposes VM display and first-basic-boot guest SSH is deferred',status='HOST_SOURCE_AND_COMPILED_OBJECT_ONLY_NOT_DEPLOYED',preparer=pin(__file__),sourceHunks=['Set existing first-display guest SSH deferral constant from NO to YES','After existing valid start-vm URL checks, hide library view before original activate/start','After existing valid start-vm URL checks, unhide existing input view before original activate/start'],genuineSSHRegistrationRouteEnabled=False,sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,persistentSSHServiceImplementationRetainedButInvocationDeferred=True,genuineSSHBridgeImplementationRetainedButRegistrationDeferred=True,guestSSHRegistrationOrServiceInvokedByThisFirstBoot=False,CPUCoreAndVMConfigurationWholeUnchanged=True,onlyPresentationFlagsAndSSHDeferralConstantChanged=True,displayAndInputImplementationWholeUnchangedExceptExistingViewHiddenFlags=True,actualAppLinked=False,codeSigned=False,actualGuestStarted=False,actualVisibleGuest=False,actualSSHAuthenticated=False,deviceOperations=0,priorMetadataCandidateHistoricalOnly=pin(A/'candidate.json'))
save(P/'candidate.json',x)
rows=[pin(P/'candidate.json'),pin(__file__),pin(A/'candidate.json'),pin(A/'freeze.json')]+[exact(r)for r in json.loads((A/'freeze.json').read_bytes())['files']]
save(P/'freeze.json',dict(files=list({r['path']:r for r in rows}.values()),metadataOnlyFinalization=True,sourceBytesUnchanged=True,codeSigningOperations=0,deviceOperations=0))
y=copy.deepcopy(o);y.update(sourceCandidate=pin(P/'candidate.json'),priorCompiledCandidateHistoricalOnly=pin(B/'candidate.json'),metadataOnlyFinalization=True,sourceAndObjectBytesWholeUnchanged=True,preparer=pin(__file__))
save(Q/'candidate.json',y)
rows=[pin(Q/'candidate.json'),pin(__file__),pin(P/'candidate.json'),pin(P/'freeze.json'),pin(B/'candidate.json'),pin(B/'freeze.json')]+[exact(r)for r in json.loads((B/'freeze.json').read_bytes())['files']]
save(Q/'freeze.json',dict(files=list({r['path']:r for r in rows}.values()),metadataOnlyFinalization=True,sourceAndObjectBytesWholeUnchanged=True,compilations=0,codeSigningOperations=0,deviceOperations=0))
print(json.dumps(dict(sourceCandidate=pin(P/'candidate.json'),sourceFreeze=pin(P/'freeze.json'),compiledCandidate=pin(Q/'candidate.json'),compiledFreeze=pin(Q/'freeze.json'))))
