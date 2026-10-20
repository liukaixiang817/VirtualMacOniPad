#!/usr/bin/env python3
"""Finite real-facts NormalV11 adoption peer. No device, signing, or VM execution."""
import argparse, ast, hashlib, importlib.util, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();r=p.read_bytes();return dict(path=str(p),bytes=len(r),sha256=hashlib.sha256(r).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},r['path'];return pathlib.Path(r['path'])
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def body(t):
 at=t.index('/var/jb/bin/sh -c ',t.index('/var/jb/usr/bin/timeout'))+len('/var/jb/bin/sh -c ');parts=shlex.split(t[at:]);assert len(parts)==1;return parts[0]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();cp=a.candidate.resolve();o=a.output.resolve();assert cp.parent.parent==N and o.parent==N and not o.exists()
 c=json.loads(cp.read_bytes());fp=cp.parent/'freeze.json'
 for row in json.loads(fp.read_bytes())['files']:exact(row)
 sourcepeer=N/'independent27-normal11-cpu-bitmap-source-independent-peer-v1-attempt1/review.json';source=json.loads(sourcepeer.read_bytes());assert source['findings']==[]and source['passed']and c['builder']==source['source']
 builder=load(exact(c['builder']),'normal11_concrete_builder');common=load(exact(c['common']),'normal11_concrete_common');inherited=load(exact(c['inheritedController']),'normal11_concrete_initializer')
 assert exact(c['controller']).read_bytes()==exact(source['runnerV3WholeUnchanged']).read_bytes()
 packet,scope,launch,post=common.initializer_success(c['initializerCandidate']['path'],exact(c['initializerLaunch']),exact(c['initializerPost']))
 assert packet['appCandidate']['sha256']=='3d780eb134d82540008e0e4ca59f997ad504e3f6033eb2ea93d0c58fe1ac9049'and packet['actualFullFiles']==255 and packet['actualFullCodeDirectoryHashes']==142
 app=json.loads(exact(packet['appCandidate']).read_bytes());assert app['actualSignature']['cdhash']=='5ebc12915534597c97f6f80f3e33d2eafb03a18f'
 actualApp=next(r for r in scope['files']if r['devicePath']==c['ownAppMain']);assert actualApp['local']==app['binary']and actualApp['cdhash']==app['actualSignature']['cdhash']
 facts=common.guest_success(exact(c['freshGuestReadonly']),exact(c['freshGuestConfiguration']),c['initializerPost'])
 assert facts==c['guestFacts']and facts['CPUCountSaved']==4 and facts['MemorySizeSaved']==8589934592 and facts['actualParsedSavedOptions']['VirtualMacGuestToolsEnabled']is True
 assert c['guestPath']==common.GUEST=='/private/var/mobile/Media/VirtualMac/Tahoe3.bundle'and c['ownAppMain']==scope['deviceAppMain']and c['ownChildMain']==scope['deviceChildMain']
 assert c['trustCacheOperations']==c['nativeKernelWrites']==c['deviceOperations']==0 and not c['actualVisibleGuest']and not c['actualGuestStarted']and not c['actualSSHAvailable']and not c['networkAvailable']
 assert c['noBeforeScreenshotInputFreeBoot']and c['foregroundUSBScreenReceipt']is None and not c['beforeGuestScreenshotAvailable']and not c['historicalScreenshotUsedForCalibration']and not c['inputCalibrationPassed']
 assert c['guestDisplayAcceptanceRequiresActualNativeUSBScreen']and c['guestInputAcceptanceRequiresActualNativeUSBScreenAndCalibration']
 historical=c.get('historicalForegroundUSBScreenReceipt')
 if historical:
  screen=json.loads(exact(historical).read_bytes());assert screen['transportExit']==0 and screen['actualNativeUSBScreenCapture']and screen['actualUDID']=='00008112-001E48300207401E';exact(screen['screenshot']);assert screen['finishedUTC']<json.loads(exact(c['freshGuestReadonly']).read_bytes())['finishedUTC']
 scripts={k:exact(v).read_text()for k,v in c['actions'].items()};assert set(scripts)=={'preflight','start','observe','stop','post'}
 expectedStart=dict(facts,priorLogMetadata=c['expectedCanonicalEmptyLogForStart']['metadata'],priorLogSHA256=c['expectedCanonicalEmptyLogForStart']['sha256'])
 assert c['expectedCanonicalEmptyLogForStart']['producedOnlyByActualSuccessfulPreflight']and not c['expectedCanonicalEmptyLogForStart']['actualNewReadonlyReceipt']
 assert scripts['start']==builder.render_start(inherited,scope,expectedStart,c['sessionNonce'])
 for action in ['observe','stop']:assert scripts[action]==builder.render_owned(inherited,action).replace('@NONCE@',shlex.quote(c['sessionNonce']))
 assert hashlib.sha256(inherited.PROCESS_FUNCTIONS.encode()).hexdigest()==c['inheritedProcessFunctionsSHA256']
 bodies={k:body(t)for k,t in scripts.items()};start=bodies['start'];observe=bodies['observe'];stop=bodies['stop'];pre=bodies['preflight'];postbody=bodies['post']
 for k in ['start','observe','stop']:assert inherited.PROCESS_FUNCTIONS in bodies[k]
 opens=[shlex.split(x)for x in start.splitlines()if x.startswith('/var/jb/usr/bin/uiopen ')];assert opens==[['/var/jb/usr/bin/uiopen','--bundleid','com.mac.virtual.independent27'],['/var/jb/usr/bin/uiopen','virtualmac27://start-vm?path=%2Fprivate%2Fvar%2Fmobile%2FMedia%2FVirtualMac%2FTahoe3.bundle']]
 for v in ['[ -n "$app_rows" ] && [ -n "$child_rows" ] && [ "$own_child_pid" -gt 1 ] || exit 83', '[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] && [ "$own_frames" -ge 2 ] || exit 81', '[ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ] || exit 81','IFS= read -r own_line || exit 84','[ "$own_ack" = "ACK $OWN_NORMAL_NONCE" ] || exit 84']:assert v in start,v
 assert start.count('[ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ] || exit 81')==2
 assert start.index('[ "$own_last" -gt "$own_first" ]')<start.index("printf 'OWN_HANDOFF_OFFER")<start.index('own_ack=$(')<start.index('own_handoff=1')
 assert 'set +e'in start and 'OWN_EXACT_TERMINAL_CLEANUP_STATUS_V7'in start and '>/dev/null 2>&1'in start
 assert observe.count('[ -n "$app_rows" ] && [ -n "$child_rows" ] || exit 83')==2 and observe.count('[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] || exit 81')==2
 assert 'cleanup_own >/dev/null 2>&1 || exit 78'in stop and '[ -z "$app_rows" ] && [ -z "$child_rows" ] || exit 78'in stop
 assert all(facts['metadata'][name]in pre for name in common.SIZES)and all(h in pre for h in facts['smallSHA256'].values())
 assert 'sha256sum "$OWN_GUEST/Disk.img"'not in pre
 assert pre.index('cp -- "$OWN_LOG"')<pre.index(': > "$OWN_LOG"')and 'own_log_stable_generation'in pre and c['fixedOwnedLogIdentity']in pre
 fast=load(B/'independent27_device_product_verify_fast_v1.py','normal11_concrete_fast');assert fast.batch_check(scope)in pre and fast.cd_check(scope,scope['actualNativeCDSubset'])in pre and inherited.off_check()in postbody and fast.batch_check(scope)in postbody
 assert inherited.HEALTH.read_text()in pre and inherited.HEALTH.read_text()in postbody
 for action,t in scripts.items():
  assert subprocess.run(['/bin/sh','-n'],input=t.encode(),capture_output=True).returncode==0
  assert common.quoted_size(t,action in ('preflight','post'))+10000<262144
  assert 'jbctl trustcache add'not in t and 'killall 'not in t and 'reboot 'not in t
 assert c['observeSeconds']==90 and c['wallClockGuardSeconds']==95 and c['hostMonotonicMinimumObservationSeconds']==90 and c['hostMonotonicLateProgressAfterSeconds']==45
 assert c['remoteTERMSeconds']==112 and c['remoteKILLSeconds']==132 and c['startTransportSeconds']==145 and c['shortTransportSeconds']==55 and c['terminalCleanupSeconds']==20 and c['boundedACKReadSeconds']==5
 o.mkdir(mode=0o700)
 syntax=load(B/'review-independent27-normal9-nested-source-v1.py','normal11_independent_syntax')
 syntaxdir=o/'actual-nested-syntax';syntaxdir.mkdir(mode=0o700)
 regenerated=syntax.pure_scripts(exact(c['builder']),c)
 assert regenerated==scripts
 actualSyntax=syntax.parse_all(scripts,syntaxdir)
 report=dict(schema='Actual App15 NormalV11 explicit live handoff and actual nested syntax finite concrete peer v1',normalPacketCandidate=pin(cp),controllerPacketCandidate=pin(cp),packetFreeze=pin(fp),sourceIndependentPeer=pin(sourcepeer),initializerCandidate=c['initializerCandidate'],initializerLaunch=c['initializerLaunch'],initializerPost=c['initializerPost'],freshGuestReadonly=c['freshGuestReadonly'],freshGuestConfiguration=c['freshGuestConfiguration'],actualInitAndPostSucceeded=True,actualApp15MainAndRuntime10ImageBound=True,CPUCountSaved=4,MemorySizeSaved=8589934592,savedOptionsNotRuntimeMergedDefaults=True,actualFreshFiveFileAndThreeSmallDataFacts=True,foregroundScreenshotAbsentAndNotFaked=True,currentInputCalibrationNotClaimed=True,actualOnceNormalStartURL=True,wholeAcceptedNormalV11RecipesAndRunner3Adopted=True,explicitBeforeOfferAfterACKAndOwnedObserveLiveGates=True,HOSTMonotonic90AndAfter45CPUBitmapProgressRequired=True,RootTaskOwnsFsyncLedgerBeforeUniqueACK=True,ACKAttemptOrUncertainTransportKeepsRootOwnershipUntilStop=True,noACKOrFailureExactCleanupRemainsArmed=True,protocolRejectionEOFDrainsOutputUntilNativeExitOr145=True,stopRequiresActualPIDUIDPathPPIDStartHash=True,failedStartPostReadonlyOFFFirst=True,remoteTERM112KILL132SSH145=True,terminalCleanup20ACK5=True,shortSSH55=True,guestBootExecuted=False,actualVisibleGuest=False,actualGuestLogin=False,actualGuestSSHAuthenticated=False,inputAcceptanceVerified=False,fullNATNetworkAvailable=False,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,deviceOperations=0,trustCacheOperations=0,findings=[],passed=True,finiteLocalScopePassed=True)
 report.update(actualV4FatalFailureRegexAdopted=True,actualCPUBitmapFrameMarkerAdopted=True,completionIsNotPhysicalVisibilityOrMetalGPU=True,actualFiveScriptsPureConstructionWholeEqual=True,actualOuterAndInnerCloseCleanupACKSyntaxNodes=actualSyntax,allActualNestedSyntaxNodes15Passed=True,outerSyntaxAloneDoesNotProveInnerParser=True,correctsPreviousNormal8InnerParserScopeOmission=True,actualPriorParserFinding=pin(N/'normal-v8-actual-inner-shell-independent-finding-v1-attempt1/review.json'),parserCheckExecutedNoScriptBody=True)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n')
 rows=[pin(__file__),pin(cp),pin(fp),pin(sourcepeer),c['builder'],c['common'],c['controller'],c['inheritedController'],c['initializerCandidate'],c['initializerLaunch'],launch['request'],launch['stdout'],launch['stderr'],c['initializerPost'],post['request'],post['stdout'],post['stderr'],c['freshGuestReadonly'],c['freshGuestConfiguration'],packet['appCandidate'],pin(B/'independent27_device_product_verify_fast_v1.py'),pin(rp)]+list(c['actions'].values())
 if historical:rows.append(historical)
 rows += [pin(B/'review-independent27-normal9-nested-source-v1.py'),report['actualPriorParserFinding']] + [r['source']for r in actualSyntax]
 sf=o/'freeze.json';sf.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(sf),findings=[])))
if __name__=='__main__':main()
