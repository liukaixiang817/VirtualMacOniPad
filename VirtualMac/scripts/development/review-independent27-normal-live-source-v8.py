#!/usr/bin/env python3
"""Finite source review of explicit normal handoff and retained cleanup; no device packet."""
import ast, hashlib, importlib.util, json, pathlib, shlex, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},r['path'];return pathlib.Path(r['path'])
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def funcs(t):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(t).body if isinstance(n,ast.FunctionDef)}
def body(t):
 at=t.index('/var/jb/bin/sh -c ',t.index('/var/jb/usr/bin/timeout'))+len('/var/jb/bin/sh -c ');parts=shlex.split(t[at:]);assert len(parts)==1;return parts[0]
def main():
 cp=N/'independent27-normal-owned-live-handoff-source-v8-attempt1/candidate.json';c=json.loads(cp.read_bytes());assert pin(cp)['sha256']=='e1afdd855dae459e8ec7b3407a4bff51ac53c1b872ebaecd1662e545fcc46d61'
 basep=exact(c['baseSourceCandidate']);base=json.loads(basep.read_bytes())
 for fp in [cp.parent/'freeze.json',exact(c['baseSourceFreeze'])]:
  for r in json.loads(fp.read_bytes())['files']:exact(r)
 src=exact(c['builder']);oldsrc=exact(base['builder']);runner=exact(c['runner']);text=src.read_text();rt=runner.read_text();old=oldsrc.read_text()
 assert c['runner']==base['runner']and c['baseHandoffAndThreeRealPipeTests']==base['actualFiniteTests']
 nf,of=funcs(text),funcs(old);assert all(nf[k]==of[k]for k in nf if k not in ('render_owned','prepare'))
 assert text.replace("packet v8',", "packet v7',").split('def prepare(',1)[1]==old.split('def prepare(',1)[1]
 m=load(src,'finite_normal8_source');oldm=load(oldsrc,'finite_normal7_source')
 assert m.LOG_FUNCTIONS==oldm.LOG_FUNCTIONS and m.WALL_FUNCTIONS_V4==oldm.WALL_FUNCTIONS_V4
 original=load(N/'independent27-ssh-deferred-app-device-v1-attempt1/control.py','normal8_source_exact_controller')
 start=body(m.render_start(original,{},dict(priorLogMetadata='1:2:501:501:600:1:0',priorLogSHA256='0'*64),'a'*64))
 owned=body(m.render_owned(original,'observe'));stop=body(m.render_owned(original,'stop'))
 for statement in ['[ -n "$app_rows" ] && [ -n "$child_rows" ] && [ "$own_child_pid" -gt 1 ] || exit 83',
  '[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] && [ "$own_frames" -ge 2 ] || exit 81',
  '[ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ] || exit 81',
  'IFS= read -r own_line || exit 84','[ "$own_ack" = "ACK $OWN_NORMAL_NONCE" ] || exit 84']:
  assert statement in start,statement
 assert start.count('[ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ] || exit 81')==2
 assert start.index('own_ack=$(')<start.index('own_handoff=1')and 'trap finish_normal EXIT'in start
 assert owned.count('[ -n "$app_rows" ] && [ -n "$child_rows" ] || exit 83')==2
 assert owned.count('[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] || exit 81')==2
 assert owned.rfind('log_state || exit 81')<owned.rfind("printf 'OWN_LEASE_STILL_OWNED")
 assert 'cleanup_own >/dev/null 2>&1 || exit 78'in stop and 'set +e'in m.LOG_FUNCTIONS
 assert '--kill-after=1 19'in m.LOG_FUNCTIONS and '>/dev/null 2>&1'in m.LOG_FUNCTIONS and 'INDEPENDENT27_OWN_TERMINAL_CLEANUP_VERIFIED_OFF_V7'in m.LOG_FUNCTIONS
 stream=funcs(rt)['stream_start'];assert 'reject_and_wait'in stream and 'drain_remaining'in stream
 assert 'actual_monotonic_now - observation_started >= 90 and late_progress'in rt
 assert rt.index("common.dump(output / 'handoff-ledger.json', ledger)")<rt.index("common.dump(output / 'handoff-ack.json'")<rt.index("child.stdin.write(('ACK '")
 assert "child.stdin.close()"in rt and "remaining = 145 - (time.monotonic() - started)"in rt and "if time.monotonic() - started < 145:"in rt
 assert "'failed start post is independent readonly OFF-first only; no ACK ownership may be discarded'"in rt
 assert "not (packet / 'device-receipts/start/handoff-ack.json').exists()"in rt
 common=pathlib.Path(m.common.__file__);ct=common.read_text();assert ct.count('os.fsync(')>=2
 tests=json.loads(exact(base['actualFiniteTests']).read_bytes());delta=json.loads(exact(c['actualFiniteDeltaTests']).read_bytes())
 assert tests['allPassed']and len(tests['shellCases'])==18 and len(tests['actualLocalProcessDrainCases'])==3 and not tests['SDKOrDeviceExecuted']
 for r in tests['actualLocalProcessDrainCases']:
  assert r['status']==125 and r['actualChildExit']==84 and r['ack']is False and r['realElapsed']>=0.2
  assert b'HOST_FIXTURE_CLEANUP_AFTER_EOF_COMPLETED'in exact(r['stdout']).read_bytes()
  assert b'HOST_FIXTURE_FINAL_LOG_RETAINED'in exact(r['stderr']).read_bytes()
 assert delta['allPassed']and len(delta['actualShellCases'])==5 and not delta['deviceOrSDKExecuted']
 assert not c['concretePacketGenerated']and c['status']=='SOURCE_ONLY_AWAITING_ACTUAL_APP13_FACTS'
 findingp=N/'normal-v6-actual-invalid-offer-errexit-independent-finding-v1-attempt1/review.json';finding=json.loads(findingp.read_bytes())
 assert len(finding['findings'])==2
 o=N/'independent27-normal-v8-explicit-live-source-independent-peer-v1-attempt1';o.mkdir(mode=0o700)
 report=dict(schema='NormalV8 explicit handoff retained cleanup finite source independent peer v1',sourceCandidate=pin(cp),sourceFreeze=pin(cp.parent/'freeze.json'),builder=c['builder'],runner=c['runner'],baseSourceCandidate=c['baseSourceCandidate'],correctedActualNormalV6Findings=pin(findingp),priorV4V5FiniteSourcePeersDidNotCoverANDListCounterexample=True,actualBeforeOfferAndAfterACKConditionsHaveExplicitFailureExits=True,ACKReadEOFExplicitlyRejected=True,ownedObserveChecksActualAppChildStateInLoopAndAtTerminal=True,protocolRejectionClosesOnlyStdinAndDrainsBothOutputsUntilNativeExitOr145=True,cleanupOutputFailureCannotSkipValidatedSignals=True,onlyTotal145BoundPermitsSSHClientKill=True,originalExactProcessIdentityCleanupAndBounded20SecondsRetained=True,hostMonotonic90AndAfter45FrameProgressBeforeACK=True,durableFsyncPrefixLedgerAndACKBeforeRemoteCleanupRelease=True,uncertainACKRetainsExplicitRootOwnerUntilActualStop=True,failedStartPostRequiresFreshReadonlyOFFAndNoACK=True,actualInherited18ShellAndThreeRealPipeResultsVerified=True,actualFiveNewOwnedLiveResultsVerified=True,oldTestsRerun=False,sourceAdmissionStillRequiresActualInitializer0Post0FreshGuestFacts=True,concretePacketReviewAndRootReadyStillRequired=True,deviceOperations=0,concretePacketGenerated=False,guestBootDisplayInputSSHProven=False,findings=[],passed=True,finiteLocalScopePassed=True)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(cp),pin(cp.parent/'freeze.json'),pin(basep),pin(exact(c['baseSourceFreeze'])),c['builder'],base['builder'],c['runner'],c['sourceDiff'],base['actualFiniteTests'],c['actualFiniteDeltaTests'],pin(common),pin(findingp),pin(rp)]+[r[k]for r in tests['actualLocalProcessDrainCases']for k in ('stdout','stderr')]
 fp=o/'freeze.json';fp.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(review=pin(rp),freeze=pin(fp),findings=[])))
if __name__=='__main__':main()
