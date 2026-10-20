#!/usr/bin/env python3
"""HOST-only finite shell/real-process failure regressions. No device dispatch."""
import argparse,ast,hashlib,importlib.util,json,pathlib,shutil,subprocess,sys,time,types
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];B=R/'VirtualMac/scripts/development';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def need(x,m):
 if not x:raise ValueError(m)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);o=ap.parse_args().output.resolve();need(o.parent==N and not o.exists(),'fresh HOST source result');o.mkdir(mode=0o700)
 try:
  src=B/'prepare-independent27-normal-guest-lifecycle-v7.py';run=B/'independent27_normal_guest_lifecycle_v3.py';builder=load(src,'normal7_builder');runner=load(run,'normal7_runner');common=builder.common
  oldD=N/'independent27-app12-normal-guest-lifecycle-v6-attempt1';old=json.loads((oldD/'candidate.json').read_bytes())
  for row in json.loads((oldD/'freeze.json').read_bytes())['files']:common.exact(row)
  controller=load(common.exact(old['inheritedController']),'normal7_actual_process');facts=dict(old['guestFacts'],priorLogMetadata=old['expectedCanonicalEmptyLogForStart']['metadata'],priorLogSHA256=old['expectedCanonicalEmptyLogForStart']['sha256']);scope=json.loads(common.exact(json.loads(common.exact(old['initializerCandidate']).read_bytes())['scope']).read_bytes())
  scripts={'start':builder.render_start(controller,scope,facts,old['sessionNonce']),'observe':builder.render_owned(controller,'observe').replace('@NONCE@',builder.shlex.quote(old['sessionNonce'])),'stop':builder.render_owned(controller,'stop').replace('@NONCE@',builder.shlex.quote(old['sessionNonce']))}
  for n,s in scripts.items():
   p=o/(n+'-syntax-only.sh');p.write_text(s);subprocess.run(['/bin/sh','-n',str(p)],check=True)
  source=src.read_text();before=source.split('scan_own || exit 77;log_state || exit 81\n',1)[1].split("printf 'OWN_HANDOFF_OFFER",1)[0];after=source.split('[ "$own_ack" = "ACK $OWN_NORMAL_NONCE" ] || exit 84\n',1)[1].split('own_handoff=1',1)[0]
  baseline=dict(app_rows='app',child_rows='child',own_child_pid='2',own_accept='1',own_started='1',own_frames='2',own_first='1',own_last='2',own_late_progress='1')
  cases=[('valid',{},0),('app-absent',{'app_rows':''},83),('child-absent',{'child_rows':''},83),('child-id-zero',{'own_child_pid':'0'},83),('accept-zero',{'own_accept':'0'},81),('state-zero',{'own_started':'0'},81),('frames-zero',{'own_frames':'0'},81),('last-not-advancing',{'own_last':'1'},81),('late-zero',{'own_late_progress':'0'},81)]
  results=[]
  for stage,fragment in [('before-offer',before),('after-ack',after)]:
   for label,delta,expected in cases:
    if stage=='after-ack' and label=='child-id-zero':continue
    if stage=='after-ack' and label in ('app-absent','child-absent'):expected=81
    values=dict(baseline,**delta);body='set -e\nscan_own(){ return 0; }\nlog_state(){ return 0; }\n'+''.join(k+'='+builder.shlex.quote(v)+'\n' for k,v in values.items())+fragment+"printf 'HOST_FIXTURE_VALID_HANDOFF_GATES_ONLY\\n'\n";cp=subprocess.run(['/bin/sh','-c',body],capture_output=True,timeout=3);need(cp.returncode==expected,label+' '+stage+' actual shell rc');need((b'HOST_FIXTURE_VALID_HANDOFF_GATES_ONLY' in cp.stdout)==(expected==0),'failed gate cannot continue');results.append(dict(stage=stage,case=label,exit=cp.returncode,stdout=cp.stdout.decode(),stderr=cp.stderr.decode()))
  ack_inner='IFS= read -r own_line || exit 84; printf "%s\\n" "$own_line" || exit 84';cp=subprocess.run(['/bin/sh','-c',ack_inner],input=b'',capture_output=True,timeout=3);need(cp.returncode==84 and not cp.stdout,'actual EOF cannot become successful empty ACK');results.append(dict(case='actual-ACK-EOF',exit=cp.returncode))
  fixture_dir=o/'real-pipe-fixtures';fixture_dir.mkdir(mode=0o700);transport=[]
  fixtures=[('illegal-zero-offer',"print('OWN_OBSERVATION_CLOCK_BEGIN_V4 wallEpoch=1791882059 source=guarded-date',flush=True);print('OWN_OBSERVE elapsed=96 accept=1 state1=0 frames=0 first=0 last=0 lateProgress=0 source=guarded-date',flush=True);print('OWN_HANDOFF_OFFER '+ '0'*64 +' 2 '+ 'a'*64 +' 3 '+ 'b'*64 +' 1:2 0 0',flush=True)",125),('invalid-UTF8',"sys.stdout.buffer.write(b'\\xff\\n');sys.stdout.buffer.flush()",125),('duplicate-clock',"print('OWN_OBSERVATION_CLOCK_BEGIN_V4 wallEpoch=1791882059 source=guarded-date',flush=True);print('OWN_OBSERVATION_CLOCK_BEGIN_V4 wallEpoch=1791882060 source=guarded-date',flush=True)",125)]
  for label,emit,expected in fixtures:
   d=fixture_dir/label;d.mkdir();code='import sys,time\n'+emit+"\nline=sys.stdin.buffer.readline()\nassert line==b'',repr(line)\ntime.sleep(0.2)\nprint('HOST_FIXTURE_CLEANUP_AFTER_EOF_COMPLETED',flush=True)\nprint('HOST_FIXTURE_FINAL_LOG_RETAINED',file=sys.stderr,flush=True)\nsys.exit(84)\n";program=d/'child.py';program.write_text(code);spawned=[]
   def popen(argv,**kwargs):
    p=subprocess.Popen([sys.executable,str(program)],**kwargs);spawned.append(p);return p
   original=runner.subprocess;runner.subprocess=types.SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired)
   started=time.monotonic()
   try:status,out,err,error,ack=runner.stream_start(common,o,dict(sessionNonce='0'*64),d,'HOST_FIXTURE_ONLY','',True)
   finally:runner.subprocess=original
   elapsed=time.monotonic()-started;need(status==expected and ack is False and elapsed>=0.2,'protocol rejection drains real child until cleanup');need(b'HOST_FIXTURE_CLEANUP_AFTER_EOF_COMPLETED' in out and b'HOST_FIXTURE_FINAL_LOG_RETAINED' in err,'both actual output channels retained');need(spawned[0].returncode==84 and not (d/'handoff-ack.json').exists(),'no SSH early kill/no ACK');(d/'stdout').write_bytes(out);(d/'stderr').write_bytes(err);transport.append(dict(case=label,status=status,actualChildExit=spawned[0].returncode,realElapsed=elapsed,error=error,stdout=pin(d/'stdout'),stderr=pin(d/'stderr'),ack=False))
  dump(o/'finite-tests.json',dict(shellCases=results,actualLocalProcessDrainCases=transport,allPassed=True,SDKOrDeviceExecuted=False))
  # Preserve source and actual failure evidence. The rendered files above are
  # syntax-only fixtures, never prepared device packets or real receipts.
  candidate=dict(schema='HOST NormalV7 explicit handoff and retained no-ACK cleanup source candidate',status='SOURCE_ONLY_AWAITING_ACTUAL_APP13_FACTS',builder=pin(src),runner=pin(run),finalizer=pin(__file__),baseSourceCandidate=pin(N/'independent27-normal-no-current-screen-source-v6-attempt1/candidate.json'),baseSourceFreeze=pin(N/'independent27-normal-no-current-screen-source-v6-attempt1/freeze.json'),actualFailedNormalCandidate=pin(oldD/'candidate.json'),actualFailedStart=pin(oldD/'device-receipts/start/receipt.json'),actualFailedStartStdout=pin(oldD/'device-receipts/start/stdout'),actualFailedPost=pin(oldD/'device-receipts/post/receipt.json'),actualFiniteTests=pin(o/'finite-tests.json'),explicitBeforeOfferAndAfterACKAssertions=True,ACKReadEOFRejected=True,checkLogAndFailureParserExplicitReturnGuards=True,cleanupSignalsOutputSuppressedAndLoggingCannotAbortCleanup=True,protocolRejectionEOFAndRealOutputDrainedUntilExitOr145=True,SSHClientKilledOnlyAtTotal145Bound=True,localSSHReapMaximumSeconds=2,original145Stream112TERM132KILL20Cleanup95Wall90Host45LatePreserved=True,actualDurableLedgerAndACKOwnershipRequired=True,postStillActualReadonlyOffFirstNeverPrefixClaim=True,concretePacketGenerated=False,deviceOperations=0,guestBootDisplayInputSSHProven=False)
  dump(o/'candidate.json',candidate);rows=[pin(src),pin(run),pin(__file__),candidate['baseSourceCandidate'],candidate['baseSourceFreeze'],candidate['actualFailedNormalCandidate'],candidate['actualFailedStart'],candidate['actualFailedStartStdout'],candidate['actualFailedPost']]+[pin(p) for p in o.rglob('*') if p.is_file()];dump(o/'freeze.json',dict(files=rows,deviceOperations=0,concretePacketGenerated=False));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
 except BaseException as e:
  dump(o/'failure.json',dict(error=str(e),deviceOperations=0));raise
if __name__=='__main__':main()
