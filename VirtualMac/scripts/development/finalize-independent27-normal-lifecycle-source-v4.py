#!/usr/bin/env python3
"""HOST-only normal lifecycle V4 source freeze; no concrete packet or dispatch."""
import ast,difflib,hashlib,importlib.util,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];B=R/'VirtualMac/scripts/development';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'independent27-normal-lifecycle-elapsed-source-v4-attempt1'
def pin(p):p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def load(p,name):sp=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def main():
 assert not O.exists();O.mkdir(mode=0o700)
 try:
  builder=B/'prepare-independent27-normal-guest-lifecycle-v4.py';runner=B/'independent27_normal_guest_lifecycle_v2.py';old=B/'prepare-independent27-normal-guest-lifecycle-v3.py';oldrunner=B/'independent27_normal_guest_lifecycle_v1.py'
  for p in (builder,runner):compile(p.read_text(),str(p),'exec')
  v4=load(builder,'normal_source_v4');controller=load(N/'independent27-uikit-filter-init-recovery-v1-attempt1/control.py','normal_source_old_controller');host=load(runner,'normal_source_new_runner')
  base=N/'independent27-uikit-filter-recovery-normal-guest-lifecycle-v3-attempt1';j=json.loads((base/'candidate.json').read_bytes())
  script=v4.render_start(controller,{},dict(priorLogMetadata='16777219:47534875:501:501:600:1:0',priorLogSHA256=hashlib.sha256(b'').hexdigest()),'1'*64)
  scripts={'start':script,'observe':v4.render_owned(controller,'observe'),'stop':v4.render_owned(controller,'stop'),'cleanup':v4.cleanup_body_v4(controller)}
  syntax=[]
  for name,text in scripts.items():
   path=O/(name+'-source-template.sh');path.write_text(text);cp=subprocess.run(['/bin/sh','-n',str(path)],capture_output=True);assert cp.returncode==0;syntax.append(dict(template=pin(path),exit=0))
  # HOST-only clock fixtures substitute the absolute date command in an isolated
  # extracted clock function. No product includes a fixture path or fallback.
  functions=v4.WALL_FUNCTIONS_V4.replace('[ -x /var/jb/usr/bin/date ] || return 82',': # HOST-only clock fixture').replace('/var/jb/usr/bin/date +%s','fixture_date_v4')
  cases=[('elapsed-overhead',[1791878976,1791878976,1791878980,1791878984,1791878996,1791879014,1791879022,1791879026,1791879045,1791879063,1791879067],0),('backward',[1791878976,1791878980,1791878979],82),('forward-jump',[1791878976,1791878976+90],82),('invalid-native-number',[1791878976,'invalid'],82)]
  results=[]
  for name,values,want in cases:
   numbers=O/(name+'-clock-data');numbers.write_text('\n'.join(map(str,values))+'\n');index=O/(name+'-index');index.write_text('1\n')
   pre='fixture_date_v4() { i=$(cat '+str(index)+'); sed -n "${i}p" '+str(numbers)+'; echo "$((i+1))" > '+str(index)+'; }\n'
   body='set -eu\n'+pre+functions+'\nwall_init_v4\n'
   body+='for step in '+ ' '.join(str(i) for i in range(len(values)-1))+'; do wall_tick_v4 || exit $?; done\n'
   body+='printf "CLOCK_RESULT elapsed=%s\\n" "$own_elapsed"\n';path=O/(name+'-fixture.sh');path.write_text(body);cp=subprocess.run(['/bin/sh',str(path)],capture_output=True,timeout=5);assert cp.returncode==want
   if name=='elapsed-overhead':assert b'elapsed=91' in cp.stdout
   (O/(name+'.stdout')).write_bytes(cp.stdout);(O/(name+'.stderr')).write_bytes(cp.stderr);results.append(dict(name=name,exit=cp.returncode,expected=want,fixture=pin(path),stdout=pin(O/(name+'.stdout')),stderr=pin(O/(name+'.stderr'))))
  assert not host.offer_clock_valid_v4(None,True,1000)
  assert not host.offer_clock_valid_v4(100,True,189.99)
  assert not host.offer_clock_valid_v4(100,False,190)
  assert host.offer_clock_valid_v4(100,True,190)
  # The original prefix false-OFF actual failure is preserved as causal input.
  actual=N/'independent27-uikit-filter-recovery-normal-guest-lifecycle-v3-attempt1/device-receipts/start/receipt.json';ar=json.loads(actual.read_bytes());assert ar['transportExit']==137 and not ar['handoffACKAttemptRecorded'];raw=pathlib.Path(ar['stdout']['path']).read_text();assert raw.startswith('INDEPENDENT27_OWN_APP_AND_CHILD_OFF\n') and 'OWN_APP_ID 5873 ' in raw and 'OWN_SIGNAL TERM 5901 ' in raw
  date=N/'normal-v3-actual-own-log-readonly-v2-attempt1/receipt.json';dr=json.loads(date.read_bytes());assert dr['transportExit']==0;dt=pathlib.Path(dr['stdout']['path']).read_text();assert '/var/jb/usr/bin/date\n' in dt and 'OWN_ACTUAL_DATE_EPOCH 1791878976' in dt
  for row in (ar['stdout'],ar['stderr'],ar['request'],dr['stdout'],dr['stderr'],dr['request']):assert pin(row['path'])==row
  assert 'kill-after=20 112' in script and 'kill-after=1 19' in script and 'OWN_TERMINAL_CLEANUP_VERIFIED_OFF_V4' in script and 'OWN_OBSERVE elapsed=' in script and 'own_second=$((own_second+1))' not in script
  assert "'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in text and" not in runner.read_text()
  assert 'failed start post is independent readonly OFF-first' in runner.read_text() and 'actual host monotonic90s' in runner.read_text()
  for name,prior,current in [('builder',old,builder),('runner',oldrunner,runner)]:
   (O/(name+'-delta.diff')).write_text(''.join(difflib.unified_diff(prior.read_text().splitlines(True),current.read_text().splitlines(True),fromfile=str(prior),tofile=str(current))))
  candidate=dict(schema='Normal lifecycle elapsed and honest post source V4 candidate',status='SOURCE_ONLY_WAITING_ACTUAL_APP12_PREFLIGHT_FACTS',builder=pin(builder),runner=pin(runner),basePacketCandidate=pin(base/'candidate.json'),actualPriorStartFailure=pin(actual),actualPriorPost=pin(base/'device-receipts/post/receipt.json'),actualDateReadOnlyReceipt=pin(date),clockSource='actual /var/jb/usr/bin/date guarded wall seconds; not monotonic',observationTargetSeconds=90,integerWallThresholdSeconds=91,hostMonotonic90AndAfter45FrameProgressBeforeACK=True,remoteTERMSeconds=112,remoteKILLAfterTERMSeconds=20,remoteHardBoundSeconds=132,transportHardBoundSeconds=145,cleanupTERMSeconds=19,cleanupKillAfterSeconds=1,cleanupTotalSeconds=20,ackReadTERMSeconds=5,ackKillAfterSeconds=1,elapsedClockFixtures=results,hostOfferClockGuardChecks=4,shellSyntax=syntax,failedStartPostAdmission='no ACK, failed real start receipt; actual post freshly rejects any live own App/child before read-only product/health verification',noInitialOFFPrefixCleanupClaim=True,distinctActualTerminalCleanupMarker='INDEPENDENT27_OWN_TERMINAL_CLEANUP_VERIFIED_OFF_V4',publicLeaseAndACKImplementationPreserved=True,concretePacketGenerated=False,deviceOperations=0,trustCacheOperations=0,actualGuestStarted=False,actualVisibleGuest=False,actualSSHAvailable=False)
  dump(O/'candidate.json',candidate)
  pins=[pin(p) for p in sorted(O.iterdir()) if p.is_file()]+[pin(builder),pin(runner),pin(old),pin(oldrunner),pin(__file__),candidate['basePacketCandidate'],candidate['actualPriorStartFailure'],candidate['actualPriorPost'],candidate['actualDateReadOnlyReceipt']]+[ar[k] for k in ('stdout','stderr','request')]+[dr[k] for k in ('stdout','stderr','request')]
  dump(O/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(O/'candidate.json'),freeze=pin(O/'freeze.json'))))
 except BaseException as e:
  if not (O/'freeze.json').exists():dump(O/'failure.json',dict(error=str(e),deviceOperations=0))
  raise
if __name__=='__main__':main()
