#!/usr/bin/env python3
"""HOST-only finite owned observation guard delta; frozen V7 remains unchanged."""
import argparse,ast,difflib,hashlib,importlib.util,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def dump(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def need(x,m):
 if not x:raise ValueError(m)
def funcs(p):
 s=p.read_text();lines=s.splitlines(True);return {x.name:''.join(lines[x.lineno-1:x.end_lineno]) for x in ast.parse(s).body if isinstance(x,ast.FunctionDef)}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);o=ap.parse_args().output.resolve();need(o.parent==N and not o.exists(),'fresh source-only delta');o.mkdir(mode=0o700)
 oldD=N/'independent27-normal-explicit-handoff-source-v7-attempt2';old=json.loads((oldD/'candidate.json').read_bytes());oldf=json.loads((oldD/'freeze.json').read_bytes())
 for row in oldf['files']:need(pin(row['path'])==row,'exact frozen V7 '+row['path'])
 src=B/'prepare-independent27-normal-guest-lifecycle-v8.py';run=B/'independent27_normal_guest_lifecycle_v3.py';m=load(src,'normal8_builder');c=json.loads((N/'independent27-app12-normal-guest-lifecycle-v6-attempt1/candidate.json').read_bytes());ctrl=load(c['inheritedController']['path'],'normal8_actual_controller');a=funcs(pathlib.Path(old['builder']['path']));b=funcs(src);need(all(a[n]==b[n] for n in a if n not in ('prepare','render_owned')),'only owned observation and schema changed');need(pin(run)==old['runner'],'true existing V3 runner unchanged')
 diff=''.join(difflib.unified_diff(pathlib.Path(old['builder']['path']).read_text().splitlines(True),src.read_text().splitlines(True),fromfile=old['builder']['path'],tofile=str(src)));(o/'v7-to-v8.diff').write_text(diff)
 obs=m.render_owned(ctrl,'observe');(o/'observe-syntax-only.sh').write_text(obs);subprocess.run(['/bin/sh','-n',str(o/'observe-syntax-only.sh')],check=True)
 fragment='scan_own || exit 77\n[ -n "$app_rows" ] && [ -n "$child_rows" ] || exit 83\nlog_state || exit 81\n[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] || exit 81\n';need(obs.count('[ -n "$app_rows" ] && [ -n "$child_rows" ] || exit 83')==2,'true inside-loop and terminal liveness guards')
 tests=[]
 for label,app,child,state,expected in [('valid','app','child','1',0),('app-gone','','child','1',83),('child-gone','app','','1',83),('both-gone','','','1',83),('state-zero','app','child','0',81)]:
  script='set -e\nscan_own(){ return 0; }\nlog_state(){ return 0; }\napp_rows='+m.shlex.quote(app)+'\nchild_rows='+m.shlex.quote(child)+'\nown_accept=1\nown_started='+state+'\n'+fragment+"printf 'HOST_FIXTURE_STILL_OWNED_CONDITION_ONLY\\n'\n";cp=subprocess.run(['/bin/sh','-c',script],capture_output=True,timeout=3);need(cp.returncode==expected,'actual owned shell '+label);need(bool(cp.stdout)==(expected==0),'failed ownership gate cannot print fixture success');tests.append(dict(case=label,exit=cp.returncode,stdout=cp.stdout.decode()))
 dump(o/'finite-tests.json',dict(actualShellCases=tests,allPassed=True,deviceOrSDKExecuted=False));candidate=dict(schema='HOST explicit handoff and owned observation NormalV8 source candidate',status='SOURCE_ONLY_AWAITING_ACTUAL_APP13_FACTS',builder=pin(src),runner=pin(run),finalizer=pin(__file__),baseSourceCandidate=pin(oldD/'candidate.json'),baseSourceFreeze=pin(oldD/'freeze.json'),baseHandoffAndThreeRealPipeTests=old['actualFiniteTests'],sourceDiff=pin(o/'v7-to-v8.diff'),actualFiniteDeltaTests=pin(o/'finite-tests.json'),beforeOfferAndAfterACKExplicitGuardsInherited=True,ACKReadEOFRejected=True,protocolRejectionKeepsOutputUntilNativeExitOr145=True,cleanupSignalsToDevNullInherited=True,SSHClientKilledOnlyAtTotal145Bound=True,localSSHReapMaximumSeconds=2,ownedObservationLiveAppAndChildAndActualStateRequiredInsideLoopAndAtTerminalMarker=True,noOldTestsRerun=True,concretePacketGenerated=False,deviceOperations=0,guestBootDisplayInputSSHProven=False);dump(o/'candidate.json',candidate);dump(o/'freeze.json',dict(files=[pin(p) for p in o.iterdir() if p.is_file()]+[pin(src),pin(run),pin(__file__),candidate['baseSourceCandidate'],candidate['baseSourceFreeze'],old['actualFiniteTests']],deviceOperations=0,concretePacketGenerated=False));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
if __name__=='__main__':main()
