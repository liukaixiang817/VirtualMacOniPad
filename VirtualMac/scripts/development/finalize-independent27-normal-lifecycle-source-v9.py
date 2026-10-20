#!/usr/bin/env python3
"""HOST only: exact newline fix and genuine nested shell syntax regressions."""
import argparse,ast,difflib,hashlib,importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
import vm27_normal_nested_shell_syntax_v1 as syntax

def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def dump(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def need(x,m):
 if not x:raise ValueError(m)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);o=ap.parse_args().output.resolve();need(o.parent==N and not o.exists(),'new syntax-only output');o.mkdir(mode=0o700)
 oldD=N/'independent27-app13-normal-guest-lifecycle-v8-attempt1';old=json.loads((oldD/'candidate.json').read_bytes());src=B/'prepare-independent27-normal-guest-lifecycle-v9.py';previous=B/'prepare-independent27-normal-guest-lifecycle-v8.py';runner=B/'independent27_normal_guest_lifecycle_v3.py'
 expected=previous.read_text().replace('\n}'+"'''",'\n}\n'+"'''").replace("packet v8'","packet v9'");need(expected==src.read_text(),'only one executing newline and schema delta')
 for row in json.loads((oldD/'freeze.json').read_bytes())['files']:need(pin(row['path'])==row,'actual old frozen input '+row['path'])
 start_failure=json.loads((oldD/'device-receipts/start/receipt.json').read_bytes());need(start_failure['transportExit']==2 and start_failure['handoffACKAttemptRecorded'] is False,'actual syntax2/noACK failure');need('expecting "}"' in pathlib.Path(start_failure['stderr']['path']).read_text(),'actual native syntax diagnosis retained');need(json.loads((oldD/'device-receipts/post/receipt.json').read_bytes())['transportExit']==0,'actual independent post0')
 m=load(src,'normal9_builder');ctrl=load(old['inheritedController']['path'],'normal9_actual_controller');init=json.loads(pathlib.Path(old['initializerCandidate']['path']).read_bytes());scope=json.loads(pathlib.Path(init['scope']['path']).read_bytes());facts=dict(old['guestFacts'],priorLogMetadata=old['expectedCanonicalEmptyLogForStart']['metadata'],priorLogSHA256=old['expectedCanonicalEmptyLogForStart']['sha256']);nonce=old['sessionNonce']
 scripts=dict(preflight=(oldD/'preflight.sh').read_text(),start=m.render_start(ctrl,scope,facts,nonce),observe=m.render_owned(ctrl,'observe').replace('@NONCE@',m.shlex.quote(nonce)),stop=m.render_owned(ctrl,'stop').replace('@NONCE@',m.shlex.quote(nonce)),post=(oldD/'post.sh').read_text());actual_cleanup=syntax.cleanup_literal(scripts['start']);need(actual_cleanup==m.cleanup_body_v4(ctrl),'actual assignment equals generated exact cleanup body')
 checks=[];negative=[]
 for name,body in scripts.items():
  d=o/('new-'+name);d.mkdir();rows=syntax.check_tree(name,body,d,actual_cleanup);need(all(row['exit']==0 for row in rows),'all real nested shell parses '+name);checks.extend(rows)
 for name in ('start','observe','stop'):
  d=o/('old-failure-'+name);d.mkdir();rows=syntax.check_tree('old-'+name,(oldD/(name+'.sh')).read_text(),d,actual_cleanup);need(any(row['depth']>0 and row['exit']==2 for row in rows),'actual old nested syntax fails '+name);negative.extend(rows)
 dump(o/'nested-syntax.json',dict(newFiveScriptsAllNestedPassed=True,actualNodes=checks,oldThreeInnerFailuresReproduced=True,negativeNodes=negative,sharedUnusedCleanupLiteralIsExactStartAssignment=True,deviceCommandsExecuted=False))
 (o/'v8-to-v9.diff').write_text(''.join(difflib.unified_diff(previous.read_text().splitlines(True),src.read_text().splitlines(True),fromfile=str(previous),tofile=str(src))))
 c=dict(schema='HOST NormalV9 actual nested shell syntax newline repair',status='SOURCE_ONLY_AWAITING_ACTUAL_FRESH_APP13_FACTS',builder=pin(src),runner=pin(runner),finalizer=pin(__file__),nestedSyntaxVerifier=pin(syntax.__file__),baseSourceCandidate=pin(N/'independent27-normal-owned-live-handoff-source-v8-attempt1/candidate.json'),baseSourceFreeze=pin(N/'independent27-normal-owned-live-handoff-source-v8-attempt1/freeze.json'),actualFailedNormalCandidate=pin(oldD/'candidate.json'),actualFailedStart=pin(oldD/'device-receipts/start/receipt.json'),actualFailedStartStderr=pin(oldD/'device-receipts/start/stderr'),actualIndependentPost=pin(oldD/'device-receipts/post/receipt.json'),sourceDiff=pin(o/'v8-to-v9.diff'),actualNestedSyntax=pin(o/'nested-syntax.json'),onlyExecutingDeltaFunctionBoundaryNewline=True,allFiveOuterAndActualInnerBodiesParsed=True,actualStaticCleanupAndACKReadAndCloseBodiesParsed=True,oldStartObserveStopInnerSyntax2Reproduced=True,noOldGateOrPipeModelsRerun=True,runnerWholeUnchanged=True,concretePacketGenerated=False,deviceOperations=0,guestBootDisplayInputSSHProven=False);dump(o/'candidate.json',c);rows=[pin(p) for p in o.rglob('*') if p.is_file()]+[pin(src),pin(runner),pin(previous),pin(__file__),pin(syntax.__file__),c['baseSourceCandidate'],c['baseSourceFreeze'],c['actualFailedNormalCandidate'],c['actualFailedStart'],c['actualFailedStartStderr'],c['actualIndependentPost']];dump(o/'freeze.json',dict(files=rows,deviceOperations=0,concretePacketGenerated=False));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),newNestedNodeCount=len(checks),oldNestedNodeCount=len(negative))))
if __name__=='__main__':main()
