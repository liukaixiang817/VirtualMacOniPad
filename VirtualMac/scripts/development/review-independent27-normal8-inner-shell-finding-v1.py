#!/usr/bin/env python3
"""Preserve actual inner-shell residual failure; syntax only, no device execution."""
import hashlib,json,pathlib,shlex,subprocess
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 p=N/'independent27-app13-normal-guest-lifecycle-v8-attempt1';cp=p/'candidate.json';c=json.loads(cp.read_bytes());o=N/'normal-v8-actual-inner-shell-independent-finding-v1-attempt1';o.mkdir(mode=0o700)
 results=[];rows=[pin(__file__),pin(cp),pin(p/'freeze.json'),c['builder'],c['controller']]
 for action,r in c['actions'].items():
  t=pathlib.Path(r['path']).read_text();outer=subprocess.run(['/bin/sh','-n'],input=t.encode(),capture_output=True)
  at=t.index('/var/jb/bin/sh -c ',t.index('/var/jb/usr/bin/timeout'))+len('/var/jb/bin/sh -c ');lexer=shlex.shlex(t[at:],posix=True);lexer.whitespace_split=True;inner=next(iter(lexer))
  innerp=o/(action+'-actual-inner.sh');innerp.write_text(inner);check=subprocess.run(['/bin/sh','-n'],input=inner.encode(),capture_output=True)
  (o/(action+'-inner-stderr')).write_bytes(check.stderr);results.append(dict(action=action,actualOuterSyntaxExit=outer.returncode,actualInnerSyntaxExit=check.returncode,inner=pin(innerp),stderr=pin(o/(action+'-inner-stderr'))));rows+=[r,pin(innerp),pin(o/(action+'-inner-stderr'))]
  if action=='start':
   assignment=next(x for x in shlex.split(inner)if x.startswith('OWN_EXACT_CLEANUP_V4='));cleanup=assignment.split('=',1)[1];cr=subprocess.run(['/bin/sh','-n'],input=cleanup.encode(),capture_output=True);assert cr.returncode==0
   (o/'nested-cleanup-actual-inner.sh').write_text(cleanup);rows.append(pin(o/'nested-cleanup-actual-inner.sh'))
   assert 'exit "$own_status"\n}trap finish_normal EXIT\n'in inner
 assert {r['action']:r['actualInnerSyntaxExit']for r in results}==dict(preflight=0,start=2,observe=2,stop=2,post=0)
 startp=p/'device-receipts/start/receipt.json';start=json.loads(startp.read_bytes());assert start['transportExit']==2
 rows+=[pin(startp),start['request'],start['stdout'],start['stderr']]
 peers=[N/'independent27-normal-v8-explicit-live-source-independent-peer-v1-attempt1/review.json',N/'independent27-app13-normal-v8-concrete-peer-finalization-v1-attempt1/review.json'];rows += [pin(x)for x in peers]
 report=dict(schema='Actual NormalV8 missing inner-shell parser independent finding v1',normalPacketCandidate=pin(cp),actualStartFailure=pin(startp),actualSyntaxResults=results,nestedExactCleanupSyntaxExit=0,priorOuterSyntaxChecksDoNotProveQuotedInnerParser=True,priorRecipeWholeEqualityCouldReproduceSameSyntaxError=True,priorPeerClaimsRequireThisCorrection=[pin(x)for x in peers],requiredNextReview='Parse actual outer scripts, every quoted sh -c body, and dynamic OWN_EXACT_CLEANUP_V4 separately before dispatch',actualGuestCPUStartupProven=False,deviceOperations=0,findings=[dict(id='NORMAL8-LOG-FUNCTION-TRAILING-NEWLINE-INNER-SYNTAX',priority='P1',detail='LOG_FUNCTIONS closes with } without a trailing newline; concatenation creates }trap or }scan_own. The actual inner start/observe/stop programs fail /bin/sh -n with exit2 while the outer programs parse. Previous finite PASS did not cover this inner-parser boundary.')],finiteLocalScopePassed=False)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows.append(pin(rp));fp=o/'freeze.json';fp.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(fp))))
if __name__=='__main__':main()
