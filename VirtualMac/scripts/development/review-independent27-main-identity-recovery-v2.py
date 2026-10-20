#!/usr/bin/env python3
"""Short same-scope recovery delta review; read-only, no device/model calls."""
import argparse,ast,hashlib,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();assert o.parent==N and not o.exists();o.mkdir();checks=[];pins={}
 def check(ok,label):
  checks.append(dict(check=label,passed=bool(ok)))
  if not ok:raise AssertionError(label)
 packet=N/'independent27-main-identity-recovery-v2-attempt1';old=N/'independent27-main-identity-device-v1-attempt1'
 c=json.loads((packet/'candidate.json').read_bytes())
 check(pin(packet/'candidate.json')['sha256']=='b0855d62895df52d8320e2e633af97a0341a1c0afcf0fc404c23e14d0ec7083f','actual requested recovery candidate')
 for row in json.loads((packet/'freeze.json').read_bytes())['files']:
  check(pin(row['path'])==row,'actual frozen pin '+row['path']);pins[row['path']]=row
 check((packet/'scope.json').read_bytes()==(old/'scope.json').read_bytes(),'actual authorized206855B scope identical')
 check((packet/'products.tar').read_bytes()==(old/'products.tar').read_bytes(),'actual eight-file archive identical')
 check(c['authorizedOriginalScope']==pin(old/'scope.json') and c['scope']['sha256']==c['authorizedOriginalScope']['sha256']=='43de06e492a450fc3f939f645231b7ae42011850c9900a08fd4deb38439a31de','exact original human authorization scope ancestry')
 for action in ['preflight','stage','verify','trust','launch','register','post']:
  check((packet/(action+'.sh')).read_bytes()==(old/(action+'.sh')).read_bytes(),'all seven original action script bytes unchanged '+action)
 oldText=(old/'control.py').read_text();newText=(packet/'control.py').read_text()
 oldTree=ast.parse(oldText);newTree=ast.parse(newText)
 funcs=lambda t:{x.name:ast.dump(x,include_attributes=False)for x in t.body if isinstance(x,ast.FunctionDef)}
 assignments=lambda t:{x.targets[0].id:ast.literal_eval(x.value)for x in t.body if isinstance(x,ast.Assign)and len(x.targets)==1 and isinstance(x.targets[0],ast.Name)and x.targets[0].id=='PROCESS_FUNCTIONS'}
 check(assignments(oldTree)==assignments(newTree),'original owned process cleanup function bytes identical')
 for name in ['run_remote','prior_receipt']:
  check(funcs(oldTree)[name]==funcs(newTree)[name],'transport/receipt exact AST retained '+name)
 expected=oldText.replace("ACTIONS = ('preflight', 'stage', 'verify', 'trust', 'launch', 'post')", "ACTIONS = ('close-reopened', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')")
 expected=expected.replace("auth['scope'] == pin(packet/'scope.json') and", "auth['scope'] == json.loads((packet/'candidate.json').read_bytes())['authorizedOriginalScope'] and\n         pin(packet/'scope.json')['sha256'] == auth['scope']['sha256'] and pin(packet/'scope.json')['bytes'] == auth['scope']['bytes'] and")
 expected=expected.replace("previous = {'stage': 'preflight'", "previous = {'preflight': 'close-reopened', 'stage': 'preflight'")
 check(expected==newText,'controller only new action/predecessor and same authorized scope comparison delta')
 for required in ["auth.get('humanUserAuthorization') is True","auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']","auth['trustCacheRegistrationCount'] == 5","review.get('controllerPacketCandidate') == pin(packet/'candidate.json')","need(not output.exists(), 'serial action never repeated')"]:
  check(required in newText,'unchanged concrete authorization/once gate '+required)
 readonly=json.loads(pathlib.Path(c['actualOwnAppReadonlySnapshot']['path']).read_bytes())
 failure=json.loads(pathlib.Path(c['priorActualPreflightFailure']['path']).read_bytes())
 check(readonly['transportExit']==0 and failure['transportExit']==8,'actual readonly success and old preflight8 kept')
 output=pathlib.Path(readonly['stdout']['path']).read_text();scope=json.loads((packet/'scope.json').read_bytes())
 identity='90350 1 501 0546501f976260f13090eb6feb86c2bb104f27b8e6e0e2551eca9ad402ea75a9'
 check('OWN_APP_ID '+identity+' '+scope['deviceAppMain'] in output and 'OWN_CHILD_ID ' not in output,'actual own PID UID PPID startHash path and no observed child')
 script=(packet/'close-reopened.sh').read_text();body=shlex.split(script)[-1]
 process=assignments(newTree)['PROCESS_FUNCTIONS'];check(process in body,'close uses exactly original independently reviewed identity/signal guards')
 first=body.index('own_app_pid=90350');tail=body[first:]
 for line in ['own_app_start=0546501f976260f13090eb6feb86c2bb104f27b8e6e0e2551eca9ad402ea75a9','scan_own\n[ "$own_child_pid" = 0 ]','501:501:755:1:869696','0d621fdffa11d3298575ee66c8f1776c0c930c18cfa473dc232da831b1a860bc','[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]']:
  check(line in tail and tail.index(line)<tail.index('cleanup_own\n'),'exact identity/old binary/no child checks before own signal '+line)
 check(tail.index('16777220:47302916:501:501:600:1:671')>tail.index('cleanup_own\n')and'80a2d77b0daa3fcd615e7ce62a482bcc311efb9e52a3464d8f93cc3a706413cb'in tail,'actual old log inode671/SHA retained after cleanup')
 for line in ['[ "$1" = "$own_app_pid" ] && [ "$own_now_start" = "$own_app_start" ]','[ "$#" = 4 ] && [ "$1" = "$own_pid" ] && [ "$3" = 501 ] && [ "$4" = "$own_path" ]','[ "$(start_hash "$own_pid")" = "$own_start" ]','signal_own TERM "$own_app_pid"','signal_own KILL "$own_app_pid"']:
  check(line in process,'exact inherited PID reuse/UID/path/start guarded TERM/KILL '+line)
 check(script.count('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 ')==1,'close external20s plus3kill grace')
 syntax=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);check(syntax.returncode==0,'actual close shell syntax')
 quote='sudo -k -S -p "" /var/jb/bin/sh -c '+shlex.quote(script)
 check(len(quote.encode())==c['quotedCommandBytes']['close-reopened']==7127 and c['maximumQuotedCommandBytes']+10000<262144,'bounded real argument sizes')
 check(not any(x in tail for x in ['jbctl','killall','pkill','cp ','mv ','chown','chmod',': >']), 'close has no trust/install/log writes or broad process kill')
 oldPeer=N/'independent27-main-identity-device-peer-v1-attempt3/review.json';p=json.loads(oldPeer.read_bytes())
 check(p['findings']==[] and p['controllerPacketCandidate']==pin(old/'candidate.json'),'original full packet peer evidence inherited without repeated source/signature/CPU tests')
 report=dict(schema='Same five-hash eight-file authorized recovery independent finite review v2',controllerPacketCandidate=pin(packet/'candidate.json'),
  finiteLocalScopePassed=True,findings=[],checks=checks,checkCount=len(checks),authorizedOriginalScope=pin(old/'scope.json'),
  identicalAuthorizedScopeAndDeltaArchive=True,allSevenOriginalActionsExactBytes=True,originalFullPacketReview=pin(oldPeer),
  actualReadonlySnapshot=c['actualOwnAppReadonlySnapshot'],oldFailedPreflight=c['priorActualPreflightFailure'],
  ownedPID=90350,ownedUID=501,ownedPPID=1,ownedStartHash=c['readonlyIdentifiedOwnPIDStartHash'],
  exactOldMainAndLogRetained=True,closeWallSeconds=20,originalActionsWallSeconds=45,newTrustEntries=5,
  deviceOperations=0,sourceModelsRepeated=False,signatureModelsRepeated=False,nativeVMOperations=0,guestBoot=False,
  cleanupBoundary='Initial live snapshot and pre-signal scan require no child. The inherited cleanup rescans and may clean a newly appeared genuine own direct child only under its unchanged PID/UID/path/PPID/startHash guards; it never captures a foreign process.',
  scope=['This is a new once-only recovery action chain; the failed original preflight remains exit8 and is never rerun or rewritten.',
   'Same original human scope authorization is required and its exact bytes/hash/count5 remain checked; this report grants no new authorization.'])
 save(o/'review.json',report)
 allpins=[pin(p)for p in o.rglob('*')if p.is_file()]+list(pins.values())+[pin(__file__),pin(packet/'freeze.json'),pin(oldPeer)]
 save(o/'freeze.json',dict(files=list({x['path']:x for x in allpins}.values())))
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=[],checks=len(checks))))
if __name__=='__main__':main()
