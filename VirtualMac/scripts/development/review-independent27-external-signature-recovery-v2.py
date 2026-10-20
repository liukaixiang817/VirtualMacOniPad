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
 packet=N/'independent27-external-signature-recovery-v2-attempt1';old=N/'independent27-external-signature-device-v1-attempt1'
 c=json.loads((packet/'candidate.json').read_bytes())
 check(pin(packet/'candidate.json')['sha256']=='1718d8508efdf016da4814de269a37b595b330b670a7af92b874c252ce351d6e','actual requested recovery candidate')
 # Only this new recovery delta is parsed. The original full product peer is inherited below.
 for name in ['candidate.json','freeze.json','scope.json','products.tar','control.py','close-reopened.sh']:
  path=packet/name;pins[str(path)]=pin(path)
 for row in [c['preparer'],c['priorCandidate'],c['authorizedOriginalScope'],c['scope'],c['archive'],c['controller'],*c['scripts'].values(),c['priorActualPreflightFailure'],c['actualOwnAppReadonlySnapshot']]:
  check(pin(row['path'])==row,'exact recovery delta pin '+row['path']);pins[row['path']]=row
 check((packet/'scope.json').read_bytes()==(old/'scope.json').read_bytes(),'actual authorized208371B scope identical')
 check((packet/'products.tar').read_bytes()==(old/'products.tar').read_bytes(),'actual nine-file archive identical')
 check(c['authorizedOriginalScope']==pin(old/'scope.json') and c['scope']['sha256']==c['authorizedOriginalScope']['sha256']=='c326228d990335f39f01411a41b61e4ff6fe560582355a6adac246a3355fe02b','exact original human authorization scope ancestry')
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
 for required in ["auth.get('humanUserAuthorization') is True","auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']","auth['trustCacheRegistrationCount'] == 6","review.get('controllerPacketCandidate') == pin(packet/'candidate.json')","need(not output.exists(), 'serial action never repeated')"]:
  check(required in newText,'unchanged concrete authorization/once gate '+required)
 readonly=json.loads(pathlib.Path(c['actualOwnAppReadonlySnapshot']['path']).read_bytes())
 failure=json.loads(pathlib.Path(c['priorActualPreflightFailure']['path']).read_bytes())
 check(readonly['transportExit']==0 and failure['transportExit']==8,'actual readonly success and old preflight8 kept')
 check(readonly['deviceWrites']==0 and readonly['processSignals']==0,'actual readonly observation did not signal or write')
 authpath=N/'independent27-external-signature-user-authorized-v1/authorization.json';auth=json.loads(authpath.read_bytes())
 check(pin(authpath)['sha256']=='4f3d7af3f8d16f70ee1aa95669a0ce08bd6424d81ff6656f9f790592001737ca' and auth['scope']==pin(old/'scope.json') and auth['humanUserAuthorization'] and auth['authorized'] and auth['trustCacheRegistrationCount']==6,'actual existing six-entry human authorization unchanged')
 pins[str(authpath)]=pin(authpath)
 for record in [readonly,failure]:
  for name in ['stdout','stderr']:
   row=record[name];check(pin(row['path'])==row,'actual captured immutable receipt output '+name);pins[row['path']]=row
 check(not any((old/(action+'-dispatched.json')).exists()for action in('stage','trust','launch')),'original failed preflight performed no product writes trust or launch')
 output=pathlib.Path(readonly['stdout']['path']).read_text();scope=json.loads((packet/'scope.json').read_bytes())
 identity='91431 1 501 3cde1b76a3d3abe85c5b87597ea8af5d4a81792c79817425bf0119094784c789'
 check('OWN_APP_ID '+identity+' '+scope['deviceAppMain'] in output and 'OWN_CHILD_ID ' not in output,'actual own PID UID PPID startHash path and no observed child')
 script=(packet/'close-reopened.sh').read_text();body=shlex.split(script)[-1]
 process=assignments(newTree)['PROCESS_FUNCTIONS'];check(process in body,'close uses exactly original independently reviewed identity/signal guards')
 first=body.index('own_app_pid=91431');tail=body[first:]
 for line in ['own_app_start=3cde1b76a3d3abe85c5b87597ea8af5d4a81792c79817425bf0119094784c789','scan_own\n[ "$own_child_pid" = 0 ]','501:501:755:1:870288','586eec6115501e8331ac76fde31e802401217aa30346a9f829437b888fa8106a','[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]']:
  check(line in tail and tail.index(line)<tail.index('cleanup_own\n'),'exact identity/old binary/no child checks before own signal '+line)
 check(tail.index('16777220:47302916:501:501:600:1:751')>tail.index('cleanup_own\n')and'f3a4328f1791518149bd06c7f9086d1b06d0ce6f648f8665bdd35fd97395caf0'in tail,'actual old log inode751/SHA retained after cleanup')
 for line in ['[ "$1" = "$own_app_pid" ] && [ "$own_now_start" = "$own_app_start" ]','[ "$#" = 4 ] && [ "$1" = "$own_pid" ] && [ "$3" = 501 ] && [ "$4" = "$own_path" ]','[ "$(start_hash "$own_pid")" = "$own_start" ]','signal_own TERM "$own_app_pid"','signal_own KILL "$own_app_pid"']:
  check(line in process,'exact inherited PID reuse/UID/path/start guarded TERM/KILL '+line)
 check(script.count('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 ')==1,'close external20s plus3kill grace')
 syntax=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);check(syntax.returncode==0,'actual close shell syntax')
 quote='sudo -k -S -p "" /var/jb/bin/sh -c '+shlex.quote(script)
 check(len(quote.encode())==c['quotedCommandBytes']['close-reopened']==7137 and c['maximumQuotedCommandBytes']+10000<262144,'bounded real argument sizes')
 check(not any(x in tail for x in ['jbctl','killall','pkill','cp ','mv ','chown','chmod',': >']), 'close has no trust/install/log writes or broad process kill')
 oldPeer=N/'independent27-external-signature-composition-peer-v1-attempt1/review.json';p=json.loads(oldPeer.read_bytes())
 check(p['findings']==[] and p['controllerPacketCandidate']==pin(old/'candidate.json'),'original full packet peer evidence inherited without repeated source/signature/CPU tests')
 report=dict(schema='Same six-hash nine-file authorized recovery independent finite review v2',controllerPacketCandidate=pin(packet/'candidate.json'),
  finiteLocalScopePassed=True,findings=[],checks=checks,checkCount=len(checks),authorizedOriginalScope=pin(old/'scope.json'),
  identicalAuthorizedScopeAndDeltaArchive=True,allSevenOriginalActionsExactBytes=True,originalFullPacketReview=pin(oldPeer),
  actualReadonlySnapshot=c['actualOwnAppReadonlySnapshot'],oldFailedPreflight=c['priorActualPreflightFailure'],
  ownedPID=91431,ownedUID=501,ownedPPID=1,ownedStartHash=c['readonlyIdentifiedOwnPIDStartHash'],
  exactOldMainAndLogRetained=True,closeWallSeconds=20,originalActionsWallSeconds=45,newTrustEntries=6,
  deviceOperations=0,sourceModelsRepeated=False,signatureModelsRepeated=False,nativeVMOperations=0,guestBoot=False,
  cleanupBoundary='Initial live snapshot and pre-signal scan require no child. The inherited cleanup rescans and may clean a newly appeared genuine own direct child only under its unchanged PID/UID/path/PPID/startHash guards; it never captures a foreign process.',
  scope=['This is a new once-only recovery action chain; the failed original preflight remains exit8 and is never rerun or rewritten.',
   'Same original human scope authorization is required and its exact bytes/hash/count6 remain checked; this report grants no new authorization.'])
 save(o/'review.json',report)
 allpins=[pin(p)for p in o.rglob('*')if p.is_file()]+list(pins.values())+[pin(__file__),pin(packet/'freeze.json'),pin(oldPeer)]
 save(o/'freeze.json',dict(files=list({x['path']:x for x in allpins}.values())))
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=[],checks=len(checks))))
if __name__=='__main__':main()
