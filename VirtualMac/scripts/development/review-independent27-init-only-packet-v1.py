#!/usr/bin/env python3
"""HOST-only finite review of the exact installed-products init-only packet."""
import argparse, ast, hashlib, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def need(v, message):
    if not v: raise ValueError(message)

def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def actual(row):
    need(pin(row['path']) == {k:row[k] for k in ('path','bytes','sha256')}, 'exact pin: '+row['path'])
    return pathlib.Path(row['path'])

def function(text, name):
    return ast.get_source_segment(text, next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name))

def constant(text, name):
    n=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    return ast.literal_eval(n.value)

def main():
    a=argparse.ArgumentParser();a.add_argument('--candidate',type=pathlib.Path,required=True);a.add_argument('--output',type=pathlib.Path,required=True);a=a.parse_args()
    out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh independent peer directory')
    c=json.loads(a.candidate.read_bytes()); freeze=a.candidate.parent/'freeze.json'
    for row in json.loads(freeze.read_bytes())['files']:actual(row)
    s=json.loads(actual(c['scope']).read_bytes());old=json.loads(actual(s['oldScope']).read_bytes())
    need(c['actions']==['preflight','launch','post'] and c['actualChangedFiles']==c['actualNewTrustEntries']==0,'three init-only actions; no delta/trust')
    need('archive' not in c and 'archive' not in s and s['deltaFiles']==[] and s['newTrustCacheCDHashes']==[] and s['trustCacheFixedBatchCounts']==[] and s['trustCacheRegistrationCount']==0,'no actual archive/update/trust lane')
    need(s['files']==old['files'] and s['directories']==old['directories'] and s['trustCacheCDHashes']==old['trustCacheCDHashes'] and len(s['files'])==253 and len(set(s['trustCacheCDHashes']))==140,'same actual installed 253 files/140CD verification inventory')
    need(c['runtimeCandidate']==s['runtimeCandidate']==old['runtimeCandidate'] and c['appCandidate']==s['appCandidate']==old['appCandidate'],'unchanged product identities')
    need(s['actualRuntimeManifestFiles']==149 and c['appRegistrationRepeated'] is False and s['productUpdatesPerformed'] is False and s['productInstallationPerformed'] is False,'149 manifest; no repeat registration or installation')
    post=json.loads(actual(c['currentInstalledProductsPost']).read_bytes());req=json.loads(actual(post['request']).read_bytes());post_stdout=actual(post['stdout']).read_text();actual(post['stderr'])
    prior_candidate=a.candidate.parent.parent/'independent27-owned-platform-device-v1-attempt1/candidate.json'
    need(post['transportExit']==0 and req['packetCandidate']==pin(prior_candidate),'real current prior post0 from installed-products packet')
    for token in ['INDEPENDENT27_OWN_APP_AND_CHILD_OFF','INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT','INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED','OWN_RETAINED_LOG_BYTES 2341','OWN_RETAINED_LOG_SHA256 f6d6da2e5fb14f3fe6fcb71c44fe06eb904f34e621b7f8dc6ac3ede64a2f2a48']:
        need(token in post_stdout,'actual prior post proof: '+token)
    need(s['retainedCurrentLog']==dict(bytes=2341,sha256='f6d6da2e5fb14f3fe6fcb71c44fe06eb904f34e621b7f8dc6ac3ede64a2f2a48'),'exact retained log contract')
    launch=json.loads(actual(s['priorInitializationLaunch']).read_bytes());previous_stdout=actual(launch['stdout']).read_text();actual(launch['request']);actual(launch['stderr'])
    need(launch['transportExit']==1 and 'OWN_ACTUAL_RUNTIME_RESULT [Independent27] runtime-startup result=1' in previous_stdout and previous_stdout.count('VM27 owned platform launchPrepared=1 sandboxProfileApplied=0 nativeSandboxApplyUnavailable=45 nativeLastDiagnosticErrno=45 policyDeferred=1 trustedGuestOwnedProcess=1')==1,'retain real failed controller race; no invented prior init0')
    control=actual(c['controller']).read_text();prior=actual(c['priorController']).read_text()
    unchanged={k:function(control,k)==function(prior,k) for k in ['run_remote','prior_receipt']}
    process=constant(control,'PROCESS_FUNCTIONS');need(all(unchanged.values()) and process==constant(prior,'PROCESS_FUNCTIONS'),'actual process identity cleanup and transport unchanged')
    need(constant(control,'ACTIONS')==('preflight','launch','post') and constant(control,'TRUST_ACTIONS')==(),'actual no trust/update dispatch actions')
    ready=function(control,'ready_gate');dispatch=function(control,'dispatch')
    for token in ['controllerPacketCandidate','specificUserAuthorization','derivedFromContinuingDirectHumanAuthorization','initializationOnly','newTrustCacheCDHashes','currentInstalledProductsPost']:
        need(token in ready,'ready exact human/current peer/current post: '+token)
    need("previous = {'launch': 'preflight', 'post': 'launch'}.get(args.action)" in dispatch and "success=args.action != 'post'" in dispatch,'exact serial predecessors; post allowed after failed launch')
    need('O_EXCL' in dispatch and 'serial action never repeated' in dispatch and "data = b''" in dispatch and "register.sh" not in dispatch,'exclusive once; no archive/registration dispatch')
    scripts={k:actual(v).read_text() for k,v in c['scripts'].items()}
    for k,text in scripts.items():
        need(subprocess.run(['/bin/sh','-n'],input=text.encode(),capture_output=True).returncode==0,'syntax only: '+k)
        command=('sudo -k -S -p "" ' if k!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(text)
        need(len(command.encode())==c['quotedCommandBytes'][k] and len(command.encode())+10000<262144,'true quoted ARGMAX bound: '+k)
        need('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c ' in text,'actual external45 wall bound: '+k)
        need('jbctl trustcache add' not in text and 'uicache ' not in text and 'mv -' not in text,'no installation or trust command: '+k)
        need('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in text,'full real products checked: '+k)
    need(c['maximumQuotedCommandBytes']==216075 and c['transportTimeoutSeconds']==55,'maximum216075 +10000 reserve / SSH55')
    pre=shlex.split(scripts['preflight'])[-1];body=shlex.split(scripts['launch'])[-1]
    need('backup-app-log' in pre and 'init-preflight-complete' in pre and '0:0:700' in pre and '501:501:600:1:2341' in pre,'new own-stage backups retained log before launch')
    inode=body.index('own_prior_log_inode=');truncate=body.index(': > "$OWN_LOG"',inode)
    need('f6d6da2e5fb14f3fe6fcb71c44fe06eb904f34e621b7f8dc6ac3ede64a2f2a48' in body[:truncate] and '[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_prior_log_inode" ]' in body[truncate:],'verify old log then truncate exact existing inode')
    readiness=actual(c['readinessLoop']).read_text();start=body.index('own_wait=0\nown_result=none\n');stop=body.index('own_accept_count=',start)
    need(body[start:stop]==readiness and c['readinessStableParentChildSeconds']==2,'actual exact new stable readiness body')
    for token in ['scan_own','own_stable_seconds=0','own_stable_identity=none','[ -n "$app_rows" ] && [ -n "$child_rows" ]','own_identity="$own_app_pid:$own_app_start:$own_child_pid:$own_child_start"','own_stable_seconds=$((own_stable_seconds+1))','own_stable_identity=$own_identity;own_stable_seconds=0','sleep 1;own_wait=$((own_wait+1))','[ "$own_stable_seconds" -ge 2 ]','OWN_PARENT_CHILD_PREPARED_STABLE_SECONDS 2']:
        need(token in readiness,'real repeated stable identity sampling: '+token)
    need(readiness.count('break;')==1 and 'if [ "$own_stable_seconds" -ge 2 ]; then break;fi' in readiness and 'break' not in readiness[:readiness.index('own_prepared_count=')],'result alone cannot break readiness loop')
    need(readiness.count('ps -p ')==2 and '^[ZTX]' in readiness and '"$own_child_pid"' in readiness and '"$own_app_pid"' in readiness,'current same parent/child nondead process samples')
    for token in ['parent-hello install-factory status=0 nativeDetailsAvailable=0','child-prepare status=0 pid=','ppid=','uid=501 euid=501 acquiredOwnerReturned=1 helloReturned=1','launchPrepared=1 sandboxProfileApplied=0 nativeSandboxApplyUnavailable=45']:
        need(token in readiness,'exact true real marker, no invented native success: '+token)
    need(process.strip() in body and 'cleanup_own\nown_cleanup_done=1' in body and 'trap ' in body,'unchanged exact cleanup remains armed')
    old_launch=shlex.split((actual(c['priorController']).parent/'launch.sh').read_text())[-1].replace(old['deviceStage'],s['deviceStage'])
    a0=old_launch.index('own_wait=0\nown_result=none\n');a1=old_launch.index('own_accept_count=',a0)
    need(body[stop:]==old_launch[a1:],'readiness successful tail and cleanup wholebytes unchanged')
    need(scripts['post']==(actual(c['priorController']).parent/'post.sh').read_text().replace(old['deviceStage'],s['deviceStage']),'post exact original body with only owned stage path changed')
    need(s['sandboxProfileApplied'] is False and s['nativeSandboxApplyUnavailable']==45 and s['nativeSandboxInitSuccessFabricated'] is False and s['guestBootRequested'] is False,'explicit deferred isolation; no guest start or fake native success')
    out.mkdir(mode=0o700)
    report=dict(schema='Independent installed-products init-only packet finite peer v1',controllerPacketCandidate=pin(a.candidate),packetFreeze=pin(freeze),actualScope=c['scope'],currentInstalledProductsPost=c['currentInstalledProductsPost'],priorInitializationRaceReceipt=s['priorInitializationLaunch'],actualCompleteFiles=253,actualFullCDVerificationInventory=140,actualRuntimeManifestRows=149,productUpdates=0,newTrustEntries=0,appRegistrationRepeated=False,retainedCurrentLog=s['retainedCurrentLog'],sameLogInodeTruncationAfterExactPriorHash=True,exactProcessIdentityAndCleanupWholebytesUnchanged=True,exactTransportAndPriorFunctionsUnchanged=unchanged,readinessRequiresRealResultPreparationHelloAndExactChildPrepare=True,readinessRequiresThreeSameIdentityObservationsWithTwoOneSecondSleeps=True,readinessRequiresCurrentNondeadParentChild=True,oldResultOnlyBreakRemoved=True,postCleanupTailWholebytesUnchanged=True,exclusiveThreeActionSequence=True,remoteWallSeconds=45,SSHTimeoutSeconds=55,actualMaximumQuotedBytes=216075,actualARGMAX=262144,reservedEnvironmentBytes=10000,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,futureInitializationSuccessNotInvented=True,deviceOperations=0,trustCacheOperations=0,guestBootRequested=False,guestSSHVerified=False,findings=[],finiteLocalScopePassed=True)
    (out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    rows=[pin(__file__),pin(a.candidate),pin(freeze),c['scope'],c['controller'],c['preparer'],c['priorController'],c['currentInstalledProductsPost'],post['request'],post['stdout'],post['stderr'],s['priorInitializationLaunch'],launch['request'],launch['stdout'],launch['stderr'],c['readinessLoop'],c['continuingHumanAuthorization']]+list(c['scripts'].values())+[pin(out/'review.json')]
    (out/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),findings=[])))

if __name__=='__main__':main()
