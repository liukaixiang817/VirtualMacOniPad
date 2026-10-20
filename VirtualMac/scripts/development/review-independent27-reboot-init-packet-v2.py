#!/usr/bin/env python3
"""HOST-only finite review of actual reboot-session trust restoration/init."""
import argparse,ast,hashlib,json,pathlib,re,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(v):
 need(pin(v['path'])=={k:v[k]for k in ('path','bytes','sha256')},'actual pin '+v['path']);return pathlib.Path(v['path'])
def function(t,n):return ast.get_source_segment(t,next(v for v in ast.parse(t).body if isinstance(v,ast.FunctionDef)and v.name==n))
def constant(t,n):return ast.literal_eval(next(v for v in ast.parse(t).body if isinstance(v,ast.Assign)and any(isinstance(x,ast.Name)and x.id==n for x in v.targets)).value)
def main():
 a=argparse.ArgumentParser();a.add_argument('--candidate',type=pathlib.Path,required=True);a.add_argument('--output',type=pathlib.Path,required=True);a=a.parse_args();out=a.output.resolve()
 need(out.parent==N and not out.exists(),'fresh finite peer output');c=json.loads(a.candidate.read_bytes());fp=a.candidate.parent/'freeze.json'
 for v in json.loads(fp.read_bytes())['files']:actual(v)
 s=json.loads(actual(c['scope']).read_bytes());old=json.loads(actual(c['priorPacket']).parent.joinpath('scope.json').read_bytes())
 need(c['actions']==['close-current-own','preflight','restore-trust','launch','post']and c['actualChangedFiles']==0 and c['actualFullFiles']==253,'actual five phases; zero product change')
 need(s['files']==old['files']and s['directories']==old['directories']and s['trustCacheCDHashes']==old['trustCacheCDHashes']and s['deltaFiles']==[]and 'archive'not in c,'all253 installed rows unchanged/no archive')
 need(c['runtimeCandidate']==old['runtimeCandidate']and c['appCandidate']==old['appCandidate']and c['productUpdatesPerformed']is False and c['productInstallationPerformed']is False and c['appRegistrationRepeated']is False,'no product/compiler/signature/registration changes')
 facts=json.loads(actual(c['currentDeviceFacts']).read_bytes());ftext=actual(facts['stdout']).read_text();actual(facts['request']);actual(facts['stderr'])
 need(facts['transportExit']==0 and facts['readOnly']is True and facts['deviceWrites']==0 and 'BOOT_TIME { sec = 1791813884, usec = 70222 }'in ftext,'actual new boot readonly facts')
 need(re.findall(r'^OWN_CURRENT_PROCESS\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$',ftext,re.M)==[('1673','1','501',s['deviceAppMain'])]and 'OWN_CURRENT_ABSENT /tmp/VirtualMacIndependent27.log'in ftext,'actual current own App/no claimed log persistence')
 plan=json.loads(actual(c['currentBootTrustPlan']).read_bytes());query=json.loads(actual(plan['actualQueryReceipt']).read_bytes());actual(query['request']);actual(query['stderr']);qtext=actual(plan['actualQueryStdout']).read_text()
 need(query['transportExit']==0 and query['stdout']==plan['actualQueryStdout']and plan['bootSeconds']==c['bootSeconds']==s['bootSeconds']==1791813884,'same actual boot and successful native trust query')
 counts=re.findall(r'^OWN_TRUST_COUNT ([a-f0-9]{40}) ([0-9]+)$',qtext,re.M)
 need([h for h,n in counts]==plan['all140CDHashes']==s['trustCacheCDHashes']and len(counts)==140 and len(set(h for h,n in counts))==140,'all140 actual ordered query rows')
 need('OWN_TRUST_QUERY_SUMMARY headers=1 footers=1 nativeExit=0'in qtext and 'OWN_CURRENT_TRUST_READONLY_COMPLETE'in qtext and 'BOOT_TIME { sec = 1791813884,'in qtext,'complete genuine native trust query')
 present=[h for h,n in counts if int(n)>0];missing=[h for h,n in counts if int(n)==0]
 need(present==plan['presentCDHashes']==['e43846ee132f920ab8d6fdfb3adef64184368de6']and missing==plan['missingCDHashes']==s['newTrustCacheCDHashes']==c['restoredExistingProductCDHashes']and len(missing)==139,'exact139 missing own runtime subset; present App not added')
 need(s['trustCacheRegistrationCount']==c['actualNewTrustEntries']==139 and s['newProductCodeHashes']==[]and s['trustMembershipAssumedFromPriorBoot']is False,'trust restoration only; no new code or assumed persistence')
 control=actual(c['controller']).read_text();prior=actual(c['priorController']).read_text();process=constant(control,'PROCESS_FUNCTIONS')
 need(process==constant(prior,'PROCESS_FUNCTIONS')and all(function(control,k)==function(prior,k)for k in ['run_remote','prior_receipt']),'exact actual process/transport/once receipt helper inheritance')
 need(constant(control,'ACTIONS')==tuple(c['actions'])and constant(control,'TRUST_ACTIONS')==('restore-trust',),'one explicit trust restoration phase')
 ready=function(control,'ready_gate');dispatch=function(control,'dispatch')
 for token in ['controllerPacketCandidate','specificUserAuthorization','derivedFromContinuingDirectHumanAuthorization','currentBootTrustPlan','currentDeviceFacts','missingCDHashes','actualQueryStdout','1791813884']:
  need(token in ready,'exact ready actual auth/query/boot gate '+token)
 need("previous = {'preflight': 'close-current-own', 'restore-trust': 'preflight', 'launch': 'restore-trust', 'post': 'launch'}.get(args.action)"in dispatch and 'O_EXCL'in dispatch and 'serial action never repeated'in dispatch and "success=args.action != 'post'"in dispatch,'exact exclusive ordered once/failurepost')
 health=actual(c['health']).read_text();oldhealth=(N/'cpu-owned-gic-counter-controller-v2/health-root.sh').read_text()
 need(oldhealth.count('1791354846')==1 and health==oldhealth.replace('1791354846','1791813884'),'health only actual one boot constant changed')
 scripts={k:actual(v).read_text()for k,v in c['scripts'].items()};bodies={k:shlex.split(t)[-1]for k,t in scripts.items()}
 for k,t in scripts.items():
  need(subprocess.run(['/bin/sh','-n'],input=t.encode(),capture_output=True).returncode==0,'shell syntax only '+k)
  command=('sudo -k -S -p "" 'if k!='launch'else'')+'/var/jb/bin/sh -c '+shlex.quote(t)
  need(len(command.encode())==c['quotedCommandBytes'][k]and len(command.encode())+10000<262144,'actual quoted ARGMAX '+k)
  seconds=20 if k=='close-current-own' else 45
  need('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c 'in t and 'uicache 'not in t and 'mv -'not in t,'actual timeout/no install '+k)
 need(c['maximumQuotedCommandBytes']==242792 and c['transportTimeoutSeconds']==55,'actual max242792+10000 below262144/SSH55')
 close=bodies['close-current-own'];need(process.strip()in close and '[ "$own_app_pid" = 0 ] || [ "$own_app_pid" = 1673 ]'in close and 'scan_own\n'in close and 'cleanup_own\n'in close,'only actual captured current own App/direct child; exact revalidated signals')
 pre=bodies['preflight'];cdcalls=[shlex.split(line)[1:]for line in pre.splitlines()if line.startswith('verify_cd ')]
 expectedcd=[[next(row['devicePath']for row in s['files']if row.get('cdhash')==h),h]for h in s['trustCacheCDHashes']]
 need('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT'in pre and cdcalls==expectedcd and len(cdcalls)==140 and 'own_cd=$(ldid -h "$1" 2>&1)'in pre,'preflight actual253+each140 device CD checked before restoration')
 for token in ['[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]','mkdir -m 700 "$OWN_STAGE"','chown 0:0 "$OWN_STAGE"','cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"','own_prior_log_metadata','own_prior_log_hash','(umask 077; set -C; : > "$OWN_LOG")','chown 501:501 "$OWN_LOG"','chmod 600 "$OWN_LOG"','501:501:600:1:0','prior-app-log-absent']:
  need(token in pre,'safe own absent/existing log handling '+token)
 restore=bodies['restore-trust'];adds=[line.split()[-1]for line in restore.splitlines()if line.startswith('jbctl trustcache add ')]
 need(adds==missing and restore.count('own_actual_trust_info=$(jbctl trustcache info)')==2 and 'own_actual_present='in restore and 'length(v)==40'in restore,'exact139 adds and before/after real native membership')
 need(restore.index('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT')<restore.index('restore-trust-dispatched')<restore.index('jbctl trustcache add ')and '(umask 077; set -C; : > "$OWN_STAGE/restore-trust-dispatched")'in restore,'full253 and actual present-set gate before exclusive restore marker')
 need("[ \"$own_actual_present\" = '"+'\n'.join(sorted(s['trustCacheCDHashes']))+"' ]"in restore and '[ "$own_actual_present" = e43846ee132f920ab8d6fdfb3adef64184368de6 ]'in restore,'exact prior present1/after complete140; no blind subset')
 need(all('jbctl trustcache add'not in t for k,t in scripts.items()if k!='restore-trust')and 'trustcache clear'not in restore and 'trustcache remove'not in restore,'no other trust phase/global clear/remove')
 loop=actual(c['readinessLoop']).read_bytes();oldloop=actual(c['priorPacket']).parent.joinpath('readiness-loop.sh').read_bytes()
 need(loop==oldloop and loop.decode()in bodies['launch']and process.strip()in bodies['launch'],'stable2s actual marker/identity gate and exact cleanup body unchanged')
 need('own_prior_log_inode='in bodies['launch']and ': > "$OWN_LOG"'in bodies['launch']and '[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_prior_log_inode" ]'in bodies['launch'],'actual existing backed-up/new log inode retained through truncate')
 oldpost=actual(c['priorPacket']).parent.joinpath('post.sh').read_text();need(scripts['post']==oldpost.replace('1791354846','1791813884').replace(old['deviceStage'],s['deviceStage']),'post original accurate identities/final253/old6 cleanup only session constants changed')
 need(s['sandboxProfileApplied']is False and s['nativeSandboxApplyUnavailable']==45 and s['nativeSandboxInitSuccessFabricated']is False and s['guestBootRequested']is False,'honest deferred sandbox/no future init or guest claim')
 out.mkdir(mode=0o700);report=dict(schema='Independent actual reboot-session init packet finite peer v2',controllerPacketCandidate=pin(a.candidate),packetFreeze=pin(fp),scope=c['scope'],actualDeviceFacts=c['currentDeviceFacts'],actualTrustPlan=c['currentBootTrustPlan'],actualQueryReceipt=plan['actualQueryReceipt'],actualQueryStdout=plan['actualQueryStdout'],bootSeconds=1791813884,bootMicroseconds=70222,actualAllCDInventory=140,actualPresentAppCD=present,actualMissingRuntimeCDHashes=missing,trustRestorationCount=139,newProductCodeHashes=[],productUpdates=0,installed253RowsUnchanged=True,each140DeviceCDCheckedInPreflight=True,full253AndExactPresentSetBeforeExclusiveRestoreMarker=True,exactAfterRestoreAll140PresentRequired=True,identityCleanupAndTransportWholebytesUnchanged=True,actualCurrentAppPIDLimit=1673,closeSeconds=20,otherRemoteSeconds=45,SSHSeconds=55,quotedMaximumBytes=242792,ARGMAX=262144,environmentReserveBytes=10000,missingLogExclusiveCreateUID501Mode600=True,existingLogStableMetadataAndSHAWithBackupBeforeTruncate=True,readinessStable2sBodyWholebytesUnchanged=True,oldPriorBootSuccessNotUsedAsCurrentInit=True,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,actualFutureInitializationSuccessNotClaimed=True,deviceOperations=0,trustCacheOperations=0,guestBootRequested=False,guestSSHVerified=False,findings=[],finiteLocalScopePassed=True)
 (out/'review.json').write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(a.candidate),pin(fp),c['scope'],c['preparer'],c['controller'],c['priorController'],c['priorPacket'],c['health'],c['readinessLoop'],c['currentDeviceFacts'],facts['request'],facts['stdout'],facts['stderr'],c['currentBootTrustPlan'],plan['actualQueryReceipt'],query['request'],query['stdout'],query['stderr'],c['continuingHumanAuthorization']]+list(c['scripts'].values())+[pin(out/'review.json')]
 (out/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),findings=[])))
if __name__=='__main__':main()
