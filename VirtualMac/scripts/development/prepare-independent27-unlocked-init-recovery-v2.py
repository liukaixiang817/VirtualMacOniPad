#!/usr/bin/env python3
"""HOST only: already-installed R31/App42 new once initialization; no product/TC updates."""
import argparse,copy,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-child-usbh-offline-device-v24-attempt1';STAGE='/private/var/mobile/Library/.VM27-independent27-unlocked-init-recovery-v2'
def load(p,name):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=load(OLD/'control.py','same_installed_controller');fast=load(B/'independent27_device_product_verify_fast_v1.py','same_products_fast')
pin,need,dump=base.pin,base.need,base.dump

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh once recovery')
 original=json.loads((OLD/'candidate.json').read_bytes());old=json.loads((OLD/'scope.json').read_bytes());actual={};pins=[]
 for action,code in [('close-current-own',0),('preflight',0),('stage',0),('verify',0),('trust',0),('launch',1),('post',0)]:
  p=OLD/'device-receipts'/action/'receipt.json';receipt=json.loads(p.read_bytes());request=json.loads(base.exact(receipt['request']).read_bytes());base.exact(receipt['stdout']);base.exact(receipt['stderr'])
  need(receipt['action']==action and receipt['transportExit']==code and request['packetCandidate']==pin(OLD/'candidate.json'),'actual same consumed V24 phase '+action)
  actual[action]=pin(p);pins.extend([pin(p),receipt['request'],receipt['stdout'],receipt['stderr']])
 trust=json.loads(base.exact(actual['trust']).read_bytes());need('INDEPENDENT27_ACTUAL_ALL_ACTIVE_OWN_TRUST_MEMBERSHIP_EXACT' in base.exact(trust['stdout']).read_text(),'actual already-installed144 native TC membership')
 post=json.loads(base.exact(actual['post']).read_bytes());text=base.exact(post['stdout']).read_text();need('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT'in text and 'INDEPENDENT27_OWN_APP_AND_CHILD_OFF'in text,'actual current same products and ownOFF')
 scope=copy.deepcopy(old);scope.update(schema='Installed R31/App42 unlocked initialization recovery only',oldScope=pin(OLD/'scope.json'),deviceStage=STAGE,historicalConsumedInitializerCandidate=pin(OLD/'candidate.json'),actualConsumedReceipts=actual,currentInstalledProductsPost=actual['post'],oldActualPost=actual['post'],originalDeltaBackupDirectory=old['deviceStage'],originalDeltaBackupsRetained=True,initializationOnly=True,productUpdatesPerformed=False,productInstallationPerformed=False,deltaFiles=[],existingOwnFilesUpdated=0,newOwnFilesAdded=0,newOwnDirectories=[],newOwnResourceFiles=[],actualChangedFiles=0,unchangedFiles=len(old['files']),unchangedSignedImages=len(old['trustCacheCDHashes']),newTrustCacheCDHashes=[],trustCacheRegistrationCount=0,trustCacheFixedBatchCounts=[],allActualTrustAlreadyRegistered=True,trustMembershipKnownBeforeDispatch=True,guestBootRequested=False,diagnosticDirectoryAndOwnLogWritesOnly=True)
 for key in ('archive','deltaArchiveBytes','deltaArchiveSHA256'):scope.pop(key,None)
 base.DEVICE_STAGE=STAGE
 wrap=lambda body,uid,seconds=45:base.prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
 close=base.prefix(0)+base.PROCESS_FUNCTIONS+'scan_own\ncleanup_own\n'+base.off_check()
 scripts={'close-current-own':wrap(close+"printf 'INDEPENDENT27_RECOVERY_EXACT_CURRENT_OWN_CLOSED_NO_PRODUCT_OR_TC_WRITE\\n'\n",0,20)}
 # Fresh full hashes/three native CDs retain the mature guard. No signatures/graph/models are re-run.
 verify=close+base.HEALTH.read_text()+fast.batch_check(scope)+fast.cd_check(scope,scope['actualNativeCDSubset'])+r'''
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = 16777219:47534875:501:501:600:1 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
printf 'OWN_RECOVERY_ACTUAL_LOG_BACKUP metadata=%s sha256=%s\n' "$own_log_meta" "$own_log_sha"
: > "$OWN_LOG"
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = 16777219:47534875:501:501:600:1:0 ]
printf 'INDEPENDENT27_RECOVERY_ACTUAL_SAME_PRODUCTS_NATIVE3_HEALTH_OFF_NO_TC_UPDATES\n'
'''
 scripts['verify']=wrap(verify,0)
 for action in ('launch','post'):scripts[action]=(OLD/(action+'.sh')).read_text().replace(old['deviceStage'],STAGE)
 control=(OLD/'control.py').read_text().replace(old['deviceStage'],STAGE).replace("TRUST_ACTIONS = ('trust',)","TRUST_ACTIONS = ()").replace("ACTIONS = ('close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')","ACTIONS = ('close-current-own', 'verify', 'launch', 'post')")
 start=control.index("    raw=(packet/'products.tar').read_bytes()");end=control.index('    return ready, scope',start)
 gate='''    need(scope['initializationOnly'] is True and scope['productUpdatesPerformed'] is False and scope['deltaFiles']==[] and scope['newTrustCacheCDHashes']==[], 'installed-only recovery has zero product/TC actions')
    old_candidate=exact(scope['historicalConsumedInitializerCandidate'])
    for action,code in [('close-current-own',0),('preflight',0),('stage',0),('verify',0),('trust',0),('launch',1),('post',0)]:
        old_receipt=json.loads(exact(scope['actualConsumedReceipts'][action]).read_bytes())
        old_request=json.loads(exact(old_receipt['request']).read_bytes())
        exact(old_receipt['stdout']);exact(old_receipt['stderr'])
        need(old_receipt['transportExit']==code and old_request['packetCandidate']==pin(old_candidate), 'actual consumed old success/failure evidence preserved')
'''
 control=control[:start]+gate+control[end:]
 control=control.replace("    previous = {'preflight':'close-current-own','stage':'preflight','verify':'stage','trust':'verify','launch':'trust','post':'launch'}.get(args.action)","    previous = {'verify':'close-current-own','launch':'verify','post':'launch'}.get(args.action)")
 control=control.replace("        data = (packet/'products.tar').read_bytes() if args.action=='stage' else b''","        data = b''");compile(control,str(out/'control.py'),'exec')
 out.mkdir(mode=0o700);(out/'control.py').write_text(control);(out/'health-root.sh').write_bytes(base.HEALTH.read_bytes());dump(out/'scope.json',scope);rows={}
 for action,script in scripts.items():
  tested=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);need(tested.returncode==0,'actual shell syntax '+action);p=out/(action+'.sh');p.write_text(script);rows[action]=pin(p)
 candidate=dict(schema='Actual installed R31/App42 fresh once init recovery noTC v2',preparer=pin(__file__),scope=pin(out/'scope.json'),controller=pin(out/'control.py'),scripts=rows,actions=list(scripts),runtimeCandidate=old['runtimeCandidate'],appCandidate=old['appCandidate'],historicalConsumedInitializerCandidate=pin(OLD/'candidate.json'),actualConsumedReceipts=actual,actualFullFiles=len(scope['files']),actualFullCodeDirectoryHashes=len(scope['trustCacheCDHashes']),actualChangedFiles=0,actualNewTrustEntries=0,actualNativeCDSubset=scope['actualNativeCDSubset'],initializationOnly=True,productUpdatesPerformed=False,allProductInstallationsOmitted=True,continuingHumanAuthorization=scope['continuingHumanAuthorization'],bootSeconds=1791813884,originalStable2sReadinessAndProcessCleanupRetained=True,closeOwnExternalWallSeconds=20,allOtherRemoteActionsExternalWallSeconds=45,transportTimeoutSeconds=55,trustCacheOperations=0,deviceOperations=0,guestBootRequested=False,readyForDeviceExecution=False)
 dump(out/'candidate.json',candidate);files=[pin(p)for p in out.iterdir()if p.is_file()]+[pin(__file__),pin(OLD/'candidate.json'),pin(OLD/'scope.json'),pin(OLD/'freeze.json'),pin(OLD/'control.py'),pin(OLD/'launch.sh'),pin(OLD/'post.sh'),pin(fast.__file__)]+pins+[r['local']for r in scope['files']];dump(out/'freeze.json',dict(files=files,deviceOperations=0));print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'))))
if __name__=='__main__':main()
