#!/usr/bin/env python3
"""HOST-only fresh verification and initialization after installed-delta verify8.

The old failed verification remains immutable. No installed product is copied
or replaced by this packet; Root executes its five new bounded phases once.
"""
import argparse
import copy
import importlib.util
import json
import pathlib
import re
import shlex
import subprocess
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-uikit-filter-device-v1-attempt1'
STAGE='/private/var/mobile/Library/.VM27-independent27-uikit-filter-init-recovery-v1'


def load(path,name):
    sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m


base=load(OLD/'control.py','installed_uikit_delta_controller')
producer=load(B/'prepare-independent27-uikit-filter-device-v1.py','frozen_uikit_delta_producer')
fast=load(B/'independent27_device_product_verify_fast_v1.py','recovery_fast_full_products')
pin,need,dump=base.pin,base.need,base.dump


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);args=ap.parse_args()
    out=args.output.resolve();need(out.parent==N and not out.exists(),'fresh recovery packet')
    for row in json.loads((OLD/'freeze.json').read_bytes())['files']:base.exact(row)
    original=json.loads((OLD/'candidate.json').read_bytes());old=json.loads((OLD/'scope.json').read_bytes())
    receipts={};raws={};actualpins=[]
    for action,code in (('stage',0),('verify',8)):
        path=OLD/'device-receipts'/action/'receipt.json';row=json.loads(path.read_bytes())
        request=json.loads(base.exact(row['request']).read_bytes());text=base.exact(row['stdout']).read_text();base.exact(row['stderr'])
        need(row['action']==action and row['transportExit']==code and request['action']==action and
             request['packetCandidate']==pin(OLD/'candidate.json'),'actual exact installed stage0 and interrupted verify8')
        receipts[action]=pin(path);raws[action]=text;actualpins.extend([pin(path),row['request'],row['stdout'],row['stderr']])
    need('INDEPENDENT27_ALL_DELTA_INSTALLED_EXACT_BACKUPS_RETAINED_NO_TRUST_OR_GUEST' in raws['stage'] and
         len(re.findall(r'^OWN_EXACT_PRODUCT_UPDATED [0-9]+ ',raws['stage'],re.M))==len(old['deltaFiles']),
         'actual complete original delta stage')
    expected='UNEXPECTED_OWN_PROCESS  4293     1   501 '+old['deviceAppMain']
    need(raws['verify'].strip()==expected and 'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' not in raws['verify'],
         'actual failed verify was precise own App4293 admission, not a product verification success')
    for name in ('trust','launch','post'):
        need(not (OLD/(name+'-dispatched.json')).exists() and not (OLD/'device-receipts'/name).exists(),
             'original later action genuinely never dispatched: '+name)
    source_scope=json.loads(base.exact(old['oldScope']).read_bytes())
    new_cd=sorted(set(old['trustCacheCDHashes'])-set(source_scope['trustCacheCDHashes']))
    need(new_cd==old['newTrustCacheCDHashes'] and len(new_cd)==original['actualNewTrustEntries'],
         'only original necessary un-dispatched new product hashes')
    scope=copy.deepcopy(old)
    historic={key:scope.pop(key) for key in ('archive','deltaArchiveBytes','deltaArchiveSHA256','deltaFiles',
        'existingOwnFilesUpdated','newOwnFilesAdded','newOwnDirectories','newOwnResourceFiles',
        'oldActualPost','currentInstalledProductsPost','historicalPriorInitAndTrustOnly') if key in scope}
    scope.update(schema='Already installed UIKit filter new verification initialization recovery scope v1',
        historicalInstalledDelta=dict(scope=pin(OLD/'scope.json'),candidate=pin(OLD/'candidate.json'),
            stage=receipts['stage'],failedVerification=receipts['verify'],prior=historic),
        originalDeltaBackupDirectory=old['deviceStage'],originalDeltaBackupsRetained=True,
        currentInstalledProductsStage=receipts['stage'],priorVerificationFailure=receipts['verify'],
        priorVerificationFailureExit=8,priorVerificationAppPID=4293,currentInstalledProductsPost=None,oldActualPost=None,
        oldScope=pin(OLD/'scope.json'),deviceStage=STAGE,deltaFiles=[],existingOwnFilesUpdated=0,newOwnFilesAdded=0,
        newOwnDirectories=[],newOwnResourceFiles=[],actualChangedFiles=0,unchangedFiles=len(old['files']),
        unchangedSignedImages=len(old['trustCacheCDHashes']),productInstallationPerformed=False,
        productUpdatesPerformed=False,initializationOnly=True,diagnosticDirectoryAndOwnLogWritesOnly=True,
        originalFailedVerificationIsNotRepeated=True,newActualAllProductsVerificationRequired=True,
        originalTrustActionNeverDispatched=True,backupOldOwnFilesAndLog=False,backupPriorOwnLogOnly=True,
        guestBootRequested=False,bootSeconds=1791813884,actualOwnAppPIDObserved=4293,
        trustCacheRegistrationCount=len(new_cd),newTrustCacheCDHashes=new_cd,
        trustCacheFixedBatchCounts=[len(new_cd)],missingOwnLogMayBeCreated=False)
    base.DEVICE_STAGE=STAGE
    wrap=lambda body,uid,seconds=45:base.prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    body=base.prefix(0)+base.PROCESS_FUNCTIONS+'scan_own\ncleanup_own\n'+base.off_check()
    scripts={'close-current-own':wrap(body+"printf 'INDEPENDENT27_EXACT_CURRENT_OWN_APP_CHILD_CLOSED_NO_PRODUCT_WRITE\\n'\n",0,20)}
    check='''[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
    complete=check+'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/verify-complete")" = 0:0:600:1:0 ]\n'
    verify=base.prefix(0)+base.off_check()+base.HEALTH.read_text()+fast.batch_check(scope)+fast.cd_check(scope,scope['actualNativeCDSubset'])
    verify+='''[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
own_log_identity=$(stat -c %d:%i "$OWN_LOG")
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
'''+check+'''cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
printf 'OWN_RECOVERY_PRIOR_LOG_BACKUP metadata=%s sha256=%s\n' "$own_log_meta" "$own_log_sha"
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
(umask 077; set -C; : > "$OWN_STAGE/verify-complete")
printf 'INDEPENDENT27_RECOVERY_ALL_PRODUCTS_AND3_NATIVE_CD_HEALTH_EXACT_NO_PRODUCT_UPDATE\n'
'''
    scripts['verify']=wrap(verify,0)
    trust=base.prefix(0)+base.off_check()+complete+fast.batch_check(scope)+'(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
    for i,value in enumerate(new_cd,1):trust+='jbctl trustcache add '+value+"\nprintf 'OWN_NEW_PRODUCT_TC_ADDED "+str(i)+' '+value+"\\n'\n"
    scripts['trust']=wrap(trust+producer.trust_check(scope['trustCacheCDHashes'])+"printf 'INDEPENDENT27_RECOVERY_ONLY_ORIGINAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE\\n'\n",0)
    for action in ('launch','post'):
        scripts[action]=(OLD/(action+'.sh')).read_text().replace(old['deviceStage'],STAGE)
    control=(OLD/'control.py').read_text().replace(old['deviceStage'],STAGE)
    control=control.replace("ACTIONS = ('close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')",
                            "ACTIONS = ('close-current-own', 'verify', 'trust', 'launch', 'post')")
    start=control.index("    raw=(packet/'products.tar').read_bytes()");end=control.index('    return ready, scope',start)
    gate='''    need(scope['initializationOnly'] is True and scope['productUpdatesPerformed'] is False and
         scope['deltaFiles']==[] and scope['originalTrustActionNeverDispatched'] is True,
         'fresh verification recovery never re-installs products or retries original trust')
    for field,code in (('currentInstalledProductsStage',0),('priorVerificationFailure',8)):
        row=json.loads(exact(scope[field]).read_bytes())
        need(row['transportExit']==code,'actual original stage0 / verify8 evidence')
        exact(row['request']);exact(row['stdout']);exact(row['stderr'])
    prior_packet=pathlib.Path(scope['oldScope']['path']).parent
    for name in ('trust','launch','post'):
        need(not (prior_packet/(name+'-dispatched.json')).exists() and
             not (prior_packet/'device-receipts'/name).exists(), 'original action still undispatched: '+name)
'''
    control=control[:start]+gate+control[end:]
    control=control.replace("    previous = {'preflight':'close-current-own','stage':'preflight','verify':'stage','trust':'verify','launch':'trust','post':'launch'}.get(args.action)",
                            "    previous = {'verify':'close-current-own','trust':'verify','launch':'trust','post':'launch'}.get(args.action)")
    control=control.replace("        data = (packet/'products.tar').read_bytes() if args.action=='stage' else b''", "        data = b''")
    compile(control,str(out/'control.py'),'exec')
    out.mkdir(mode=0o700);(out/'control.py').write_text(control);(out/'health-root.sh').write_bytes(base.HEALTH.read_bytes());dump(out/'scope.json',scope)
    rows={};sizes={}
    for action,script in scripts.items():
        result=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);need(result.returncode==0,'actual sh-n '+action)
        path=out/(action+'.sh');path.write_text(script);rows[action]=pin(path);(out/(action+'-syntax.stderr')).write_bytes(result.stderr)
        command=('sudo -k -S -p "" ' if action!='launch'else'')+'/var/jb/bin/sh -c '+shlex.quote(script)
        sizes[action]=len(command.encode());need(sizes[action]+10000<262144,'actual ARG_MAX '+action)
    candidate=dict(schema='Inactive genuine installed UIKit filter initialization recovery packet v1',
        preparer=pin(__file__),scope=pin(out/'scope.json'),controller=pin(out/'control.py'),scripts=rows,actions=list(scripts),
        originalInstalledDeltaCandidate=pin(OLD/'candidate.json'),actualOriginalStage0=receipts['stage'],actualOriginalVerify8=receipts['verify'],
        actualFullFiles=len(scope['files']),actualFullCodeDirectoryHashes=len(scope['trustCacheCDHashes']),
        actualChangedFiles=0,actualNewTrustEntries=len(new_cd),actualNativeCDSubset=scope['actualNativeCDSubset'],
        inheritedActualSignedRuntimeCDProof=scope['inheritedActualSignedRuntimeCDProof'],
        inheritedActualSignedAppPeer=scope['inheritedActualSignedAppPeer'],
        actualSignedRuntimeIndependentPeer=scope['actualSignedRuntimeIndependentPeer'],
        continuingHumanAuthorization=scope['continuingHumanAuthorization'],bootSeconds=1791813884,
        allProductInstallationsOmitted=True,oldFailurePreserved=True,newFreshVerificationRequired=True,
        originalStable2sReadinessAndProcessCleanupRetained=True,maximumQuotedCommandBytes=max(sizes.values()),quotedCommandBytes=sizes,
        closeOwnExternalWallSeconds=20,allOtherRemoteActionsExternalWallSeconds=45,transportTimeoutSeconds=55,
        sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,nativeSandboxInitSuccessFabricated=False,
        actualVMConstructorExecuted=False,guestBootRequested=False,deviceOperations=0,trustCacheOperations=0,readyForDeviceExecution=False)
    dump(out/'candidate.json',candidate)
    pins=[pin(p)for p in sorted(out.iterdir())if p.is_file()]+[pin(__file__),pin(producer.__file__),pin(fast.__file__),
        pin(OLD/'candidate.json'),pin(OLD/'freeze.json'),pin(OLD/'scope.json'),pin(OLD/'control.py'),pin(OLD/'launch.sh'),pin(OLD/'post.sh'),pin(base.HEALTH)]
    pins+=actualpins+[row['local']for row in scope['files']]+[scope[k]for k in ('continuingHumanAuthorization',
        'inheritedActualSignedRuntimeCDProof','inheritedActualSignedAppPeer','actualSignedRuntimeIndependentPeer')]
    dump(out/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'),
        products=len(scope['files']),CDs=len(scope['trustCacheCDHashes']),newTC=len(new_cd),maximumQuotedCommandBytes=max(sizes.values()))))


if __name__=='__main__':main()
