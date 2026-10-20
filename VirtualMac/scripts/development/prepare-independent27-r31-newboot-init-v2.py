#!/usr/bin/env python3
"""HOST preparation: unchanged installed R31/App42, actual missing trust, new boot."""
import argparse,copy,importlib.util,json,pathlib,re,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];B=pathlib.Path(__file__).resolve().parent
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD=N/'independent27-app42-unlocked-init-recovery-v3-attempt1'
BOOT=1792055689;BOOT_UUID='A3247B1A-473D-4786-8585-A99DB5B5BDA0'
STAGE='/private/var/mobile/Library/.VM27-independent27-r31-newboot-init-v2'
AUTH=N/'independent27-continuing-human-authorization-v2/authorization.json'
def load(p,name):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=load(OLD/'control.py','r31_newboot_controller')
fast=load(B/'independent27_device_product_verify_fast_v1.py','r31_newboot_products')
old_prepare=load(B/'prepare-independent27-child-usbh-offline-device-v24.py','r31_newboot_trust_renderer')
pin,need,dump=base.pin,base.need,base.dump
def unwrap(script):
 where=script.index('/var/jb/bin/sh -c ',script.index('/var/jb/usr/bin/timeout'))+len('/var/jb/bin/sh -c ')
 values=shlex.split(script[where:]);need(len(values)==1,'one actual bounded body');return values[0]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--inventory',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 out=a.output.resolve();inv_path=a.inventory.resolve();need(out.parent==N and not out.exists(),'fresh same-product newboot initialization')
 inv=json.loads(inv_path.read_bytes());receipt_path=base.exact(inv['actualReadonly']);receipt=json.loads(receipt_path.read_bytes());request=json.loads(base.exact(receipt['request']).read_bytes());text=base.exact(receipt['stdout']).read_text();base.exact(receipt['stderr'])
 old=json.loads((OLD/'scope.json').read_bytes());expected=sorted(old['trustCacheCDHashes'])
 need(receipt['transportExit']==0 and inv['bootSeconds']==BOOT and inv['bootSessionUUID']==BOOT_UUID and request['bootSeconds']==BOOT and request['bootSessionUUID']==BOOT_UUID and inv['expectedActiveCDHashes']==expected and len(expected)==144 and inv['actualInstalledProductsWholeExact'] is True and inv['actualFullFiles']==258,'actual exact same installed products/new boot readonly')
 info=text.split('OWN_NEWBOOT_TRUST_INFO_BEGIN\n',1)[1].split('\nOWN_NEWBOOT_TRUST_INFO_END',1)[0]
 present={line.split()[-1].lower() for line in info.splitlines() if line.split() and re.fullmatch('[0-9a-fA-F]{40}',line.split()[-1])}
 missing=sorted(set(expected)-present)
 need(missing==inv['actualMissingCDHashes'] and sorted(set(expected)&present)==inv['actualPresentExpectedCDHashes'] and 'INDEPENDENT27_NEWBOOT_INSTALLED_PRODUCTS_AND_TRUST_READONLY_COMPLETE' in text,'actual native stdout independently derives precise missing subset')
 auth=json.loads(AUTH.read_bytes());need(auth.get('humanUserAuthorization',True) and auth['rootIsSoleDeviceOperator'] and auth['trustEntryEffectsThatEndAtDeviceRebootExplicitlyAccepted'],'current direct human authorization')
 scope=copy.deepcopy(old)
 scope.update(schema='Installed unchanged R31 App42 actual newboot trust restoration and initialization v2',deviceStage=STAGE,bootSeconds=BOOT,bootMicroseconds=500418,bootSessionUUID=BOOT_UUID,currentBootTrustInventory=pin(inv_path),currentDeviceFacts=request['actualCurrentSession'],currentInstalledProductsPost=None,oldActualPost=None,priorHistoricalInstalledProductsPost=old['currentInstalledProductsPost'],continuingHumanAuthorization=pin(AUTH),newTrustCacheCDHashes=missing,trustCacheRegistrationCount=len(missing),trustCacheFixedBatchCounts=([len(missing)] if missing else []),restoredExistingProductCDHashes=missing,newProductCodeHashes=[],trustMembershipAssumedFromPriorBoot=False,trustMembershipKnownBeforeDispatch=True,allActualTrustAlreadyRegistered=not missing,productUpdatesPlanned=False,productUpdatesPerformed=False,productInstallationPerformed=False,deltaFiles=[],existingOwnFilesUpdated=0,newOwnFilesAdded=0,newOwnDirectories=[],newOwnResourceFiles=[],actualChangedFiles=0,unchangedFiles=258,unchangedSignedImages=144,missingOwnLogMayBeCreated=True,fixedOwnedLogIdentity=None,newLogIdentityMustBeActuallyCapturedBeforeLaunch=True,existingOwnLogMustBeBackedUpBeforeTruncation=True,initializationOnly=True,diagnosticDirectoryAndOwnLogWritesOnly=True,installedProductsCurrentBootVerificationRequired=True,originalFailedVerificationIsNotRepeated=True)
 scope.pop('archive',None)
 prior_prefix=base.prefix;base.DEVICE_STAGE=STAGE
 base.prefix=lambda uid:prior_prefix(uid).replace('1791813884',str(BOOT))+'[ "$(sysctl -n kern.bootsessionuuid)" = '+shlex.quote(BOOT_UUID)+' ]\n'
 def wrap(body,uid,seconds=45):return base.prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
 close=base.prefix(0)+base.PROCESS_FUNCTIONS+'scan_own\n[ -z "$child_rows" ] || exit 8\ncleanup_own\n'+base.off_check()
 stage_check='''[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
 log_check='''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
'''
 verify=close+base.HEALTH.read_text().replace('1791813884',str(BOOT))+fast.batch_check(scope)+fast.cd_check(scope,scope['actualNativeCDSubset'])+'''
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
'''+stage_check+'''
if [ -e "$OWN_LOG" ] || [ -L "$OWN_LOG" ];then
'''+log_check+'''
 own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
 own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
 cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
 [ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_log_sha" ]
 [ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
 [ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
 printf 'OWN_NEWBOOT_ACTUAL_LOG_BACKUP %s %s\n' "$own_log_meta" "$own_log_sha"
else
 [ ! -e "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
 (umask 077; set -C; : > "$OWN_LOG")
 chown 501:501 "$OWN_LOG"
 chmod 600 "$OWN_LOG"
 printf 'OWN_NEWBOOT_EXCLUSIVE_EMPTY_LOG_CREATED\n'
fi
'''+log_check+'''
own_log_identity=$(stat -c %d:%i "$OWN_LOG")
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
printf 'OWN_NEWBOOT_LOG_READY %s\n' "$own_log_identity"
printf 'INDEPENDENT27_NEWBOOT_SAME_PRODUCTS_NATIVE3_OFF_LOG_READY\n'
'''
 trust=close+fast.batch_check(scope)+stage_check+'(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
 for i,value in enumerate(missing,1):trust+='jbctl trustcache add '+value+"\nprintf 'OWN_EXISTING_PRODUCT_TC_RESTORED "+str(i)+' '+value+"\\n'\n"
 trust+=old_prepare.trust_check(expected)
 def current_body(action):return unwrap((OLD/(action+'.sh')).read_text()).replace('1791813884',str(BOOT)).replace(old['deviceStage'],STAGE)
 launch=current_body('launch');needle='own_prior_log_inode=$(stat -c %d:%i "$OWN_LOG")'
 need(launch.count(needle)==1,'one actual inherited initialization log boundary')
 launch=launch.replace(needle,'[ "$(stat -c %d:%i "$OWN_LOG")" = VM27_NEWBOOT_ACTUAL_LOG_IDENTITY ]\n'+needle)
 post=current_body('post')+log_check+'[ "$(stat -c %d:%i "$OWN_LOG")" = VM27_NEWBOOT_ACTUAL_LOG_IDENTITY ]\nprintf \'OWN_POST_ACTUAL_LOG_IDENTITY %s\\n\' "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")"\n'
 scripts={'close-current-own':wrap(close,0,20),'verify':wrap(verify,0),'trust':wrap(trust,0),'launch':wrap(launch,501),'post':wrap(post,0)}
 control=(OLD/'control.py').read_text().replace(old['deviceStage'],STAGE).replace('1791813884',str(BOOT))
 needle='def off_check():'
 control=control.replace(needle,'_newboot_inherited_prefix=prefix\ndef prefix(uid):\n    return _newboot_inherited_prefix(uid)+\'[ "$(sysctl -n kern.bootsessionuuid)" = '+BOOT_UUID+' ]\\n\'\n\n\n'+needle,1)
 control=control.replace('TRUST_ACTIONS = ()',"TRUST_ACTIONS = ('trust',)").replace("ACTIONS = ('close-current-own', 'verify', 'launch', 'post')","ACTIONS = ('close-current-own', 'verify', 'trust', 'launch', 'post')")
 start=control.index("    need(scope['initializationOnly'] is True");end=control.index('    return ready, scope',start)
 gate='''    inventory=json.loads(exact(scope['currentBootTrustInventory']).read_bytes())
    actual_read=json.loads(exact(inventory['actualReadonly']).read_bytes())
    exact(actual_read['request']);exact(actual_read['stdout']);exact(actual_read['stderr'])
    need(actual_read['transportExit']==0 and inventory['bootSeconds']==scope['bootSeconds']==1792055689 and inventory['bootSessionUUID']==scope['bootSessionUUID']=='A3247B1A-473D-4786-8585-A99DB5B5BDA0' and inventory['actualInstalledProductsWholeExact'] is True and inventory['actualMissingCDHashes']==scope['newTrustCacheCDHashes'] and inventory['expectedActiveCDHashes']==sorted(scope['trustCacheCDHashes']), 'actual current boot unchanged products and precise missing TC subset')
    need(scope['initializationOnly'] is True and scope['productUpdatesPlanned'] is False and scope['productUpdatesPerformed'] is False and scope['deltaFiles']==[] and scope['actualChangedFiles']==0, 'no product installation or update in newboot reinitialization')
'''
 control=control[:start]+gate+control[end:]
 control=control.replace("previous = {'verify':'close-current-own','launch':'verify','post':'launch'}","previous = {'verify':'close-current-own','trust':'verify','launch':'trust','post':'launch'}")
 needle="        script = (packet/(args.action+'.sh')).read_text()"
 rendered=needle+'''
        if args.action in ('launch','post'):
            verified=(packet/'device-receipts/verify/stdout').read_text()
            log_ids=re.findall(r'^OWN_NEWBOOT_LOG_READY ([0-9]+:[0-9]+)$',verified,re.M)
            need(len(log_ids)==1,'one actually captured same packet newboot log identity')
            need(script.count('VM27_NEWBOOT_ACTUAL_LOG_IDENTITY')==1,'one exact rendered log identity gate')
            script=script.replace('VM27_NEWBOOT_ACTUAL_LOG_IDENTITY',log_ids[0])
            (output/'actual-rendered-script.sh').write_text(script)
'''
 need(control.count(needle)==1,'one mature dispatch script boundary');control=control.replace(needle,rendered)
 control=control.replace("'ready': pin(args.ready.resolve()), 'script': pin(packet/(args.action+'.sh'))","'ready': pin(args.ready.resolve()), 'script': pin(output/'actual-rendered-script.sh') if args.action in ('launch','post') else pin(packet/(args.action+'.sh')), 'sourceScript': pin(packet/(args.action+'.sh'))")
 compile(control,str(out/'control.py'),'exec');out.mkdir(mode=0o700);(out/'control.py').write_text(control);(out/'health-root.sh').write_text(base.HEALTH.read_text().replace('1791813884',str(BOOT)));dump(out/'scope.json',scope)
 script_rows={}
 for action,script in scripts.items():
  tested=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);need(tested.returncode==0,'actual generated shell syntax '+action)
  command=('sudo -k -S -p "" ' if action!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script);need(len(command.encode())+10000<262144,'finite actual ARG_MAX')
  p=out/(action+'.sh');p.write_text(script);script_rows[action]=pin(p)
 candidate=dict(schema='Installed R31 App42 actual newboot missing-only trust and init v2',preparer=pin(__file__),scope=pin(out/'scope.json'),controller=pin(out/'control.py'),health=pin(out/'health-root.sh'),scripts=script_rows,actions=list(scripts),runtimeCandidate=scope['runtimeCandidate'],appCandidate=scope['appCandidate'],currentBootTrustInventory=pin(inv_path),bootSeconds=BOOT,bootSessionUUID=BOOT_UUID,actualChangedFiles=0,actualNewTrustEntries=len(missing),restoredExistingProductCDHashes=missing,actualFullFiles=258,actualFullCodeDirectoryHashes=144,productUpdatesPlanned=False,productUpdatesPerformed=False,initializationOnly=True,allProductInstallationsOmitted=True,continuingHumanAuthorization=pin(AUTH),originalStable2sReadinessAndProcessCleanupRetained=True,initializationExternalWallSeconds=45,trustStageExternalWallSeconds=45,deviceOperations=0,guestBootRequested=False,readyForDeviceExecution=False)
 dump(out/'candidate.json',candidate)
 pins=[pin(p) for p in out.iterdir() if p.is_file()]+[pin(__file__),pin(OLD/'candidate.json'),pin(OLD/'scope.json'),pin(OLD/'control.py'),pin(OLD/'launch.sh'),pin(OLD/'post.sh'),pin(inv_path),inv['actualReadonly'],receipt['request'],receipt['stdout'],receipt['stderr'],request['actualCurrentSession'],pin(AUTH),pin(fast.__file__),pin(old_prepare.__file__)]+[row['local'] for row in scope['files']]
 dump(out/'freeze.json',dict(files=pins,deviceOperations=0));print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'))))
if __name__=='__main__':main()
