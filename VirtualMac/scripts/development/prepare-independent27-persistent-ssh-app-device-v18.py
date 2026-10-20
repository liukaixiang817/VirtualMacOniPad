#!/usr/bin/env python3
"""HOST prepare the actual future App35 persistent SSH App-only delta after actual Runtime25 shutdown on the current boot.

Actual product trees derive every replacement/addition and trust entry. Root
alone dispatches under continuing human authorization after exact product/scope review.
"""
import argparse
import copy
import importlib.util
import io
import json
import pathlib
import plistlib
import shlex
import subprocess
import sys
import tarfile

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-buffer-capability-device-v17-attempt1'
TEMPLATE=N/'independent27-buffer-capability-device-v17-attempt1'
POST=N/'independent27-app34-normal-guest-lifecycle-v26-attempt1/device-receipts/post/receipt.json'
STAGE='/private/var/mobile/Library/.VM27-independent27-persistent-ssh-app-stage-v18'
APP_PEER=None
RUNTIME_PEER=N/'independent27-runtime10-signed-delta-independent-peer-v1-attempt1/review.json'


def load(path,name):
    sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

base=load(TEMPLATE/'control.py','current_boot_delta_controller')
fast=load(B/'independent27_device_product_verify_fast_v1.py','current_boot_delta_fast')
pin,need,dump=base.pin,base.need,base.dump
# A same captured child in state Z has already exited; keep UID/PPID/start
# checks and allow the still-live App cleanup to proceed without signalling Z.
OLD_SIGNAL_LINE=' [ "$#" = 4 ] && [ "$1" = "$own_pid" ] && [ "$3" = 501 ] && [ "$4" = "$own_path" ] || return 77'
ZOMBIE_SIGNAL_PREFIX=r''' if [ "$own_kind" = child ] && [ "$#" = 4 ] && [ "$4" = '<defunct>' ];then
  [ "$1" = "$own_pid" ] && [ "$3" = 501 ] || return 77
  [ "$(start_hash "$own_pid")" = "$own_start" ] || return 77
  if ps -p "$own_app_pid" -o pid= | awk 'NF {seen=1} END {exit !seen}';then [ "$2" = "$own_app_pid" ] || return 77;else [ "$2" = 1 ] || return 77;fi
  own_dead_state=$(ps -p "$own_pid" -o state=)
  case "$own_dead_state" in Z*) return 0;; *) return 77;;esac
 fi
'''
need(ZOMBIE_SIGNAL_PREFIX+OLD_SIGNAL_LINE in base.PROCESS_FUNCTIONS,'existing exact captured zombie signal predicate inherited')


def frozen(directory):
    for row in json.loads((directory/'freeze.json').read_bytes())['files']:
        actual={k:row[k] for k in ('path','bytes','sha256')}
        if pathlib.Path(actual['path']).is_relative_to(R):
            base.exact(actual)
        else:
            need(actual['path']=='/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/SDKSettings.json',
                 'only frozen external SDK settings provenance')
            data=pathlib.Path(actual['path']).read_bytes()
            need(len(data)==actual['bytes'] and base.digest(data)==actual['sha256'],'exact external frozen SDK settings')


def unwrap(script):
    first=script.index('/var/jb/usr/bin/timeout');where=script.index('/var/jb/bin/sh -c ',first)+len('/var/jb/bin/sh -c ')
    values=shlex.split(script[where:]);need(len(values)==1,'one inherited bounded action');return values[0]


def trust_check(all_hashes):
    # One native query; exact expected membership uses the frozen V3 parser.
    values=';'.join('expected["'+x+'"]=1' for x in all_hashes)
    awk='BEGIN {'+values+'} {v=tolower($NF);if(length(v)==40 && v~/^[[:xdigit:]]+$/ && (v in expected))found[v]=1} END {for(v in found)print v}'
    return '''own_actual_trust_exit=0
own_actual_trust_info=$(jbctl trustcache info) || own_actual_trust_exit=$?
printf 'OWN_ACTUAL_TRUST_NATIVE_EXIT %s\n' "$own_actual_trust_exit"
printf '%s\n' "$own_actual_trust_info"
[ "$own_actual_trust_exit" = 0 ]
own_actual_present=$(printf '%s\n' "$own_actual_trust_info" | awk '''+shlex.quote(awk)+''' | sort)
[ "$own_actual_present" = '''+shlex.quote('\n'.join(sorted(all_hashes)))+''' ]
printf 'INDEPENDENT27_ACTUAL_ALL_ACTIVE_OWN_TRUST_MEMBERSHIP_EXACT\n'
'''


# No future facts are created by these constants. Every artifact below must
# really exist with successful transport and immutable prior/lease provenance.
READONLY_PACKET=N/'independent27-app34-guest-readonly-v19-attempt1'
READONLY_ACTUAL=N/'independent27-app34-guest-current-readonly-v1-attempt1'
NORMAL_PACKET=N/'independent27-app34-normal-guest-lifecycle-v26-attempt1'
APP35_SHA='38d2c1bb5d59b5398e8f1f07f2afeee4bde5d09eedc82df8dccd3d51f9e2c14c'
COMMON=B/'independent27_normal_guest_common_v2.py'
RUNNER=B/'independent27_normal_guest_lifecycle_v3.py'

def require_prior_shutdown():
    common=load(COMMON,'actual_shutdown_common')
    need(pin(COMMON)['sha256']=='7b0c8309ea8e5677b482f0debe49b72aad7e84d30cde0e402b778d2d56681b0a' and
         pin(RUNNER)['sha256']=='206e8798f14b2532ae44ed26167cbbb5b3906ac8da2a1b3bb7ca3a223198c2b8',
         'frozen genuine initializer/guest/lease provenance utilities')
    init=OLD/'candidate.json';launch=OLD/'device-receipts/launch/receipt.json';ipost=OLD/'device-receipts/post/receipt.json'
    common.initializer_success(init,launch,ipost)
    need(pin(READONLY_PACKET/'candidate.json')['sha256']=='f08294729a91e98f436fc48e532e3cda9f87cf9e67009811c47d3de5e2c977eb',
         'exact inactive Readonly19 packet')
    read=READONLY_ACTUAL/'receipt.json';config=READONLY_ACTUAL/'configuration.json'
    common.guest_success(read,config,pin(ipost))
    readrow,_=common.receipt(read);readrequest=json.loads(common.exact(readrow['request']).read_bytes())
    need(readrequest['preparedCandidate']==pin(READONLY_PACKET/'candidate.json') and readrequest['initializerCandidate']==pin(init),
         'actual successful Readonly19 from the same actual initialized Runtime25/App34')
    normal=NORMAL_PACKET/'candidate.json';nc=json.loads(normal.read_bytes());frozen(NORMAL_PACKET)
    need(nc['initializerCandidate']==pin(init) and nc['initializerLaunch']==pin(launch) and nc['initializerPost']==pin(ipost) and
         nc['freshGuestReadonly']==pin(read) and nc['freshGuestConfiguration']==pin(config),
         'actual Normal26 candidate binds the same initialized and freshly read products')
    need(not (NORMAL_PACKET/'normal-dispatch.lock').exists(),'no live Root normal operation may be updated')
    runner=load(RUNNER,'actual_normal_lease_provenance')
    start,startpin=runner.prior(common,NORMAL_PACKET,'start',False)
    post,postpin=runner.prior(common,NORMAL_PACKET,'post',True)
    postrequest=json.loads(common.exact(post['request']).read_bytes());posttext=common.exact(post['stdout']).read_text()
    need(postrequest['script']==nc['actions']['post'] and
         'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in posttext and
         'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in posttext and
         'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF' in posttext,
         'actual Normal26 full products/health and explicit App+Child OFF, never mere post0/live ownership')
    pins=[pin(COMMON),pin(RUNNER),pin(init),pin(OLD/'freeze.json'),pin(launch),pin(ipost),
          pin(READONLY_PACKET/'candidate.json'),pin(READONLY_PACKET/'freeze.json'),pin(read),pin(config),readrow['request'],readrow['stdout'],readrow['stderr'],
          pin(normal),pin(NORMAL_PACKET/'freeze.json'),startpin,start['request'],start['stdout'],start['stderr'],postpin,post['request'],post['stdout'],post['stderr']]
    ack=NORMAL_PACKET/'device-receipts/start/handoff-ack.json';ledger=NORMAL_PACKET/'device-receipts/start/handoff-ledger.json'
    if ack.exists() or start.get('handoffACKAttemptRecorded') or start.get('handoffACKSent'):
        # Keep the durable original ownership documents unchanged. The actual
        # same-lease stop0 plus fresh OFF/health post discharges the obligation.
        payload,ledgerpin=runner.lease_data(common,NORMAL_PACKET,nc,ledger)
        stop,stoppin=runner.prior(common,NORMAL_PACKET,'stop',True)
        request=json.loads(common.exact(stop['request']).read_bytes())
        need(request['priorPins']==[ledgerpin] and request['inputBytes']==len(payload) and
             request['inputSHA256']==base.digest(payload) and request['script']==nc['actions']['stop'] and
             postrequest['priorPins']==[stoppin],
             'actual stop of the exact captured Root ledger required before any App update')
        from datetime import datetime
        need(datetime.fromisoformat(post['finishedUTC'])>=datetime.fromisoformat(stop['finishedUTC'])>=datetime.fromisoformat(start['finishedUTC']),
             'actual stop/post chronology, not rewritten released/ownership claims')
        pins += [pin(ack),ledgerpin,stoppin,stop['request'],stop['stdout'],stop['stderr']]
        mode='actual same-ledger stop0 then products-health-App-Child-OFF post0'
    else:
        need(start['transportExit']!=0 and not start.get('handoffACKAttemptRecorded') and not start.get('handoffACKSent') and
             postrequest['priorPins']==[startpin],
             'failed start without ACK plus actual terminal OFF/health post, never a running guest update')
        mode='actual failed start without ACK then products-health-App-Child-OFF post0'
    return dict(schema='Actual pre-update Runtime25/App34 initialization/read/Normal26 shutdown provenance',
                initializerLaunch=pin(launch),initializerPost=pin(ipost),actualReadonly=pin(read),actualConfiguration=pin(config),
                actualNormalCandidate=pin(normal),actualNormalStart=startpin,actualNormalPost=postpin,
                actualOwnershipObligationDischargedByStopAndOffProof=mode,pins=list({p['path']:p for p in pins}.values()))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--app-candidate',type=pathlib.Path,required=True)
    args=ap.parse_args()
    prerequisites=require_prior_shutdown()  # fails before creating any output if real future receipts are absent
    global APP_PEER,RUNTIME_PEER
    APP_PEER=args.app_candidate.resolve();RUNTIME_PEER=args.runtime_candidate.resolve()
    out=args.output.resolve();need(out.parent==N and not out.exists(),'fresh concrete delta packet')
    runtime_path=args.runtime_candidate.resolve();app_path=args.app_candidate.resolve()
    for path in (runtime_path,app_path):frozen(path.parent)
    frozen(OLD);frozen(TEMPLATE)
    template_scope=json.loads((TEMPLATE/'scope.json').read_bytes())
    runtime=json.loads(runtime_path.read_bytes());app=json.loads(app_path.read_bytes())
    need(pin(runtime_path)==json.loads((OLD/'scope.json').read_bytes())['runtimeCandidate'] and pin(app_path)['sha256']==APP35_SHA,
         'exact current Runtime25 and actual frozen future App35 product only')
    need(app['actualCodeSigned'] is True and app['runtimeCandidate']==pin(runtime_path) and
         runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True,
         'actual signed App and actual signed Runtime product proofs; repeated peers omitted at user request')
    app_peer={'actualSignature':app['actualSignature']}
    signature_pin=runtime['signatureVerification'];signature=json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True,
         'actual signed current Runtime whole code-page and special-slot proof')
    old=json.loads((OLD/'scope.json').read_bytes());post=json.loads(POST.read_bytes())
    base.exact(post['request']);text=base.exact(post['stdout']).read_text();base.exact(post['stderr'])
    need(post['transportExit']==0 and 'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in text and
         'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in text and 'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF' in text,
         'actual current normal failure cleanup left all installed products exact/off')
    need(runtime['actualProductPreflightPassed'] is True and runtime['localCodeSigned'] is True and
         app['actualCodeSigned'] is True and runtime['sandboxProfileApplied'] is False and
         runtime['nativeSandboxApplyUnavailable']==45 and runtime['nativeSandboxInitSuccessFabricated'] is False,
         'actual signed products and truthful deferred sandbox')
    manifest=plistlib.loads(base.exact(runtime['manifest']).read_bytes())
    cd_by_name={'runtime/'+row['path']:row['cdhash'] for row in manifest['files'] if row['kind']=='mach-o'}
    signature_by_name={'runtime/'+row['relativePath']:row for row in signature['actualSignedFiles']}
    need(set(signature_by_name)==set(cd_by_name) and all(signature_by_name[name]['cdhash']==value and
         signature_by_name[name]['allPrimaryPagesAndSpecialSlotsVerified'] is True for name,value in cd_by_name.items()),
         'every current runtime manifest code hash joins actual current Runtime signature proof')
    cd_by_name['VirtualMacIndependent27.app/VirtualMacIndependent27']=app['actualSignature']['cdhash']
    roots=[(pathlib.Path(runtime['runtimeRoot']),'runtime'),(pathlib.Path(app['app']),'VirtualMacIndependent27.app')]
    old_by_name={row['archivePath']:row for row in old['files']};files=[];directories={};changes=[]
    for root,top in roots:
        need(root.is_dir() and not root.is_symlink(),'real finalized ordinary product root')
        directories[top]=0o755 if top=='VirtualMacIndependent27.app' else 0o700
        for path in sorted(root.rglob('*')):
            need(not path.is_symlink() and (path.is_file() or path.is_dir()),'ordinary complete finalized product tree')
            name=top+'/'+path.relative_to(root).as_posix()
            if path.is_dir():
                directories[name]=old['directories'].get(name,0o755 if top=='VirtualMacIndependent27.app' else 0o700)
                continue
            need(path.stat().st_nlink==1,'one actual source file link')
            device=(old['deviceRuntime'] if top=='runtime' else old['deviceApp'])+'/'+path.relative_to(root).as_posix()
            source=pin(path);prior=old_by_name.get(name)
            mode=prior['mode'] if prior else 0o700 if name in cd_by_name else 0o600
            row=dict(archivePath=name,devicePath=device,mode=mode,local=source)
            if name in cd_by_name:row['cdhash']=cd_by_name[name]
            files.append(row)
            if prior is None or prior['local']['sha256']!=source['sha256']:
                changes.append(dict(index=len(changes),archivePath=name,devicePath=device,mode=mode,
                    old=prior['local'] if prior else None,new=source,newResource=prior is None))
    need(set(old_by_name)<= {row['archivePath'] for row in files},'no installed product deletion')
    for row in files:
        if row['archivePath'] in signature_by_name:
            need(row['local']==signature_by_name[row['archivePath']]['actualSignedFile'],
                 'current signed runtime proof belongs to every exact finalized whole file')
    need(next(row['local'] for row in files if row['archivePath']=='VirtualMacIndependent27.app/VirtualMacIndependent27')==
         app_peer['actualSignature']['file'] and app_peer['actualSignature']==app['actualSignature'],
         'current App signed product exactly joins finalized App file and code hash')
    new_dirs=[dict(archivePath=name,devicePath=(old['deviceRuntime']+name[len('runtime'):] if name.startswith('runtime') else old['deviceApp']+name[len('VirtualMacIndependent27.app'):]),mode=mode)
              for name,mode in sorted(directories.items()) if name not in old['directories']]
    need(all(name in directories and directories[name]==mode for name,mode in old['directories'].items()),'all existing directory contracts preserved')
    full=sorted(cd_by_name.values());new_cd=sorted(set(full)-set(old['trustCacheCDHashes']))
    need(len(full)==len(set(full)) and len(files)<=256+256 and changes and
         all(value in full for value in new_cd),'actual complete unique finalized code inventory and delta')
    guest_helper='VirtualMacIndependent27.app/GuestTools/vm27-guest-vsock-ssh-signed-v1'
    app_main='VirtualMacIndependent27.app/VirtualMacIndependent27'
    app_seal='VirtualMacIndependent27.app/_CodeSignature/CodeResources'
    allowed={app_main,app_seal,guest_helper}
    need({row['archivePath'] for row in files}==set(old_by_name)|{guest_helper} and
         {row['archivePath'] for row in changes}==allowed and
         {row['archivePath'] for row in changes if row['old'] is None}=={guest_helper} and
         len(full)==len(old['trustCacheCDHashes']) and new_cd==[app['actualSignature']['cdhash']],
         'only App executable/seal plus fixed guest MacOS helper data; one new iPad App CD, no guest helper trust entry')
    helperfile=next(row for row in files if row['archivePath']==guest_helper)
    need(helperfile['local']['bytes']==52448 and helperfile['local']['sha256']=='33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c' and
         helperfile['mode']==0o600 and 'cdhash' not in helperfile,
         'exact previously signed guest MacOS helper uploaded only as ordinary nonexecutable iPad data')
    need({row['archivePath'] for row in new_dirs}=={'VirtualMacIndependent27.app/GuestTools'} and
         all(row['mode']==0o755 for row in new_dirs),'one real fixed App GuestTools directory, UID501/GID501 mode0755')
    need(all(row['archivePath'].startswith('VirtualMacIndependent27.app/') for row in changes) and
         all(row['old'] is None or row['new']['sha256']!=row['old']['sha256'] for row in changes),
         'no Runtime/provider/permission mutation in the future persistent SSH App update')
    cache_path='/private/var/mobile/Library/VirtualMacIndependent27Cache-v1/virtualization/'
    cache_dirs=['/private/var/mobile/Library/VirtualMacIndependent27Cache-v1',cache_path.rstrip('/')]
    helper=next(row for row in files if row['archivePath']=='runtime/parent-flat/VM27OwnedVZStartCompat.dylib')
    need(cache_path.encode()+b'\0' in base.exact(helper['local']).read_bytes() and
         runtime.get('cacheAdapterContract') is not None,
         'actual signed helper contains the exact owned cache path and source contract')
    cache_missing=''  # Existing private cache directories are retained.
    cache_check=''
    cache_create=''
    for q in cache_dirs:
        path=shlex.quote(q);parent=shlex.quote(str(pathlib.PurePosixPath(q).parent))
        cache_check+='[ -d '+path+' ] && [ ! -L '+path+' ] || exit 8\n'
        cache_check+='[ "$(realpath '+path+')" = '+path+' ] || exit 8\n'
        cache_check+='[ "$(stat -c %u:%g:%a '+path+')" = 501:501:700 ] || exit 8\n'
        cache_create+='[ -d '+parent+' ] && [ ! -L '+parent+' ] || exit 8\n'
        cache_create+='[ "$(realpath '+parent+')" = '+parent+' ] || exit 8\n'
        cache_create+='[ ! -e '+path+' ] && [ ! -L '+path+' ] || exit 8\n'
        cache_create+='mkdir -m 700 '+path+'\nchown 501:501 '+path+'\n'
    cache_create=cache_check+"printf 'OWN_EXISTING_PRIVATE_CACHE_DIRECTORIES_VERIFIED_AND_RETAINED\\n'\n"
    scope=copy.deepcopy(old)
    inherited={key:scope.pop(key) for key in ('currentBootTrustPlan','restoredExistingProductCDHashes','newProductCodeHashes','priorInitializationLaunch',
        'priorAppRegistration','historicalPriorBootInitializationOnly','inheritedActualSignedRuntimeCDProof',
        'actualSignedAppProductProof','trustMembershipKnownBeforeDispatch','currentDeviceFacts','actualOwnAppPIDObserved') if key in scope}
    scope.update(schema='Future actual App35 persistent SSH App-only delta after Runtime25 shutdown scope v18',
        historicalPriorInitAndTrustOnly=dict(scope=pin(OLD/'scope.json'),prior=inherited),
        oldActualPost=pin(POST),currentInstalledProductsPost=pin(POST),oldScope=pin(OLD/'scope.json'),
        deviceStage=STAGE,files=files,directories=directories,runtimeCandidate=pin(runtime_path),appCandidate=pin(app_path),
        trustCacheCDHashes=full,trustCacheRegistrationCount=len(new_cd),newTrustCacheCDHashes=new_cd,
        trustCacheFixedBatchCounts=[len(new_cd)],actualFullCodeDirectoryHashes=len(full),actualRuntimeManifestFiles=len(manifest['files']),
        deltaFiles=changes,existingOwnFilesUpdated=sum(row['old'] is not None for row in changes),
        newOwnFilesAdded=sum(row['old'] is None for row in changes),newOwnDirectories=new_dirs,
        newOwnResourceFiles=[row['archivePath'] for row in changes if row['old'] is None],
        actualChangedFiles=len(changes),unchangedFiles=len(files)-len(changes),
        unchangedSignedImages=sum(row.get('cdhash') in old['trustCacheCDHashes'] for row in files if 'cdhash' in row),
        initializationOnly=False,productInstallationPerformed=False,productUpdatesPerformed=False,productUpdatesPlanned=True,
        backupOldOwnFilesAndLog=True,backupPriorOwnLogOnly=False,
        exactFullProductsAndSignedCDProofInherited=True,ownMacEventFilterContract=runtime['ownMacEventFilterContract'],
        inheritedActualSignedRuntimeCDProof=signature_pin,actualSignedAppProductProof=pin(APP_PEER),
        actualSignedRuntimeProductProof=pin(RUNTIME_PEER),
        actualFullCodeTrustMembershipVerifiedAfterAddRequired=True,trustMembershipKnownBeforeDispatch=False,
        missingOwnLogMayBeCreated=False,
        sourceArtifactContract=runtime['sourceArtifactContract'],
        sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,nativeSandboxInitSuccessFabricated=False,
        bootSeconds=1791813884,guestBootRequested=False,diagnosticDirectoryAndOwnLogWritesOnly=False,
        systemSandboxFilesModified=False,deviceSystemFilesModified=False,perPIDKernelPrivilegeModification=False,
        originalChildAndVMMCodePreserved=True,ordinaryUIKitBasicOnly=True,
        fullMacRawHIDImplemented=False,panPinchRotationImplemented=False,
        cleanupRequiresExactPIDUIDPathPPIDAndStartTimeHash=True,
        initializationExternalWallSeconds=45,updateExternalWallSeconds=45)
    scope['runtimeAllWholebytesUnchanged']=True
    scope['runtimeFilesUnchanged']=True
    scope['originalChildAllWholebytesUnchanged']=True
    scope['originalParentAllWholebytesUnchanged']=True
    scope['originalMainAppResourcesAllWholebytesUnchanged']=False
    scope['onlyOwnMainFileUpdated']=False
    scope['exactActualShutdownPrerequisites']=prerequisites
    scope['futureAppPersistentSSHIntended']=True
    scope['actualGuestSSHServiceInstalled']=False
    scope['actualGuestSSHAuthenticated']=False
    scope['guestMacOSHelperIsIPadDataOnly']=True
    scope['guestMacOSHelperIPadTrustCacheEntries']=0
    scope['repeatedProductPeerReviewsOmittedAtDirectUserRequest']=True
    scope['cacheAdapterContract']=runtime['cacheAdapterContract']
    scope['ownedMutableCacheDirectories']=[dict(devicePath=q,uid=501,gid=501,mode=0o700) for q in cache_dirs]
    scope['ownedCacheDirectoryPreparationProtocolBeforeFirstReplacement']=False
    scope['ownedCacheDirectoriesActuallyPrepared']=True
    scope['existingCacheDirectoriesVerifiedAgainBeforeReplacement']=True
    scope['originalFactoryAttestationContractBodyInherited']=True
    scope['deploymentCloseSignalOutputSuppressedUntilSignalsComplete']=True
    scope['fixedOwnedLogIdentity']='16777219:47534875:501:501:600:1'
    native_subset=[cd_by_name['VirtualMacIndependent27.app/VirtualMacIndependent27'],
        next(row['cdhash'] for row in files if row['archivePath']=='runtime/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine'),
        next(row['cdhash'] for row in files if row['archivePath']=='runtime/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/VM27OwnedAppChildPreMainV3.dylib')]
    scope['actualNativeCDSubset']=native_subset;scope['actualNativeCDSubsetCount']=len(native_subset)
    scope['all140NativeCodeDirectoriesRequeried']=False
    archive_io=io.BytesIO()
    with tarfile.open(fileobj=archive_io,mode='w:',format=tarfile.USTAR_FORMAT) as archive:
        for row in changes:
            data=base.exact(row['new']).read_bytes();item=tarfile.TarInfo('new-'+str(row['index']))
            item.mode=0o600;item.uid=item.gid=item.mtime=0;item.size=len(data);archive.addfile(item,io.BytesIO(data))
    archive=archive_io.getvalue();scope['deltaArchiveBytes']=len(archive);scope['deltaArchiveSHA256']=base.digest(archive)
    scope['archive']=dict(path=str(out/'products.tar'),bytes=len(archive),sha256=base.digest(archive))
    base.DEVICE_STAGE=STAGE
    prefix,off=base.prefix,base.off_check
    wrap=lambda body,uid,seconds=45:prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    before,after=fast.batch_check(old)+cache_check,fast.batch_check(scope)+cache_check
    missing=''.join('[ ! -e '+shlex.quote(row['devicePath'])+' ] && [ ! -L '+shlex.quote(row['devicePath'])+' ] || exit 8\n' for row in changes if row['old'] is None)
    missing+=''.join('[ ! -e '+shlex.quote(row['devicePath'])+' ] && [ ! -L '+shlex.quote(row['devicePath'])+' ] || exit 8\n' for row in new_dirs)
    missing+=cache_missing
    scripts={}
    close=prefix(0)+base.PROCESS_FUNCTIONS+'''own_close_status=0
cleanup_own >/dev/null 2>&1 || own_close_status=$?
[ "$own_close_status" = 0 ] || exit "$own_close_status"
'''+off()+"printf 'INDEPENDENT27_EXACT_CURRENT_OWN_APP_CHILD_CLOSED_NO_PRODUCT_WRITE\\n'\n"
    scripts['close-current-own']=wrap(close,0,20)
    health=base.HEALTH.read_text()
    # Same reviewed Normal11 exact UI-only close, isolated from the real launch
    # PID variables. Each signal rechecks captured PID/UID/path/PPID/start.
    def close_ui_guard(current,uid):
        app_file=next(row for row in current['files'] if row['devicePath']==current['deviceAppMain'])
        close_ui=prefix(uid)+"[ -f \"$OWN_APP_MAIN\" ] && [ ! -L \"$OWN_APP_MAIN\" ] || exit 8\n[ \"$(realpath \"$OWN_APP_MAIN\")\" = \"$OWN_APP_MAIN\" ] || exit 8\n"
        close_ui+='[ \"$(stat -c %u:%g:%a:%h:%s \"$OWN_APP_MAIN\")\" = '+shlex.quote('501:501:'+format(app_file['mode'],'o')+':1:'+str(app_file['local']['bytes']))+' ] || exit 8\n'
        close_ui+='[ \"$(sha256sum \"$OWN_APP_MAIN\" | cut -d \' \' -f1)\" = '+app_file['local']['sha256']+' ] || exit 8\n'
        close_ui+=base.PROCESS_FUNCTIONS+"scan_own || exit 77\n[ -z \"$child_rows\" ] || exit 8\nsignal_own TERM \"$own_app_pid\" \"$OWN_APP_MAIN\" \"$own_app_start\" app || exit 77\nsleep 1\nsignal_own KILL \"$own_app_pid\" \"$OWN_APP_MAIN\" \"$own_app_start\" app || exit 77\n"+off()
        return "own_ui_close_status=0\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c "+shlex.quote(close_ui)+" >/dev/null 2>&1 || own_ui_close_status=$?\n[ \"$own_ui_close_status\" = 0 ] || exit \"$own_ui_close_status\"\n"
    scripts['close-current-own']=wrap(prefix(0)+close_ui_guard(old,0)+off()+"printf 'INDEPENDENT27_EXACT_UI_ONLY_CLOSED_NO_CHILD_OR_GUEST_UPDATE\\n'\n",0,20)
    scripts['preflight']=wrap(prefix(0)+off()+health+before+missing+'''[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %d:%i "$OWN_LOG")" = 16777219:47534875 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
printf 'INDEPENDENT27_CURRENT_INSTALLED_PRODUCTS_EXACT_DELTA_PREFLIGHT_NO_WRITE\n'
''',0)
    stage_check='''[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
    check_file='''check_own_file() {
 [ -f "$1" ] && [ ! -L "$1" ]
 [ "$(realpath "$1")" = "$1" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$1")" = "501:501:$4:1:$3" ]
 [ "$(sha256sum "$1" | cut -d ' ' -f1)" = "$2" ]
}
'''
    stage=prefix(0)+off()+check_file+missing+'''[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
'''+stage_check+'''dd of="$OWN_STAGE/products.tar" bs=65536 2>/dev/null
'''+f'[ "$(stat -c %u:%g:%h:%s "$OWN_STAGE/products.tar")" = 0:0:1:{len(archive)} ]\n[ "$(sha256sum "$OWN_STAGE/products.tar" | cut -d \' \' -f1)" = {base.digest(archive)} ]\ntar -xpf "$OWN_STAGE/products.tar" -C "$OWN_STAGE"\n'
    for row in changes:
        path=shlex.quote(row['devicePath']);i=row['index'];old_file,new_file=row['old'],row['new']
        if old_file:
            stage+=f'check_own_file {path} {old_file["sha256"]} {old_file["bytes"]} {row["mode"]:o}\ncp -p {path} "$OWN_STAGE/backup-{i}"\n[ "$(sha256sum "$OWN_STAGE/backup-{i}" | cut -d \' \' -f1)" = {old_file["sha256"]} ]\n'
        else:stage+=f'[ ! -e {path} ] && [ ! -L {path} ] || exit 8\n(umask 077; set -C; : > "$OWN_STAGE/backup-new-absent-{i}")\n'
        stage+=f'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/new-{i}")" = 0:0:600:1:{new_file["bytes"]} ]\n[ "$(sha256sum "$OWN_STAGE/new-{i}" | cut -d \' \' -f1)" = {new_file["sha256"]} ]\n'
    stage+='''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %d:%i "$OWN_LOG")" = 16777219:47534875 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
own_log_identity=$(stat -c %d:%i "$OWN_LOG")
cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
printf 'OWN_PRIOR_LOG_BACKUP metadata=%s sha256=%s\n' "$own_log_meta" "$own_log_sha"
'''
    stage+=cache_create
    for row in new_dirs:
        path=shlex.quote(row['devicePath']);parent=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent))
        stage+=f'[ -d {parent} ] && [ ! -L {parent} ] || exit 8\n[ "$(realpath {parent})" = {parent} ] || exit 8\n[ ! -e {path} ] && [ ! -L {path} ] || exit 8\nmkdir -m {row["mode"]:o} {path}\nchown 501:501 {path}\n'
    for row in changes:
        path=shlex.quote(row['devicePath']);i=row['index'];new_file=row['new']
        temporary=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-persistent-ssh-app-v18-'+str(i)+'.pending')))
        stage+=f'[ ! -e {temporary} ] && [ ! -L {temporary} ] || exit 8\ncp "$OWN_STAGE/new-{i}" {temporary}\nchown 501:501 {temporary}\nchmod {row["mode"]:o} {temporary}\ncheck_own_file {temporary} {new_file["sha256"]} {new_file["bytes"]} {row["mode"]:o}\n'
        if row['old']:
            stage+=f'check_own_file {path} {row["old"]["sha256"]} {row["old"]["bytes"]} {row["mode"]:o}\nmv -f {temporary} {path}\n'
        else:stage+=f'[ ! -e {path} ] && [ ! -L {path} ] || exit 8\nmv -n {temporary} {path}\n[ ! -e {temporary} ] && [ ! -L {temporary} ] || exit 8\n'
        stage+=f'check_own_file {path} {new_file["sha256"]} {new_file["bytes"]} {row["mode"]:o}\nprintf \'OWN_EXACT_PRODUCT_UPDATED {i} {row["archivePath"]}\\n\'\n'
    stage+='''[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
(umask 077; set -C; : > "$OWN_STAGE/stage-complete")
printf 'INDEPENDENT27_ALL_DELTA_INSTALLED_EXACT_BACKUPS_RETAINED_NO_TRUST_OR_GUEST\n'
'''
    scripts['stage']=wrap(stage,0)
    complete=stage_check+'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/stage-complete")" = 0:0:600:1:0 ]\n'
    scripts['verify']=wrap(prefix(0)+off()+complete+after+fast.cd_check(scope,native_subset)+"printf 'INDEPENDENT27_NEW_PRODUCTS_ALL_SHA_AND3_NATIVE_CD_EXACT\\n'\n",0)
    trust=prefix(0)+off()+complete+after+'(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
    for i,value in enumerate(new_cd,1):trust+='jbctl trustcache add '+value+"\nprintf 'OWN_NEW_PRODUCT_TC_ADDED "+str(i)+' '+value+"\\n'\n"
    scripts['trust']=wrap(trust+trust_check(full)+"printf 'INDEPENDENT27_ONLY_ACTUAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE\\n'\n",0)
    launch=unwrap((TEMPLATE/'launch.sh').read_text()).replace(template_scope['deviceStage'],STAGE)
    need(launch.count(close_ui_guard(old,501))==1,'one inherited initial exact UI-only close')
    launch=launch.replace(close_ui_guard(old,501),'',1)
    need(launch.count(before)==1,'one exact old full-product launch guard')
    launch=launch.replace(before,after,1)
    scripts['launch']=wrap(launch,501)
    post_script=(TEMPLATE/'post.sh').read_text().replace(template_scope['deviceStage'],STAGE)
    need(post_script.count(before.replace("'","'\"'\"'"))==1,'one inherited quoted full-product post guard')
    scripts['post']=post_script.replace(before.replace("'","'\"'\"'"),after.replace("'","'\"'\"'"),1)
    # Only initial off-required portions change. The live child readiness,
    # captured launch identity and post cleanup protocol remain untouched.
    for action in ('preflight','stage','verify','trust','launch'):
        uid=501 if action=='launch' else 0
        actual=unwrap(scripts[action])
        need(off() in actual,'one inherited initial off guard '+action)
        current=old if action in ('preflight','stage') else scope
        actual=actual.replace(off(),close_ui_guard(current,uid)+off(),1)
        scripts[action]=wrap(actual,uid)
    scope['sameActionExactUIOnlyCloseBeforeOffRequiredPhases']=['preflight','stage','verify','trust','launch']
    scope['sameActionUIOnlyCloseExternalWallSeconds']=20
    scope['sameActionUIOnlyCloseRejectsAnyCurrentChild']=True
    scope['originalLiveChildReadinessAndCapturedPostProtocolUnchanged']=True
    controller=(TEMPLATE/'control.py').read_text().replace(template_scope['deviceStage'],STAGE)
    need(ZOMBIE_SIGNAL_PREFIX+OLD_SIGNAL_LINE in controller,'existing captured zombie predicate unchanged')
    need("ready.get('rootActualSignedProductScopeAndControllerReviewed')" in controller,'existing direct Root actual-product review gate unchanged')
    controller=controller.replace("TRUST_ACTIONS = ('restore-trust',)","TRUST_ACTIONS = ('trust',)")
    controller=controller.replace("ACTIONS = ('close-current-own', 'preflight', 'restore-trust', 'launch', 'post')",
        "ACTIONS = ('close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')")
    controller=controller.replace('requires pinned independent review and a new human authorization for this exact\npersistent trust-cache set. No permission record is generated by this tool.',
        'requires exact Root product/scope review and a concrete authorization derived\nfrom continuing direct human authorization. No permission record is generated by this tool.')
    redundant_boot_gate="""    need(scope['bootSeconds']==1791813884 and scope['sandboxProfileApplied'] is False and
         scope['nativeSandboxInitSuccessFabricated'] is False and scope['actualNativeCDSubsetCount']==3,
         'current boot and truthful basic-only profile')
"""
    need(controller.count(redundant_boot_gate)>=1,'inherited current boot/profile guards present')
    controller=controller.replace(redundant_boot_gate,'')
    a=controller.index("    raw=(packet/'products.tar').read_bytes()");z=controller.index('    return ready, scope',a)
    gate='''    need(scope['bootSeconds']==1791813884 and scope['sandboxProfileApplied'] is False and
         scope['nativeSandboxInitSuccessFabricated'] is False and scope['actualNativeCDSubsetCount']==3,
         'current boot and truthful basic-only profile')
    raw=(packet/'products.tar').read_bytes()
    need(len(raw)==scope['deltaArchiveBytes'] and digest(raw)==scope['deltaArchiveSHA256'],'exact actual delta archive')
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        members=archive.getmembers()
        need(len(members)==len(scope['deltaFiles']) and
             [r.name for r in members]==['new-'+str(i) for i in range(len(members))], 'exact delta member names/count')
        for item,row in zip(members,scope['deltaFiles'],strict=True):
            need(item.isreg() and not item.linkname and not item.pax_headers and
                 item.uid==item.gid==item.mtime==0 and item.mode==0o600 and item.size==row['new']['bytes'],
                 'ordinary exact delta member')
            need(digest(archive.extractfile(item).read())==row['new']['sha256'],'actual exact delta payload')
'''
    controller=controller[:a]+gate+controller[z:]
    controller=controller.replace("    previous = {'preflight': 'close-current-own', 'restore-trust': 'preflight', 'launch': 'restore-trust', 'post': 'launch'}.get(args.action)",
        "    previous = {'preflight':'close-current-own','stage':'preflight','verify':'stage','trust':'verify','launch':'trust','post':'launch'}.get(args.action)")
    need(controller.count("        data = (packet/'products.tar').read_bytes() if args.action=='stage' else b''")==1,'one actual inherited delta action payload')
    safety="""    proof=scope['exactActualShutdownPrerequisites']
    for row in proof['pins']:exact(row)
    sp=importlib.util.spec_from_file_location('same_actual_shutdown_source',json.loads((packet/'candidate.json').read_bytes())['preparer']['path'])
    module=importlib.util.module_from_spec(sp);sp.loader.exec_module(module)
    need(module.require_prior_shutdown()==proof,'same actual shutdown provenance, never live Root guest update')
"""
    need('import importlib.util' in controller,'existing controller source loader import')
    at=controller.index('    return ready, scope');controller=controller[:at]+safety+controller[at:]
    compile(controller,str(out/'control.py'),'exec')
    out.mkdir(mode=0o700);(out/'control.py').write_text(controller);(out/'products.tar').write_bytes(archive)
    (out/'health-root.sh').write_text(health);dump(out/'scope.json',scope)
    script_rows,sizes={},{}
    for action,script in scripts.items():
        result=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);need(result.returncode==0,'actual sh-n '+action)
        path=out/(action+'.sh');path.write_text(script);script_rows[action]=pin(path)
        (out/(action+'-syntax.stderr')).write_bytes(result.stderr)
        command=('sudo -k -S -p "" ' if action!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script)
        sizes[action]=len(command.encode());need(sizes[action]+10000<262144,'actual ARG_MAX reserve '+action)
    candidate=dict(schema='Future actual App35 persistent SSH App-only device delta packet v18',preparer=pin(__file__),
        scope=pin(out/'scope.json'),archive=pin(out/'products.tar'),controller=pin(out/'control.py'),scripts=script_rows,actions=list(scripts),
        runtimeCandidate=pin(runtime_path),appCandidate=pin(app_path),currentInstalledProductsPost=pin(POST),
        actualFullFiles=len(files),actualFullCodeDirectoryHashes=len(full),actualChangedFiles=len(changes),
        actualExistingFilesUpdated=scope['existingOwnFilesUpdated'],actualNewFilesAdded=scope['newOwnFilesAdded'],
        actualNewDirectoriesAdded=len(new_dirs),actualNewOwnedMutableCacheDirectories=0,actualNewTrustEntries=len(new_cd),actualNativeCDSubset=native_subset,
        continuingHumanAuthorization=scope['continuingHumanAuthorization'],bootSeconds=1791813884,
        requiresActualInitializerReadonlyAndNormalShutdown=True,guestHelperHasNoIPadTrustEntry=True,
        inheritedActualSignedRuntimeCDProof=signature_pin,actualSignedAppProductProof=pin(APP_PEER),
        actualSignedRuntimeProductProof=pin(RUNTIME_PEER),actualSingleNativeTrustMembershipQueryRequired=True,
        maximumQuotedCommandBytes=max(sizes.values()),quotedCommandBytes=sizes,
        closeOwnExternalWallSeconds=20,allOtherRemoteActionsExternalWallSeconds=45,transportTimeoutSeconds=55,
        priorAllInstalledProductsAndCurrentHealthActualPassed=True,allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True,
        sameDirectoryTemporaryReplacements=True,originalStable2sReadinessAndProcessCleanupRetained=True,
        deploymentCloseSignalOutputSuppressedUntilSignalsComplete=True,
        sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,nativeSandboxInitSuccessFabricated=False,
        basicSingleTouchOnly=True,panPinchRotationImplemented=False,
        actualVMConstructorExecuted=False,guestBootRequested=False,deviceOperations=0,trustCacheOperations=0,readyForDeviceExecution=False)
    dump(out/'candidate.json',candidate)
    pins=[pin(p)for p in sorted(out.iterdir())if p.is_file()]+[pin(__file__),pin(OLD/'candidate.json'),pin(OLD/'scope.json'),pin(OLD/'freeze.json'),
        pin(OLD/'control.py'),pin(OLD/'launch.sh'),pin(OLD/'post.sh'),pin(TEMPLATE/'scope.json'),pin(TEMPLATE/'control.py'),pin(TEMPLATE/'launch.sh'),pin(TEMPLATE/'post.sh'),pin(TEMPLATE/'freeze.json'),pin(base.HEALTH),pin(B/'independent27_device_product_verify_fast_v1.py'),
        pin(POST),post['request'],post['stdout'],post['stderr'],pin(runtime_path),pin(runtime_path.parent/'freeze.json'),
        pin(app_path),pin(app_path.parent/'freeze.json'),scope['continuingHumanAuthorization'],signature_pin,
        pin(APP_PEER),pin(APP_PEER.parent/'freeze.json'),pin(RUNTIME_PEER),pin(RUNTIME_PEER.parent/'freeze.json'),
        scope['factoryAttestationSource'],pin(N/'independent27-runtime-v5-factory-attestation-source-v1-attempt1/freeze.json')]
    pins += prerequisites['pins']+[pin(READONLY_PACKET/'freeze.json'),pin(NORMAL_PACKET/'freeze.json')]
    pins += [row['local']for row in files]+[row['old']for row in changes if row['old'] is not None]
    dump(out/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'),
        files=len(files),CDs=len(full),delta=len(changes),newTC=len(new_cd),maximumQuotedCommandBytes=max(sizes.values()))))

if __name__=='__main__':main()
