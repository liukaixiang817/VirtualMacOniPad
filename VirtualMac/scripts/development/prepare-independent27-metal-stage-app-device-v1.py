#!/usr/bin/env python3
"""HOST prepare exact actual Runtime10/App14 one-main delta on the current boot.

Actual product trees derive every replacement/addition and trust entry. Root
alone dispatches under continued authorization after independent review.
"""
import argparse
import copy
import importlib.util
import io
import json
import pathlib
import shlex
import subprocess
import sys
import tarfile

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-ssh-deferred-app-device-v1-attempt1'
TEMPLATE=N/'independent27-ssh-deferred-app-device-v1-attempt1'
POST=N/'independent27-app13-normal-guest-lifecycle-v9-attempt1/device-receipts/post/receipt.json'
STAGE='/private/var/mobile/Library/.VM27-independent27-metal-stage-app-stage-v1'
APP_PEER=None
RUNTIME_PEER=N/'independent27-runtime10-signed-delta-independent-peer-v1-attempt1/review.json'


def load(path,name):
    sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

base=load(TEMPLATE/'control.py','current_boot_delta_controller')
fast=load(B/'independent27_device_product_verify_fast_v1.py','current_boot_delta_fast')
pin,need,dump=base.pin,base.need,base.dump


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


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--app-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--app-peer',type=pathlib.Path,required=True);args=ap.parse_args()
    global APP_PEER
    APP_PEER=args.app_peer.resolve()
    out=args.output.resolve();need(out.parent==N and not out.exists(),'fresh concrete delta packet')
    runtime_path=args.runtime_candidate.resolve();app_path=args.app_candidate.resolve()
    for path in (runtime_path,app_path):frozen(path.parent)
    frozen(OLD);frozen(TEMPLATE)
    template_scope=json.loads((TEMPLATE/'scope.json').read_bytes())
    runtime=json.loads(runtime_path.read_bytes());app=json.loads(app_path.read_bytes())
    app_peer=json.loads(APP_PEER.read_bytes());runtime_peer=json.loads(RUNTIME_PEER.read_bytes())
    need(app_peer['signedCandidate']==pin(app_path) and app_peer['runtimeCandidate']==pin(runtime_path) and
         app_peer['findings']==[] and app_peer['finiteLocalScopePassed'] is True and
         runtime_peer['runtimeCandidate']==pin(runtime_path) and runtime_peer['passed'] is True and
         runtime_peer['findings']==[], 'actual current App14 and Runtime10 independent product peers')
    signature_pin=runtime['signatureVerification'];signature=json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True,
         'actual signed Runtime10 whole code-page and special-slot proof')
    old=json.loads((OLD/'scope.json').read_bytes());post=json.loads(POST.read_bytes())
    base.exact(post['request']);text=base.exact(post['stdout']).read_text();base.exact(post['stderr'])
    need(post['transportExit']==0 and 'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in text and
         'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in text and 'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF' in text,
         'actual current normal failure cleanup left all installed products exact/off')
    need(runtime['actualProductPreflightPassed'] is True and runtime['localCodeSigned'] is True and
         app['actualCodeSigned'] is True and runtime['sandboxProfileApplied'] is False and
         runtime['nativeSandboxApplyUnavailable']==45 and runtime['nativeSandboxInitSuccessFabricated'] is False,
         'actual signed products and truthful deferred sandbox')
    manifest=json.loads((runtime_path.parent/'manifest.json').read_bytes())
    cd_by_name={'runtime/'+row['path']:row['cdhash'] for row in manifest['files'] if row['kind']=='mach-o'}
    signature_by_name={'runtime/'+row['relativePath']:row for row in signature['actualSignedFiles']}
    need(set(signature_by_name)==set(cd_by_name) and all(signature_by_name[name]['cdhash']==value and
         signature_by_name[name]['allPrimaryPagesAndSpecialSlotsVerified'] is True for name,value in cd_by_name.items()),
         'every current runtime manifest code hash joins actual Runtime10 signature proof')
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
         'current App14 signed peer exactly joins finalized App file and code hash')
    new_dirs=[dict(archivePath=name,devicePath=(old['deviceRuntime']+name[len('runtime'):] if name.startswith('runtime') else old['deviceApp']+name[len('VirtualMacIndependent27.app'):]),mode=mode)
              for name,mode in sorted(directories.items()) if name not in old['directories']]
    need(all(name in directories and directories[name]==mode for name,mode in old['directories'].items()),'all existing directory contracts preserved')
    full=sorted(cd_by_name.values());new_cd=sorted(set(full)-set(old['trustCacheCDHashes']))
    need(len(full)==len(set(full)) and len(files)<=256+256 and changes and
         all(value in full for value in new_cd),'actual complete unique finalized code inventory and delta')
    need(len(changes)==1 and changes[0]['devicePath']==old['deviceAppMain'] and
         changes[0]['old']==old_by_name['VirtualMacIndependent27.app/VirtualMacIndependent27']['local'] and
         len(new_cd)==1 and new_cd==[app['actualSignature']['cdhash']] and not new_dirs and
         runtime_path==pathlib.Path(old['runtimeCandidate']['path']) and len(files)==len(old['files']) and
         len(full)==len(old['trustCacheCDHashes']), 'only actual new App14 main and its one code hash; runtime and resources unchanged')
    scope=copy.deepcopy(old)
    inherited={key:scope.pop(key) for key in ('currentBootTrustPlan','restoredExistingProductCDHashes','newProductCodeHashes','priorInitializationLaunch',
        'priorAppRegistration','historicalPriorBootInitializationOnly','inheritedActualSignedRuntimeCDProof',
        'inheritedActualSignedAppPeer','trustMembershipKnownBeforeDispatch','currentDeviceFacts','actualOwnAppPIDObserved') if key in scope}
    scope.update(schema='Actual independent27 App14 Metal stage diagnostic only-main signed product delta scope v1',
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
        initializationOnly=False,productInstallationPerformed=False,productUpdatesPerformed=True,
        backupOldOwnFilesAndLog=True,backupPriorOwnLogOnly=False,
        exactFullProductsAndSignedCDProofInherited=True,ownMacEventFilterContract=runtime['ownMacEventFilterContract'],
        inheritedActualSignedRuntimeCDProof=signature_pin,inheritedActualSignedAppPeer=pin(APP_PEER),
        actualSignedRuntimeIndependentPeer=pin(RUNTIME_PEER),
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
    scope['factoryAttestationSource']=pin(N/'independent27-runtime-v5-factory-attestation-source-v1-attempt1/candidate.json')
    scope['runtimeAllWholebytesUnchanged']=True
    scope['originalFactoryAttestationContractBodyInherited']=True
    scope['deploymentCloseSignalOutputSuppressedUntilSignalsComplete']=True
    scope['originalMainAppResourcesAllWholebytesUnchanged']=True
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
    before,after=fast.batch_check(old),fast.batch_check(scope)
    missing=''.join('[ ! -e '+shlex.quote(row['devicePath'])+' ] && [ ! -L '+shlex.quote(row['devicePath'])+' ]\n' for row in changes if row['old'] is None)
    missing+=''.join('[ ! -e '+shlex.quote(row['devicePath'])+' ] && [ ! -L '+shlex.quote(row['devicePath'])+' ]\n' for row in new_dirs)
    scripts={}
    close=prefix(0)+base.PROCESS_FUNCTIONS+'''own_close_status=0
cleanup_own >/dev/null 2>&1 || own_close_status=$?
[ "$own_close_status" = 0 ] || exit "$own_close_status"
'''+off()+"printf 'INDEPENDENT27_EXACT_CURRENT_OWN_APP_CHILD_CLOSED_NO_PRODUCT_WRITE\\n'\n"
    scripts['close-current-own']=wrap(close,0,20)
    health=base.HEALTH.read_text()
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
        else:stage+=f'[ ! -e {path} ] && [ ! -L {path} ]\n(umask 077; set -C; : > "$OWN_STAGE/backup-new-absent-{i}")\n'
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
    for row in new_dirs:
        path=shlex.quote(row['devicePath']);parent=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent))
        stage+=f'[ -d {parent} ] && [ ! -L {parent} ]\n[ "$(realpath {parent})" = {parent} ]\n[ ! -e {path} ] && [ ! -L {path} ]\nmkdir -m {row["mode"]:o} {path}\nchown 501:501 {path}\n'
    for row in changes:
        path=shlex.quote(row['devicePath']);i=row['index'];new_file=row['new']
        temporary=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-metal-stage-app-v1-'+str(i)+'.pending')))
        stage+=f'[ ! -e {temporary} ] && [ ! -L {temporary} ]\ncp "$OWN_STAGE/new-{i}" {temporary}\nchown 501:501 {temporary}\nchmod {row["mode"]:o} {temporary}\ncheck_own_file {temporary} {new_file["sha256"]} {new_file["bytes"]} {row["mode"]:o}\n'
        if row['old']:
            stage+=f'check_own_file {path} {row["old"]["sha256"]} {row["old"]["bytes"]} {row["mode"]:o}\nmv -f {temporary} {path}\n'
        else:stage+=f'[ ! -e {path} ] && [ ! -L {path} ]\nmv -n {temporary} {path}\n[ ! -e {temporary} ] && [ ! -L {temporary} ]\n'
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
    need(launch.count(before)==1,'one exact old full-product launch guard')
    launch=launch.replace(before,after,1)
    scripts['launch']=wrap(launch,501)
    post_script=(TEMPLATE/'post.sh').read_text().replace(template_scope['deviceStage'],STAGE)
    need(post_script.count(before.replace("'","'\"'\"'"))==1,'one inherited quoted full-product post guard')
    scripts['post']=post_script.replace(before.replace("'","'\"'\"'"),after.replace("'","'\"'\"'"),1)
    controller=(TEMPLATE/'control.py').read_text().replace(template_scope['deviceStage'],STAGE)
    controller=controller.replace("TRUST_ACTIONS = ('restore-trust',)","TRUST_ACTIONS = ('trust',)")
    controller=controller.replace("ACTIONS = ('close-current-own', 'preflight', 'restore-trust', 'launch', 'post')",
        "ACTIONS = ('close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')")
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
    candidate=dict(schema='Actual Runtime10 App14 Metal stage diagnostic only-main device delta packet v1',preparer=pin(__file__),
        scope=pin(out/'scope.json'),archive=pin(out/'products.tar'),controller=pin(out/'control.py'),scripts=script_rows,actions=list(scripts),
        runtimeCandidate=pin(runtime_path),appCandidate=pin(app_path),currentInstalledProductsPost=pin(POST),
        actualFullFiles=len(files),actualFullCodeDirectoryHashes=len(full),actualChangedFiles=len(changes),
        actualExistingFilesUpdated=scope['existingOwnFilesUpdated'],actualNewFilesAdded=scope['newOwnFilesAdded'],
        actualNewDirectoriesAdded=len(new_dirs),actualNewTrustEntries=len(new_cd),actualNativeCDSubset=native_subset,
        continuingHumanAuthorization=scope['continuingHumanAuthorization'],bootSeconds=1791813884,
        inheritedActualSignedRuntimeCDProof=signature_pin,inheritedActualSignedAppPeer=pin(APP_PEER),
        actualSignedRuntimeIndependentPeer=pin(RUNTIME_PEER),actualSingleNativeTrustMembershipQueryRequired=True,
        maximumQuotedCommandBytes=max(sizes.values()),quotedCommandBytes=sizes,
        closeOwnExternalWallSeconds=20,allOtherRemoteActionsExternalWallSeconds=45,transportTimeoutSeconds=55,
        priorAll255AndCurrentHealthActualPassed=True,allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True,
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
    pins += [row['local']for row in files]+[row['old']for row in changes if row['old'] is not None]
    dump(out/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'),
        files=len(files),CDs=len(full),delta=len(changes),newTC=len(new_cd),maximumQuotedCommandBytes=max(sizes.values()))))

if __name__=='__main__':main()
