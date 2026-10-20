#!/usr/bin/env python3
"""HOST prepare the actual Runtime65 same-task additive RAM mapping delta on the current boot.

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
OLD=N/'independent27-borrowed-host-input-newboot-device-v61-attempt1'
TEMPLATE=N/'independent27-child-usbh-offline-device-v24-attempt1'
POST=N/'independent27-app76-normal-guest-lifecycle-v70-attempt1/device-receipts/post/receipt.json'
POST_SHA256='c7edef0e7a2e21706d317fb1230a0fa62ef5e0aa3f0c572de5beca370359ac5c'
STAGE='/private/var/mobile/Library/.VM27-independent27-task-scoped-ram-stage-v62'
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



def stage_transport_controller(controller):
    edits=(
        ('def run_remote(script, data, root, password):',
         "def run_remote(script, data, root, password, transport_timeout=55):\n    need(transport_timeout in (55,100), 'only original55 or bounded stage100 SSH transport')"),
        ('capture_output=True, timeout=55)', 'capture_output=True, timeout=transport_timeout)'),
        ("'SSH 55-second timeout; no retry'", "'SSH '+str(transport_timeout)+'-second timeout; no retry'"),
        ("run_remote(script, data, args.action != 'launch', password)",
         "run_remote(script, data, args.action != 'launch', password, transport_timeout=100 if args.action=='stage' else 55)"))
    for before,after in edits:
        need(controller.count(before)==1,'one exact stage transport delta: '+before)
        controller=controller.replace(before,after,1)
    return controller


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--app-candidate',type=pathlib.Path,required=True)
    args=ap.parse_args()
    global APP_PEER,RUNTIME_PEER
    APP_PEER=args.app_candidate.resolve();RUNTIME_PEER=args.runtime_candidate.resolve()
    out=args.output.resolve();need(out.parent==N and not out.exists(),'fresh concrete delta packet')
    runtime_path=args.runtime_candidate.resolve();app_path=args.app_candidate.resolve()
    for path in (runtime_path,app_path):frozen(path.parent)
    frozen(OLD);frozen(TEMPLATE)
    template_scope=json.loads((TEMPLATE/'scope.json').read_bytes())
    runtime=json.loads(runtime_path.read_bytes());app=json.loads(app_path.read_bytes())
    need(app['actualCodeSigned'] is True and app['runtimeCandidate']==pin(runtime_path) and
         runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True,
         'actual signed App and actual signed Runtime product proofs; repeated peers omitted at user request')
    app_peer={'actualSignature':app['actualSignature']}
    old=json.loads((OLD/'scope.json').read_bytes())
    app_input=json.loads(base.exact(app['sourceCandidate']).read_bytes())
    main21=json.loads(base.exact(app_input['sourceCandidate']).read_bytes())
    need(app_input['actualUnchangedCompiledObjects']==34 and app_input['actualMain21ObjectReused'] is True and app_input['actualMain21AndOther33CompiledObjectsWholeUnchanged'] is True,'actual34 Main21 App76 objects whole with only new Runtime65 anchor')
    need(app_input['genuineSSHRegistrationRouteEnabled'] is False and app_input['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and app_input['actualMain20UIAndSSHDeferralPreserved'] is True,'Main20 display exposure and user-requested guest SSH deferral preserved')
    need(main21['rawDiskThreadPoolAttachmentContract']==app_input['rawDiskThreadPoolAttachmentContract'],'actual compiled Main21 raw-disk attachment contract')
    need(app_input['sourceCandidate']==old['appMain21SourceAndObjectCandidate'] and main21['actualRuntimeCandidate']==json.loads(base.exact(main21['baselineCompiledAppCandidate']).read_bytes())['actualRuntimeCandidate'],'same actual compiled Main21 source and original Runtime43 raw-disk constructor basis')
    raw_contract=main21['rawDiskThreadPoolAttachmentContract']
    need(raw_contract['parentOriginalDescriptorBackendType']==1 and raw_contract['actualChildEncodedBackend']==3 and all(raw_contract[k] is True for k in ('onlyIndependent27OrdinaryRawDiskImgChanged','otherBackendPublicInitializationWholeUnchanged','cachingAutomatic0AndFullSynchronization1Preserved','rootStorageRole1Preserved','originalRawDiskImageFormatAndOwnedFDThreadPoolIOSelected','noDI2SuccessFabricated','noMacOS13Fallback','missingClassesOrMethodsOrActualInitializationErrorsRefuse','allThreeClassesMustBelongToActualVZ27Image','descriptorAndDiskReleasedOnEveryPath','originalFactoryStronglyOwnsDisk','autoreleasedFactoryResultRetainedToOriginalPlusOne','allOtherMain20CodeWholeUnchanged','main20URLDisplayAndSSHDeferralWholeUnchanged','noRuntimeOrChildMachineCodeChanged','actualGuestIOOrBootNotYetExecuted')),'original typed raw Disk image/FD/ThreadPool selection, refusal and unchanged UI/SSH/ownership')
    base.exact(main21['originalParentAndChildBasis'])
    signature_pin=runtime['signatureVerification'];signature=json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True,
         'actual signed current Runtime whole code-page and special-slot proof')
    post=json.loads(POST.read_bytes())
    need(pin(POST)['sha256']==POST_SHA256 and post['transportExit']==0 and post['finishedUTC']=='2026-10-18T00:58:30.436705+00:00','actual Normal70 post0 binds this new product baseline')
    generation=load(B/'independent27_initializer_log_generation_v1.py','actual_current_log_generation')
    actual_generation=generation.actual_post_log_generation(OLD/'candidate.json',OLD/'device-receipts/launch/receipt.json',OLD/'device-receipts/post/receipt.json')
    BOOT=actual_generation['bootSeconds'];BOOT_UUID=actual_generation['bootSessionUUID'];LOG_IDENTITY=actual_generation['identity'];LOG_DEVICE_INODE=':'.join(LOG_IDENTITY.split(':')[:2])
    need(BOOT==1792161311 and BOOT_UUID=='C7D63D1F-86E9-4224-A1C7-108F02E91942', 'actual currently installed newboot initialization provenance')

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
    shader_name='runtime/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/default.metallib'
    need({row['archivePath'] for row in files}==set(old_by_name) and not new_dirs and
         len(files)==len(old['files']) and len(full)==len(old['trustCacheCDHashes']) and
         all(row['old'] is not None for row in changes),
         'exact existing shader/product replacement with no added/deleted file or directory')
    need(len(files)==259 and len(full)==144 and sum(row['archivePath'].startswith('VirtualMacIndependent27.app/') for row in files)==104 and len(new_cd)==4,'actual installed259 files including104 App files and144 code hashes; only4 new iPad trust entries')
    need(all(row['archivePath'].startswith('runtime/') or row['archivePath']=='VirtualMacIndependent27.app/VirtualMacIndependent27' for row in changes),'only actual CPU runtime delta and Main21 App anchor may change')
    need(all(row['old'] is None or row['new']['sha256']!=row['old']['sha256'] for row in changes),
         'each deployment payload has an actual whole-file change or proven absent new resource')
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
    scope['historicalRuntime64BorrowedHostInputV1Verification']=runtime['historicalRuntime64BorrowedHostInputV1Verification']
    for key in ('cpu26OtherObjectsWholeRuntime63','consumerProvidersWholeRuntime63','currentConsumerWholeR63','factory7AndGICEngine5CurrentObjects','factory7ActualChangedObject','bootstrap26ActualChangedObject','gicEngine5ObjectWholeRuntime63','mandatory4ObjectWholeRuntime63','currentRuntimeConsumerWholeUnchangedFromRuntime63Required','currentRuntimeConsumerWholeUnchangedFromRuntime63'):
        scope.pop(key,None)
    scope['historicalRuntime63SerializedWakeV1Verification']=runtime['historicalRuntime63SerializedWakeV1Verification']
    for key in ('cpu28OtherObjectsWholeRuntime62','consumerProvidersWholeRuntime62','currentConsumerWholeR62','factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime62','gicEngine5ObjectWholeRuntime62','factory6ObjectWholeRuntime62','bootstrap25ObjectWholeRuntime62','mandatory4ObjectWholeRuntime62','currentRuntimeConsumerWholeUnchangedFromRuntime62Required','currentRuntimeConsumerWholeUnchangedFromRuntime62'):
        scope.pop(key,None)
    scope['historicalRuntime62OwnedMandatoryFailureV1Verification']=runtime['historicalRuntime62OwnedMandatoryFailureV1Verification']
    for key in ('cpu28OtherObjectsWholeRuntime61','consumerProvidersWholeRuntime61','currentConsumerWholeR61','factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime61','gicEngine5ObjectWholeRuntime61','factory6ObjectWholeRuntime61','bootstrap25ObjectWholeRuntime61','currentRuntimeConsumerWholeUnchangedFromRuntime61Required','currentRuntimeConsumerWholeUnchangedFromRuntime61'):
        scope.pop(key,None)
    scope['historicalRuntime61AdditiveRAMV1Verification']=runtime['historicalRuntime61AdditiveRAMV1Verification']
    for key in ('cpu26OtherObjectsWholeRuntime60','consumerProvidersWholeRuntime60','currentConsumerWholeR60','factory6AndGICEngine5CurrentObjects','gicEngine5ObjectWholeRuntime60','factory6ActualChangedObject','bootstrap25ActualChangedObject','currentRuntimeConsumerWholeUnchangedFromRuntime60Required','currentRuntimeConsumerWholeUnchangedFromRuntime60'):
        scope.pop(key,None)
    scope['historicalRuntime60PinnedRAMReadV1Verification']=runtime['historicalRuntime60PinnedRAMReadV1Verification']
    for key in ('cpu28OtherObjectsWholeRuntime59','consumerProvidersWholeRuntime59','currentConsumerWholeR59','factory5AndGICEngine5ObjectsWholeRuntime59','currentRuntimeConsumerWholeUnchangedFromRuntime59Required','currentRuntimeConsumerWholeUnchangedFromRuntime59','factory5ObjectWholeRuntime43'):
        scope.pop(key,None)
    scope['historicalRuntime59DisabledAMXStateV1Verification']=runtime['historicalRuntime59DisabledAMXStateV1Verification']
    for key in ('cpu28OtherObjectsWholeRuntime58','consumerProvidersWholeRuntime58','currentConsumerWholeR58','factory5AndGICEngine5ObjectsWholeRuntime58','currentRuntimeConsumerWholeUnchangedFromRuntime58Required','currentRuntimeConsumerWholeUnchangedFromRuntime58'):
        scope.pop(key,None)
    scope['historicalRuntime58EncodedExitV1Verification']=runtime['historicalRuntime58EncodedExitV1Verification']
    for key in ('cpu28OtherObjectsWholeRuntime57','consumerProvidersWholeRuntime57','currentConsumerWholeR57','factory5AndGICEngine5ObjectsWholeRuntime57','currentRuntimeConsumerWholeUnchangedFromRuntime57Required','currentRuntimeConsumerWholeUnchangedFromRuntime57'):
        scope.pop(key,None)
    scope['historicalRuntime57DisabledAMXConfigV3Verification']=runtime['historicalRuntime57DisabledAMXConfigV3Verification']
    for key in ('cpu28OtherObjectsWholeRuntime56','consumerProvidersWholeRuntime56','currentConsumerWholeR56','factory5AndGICEngine5ObjectsWholeRuntime56','currentRuntimeConsumerWholeUnchangedFromRuntime56Required','currentRuntimeConsumerWholeUnchangedFromRuntime56'):
        scope.pop(key,None)
    scope['historicalRuntime56DisabledAMXConfigV2Verification']=runtime['historicalRuntime56DisabledAMXConfigV2Verification']
    for key in ('cpu28OtherObjectsWholeRuntime55','consumerProvidersWholeRuntime55','currentConsumerWholeR55','factory5AndGICEngine5ObjectsWholeRuntime55','currentRuntimeConsumerWholeUnchangedFromRuntime55Required','currentRuntimeConsumerWholeUnchangedFromRuntime55'):
        scope.pop(key,None)
    scope['historicalRuntime55DisabledAMXConfigVerification']=runtime['historicalRuntime55DisabledAMXConfigVerification']
    for key in ('cpu28OtherObjectsWholeRuntime54','consumerProvidersWholeRuntime54','currentConsumerWholeR54','factory5AndGICEngine5ObjectsWholeRuntime54','currentRuntimeConsumerWholeUnchangedFromRuntime54Required','currentRuntimeConsumerWholeUnchangedFromRuntime54'):
        scope.pop(key,None)
    scope['historicalRuntime54Raw7FaultOpcodeSnapshotVerification']=runtime['historicalRuntime54Raw7FaultOpcodeSnapshotVerification']
    for key in ('cpu28OtherObjectsWholeRuntime53','consumerProvidersWholeRuntime53','currentConsumerWholeR53','factory5AndGICEngine5ObjectsWholeRuntime53','currentRuntimeConsumerWholeUnchangedFromRuntime53Required','currentRuntimeConsumerWholeUnchangedFromRuntime53'):
        scope.pop(key,None)
    scope['historicalRuntime53KernelTTBR1SnapshotVerification']=runtime['historicalRuntime53KernelTTBR1SnapshotVerification']
    for key in ('cpu28OtherObjectsWholeRuntime52','consumerProvidersWholeRuntime52','currentConsumerWholeR52','factory5AndGICEngine5ObjectsWholeRuntime52','currentRuntimeConsumerWholeUnchangedFromRuntime52Required','currentRuntimeConsumerWholeUnchangedFromRuntime52'):
        scope.pop(key,None)
    scope['historicalRuntime52Raw7UndefinedInjectionVerification']=runtime['historicalRuntime52Raw7UndefinedInjectionVerification']
    for key in ('cpu28OtherObjectsWholeRuntime51','consumerProvidersWholeRuntime51','currentConsumerWholeR51','factory5AndGICEngine5ObjectsWholeRuntime51','currentRuntimeConsumerWholeUnchangedFromRuntime51Required','currentRuntimeConsumerWholeUnchangedFromRuntime51'):
        scope.pop(key,None)
    scope['historicalRuntime51NativePACServiceVerification']=runtime['historicalRuntime51NativePACServiceVerification']
    for key in ('cpu28OtherObjectsWholeRuntime50','consumerProvidersWholeRuntime50','currentConsumerWholeR50','factory5AndGICEngine5ObjectsWholeRuntime50','currentRuntimeConsumerWholeUnchangedFromRuntime50Required','currentRuntimeConsumerWholeUnchangedFromRuntime50'):
        scope.pop(key,None)
    scope['historicalRuntime50EL1VirtualTimerPagewalkVerification']=runtime['historicalRuntime50EL1VirtualTimerPagewalkVerification']
    for key in ('cpu27OtherObjectsWholeRuntime49','consumerProvidersWholeRuntime49','currentConsumerWholeR49','factory5ObjectWholeRuntime49','currentRuntimeConsumerWholeUnchangedFromRuntime49Required','currentRuntimeConsumerWholeUnchangedFromRuntime49'):
        scope.pop(key,None)
    scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']=runtime['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']
    for key in ('cpu28OtherObjectsWholeRuntime48','consumerProvidersWholeRuntime48','currentConsumerWholeR48','factory5AndGICEngine4ObjectsWholeRuntime48','currentRuntimeConsumerWholeUnchangedFromRuntime48Required','currentRuntimeConsumerWholeUnchangedFromRuntime48'):
        scope.pop(key,None)
    scope['historicalRuntime48VirtualTimerGICVerification']=runtime['historicalRuntime48VirtualTimerGICVerification']
    for key in ('cpu27OtherObjectsWholeRuntime47','consumerProvidersWholeRuntime47','currentConsumerWholeR47','factory5ObjectWholeRuntime47','currentRuntimeConsumerWholeUnchangedFromRuntime47Required','currentRuntimeConsumerWholeUnchangedFromRuntime47'):
        scope.pop(key,None)
    scope['historicalRuntime47BoundedWakePostSnapshotVerification']=runtime['historicalRuntime47BoundedWakePostSnapshotVerification']
    for key in ('cpu28OtherObjectsWholeRuntime46','consumerProvidersWholeRuntime46','currentConsumerWholeR46','factory5AndGICEngine3ObjectsWholeRuntime46','currentRuntimeConsumerWholeUnchangedFromRuntime46Required','currentRuntimeConsumerWholeUnchangedFromRuntime46'):
        scope.pop(key,None)
    scope['historicalRuntime46InternalRunSparseVerification']=runtime['historicalRuntime46InternalRunSparseVerification']
    for key in ('cpu28OtherObjectsWholeRuntime45','consumerProvidersWholeRuntime45','currentConsumerWholeR45','factory5AndGICEngine3ObjectsWholeRuntime45','currentRuntimeConsumerWholeUnchangedFromRuntime45Required','currentRuntimeConsumerWholeUnchangedFromRuntime45'):
        scope.pop(key,None)
    scope['historicalRuntime45WFxCounterReaderVerification']=runtime['historicalRuntime45WFxCounterReaderVerification']
    for key in ('cpu28OtherObjectsWholeRuntime44','consumerProvidersWholeRuntime44','currentConsumerWholeR44','factory5AndGICEngine3ObjectsWholeRuntime44','currentRuntimeConsumerWholeUnchangedFromRuntime44Required','currentRuntimeConsumerWholeUnchangedFromRuntime44'):
        scope.pop(key,None)
    scope['historicalRuntime44WFxWaitVerification']=runtime['historicalRuntime44WFxWaitVerification']
    for key in ('cpu27OtherObjectsWholeRuntime43','consumerProvidersWholeRuntime43','currentConsumerWholeR43','currentRuntimeConsumerWholeUnchangedFromRuntime43Required','currentRuntimeConsumerWholeUnchangedFromRuntime43'):
        scope.pop(key,None)
    scope['historicalMain20AppDeployment']={key:scope.pop(key) for key in ('appMain20SourceCandidate','appMain20CompiledObjectCandidate','urlDisplayPresentationContract') if key in scope}
    history_keys=('onlyNewAppResourceIsExactSignedMacOSGuestSSHHelper','appCodeResourcesUpdatedToSealExactGuestHelper',
        'newGuestHelperResource','newGuestHelperRequiresExactAbsentPathAndNoOverwrite',
        'newGuestToolsDirectoryRequiresExactAbsenceBeforeCreation','onlyNewDirectoryIsGuestToolsMode755Owner501',
        'currentInstalledProductsPartialState','originalStageFailurePreserved','recoveryOnlyProductReplacement',
        'recoveryDoesNotReplayOriginalStage','originalStageCompleteNotFabricated','recoveryProductCopiesOrPermissionChanges',
        'originalDeltaBackupDirectory','originalDeltaBackupsRetained','currentInstalledProductsStage',
        'originalFailedStageReceipt','originalTrustActionNeverDispatched','currentBootTrustInventory','currentInstalledProductsActualReadonly','currentInstalledProductScope','actualReadonlyOwnLogObservation','newLogIdentityMustBeActuallyCapturedBeforeLaunch','currentBootAndLogBindingReplacesHistoricalInitializerGeneration','initialCurrentBootNativePresentCodeHashes')
    scope['historicalCurrentBaselineDeployment']=dict(scope=pin(OLD/'scope.json'),
        candidate=pin(OLD/'candidate.json'),launch=actual_generation['initializerLaunch'],
        post=actual_generation['initializerPost'],historicalFacts={key:scope.pop(key) for key in history_keys if key in scope})
    inherited={key:scope.pop(key) for key in ('currentBootTrustPlan','restoredExistingProductCDHashes','newProductCodeHashes','priorInitializationLaunch',
        'priorAppRegistration','historicalPriorBootInitializationOnly','inheritedActualSignedRuntimeCDProof',
        'actualSignedAppProductProof','trustMembershipKnownBeforeDispatch','currentDeviceFacts','actualOwnAppPIDObserved') if key in scope}
    scope.update(schema='Actual Runtime65 same-task additive RAM mapping scope v62',
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
        bootSeconds=BOOT,bootSessionUUID=BOOT_UUID,guestBootRequested=False,diagnosticDirectoryAndOwnLogWritesOnly=False,
        systemSandboxFilesModified=False,deviceSystemFilesModified=False,perPIDKernelPrivilegeModification=False,
        originalChildAndVMMCodePreserved=False,ordinaryUIKitBasicOnly=True,
        fullMacRawHIDImplemented=False,panPinchRotationImplemented=False,
        cleanupRequiresExactPIDUIDPathPPIDAndStartTimeHash=True,
        initializationExternalWallSeconds=45,updateExternalWallSeconds=90,
        deploymentStageExternalWallSeconds=90,deploymentStageTransportTimeoutSeconds=100,
        nonStageTransportTimeoutSeconds=55,nonStageNonCloseExternalWallSeconds=45)
    scope['factoryAttestationSource']=pin(N/'independent27-runtime-v5-factory-attestation-source-v1-attempt1/candidate.json')
    scope['appMain21SourceAndObjectCandidate']=app_input['sourceCandidate']
    scope['rawDiskThreadPoolAttachmentContract']=main21['rawDiskThreadPoolAttachmentContract']
    scope['rawDiskOriginalParentAndChildBasis']=main21['originalParentAndChildBasis']
    scope['urlDisplayPresentationContract']=app_input['urlDisplayPresentationContract']
    scope['actualMain20UIAndSSHDeferralPreserved']=True
    scope['runtimeProductAndAllFilesWholeUnchanged']=False
    scope['guestDiskFileIncludedInDeployment']=False
    scope['guestSSHExplicitlyDeferredForFirstBasicGuestBoot']=True
    scope['guestSSHRegistrationOrServiceInvokedByThisFirstBoot']=False
    scope['currentRuntimeConsumerWholeUnchangedFromRuntime64Required']=True
    need(runtime['cpuProviderAndAll29CPUObjectsWholeR41'] is False and 'cpuProviderWholeR41' not in runtime,'prior whole-R41 CPU proof is historical after FactoryV5 replacement')
    scope['cpuProviderAndAll29CPUObjectsWholeR41']=False
    scope['runtimeAllWholebytesUnchanged']=False
    scope['originalChildAllWholebytesUnchanged']=not any(row['archivePath'].startswith('runtime/child-flat/') for row in changes)
    scope['originalParentAllWholebytesUnchanged']=not any(row['archivePath'].startswith('runtime/parent-flat/') for row in changes)
    scope['gicBaseAlignmentSourceCandidate']=runtime['root20Candidate']
    scope['childVirtualAddressEntitlementContract']=runtime['extendedVirtualAddressingContract']
    # The existing GPU permission contract is historical and remains unchanged.
    scope['gpuUserClientEntitlementContract']=runtime['gpuUserClientEntitlementContract']
    scope['child15PermissionsSourceCandidate']=runtime['child15PermissionsCandidate']
    scope['gpuUserClientEntitlementChangesPlanned']=False
    scope['PGResourceSourceCandidate']=runtime['PGResourceSourceCandidate']
    scope['PGResourceLookupContract']=runtime['PGResourceLookupContract']
    scope['genuineResources']=runtime['genuineResources']
    scope['runtime25AddressCapabilityDeltaVerification']=runtime['runtime25AddressCapabilityDeltaVerification']
    scope['runtime26UnifiedStorageDeltaVerification']=runtime['runtime26UnifiedStorageDeltaVerification']
    scope['pvgUnifiedStorageCandidate']=runtime['pvgUnifiedStorageCandidate']
    scope['pvgUnifiedStorageContracts']=runtime['pvgUnifiedStorageContracts']
    scope['pvgUnifiedStorageEvidence']=runtime['pvgUnifiedStorageEvidence']
    scope['childErrorReasonDiagnosticCandidate']=runtime['childErrorReasonDiagnosticCandidate']
    scope['childErrorReasonDiagnosticContract']=runtime['childErrorReasonDiagnosticContract']
    scope['runtime27ErrorReasonDeltaVerification']=runtime['runtime27ErrorReasonDeltaVerification']
    scope['historicalChildVMInitializationDiagnosticCandidate']=runtime['historicalChildVMInitializationDiagnosticCandidate']
    scope['historicalChildVMInitializationDiagnosticContract']=runtime['historicalChildVMInitializationDiagnosticContract']
    scope.pop('childVMInitializationDiagnosticCandidate',None)
    scope.pop('childVMInitializationDiagnosticContract',None)
    scope['childVMExceptionBoundaryCandidate']=runtime['childVMExceptionBoundaryCandidate']
    scope['childVMExceptionBoundaryContract']=runtime['childVMExceptionBoundaryContract']
    scope['runtime29VMExceptionBoundaryDeltaVerification']=runtime['runtime29VMExceptionBoundaryDeltaVerification']
    scope['childUSBHAdapterCandidate']=runtime['childUSBHAdapterCandidate']
    scope['childUSBHAdapterContract']=runtime['childUSBHAdapterContract']
    scope['runtime31ChildUSBHDeltaVerification']=runtime['runtime31ChildUSBHDeltaVerification']
    scope['cpuNativeDistinctSlotsCandidate']=runtime['cpuNativeDistinctSlotsCandidate']
    scope['cpuNativeDistinctSlotsContract']=runtime['cpuNativeDistinctSlotsContract']
    scope['runtime32CPUSlotsDeltaVerification']=runtime['runtime32CPUSlotsDeltaVerification']
    scope['cpuControlFieldsCandidate']=runtime['cpuControlFieldsCandidate']
    scope['cpuControlFieldsContract']=runtime['cpuControlFieldsContract']
    scope['runtime33CPUStartupDeltaVerification']=runtime['runtime33CPUStartupDeltaVerification']
    scope['cpuPublicAPIFailureDiagnosticsCandidate']=runtime['cpuPublicAPIFailureDiagnosticsCandidate']
    scope['cpuPublicAPIFailureDiagnosticsContract']=runtime['cpuPublicAPIFailureDiagnosticsContract']
    scope['cpuStartupISAR2Candidate']=runtime['cpuStartupISAR2Candidate']
    scope['cpuStartupISAR2Contract']=runtime['cpuStartupISAR2Contract']
    scope['runtime34CPUStartupISAR2DeltaVerification']=runtime['runtime34CPUStartupISAR2DeltaVerification']
    scope['cpuSCXTFeatureGuardCandidate']=runtime['cpuSCXTFeatureGuardCandidate']
    scope['cpuSCXTFeatureGuardContract']=runtime['cpuSCXTFeatureGuardContract']
    scope['childSCXTGuardRecipe']=runtime['childSCXTGuardRecipe']
    scope['runtime34CPUStartupSCXTDeltaVerification']=runtime['runtime34CPUStartupSCXTDeltaVerification']
    scope['cpuReservedZeroCandidate']=runtime['cpuReservedZeroCandidate']
    scope['cpuReservedZeroContract']=runtime['cpuReservedZeroContract']
    scope['cpuPMUDisabledGuardContract']=runtime['cpuPMUDisabledGuardContract']
    scope['childReservedZeroRouteRecipe']=runtime['childReservedZeroRouteRecipe']
    scope['runtime35CPUReservedZeroDeltaVerification']=runtime['runtime35CPUReservedZeroDeltaVerification']
    scope['nativeRunAdmissionDiagnosticsCandidate']=runtime['nativeRunAdmissionDiagnosticsCandidate']
    scope['nativeRunAdmissionDiagnosticsContract']=runtime['nativeRunAdmissionDiagnosticsContract']
    scope['runtime36NativeRunAdmissionDiagnosticDeltaVerification']=runtime['runtime36NativeRunAdmissionDiagnosticDeltaVerification']
    scope['cpuISAProfileCandidate']=runtime['cpuISAProfileCandidate']
    scope['cpuISAProfileContract']=runtime['cpuISAProfileContract']
    scope['runtime37CPUISAProfileDeltaVerification']=runtime['runtime37CPUISAProfileDeltaVerification']
    for key in ('consumerStdioInheritanceCandidate','consumerStdioInheritanceContract','runtime41ConsumerStdioInheritanceDeltaVerification','actualConsumerExports','actualConsumerImports','actualConsumerLoads','actualConsumerAddedImports','consumerFourOwnDependencyLoadsNormalizedToBaselineLoaderPath','cpu25OtherObjectsWholeRuntime64','consumerProvidersWholeRuntime64','currentConsumerWholeR64','factory8AndGICEngine5CurrentObjects','gicEngine5ObjectWholeRuntime64','factory8ActualChangedObject','bootstrap27ActualChangedObject','production7ActualChangedObject','mandatory4ObjectWholeRuntime64'):
        scope[key]=runtime[key]
    need(runtime['cpuVirtualTimerGICContractAppliesToHistoricalFunctionalDeltaOnly'] is True and runtime['currentDiagnosticMaximumExistingPrepareSystemNative8Calls']==1,'old Life35 no-new-native8 contract is source-scoped history; current diagnostic permits atmost one existing typed missing-bank sync')
    scope['cpuVirtualTimerGICContractAppliesToHistoricalFunctionalDeltaOnly']=True
    scope['currentDiagnosticMaximumExistingPrepareSystemNative8Calls']=1
    need(runtime['historicalLife35PPI26RouteWasArchitecturallyIncorrect'] is True and runtime['historicalLife35PPI26ContractIsNotCurrentEL1VirtualTimerEvidence'] is True,'old Life35 PPI26 mapping is explicitly incorrect history, not current EL1 virtual-timer support')
    scope['historicalLife35PPI26RouteWasArchitecturallyIncorrect']=True
    scope['historicalLife35PPI26ContractIsNotCurrentEL1VirtualTimerEvidence']=True
    scope['cpuPostWakeRegisterCodeSnapshotContractAppliesToHistoricalDiagnosticDeltaOnly']=True
    need(runtime['cpuPostWakeRegisterCodeSnapshotContractAppliesToHistoricalDiagnosticDeltaOnly'] is True,'old MMUon-unknown diagnostic contract describes its historical source delta only')
    scope['officialSDKTimerInterruptIDs']=runtime['officialSDKTimerInterruptIDs']
    scope['officialARMTranslationGuideURL']=runtime['officialARMTranslationGuideURL']
    scope['officialARMNonLPA2DescriptorFormatsURL']=runtime['officialARMNonLPA2DescriptorFormatsURL']
    need(runtime['cpuEL1VirtualTimerPagewalkContractAppliesToHistoricalDeltaOnly'] is True and runtime['currentPACServiceMaximumExistingNative8Calls']==3,'prior source-scoped pagewalk proof preserved; current genuine PAC service bounded by three existing native8 calls')
    scope['cpuEL1VirtualTimerPagewalkContractAppliesToHistoricalDeltaOnly']=True
    scope['currentPACServiceMaximumExistingNative8Calls']=3
    need(runtime['currentRaw7InjectionMaximumExistingNative8Calls']==1,'new raw7 injection uses atmost one existing bank1 native8 sync')
    scope['currentRaw7InjectionMaximumExistingNative8Calls']=1
    old_dependency_proof=next(row['local']for row in old['files']if row['archivePath']=='runtime/Independent27ActualDependencyProof.json')
    need(runtime['baselineDependencyProofReferencedWithoutRecursiveInline']==old_dependency_proof,'dependency history is the exact installed baseline proof pin')
    scope['baselineDependencyProofReferencedWithoutRecursiveInline']=runtime['baselineDependencyProofReferencedWithoutRecursiveInline']
    scope['currentDependencyProofFile']=next(row['local']for row in files if row['archivePath']=='runtime/Independent27ActualDependencyProof.json')
    need(runtime['cpuKernelTTBR1SnapshotContractAppliesToHistoricalDiagnosticDeltaOnly'] is True,'prior x2+x19 kernel budget is historical source delta; new faultPC/wake budget uses current contract')
    scope['cpuKernelTTBR1SnapshotContractAppliesToHistoricalDiagnosticDeltaOnly']=True
    need(runtime['cpuRaw7FaultOpcodeSnapshotContractAppliesToHistoricalDiagnosticDeltaOnly'] is True,'prior no-write raw7 diagnostic contract is historical; current functional delta performs exact guarded disabled-control GPR/PC updates')
    scope['cpuRaw7FaultOpcodeSnapshotContractAppliesToHistoricalDiagnosticDeltaOnly']=True
    need(runtime['cpuDisabledAMXConfigContractAppliesToHistoricalV1DeltaOnly'] is True,'prior disabled AMX V1 proof describes its historical source delta; present V2 corrects guarded active metadata getter and first-unhandled sample')
    scope['cpuDisabledAMXConfigContractAppliesToHistoricalV1DeltaOnly']=True
    need(runtime['cpuDisabledAMXConfigV2ContractAppliesToHistoricalV2DeltaOnly'] is True,'prior V2 zero-only contract is historical delta; current V3 is exact0/100 read-zero disabled profile')
    scope['cpuDisabledAMXConfigV2ContractAppliesToHistoricalV2DeltaOnly']=True
    need(runtime['cpuDisabledAMXConfigV3ContractAppliesToHistoricalV3DeltaOnly'] is True,'prior V3 disabled-configuration contract describes historical delta; present CPU adds genuine ABI14 encoded raw8 decoding')
    scope['cpuDisabledAMXConfigV3ContractAppliesToHistoricalV3DeltaOnly']=True
    need(runtime['cpuEncodedExitV1ContractAppliesToHistoricalV1DeltaOnly'] is True,'prior encoded decoder contract describes its historical delta; present CPU adds exact disabled AMX state read route6')
    scope['cpuEncodedExitV1ContractAppliesToHistoricalV1DeltaOnly']=True
    need(runtime['cpuDisabledAMXStateV1ContractAppliesToHistoricalV1DeltaOnly'] is True and runtime['historicalReaderGlobalVMOperationGuardsApplyToPriorSourceDeltasOnly'] is True,'prior source contracts requiring global VM operation are historical; present reader uses retained CPU/post/RAM mutation exclusion plus Registry then VM locks')
    scope['cpuDisabledAMXStateV1ContractAppliesToHistoricalV1DeltaOnly']=True
    scope['historicalReaderGlobalVMOperationGuardsApplyToPriorSourceDeltasOnly']=True
    need(runtime['cpuPinnedRAMReadV1ContractAppliesToHistoricalV1DeltaOnly'] is True and runtime['factory5WholeClaimsApplyToHistoricalSourceDeltasOnly'] is True,'prior RAM immutability/Factory5 whole claims apply only to historical deltas; current additive3-object scope uses Factory6 and Bootstrap25')
    scope['cpuPinnedRAMReadV1ContractAppliesToHistoricalV1DeltaOnly']=True
    scope['factory5WholeClaimsApplyToHistoricalSourceDeltasOnly']=True
    need(runtime['cpuAdditiveRAMV1ContractAppliesToHistoricalV1DeltaOnly'] is True,'prior additive3-object contract describes its source delta; present MandatoryField diagnostics preserve those functional paths whole')
    scope['cpuAdditiveRAMV1ContractAppliesToHistoricalV1DeltaOnly']=True
    need(runtime['cpuOwnedMandatoryFailureV1ContractAppliesToHistoricalV1DeltaOnly'] is True,'prior MandatoryField1-object contract is historical; present Life51 serializes real wake and retains Mandatory4 whole')
    scope['cpuOwnedMandatoryFailureV1ContractAppliesToHistoricalV1DeltaOnly']=True
    need(runtime['cpuSerializedWakeV1ContractAppliesToHistoricalV1DeltaOnly'] is True and runtime['factory6AndBootstrap25WholeClaimsApplyToHistoricalSourceDeltasOnly'] is True,'prior serialized1+28 and Factory6/Bootstrap25 whole claims are historical; current host input changes Life52 Factory7 Bootstrap26')
    scope['cpuSerializedWakeV1ContractAppliesToHistoricalV1DeltaOnly']=True
    scope['factory6AndBootstrap25WholeClaimsApplyToHistoricalSourceDeltasOnly']=True
    need(runtime['cpuBorrowedHostInputV1ContractAppliesToHistoricalV1DeltaOnly'] is True and runtime['additiveRAMCreatorPthreadWholeClaimsApplyToHistoricalSourceDeltasOnly'] is True,'prior borrowed3+26 and creator-pthread mapping claims are historical; current task scope changes four objects only')
    scope['cpuBorrowedHostInputV1ContractAppliesToHistoricalV1DeltaOnly']=True
    scope['additiveRAMCreatorPthreadWholeClaimsApplyToHistoricalSourceDeltasOnly']=True
    for key in ('cpuTaskScopedRAMV1Candidate','cpuTaskScopedRAMV1Contract','runtime64CPUTaskScopedRAMV1DeltaVerification','cpuTaskScopedRAMSourcePlan'):
        scope[key]=runtime[key]
    task_plan=json.loads(base.exact(scope['cpuTaskScopedRAMSourcePlan']).read_bytes())
    for key in task_plan['proofs']:scope[key]=runtime[key]
    for key in ('cpuBorrowedHostInputV1Candidate','cpuBorrowedHostInputV1Contract','runtime63CPUBorrowedHostInputV1DeltaVerification','cpuBorrowedHostInputSourcePlan','all94NativeImportSemanticsPreserved'):
        scope[key]=runtime[key]
    borrowed_plan=json.loads(base.exact(scope['cpuBorrowedHostInputSourcePlan']).read_bytes())
    for key in borrowed_plan['proofs']:scope[key]=runtime[key]
    for key in ('cpuSerializedWakeV1Candidate','cpuSerializedWakeV1Contract','runtime62CPUSerializedWakeV1DeltaVerification','cpuSerializedWakeSourcePlan','additionalNativeImports','all93ExistingNativeImportSemanticsPreserved','additionalNativeImportStrongDefinitionProof','nativeImportClosureSources'):
        scope[key]=runtime[key]
    serialized_plan=json.loads(base.exact(scope['cpuSerializedWakeSourcePlan']).read_bytes())
    for key in serialized_plan['proofs']:scope[key]=runtime[key]
    for key in ('cpuOwnedMandatoryFailureV1Candidate','cpuOwnedMandatoryFailureV1Contract','runtime61CPUOwnedMandatoryFailureV1DeltaVerification','cpuOwnedMandatoryFailureSourcePlan'):
        scope[key]=runtime[key]
    mandatory_plan=json.loads(base.exact(scope['cpuOwnedMandatoryFailureSourcePlan']).read_bytes())
    for key in mandatory_plan['proofs']:scope[key]=runtime[key]
    for key in ('cpuAdditiveRAMV1Candidate','cpuAdditiveRAMV1Contract','runtime60CPUAdditiveRAMV1DeltaVerification','cpuAdditiveRAMSourcePlan','cpuRegisterFailureV2Contract','publicMapFailureV25Contract'):
        scope[key]=runtime[key]
    additive_plan=json.loads(base.exact(scope['cpuAdditiveRAMSourcePlan']).read_bytes())
    for key in additive_plan['proofs']:scope[key]=runtime[key]
    for key in ('cpuPinnedRAMReadV1Candidate','cpuPinnedRAMReadV1Contract','runtime59CPUPinnedRAMReadV1DeltaVerification','actualNormal65SecondaryCPUAndRAMBusySnapshot','actualRAMCPUImmutabilitySource','originalVMOperationReadGateSource'):
        scope[key]=runtime[key]
    for key in ('cpuDisabledAMXStateV1Candidate','cpuDisabledAMXStateV1Contract','runtime58CPUDisabledAMXStateV1DeltaVerification','actualNormal64EncodedIDAndAMXStateSnapshot','actualNativeAMXStateZeroBranchDisassembly','actualNativeAMXBank57SaveDisassembly'):
        scope[key]=runtime[key]
    for key in ('cpuEncodedExitV1Candidate','cpuEncodedExitV1Contract','runtime57CPUEncodedExitV1DeltaVerification','actualNormal63AcceptedConfigAndRaw8Snapshot','original13EncodedExitDecoderDisassembly','actualNativeABI14EncodedExitConsumerDisassembly'):
        scope[key]=runtime[key]
    for key in ('cpuDisabledAMXConfigV3Candidate','cpuDisabledAMXConfigV3Contract','runtime56CPUDisabledAMXConfigV3DeltaVerification','actualNormal62Operand100Snapshot','actualNativeBootConfig100Disassembly','actualNativeContextEnable63Disassembly'):
        scope[key]=runtime[key]
    for key in ('cpuDisabledAMXConfigV2Candidate','cpuDisabledAMXConfigV2Contract','runtime55CPUDisabledAMXConfigV2DeltaVerification','actualNormal61RepeatedFaultSnapshot'):
        scope[key]=runtime[key]
    for key in ('cpuDisabledAMXConfigCandidate','cpuDisabledAMXConfigContract','runtime54CPUDisabledAMXConfigDeltaVerification','actualNormal60FaultInstructionSnapshot'):
        scope[key]=runtime[key]
    for key in ('cpuRaw7FaultOpcodeSnapshotCandidate','cpuRaw7FaultOpcodeSnapshotContract','runtime53CPURaw7FaultOpcodeSnapshotDeltaVerification','actualNormal59KernelPanicSnapshot'):
        scope[key]=runtime[key]
    for key in ('cpuKernelTTBR1SnapshotCandidate','cpuKernelTTBR1SnapshotContract','runtime52CPUKernelTTBR1SnapshotDeltaVerification','actualNormal58PostSnapshot','uninstalledKernelTTBR1SnapshotSourceHistory','officialARMAddressSizeGuideURL','officialAppleTCRDefinitionsURL'):
        scope[key]=runtime[key]
    for key in ('cpuRaw7UndefinedInjectionCandidate','cpuRaw7UndefinedInjectionContract','runtime51CPURaw7UndefinedInjectionDeltaVerification','original13Raw7UndefinedDisassembly','original13RunDisassembly','original13ExceptionInjectionHelper'):
        scope[key]=runtime[key]
    for key in ('cpuNativePACServiceCandidate','cpuNativePACServiceContract','runtime50CPUNativePACServiceDeltaVerification','uninstalledPrecedingPCSourceHistory','original13PACServiceDisassembly','original13HypervisorBinary','currentKernelActualNative9Disassembly'):
        scope[key]=runtime[key]
    for key in ('cpuEL1VirtualTimerPagewalkCandidate','cpuEL1VirtualTimerPagewalkContract','runtime49CPUEL1VirtualTimerPagewalkDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuPostWakeRegisterCodeSnapshotCandidate','cpuPostWakeRegisterCodeSnapshotContract','runtime48CPUPostWakeRegisterCodeSnapshotDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuVirtualTimerGICCandidate','cpuVirtualTimerGICContract','runtime47CPUVirtualTimerGICDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuBoundedWakePostSnapshotCandidate','cpuBoundedWakePostSnapshotContract','runtime46CPUBoundedWakePostSnapshotDeltaVerification','actualSameImageVCPUsExitBinding'):
        scope[key]=runtime[key]
    for key in ('cpuInternalRunSparseCandidate','cpuInternalRunSparseContract','runtime45CPUInternalRunSparseDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuWFxCounterReaderCandidate','cpuWFxCounterReaderContract','runtime44CPUWFxCounterReaderDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuWFxWaitCandidate','cpuWFxWaitContract','runtime43CPUWFxWaitDeltaVerification'):
        scope[key]=runtime[key]
    scope['cpu28OtherObjectsWholeRuntime42']=False
    for key in ('cpuPublicRunSparseClockCandidate','publicRunSparseClockDiagnosticsContract','runtime42PublicRunSparseClockDeltaVerification','actualCurrentCPUExports','actualCurrentCPUImports','actualCurrentCPULoads'):
        scope[key]=runtime[key]
    for key in ('cpuScratchGPRTraceCandidate','scratchGPRTraceContract','runtime40ScratchGPRTraceDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuSYSExceptionHandoffCandidate','ordinarySystemExitForwardingContract','runtime39CPUSYSExceptionDeltaVerification'):
        scope[key]=runtime[key]
    for key in ('cpuRunReceiptDiagnosticsCandidate','publicRunResultDiagnosticsContract','runtime38CPURunReceiptDiagnosticDeltaVerification','historicalRuntime38AMXChildVerification','allExistingAMXGuardCodeWholeUnchanged'):
        scope[key]=runtime[key]
    for key in ('modernHVISA3ToNative2Contract','nativeSystemBank60RouteContract','amxAvailabilityContract','amxCallerGuardContract','cpuAMXAvailabilityChildCandidate','childAMXAvailabilityGuardRecipe','historicalRuntime37ChildVerification','currentChildImportsWholeUnchanged','currentChildPresignatureBodyWholeExceptExactAMXGuardRangesAndSignatureMetadata'):
        scope[key]=runtime[key]
    scope['historicalRuntime36ReservedPMUChildVerification']=runtime['historicalRuntime36ReservedPMUChildVerification']
    scope['currentChildCodeAndImportsWholeUnchanged']=runtime['currentChildCodeAndImportsWholeUnchanged']
    scope['currentChildPresignatureBodyWholeExceptSignatureMetadata']=runtime['currentChildPresignatureBodyWholeExceptSignatureMetadata']
    scope['allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged']=runtime['allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged']
    scope['historicalRuntime35SCXTChildVerification']=runtime['historicalRuntime35SCXTChildVerification']
    scope['originalChildPresignatureBodyWholeExceptExactReservedZeroAndPMUGuardRangesAndSignatureMetadata']=runtime['originalChildPresignatureBodyWholeExceptExactReservedZeroAndPMUGuardRangesAndSignatureMetadata']
    scope['allExistingSCXTGuardRangesWholeUnchanged']=runtime['allExistingSCXTGuardRangesWholeUnchanged']
    scope['originalChildCodeWholeUnchanged']=False
    scope['originalChildNamespaceWholeUnchanged']=runtime['originalChildNamespaceWholeUnchanged']
    scope['originalChildPresignatureBodyWholeExceptExactSCXTGuardRangesAndSignatureMetadata']=runtime['originalChildPresignatureBodyWholeExceptExactSCXTGuardRangesAndSignatureMetadata']
    scope['runtime28VMInitializationDeltaVerification']=runtime['runtime28VMInitializationDeltaVerification']
    scope['pvgAddressRangeCapabilityCandidate']=runtime['pvgAddressRangeCapabilityCandidate']
    scope['pvgHeapCapabilityContract']=runtime['pvgHeapCapabilityContract']
    scope['pvgDetachCapabilityContract']=runtime['pvgDetachCapabilityContract']
    scope['pvgLegacyHeapCapabilityEvidence']=runtime['pvgLegacyHeapCapabilityEvidence']
    scope['pvgDetachLegacyEvidence']=runtime['pvgDetachLegacyEvidence']
    scope['pvgBufferCapabilityCandidate']=runtime['pvgBufferCapabilityCandidate']
    scope['pvgBufferCapabilityContract']=runtime['pvgBufferCapabilityContract']
    scope['pvgLegacyCapabilityEvidence']=runtime['pvgLegacyCapabilityEvidence']
    scope['nativeTargetShaderCandidate']=runtime['nativeTargetShaderCandidate']
    scope['nativeTargetShaderContract']=runtime['nativeTargetShaderContract']
    base.exact(scope['PGResourceSourceCandidate']);base.exact(scope['runtime25AddressCapabilityDeltaVerification']);base.exact(scope['pvgAddressRangeCapabilityCandidate']);base.exact(scope['pvgBufferCapabilityCandidate']);base.exact(scope['nativeTargetShaderCandidate'])
    need(runtime['baselineRuntimeCandidate']==old['runtimeCandidate'] and len(runtime['genuineResources'])==1,'actual Runtime65 signs from installed Runtime64 with same genuine resource')
    genuine=runtime['genuineResources'][0]
    shader=next(row for row in files if row['archivePath']==shader_name)
    need((shader['local']['bytes'],shader['local']['sha256'])==(genuine['actualRuntimeResource']['bytes'],genuine['actualRuntimeResource']['sha256']) and
         shader['local']['bytes']==20595 and shader['local']['sha256']=='e9f63d3f615ba39653e3550bde39ae7deaf098bea93b7bd79494026ef225e6ab' and
         shader['mode']==0o600 and 'cdhash' not in shader and
         genuine['runtimeRelativePath']==shader_name[len('runtime/'):] and
         runtime['PGResourceLookupContract']['exactRuntimeRelativePath']==genuine['runtimeRelativePath'],
         'actual source-native iOS16.1 default.metallib bytes at the existing Child resource path; no executable trust entry')
    need(scope['nativeTargetShaderContract']['sourceNativeAdaptation'] is True and
         scope['nativeTargetShaderContract']['platformOrVersionBytePatching'] is False and
         scope['nativeTargetShaderContract']['macOS13PayloadUsed'] is False and
         scope['nativeTargetShaderContract']['actualDevicePipelineVerified'] is False,
         'actual native compiler output retains honest unexecuted device pipeline boundary')
    scope['actualUnchangedIOS16NativeShaderFile']=shader['local']
    scope['all14ChildPermissionsWholeUnchanged']=True
    port=json.loads(base.exact(scope['pvgUnifiedStorageCandidate']).read_bytes())
    base.exact(scope['pvgUnifiedStorageEvidence']);base.exact(scope['runtime26UnifiedStorageDeltaVerification'])
    prior_runtime=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    need(runtime['pvgUnifiedStorageCandidate']==old['pvgUnifiedStorageCandidate'] and
         runtime['pvgUnifiedStorageContracts']==old['pvgUnifiedStorageContracts'] and port['providerKey']=='MD' and port['roles']==['child'] and
         port['adapterContract']==scope['pvgHeapCapabilityContract'] and port['detachAdapterContract']==scope['pvgDetachCapabilityContract'] and
         port['inheritedBufferContract']==scope['pvgBufferCapabilityContract'] and port['pipelineDiagnosticNotIncluded'] is True,
         'actual final two-port unified storage source with installed three capability contracts preserved')
    heap=scope['pvgHeapCapabilityContract'];detach=scope['pvgDetachCapabilityContract']
    need(heap['requiredPGOrdinal']==detach['requiredPGOrdinal']==10 and heap['requiredPGImportIndex']==262 and detach['requiredPGImportIndex']==263 and
         heap['nativeMethodMissingReturnsFalseCapabilityUnsupported'] is True and heap['noAppleMethodAddition'] is True and
         heap['noGlobalSwizzle'] is True and heap['noBufferFabrication'] is True and heap['wrongOwnedScopeTraps'] is True and
         detach['methodMissingReturnsFalseUnsupported'] is True and port['existingCapabilityRoutes261262263WholeUnchanged'] is True and port['heapCreationAndHeapBufferRoutesWholeUnchanged'] is True,
         'honest optional capability results retain original legacy behavior and real unsupported-range rejection')
    contracts=scope['pvgUnifiedStorageContracts']
    need(contracts==port['unifiedStorageContracts'] and len(contracts)==2 and
         {row['symbol'] for row in contracts}=={'_VM27OwnedPVGNewBufferWithLengthOptionsV1','_VM27OwnedPVGDidModifyManagedRangeV1'} and
         contracts[0]['newImportIndex']==264 and contracts[1]['newImportIndex']==265 and
         all(row['requiredOrdinal']==10 for row in contracts) and
         contracts[0]['genuineHasUnifiedMemoryRequiredForConversion'] is True and contracts[0]['allOtherOptionsPreserved'] is True and
         contracts[0]['nativeMethodTypedAndCalledOnce'] is True and contracts[0]['nativeNewResourcePlusOneOwnershipPreserved'] is True and
         contracts[1]['skipManagedSynchronizationOnlyActualSharedAndNativeUnified'] is True and
         contracts[1]['nonSharedNativeTypedMethodForwarded'] is True and contracts[1]['originalCommandSubmissionAndCompletionUnchanged'] is True and
         port['globalAppleClassMutation'] is False and port['genuineUnifiedSharedResourceOperationsActuallyExecuted'] is False,
         'genuine scoped native resource creation and Shared synchronization adaptation, no fake resource or device claim')
    scope['genuineUnifiedSharedResourceOperationsActuallyExecuted']=False
    scope['globalAppleClassMutation']=False
    need('root26Candidate' not in runtime and 'childCxxRouteRecipe' not in runtime,
         'uninstalled CXX diagnostics are outside the Child buffer capability scope')
    macos='runtime/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/'
    need({row['archivePath'] for row in changes}=={
        macos+'com.apple.Virtualization.VirtualMachine',macos+'VM27HVVMProduction.dylib',
        'runtime/parent-flat/VM27HVVMProduction.dylib',
        'runtime/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/_CodeSignature/CodeResources',
        'runtime/Independent27ActualDependencyProof.json','runtime/VM27IndependentRuntimeManifestV1.plist',
        'VirtualMacIndependent27.app/VirtualMacIndependent27'},
        'actual existing-file delta is precisely two CPU provider roles, original Child reseal, proof, manifest and Main21 App anchor')
    for name in ('runtime/parent-flat/VM27LargeConsumerV2.dylib',macos+'VM27LargeConsumerV2.dylib'):
        current_consumer=next(row for row in files if row['archivePath']==name);prior_consumer=old_by_name[name]
        need((current_consumer['local']['bytes'],current_consumer['local']['sha256'],current_consumer['cdhash'])==(prior_consumer['local']['bytes'],prior_consumer['local']['sha256'],prior_consumer['cdhash']),'actual whole R42 Consumer stdio image and code hash retained in both roles')
    scope['currentRuntimeConsumerWholeUnchangedFromRuntime64']=True
    need(scope['currentConsumerWholeR64']['wholeBytesUnchanged'] is True and scope['currentConsumerWholeR64']['baselineRuntimeCandidate']==old['runtimeCandidate'],'current Consumer whole-body proof joins actual installed Runtime64')
    need(scope['consumerProvidersWholeRuntime64'] is True and scope['cpu25OtherObjectsWholeRuntime64'] is True,'actual Runtime65 consumer whole Runtime64 and25 untouched CPU objects')
    reason_port=json.loads(base.exact(scope['childErrorReasonDiagnosticCandidate']).read_bytes())
    base.exact(scope['runtime27ErrorReasonDeltaVerification'])
    need(runtime['childErrorReasonDiagnosticCandidate']==old['childErrorReasonDiagnosticCandidate'] and reason_port['providerKey']=='MD'and reason_port['roles']==['child']and
         reason_port['errorReasonContract']==scope['childErrorReasonDiagnosticContract'],
         'actual child-only structured error source port and typed contract match current installed baseline')
    reason_recipe=json.loads(base.exact(reason_port['recipe']).read_bytes())
    need(reason_recipe['newSymbol']=='_VM27OwnedChildBuildErrorReasonDiagnosticV1'and reason_recipe['existingRequiredOrdinal']==3 and
         reason_recipe['newRequiredLoads']==0 and reason_recipe['originalErrorFunctionRVA']==0x3e4fb0 and
         reason_recipe['originalErrorFunctionWholeUnchanged']is True,
         'only selected original error construction routes through existing required MD3; no API result substitution')
    need(scope['historicalChildVMInitializationDiagnosticCandidate']==old['historicalChildVMInitializationDiagnosticCandidate'] and
         scope['historicalChildVMInitializationDiagnosticContract']==old['historicalChildVMInitializationDiagnosticContract'],
         'original no-catch initializer source is historical; its actual Child route remains whole unchanged')
    boundary_port=json.loads(base.exact(scope['childVMExceptionBoundaryCandidate']).read_bytes())
    base.exact(scope['runtime29VMExceptionBoundaryDeltaVerification'])
    need(runtime['childVMExceptionBoundaryCandidate']==old['childVMExceptionBoundaryCandidate'] and boundary_port['providerKey']=='MD' and boundary_port['roles']==['child'] and
         boundary_port['exceptionBoundaryContract']==scope['childVMExceptionBoundaryContract'] and
         'patchedChildMain' not in boundary_port and 'recipe' not in boundary_port,
         'actual helper-only exception boundary matches current installed baseline; no Child/DI/PG port')
    initialization=scope['childVMExceptionBoundaryContract']
    need(initialization['symbol']=='_VM27OwnedChildInitializeVMResultDiagnosticV1' and initialization['originalInitializerRVA']==0x2e9b24 and
         initialization['selectedCallerReturnRVA']==0x24a78 and initialization['originalFunctionCalledOnce'] is True and
         initialization['allThreePointersPassedUnchanged'] is True and initialization['resultAndGuestStructuresNeverModified'] is True and
         runtime['actualChildMachineBodyChanged'] is False and runtime['currentChildPresignatureBodyWholeExceptSignatureMetadata'] is True,
         'original initializer and result ownership preserved; bounded genuine exception log and original rethrow only')
    need(initialization['cppRethrowUsesBareThrow'] is True and initialization['objectiveCRethrowUsesBareAtThrow'] is True and
         initialization['catchOnlyForObservationAndOriginalRethrow'] is True and initialization['loggingSideExceptionsContainedAndOriginalPreserved'] is True,
         'bounded actual exception observation rethrows the original CXX/ObjC object, without swallowing or substitution')
    usb_port=json.loads(base.exact(scope['childUSBHAdapterCandidate']).read_bytes())
    base.exact(scope['runtime31ChildUSBHDeltaVerification'])
    need(runtime['childUSBHAdapterCandidate']==old['childUSBHAdapterCandidate'] and runtime['childUSBHAdapterContract']==old['childUSBHAdapterContract'] and usb_port['providerKey']=='USBH' and usb_port['roles']==['child'] and
         usb_port['offlineAVPSuperclassContract']==scope['childUSBHAdapterContract'] and 'patchedChildMain' not in usb_port,
         'actual Child-only USBH offline superclass adapter; no original Child instructions or namespace port')
    usb=scope['childUSBHAdapterContract']
    need(usb['actualCallerReturnRVA']==0x2449e8 and usb['realNSObjectInitialization'] is True and
         usb['actualCapabilitiesCopied'] is True and usb['ownedSerialQueueRetained'] is True and
         usb['originalCommandAndDoorbellBlocksCopied'] is True and usb['controllerState']=='Off' and
         usb['kernelUserClientCreated'] is False and usb['noHostCICommandsGenerated'] is True and usb['noDoorbellsGenerated'] is True and
         usb['noInterruptResponseFabricated'] is True and usb['externalControllerPortDeviceEndpointOperationsExplicitUnsupported'] is True and
         usb['guestAVPNodeRetained'] is True and usb['standardGuestUSBKeyboardPointingAndXHCIUnchanged'] is True and
         usb['destroyReleasesCallbacksQueueCapabilityAndWeakOwner'] is True,
         'actual scoped offline object/lifetime; no physical host CI or fabricated ACK; guest AVP and basic USB retained')
    cpu_port=json.loads(base.exact(scope['cpuNativeDistinctSlotsCandidate']).read_bytes())
    base.exact(scope['runtime32CPUSlotsDeltaVerification'])
    need(cpu_port['root25Candidate']==runtime['root25Candidate']==old['cpuEmulatorDupSourceCandidate'] and
         all(value is True for value in scope['cpuNativeDistinctSlotsContract'].values()),
         'actual existing Root25 provider minimal distinct native slot ownership and no native return substitution')
    startup=json.loads(base.exact(scope['cpuControlFieldsCandidate']).read_bytes())
    base.exact(scope['runtime33CPUStartupDeltaVerification'])
    need(runtime['cpuNativeDistinctSlotsCandidate']==old['cpuNativeDistinctSlotsCandidate'] and startup['baselineCPUSlotsCandidate']==old['cpuNativeDistinctSlotsCandidate'] and startup['cpuControlFieldsContract']==scope['cpuControlFieldsContract'] and len(startup['actualChangedObjects'])==1 and startup['allOther28ObjectsWholeUnchanged'] is True,'actual single lifecycle startup change preserves the tested distinct native CPU slot provider')
    need(scope['cpuControlFieldsContract']['nativeControlOffsets']=={'0':'0x670','9':'0x6f0'} and scope['cpuControlFieldsContract']['freshReadUnsupported'] is True and scope['cpuControlFieldsContract']['nonzeroWriteUnsupported'] is True and scope['cpuControlFieldsContract']['noNativeFeatureResponseFabricated'] is True,'real native control fields and explicit requested-zero virtual feature state')
    diagnostic=json.loads(base.exact(scope['cpuPublicAPIFailureDiagnosticsCandidate']).read_bytes())
    base.exact(scope['runtime34CPUStartupISAR2DeltaVerification'])
    need(runtime['cpuControlFieldsCandidate']==old['cpuControlFieldsCandidate'] and
         runtime['cpuControlFieldsContract']==old['cpuControlFieldsContract'] and
         runtime['runtime33CPUStartupDeltaVerification']==old['runtime33CPUStartupDeltaVerification'] and
         diagnostic['cpuStartupControlsCandidate']==old['cpuControlFieldsCandidate'] and
         diagnostic['cpuPublicAPIFailureDiagnosticsContract']==scope['cpuPublicAPIFailureDiagnosticsContract'] and
         diagnostic['cpuControlFieldsContract']==scope['cpuStartupISAR2Contract'] and
         scope['cpuStartupISAR2Candidate']==scope['cpuPublicAPIFailureDiagnosticsCandidate'] and
         len(diagnostic['actualChangedObjects'])==2 and diagnostic['allOther27ObjectsWholeUnchanged'] is True,
         'two exact startup SYS and Factory observation objects preserve actual Runtime34 native controls and distinct CPU slot ownership')
    expected_startup=copy.deepcopy(old['cpuControlFieldsContract']);expected_startup['explicitPerCPURequestedZeroSYS']+=['0xc032'];expected_startup['sixZeroPolicyMatchesExistingOwnFeatureSelectors']=expected_startup.pop('fiveZeroPolicyMatchesExistingOwnFeatureSelectors')+[14]
    need(all(scope['cpuStartupISAR2Contract'].get(k)==v for k,v in expected_startup.items()) and
         diagnostic['noNativeReturnSubstitution'] is True,
         'sixth explicit requested-zero ISAR2 state preserves all prior native controls and failure semantics')
    observation=scope['cpuPublicAPIFailureDiagnosticsContract']
    need('life26AndNativeOps5WholeObjectsInherited' not in observation and observation['life27AndNativeOps5IncludedWithoutDiagnosticStateChanges'] is True,
         'current merged diagnostic contract truthfully names Life27 and preserves separate prior source proof')
    need(observation['operations']==['get-control','set-control','get-sys','set-sys'] and observation['perProcessMaximumFailureLogs']==8 and
         all(observation[k] is True for k in ('observesOnlyOriginalReturnedFailure','logsOnlyOperationSelectorRequestedWriteValueAndOriginalStatus','noGetterOutputDereference','originalAPICalledExactlyOnce','originalReturnErrnoAndOutputPreserved','noAssertionOrCPUStateChanges','fourTrueNativeSlotFixPreserved')),
         'bounded original CPU failure diagnostic preserves status, errno, outputs, assertions and CPU state')
    scxt=json.loads(base.exact(scope['cpuSCXTFeatureGuardCandidate']).read_bytes())
    base.exact(scope['childSCXTGuardRecipe']);base.exact(scope['runtime34CPUStartupSCXTDeltaVerification'])
    need(scxt['cpuStartupISAR2FailureCandidate']==scope['cpuStartupISAR2Candidate'] and
         scxt['cpuSCXTFeatureGuardContract']==scope['cpuSCXTFeatureGuardContract'] and
         scxt['childSCXTGuardRecipe']==scope['childSCXTGuardRecipe'] and len(scxt['actualChangedObjects'])==3 and
         scxt['allOther26ObjectsWholeUnchanged'] is True and runtime['originalChildCodeWholeUnchanged'] is False and
         scope['originalChildNamespaceWholeUnchanged'] is True and
         scope['originalChildPresignatureBodyWholeExceptExactSCXTGuardRangesAndSignatureMetadata'] is False and
         scope['historicalRuntime35SCXTChildVerification']==old['historicalRuntime35SCXTChildVerification'] and
         scope['historicalRuntime35SCXTChildVerification']['originalChildPresignatureBodyWholeExceptExactSCXTGuardRangesAndSignatureMetadata'] is True and
         scope['allExistingSCXTGuardRangesWholeUnchanged'] is True,
         'actual Runtime35 SCXT source and exact four-range body proof remain historical; all existing SCXT guards and original namespace remain whole in the current reserved-zero delta')
    need(all(scope['cpuSCXTFeatureGuardContract'][k] is True for k in ('beforeCPUCreationOwnPFR0CSV2Known2Or3ReducedTo1', 'known0Or1Preserved', 'unknownPFR0CSV2Unsupported', 'unrelatedPFR0FeatureBitsUnchangedExceptExistingWithheldPolicy', 'PFR1FractionZeroConsistentWithExistingPolicy', 'PFR0SYSWritesCannotExposeCSV2_2', 'actualSameCPURequestedPFR0AndPFR1ReadViaExistingPublicOwnerCheckedSYS', 'guardValidAbsentCSV2LessThan2SkipsWholeSCXTSection', 'absentNeverReadsWritesOrPublishesSCXTFrameSlots', 'presentPreservesAllFourOriginalCallsAndErrors', 'invalidProfileOrRealPFRGetterFailureTakesOriginalFatal', 'allX0ThroughX30AndQ0ThroughQ31SP_LR_NZCVPreserved', 'noNativeSYSFakeSuccess', 'noNewPublicABIOrImports', 'initialRestoreDoesNotInventSavedSCXTState', 'snapshotAndCrossProfileMigrationDeferred', 'fourTrueNativeSlotsAndLife27ControlISAR2FixUnchanged')),
         'creation-time optional CSV2_2 withheld; same-CPU actual PFR guard preserves real calls/failure and does not claim snapshot or migration')
    reserved=json.loads(base.exact(scope['cpuReservedZeroCandidate']).read_bytes())
    base.exact(scope['childReservedZeroRouteRecipe']);base.exact(scope['runtime35CPUReservedZeroDeltaVerification'])
    need(reserved['baselineActualRuntime35']==scope['historicalRuntime35SCXTChildVerification']['baselineRuntimeCandidate'] and reserved['cpuSCXTFeatureGuardCandidate']==scope['cpuSCXTFeatureGuardCandidate'] and
         reserved['cpuReservedZeroContract']==scope['cpuReservedZeroContract'] and reserved['childReservedZeroRouteRecipe']==scope['childReservedZeroRouteRecipe'] and
         len(reserved['actualChangedObjects'])==2 and reserved['allOther27ObjectsWholeUnchanged'] is True and
         scope['originalChildPresignatureBodyWholeExceptExactReservedZeroAndPMUGuardRangesAndSignatureMetadata'] is False and scope['historicalRuntime37ChildVerification']['originalChildPresignatureBodyWholeExceptExactReservedZeroAndPMUGuardRangesAndSignatureMetadata'] is True,
         'two typed metadata and feature-admission objects plus exact reserved-zero/absent-PMU routes retain the actual Runtime35 CPU/SCXT product and namespace')
    need(reserved['cpuPMUDisabledGuardContract']==scope['cpuPMUDisabledGuardContract'] and all(scope['cpuPMUDisabledGuardContract'][k] is True for k in ('actualSameCPURequestedDFR0ViaRealPublicOwnerCheckedSYS', 'existingFeatureSeedAlreadyAdvertisesPMUVerZero', 'featureAdvertisementUnchanged', 'SYSWritePMUVerNonzeroUnsupported', 'omitOnlyWhenPMUVerZeroAndOriginalFramePMCR1Zero', 'nonzeroPMUVerPreservesOriginalContextPathAndFailure', 'zeroPMUVerNonzeroFrameTakesOriginalFatal', 'getterFailureTakesOriginalFatal', 'saveDoesNotReadNativePMCR1OrGenerateCounterState', 'omissionLeavesAllOriginalFrameBytesUnchanged', 'PMUFrameValidityControlledByImmutableDisabledProfile', 'originalConstructorZeroAtFrame1da0', 'noPublicSYS0xcf88SuccessInvented', 'PMUPrivatePropertyMethodsRemainExplicitUnsupported', 'performanceCountersAndCrossProfileMigrationDeferred')),
         'same-CPU actual disabled PMU and zero frame alone omit unavailable state; present feature and errors retain original behavior, SYS/private properties remain unsupported')
    metadata=scope['cpuReservedZeroContract']
    need(metadata['originalSerializedKey']=='reserved_0' and metadata['originalConstructorExplicitZeroRVA']==0x399674 and metadata['observedActualNormal37CPU1RestoreValue']==0 and
         all(metadata[k] is True for k in ('explicitZeroOnlyOwnMetadata', 'nonzeroUnsupported', 'freshReadUnsupported', 'realOwnerBorrowAndValidatedViewBeforeAfter', 'identityVMEpochCPUGenerationTupleSeparatesState', 'actualOneCPUPerOwnerThreadTLS', 'newTupleInvalidatesOldMetadata', 'destroyedCPUInaccessibleViaFactory', 'failedReleaseRetainsBorrowWithoutCommit', 'onlyCommitAndPublishAfterSuccessfulRelease', 'noNativeContextAccessOrReturnedPointer', 'noPhysicalSYSOrArchitectureStateEmulation', 'existingPhysicalACTLRAndDebugClaimRoutesPreserved', 'allFourKnownConsumersUseSameTypedStorage', 'PMCR1_cf88NotImplementedOrShadowed', 'guestBootStillUnproven')),
         'explicit zero-only opaque metadata uses real owner/epoch/generation and successful release; no unknown native context or physical SYS state is fabricated')
    diagnostic=json.loads(base.exact(scope['nativeRunAdmissionDiagnosticsCandidate']).read_bytes())
    base.exact(scope['runtime36NativeRunAdmissionDiagnosticDeltaVerification'])
    need(diagnostic['cpuReservedZeroPMUGuardCandidate']==old['cpuReservedZeroCandidate'] and
         diagnostic['nativeRunAdmissionDiagnosticsContract']==scope['nativeRunAdmissionDiagnosticsContract'] and
         len(diagnostic['actualChangedObjects'])==1 and diagnostic['allOther28ObjectsWholeUnchanged'] is True and
         scope['historicalRuntime36ReservedPMUChildVerification']==old['historicalRuntime36ReservedPMUChildVerification'] and
         scope['historicalRuntime36ReservedPMUChildVerification']['actualChildMachineBodyChanged'] is True and
         scope['currentChildCodeAndImportsWholeUnchanged'] is True and scope['currentChildPresignatureBodyWholeExceptSignatureMetadata'] is True and scope['historicalRuntime37ChildVerification']['currentChildCodeAndImportsWholeUnchanged'] is True and scope['historicalRuntime37ChildVerification']['currentChildPresignatureBodyWholeExceptSignatureMetadata'] is True and
         scope['allExistingSCXTReservedAndPMUGuardCodeWholeUnchanged'] is True,
         'historical one-object Runtime37 diagnostic Child proof retained; all installed guard and metadata code remains whole in current AMX caller delta')
    observation=scope['nativeRunAdmissionDiagnosticsContract']
    need(observation['readsOnlyOwnMappedOffsets']==[0x4000,0x748,0x4100,0x4108,0x4110] and all(observation[k] is True for k in ('firstEightNative9AttemptsOnly', 'sameActualOwnerCPUAndContextVersionRequiredForReads', 'recordsActualSuccessfulNative1PacketISA', 'noKernelPointerReads', 'noSharedWordWrites', 'noDirtyMaskChanges', 'noNativeArgumentsFlagsCallsOrReturnsChanged', 'noExtraNativeCall', 'readFailureOnlyReducesKnownMask', 'noPublicSuccessClaim', 'ChildBodyUnchanged')),
         'bounded actual owner/version and own-mapping snapshots preserve every original native argument, flag, call and return')
    combined=json.loads(base.exact(scope['cpuISAProfileCandidate']).read_bytes())
    base.exact(scope['runtime37CPUISAProfileDeltaVerification'])
    caller=json.loads(base.exact(scope['cpuAMXAvailabilityChildCandidate']).read_bytes())
    recipe=json.loads(base.exact(scope['childAMXAvailabilityGuardRecipe']).read_bytes())
    need(combined['modernHVISA3ToNative2Contract']==scope['modernHVISA3ToNative2Contract']==scope['cpuISAProfileContract'] and combined['nativeSystemBank60RouteContract']==scope['nativeSystemBank60RouteContract'] and combined['amxAvailabilityContract']==scope['amxAvailabilityContract'] and combined['amxCallerGuardContract']==scope['amxCallerGuardContract'],'actual combined typed ISA/bank60/AMX source contracts')
    need(combined['cpuAMXAvailabilityChildCandidate']==scope['cpuAMXAvailabilityChildCandidate'] and combined['childAMXAvailabilityGuardRecipe']==scope['childAMXAvailabilityGuardRecipe']==caller['childAMXAvailabilityGuardRecipe'] and combined['patchedChildMain']==caller['patchedChildMain'] and caller['actualIOSCompileAndChildDyldPassed'] is True,'actual source-only caller product joins final provider')
    need(combined['actualExports']==155 and combined['actualNativeImports']==93 and combined['actualLoads']==4,'old native namespace plus sole explicit AMX availability export')
    baseline=json.loads(base.exact(scope['historicalRuntime37ChildVerification']['baselineRuntimeCandidate']).read_bytes());baseline_manifest=plistlib.loads(base.exact(baseline['manifest']).read_bytes());baseline_row=next(r for r in baseline_manifest['files']if r['id']=='child:com.apple.Virtualization.VirtualMachine')
    original=pin(pathlib.Path(baseline['runtimeRoot'])/baseline_row['path'])
    need(recipe['original']==original and recipe['baselineActualRuntime37']==scope['historicalRuntime37ChildVerification']['baselineRuntimeCandidate'],'actual current R37 Child source and historical body proof')
    need([(r['type'],r['fileoff'],r['bytes'])for r in recipe['ranges']]==[('AMX-save-prefix',0x289c50,4),('AMX-restore-prefix',0x28c978,4),('AMX-save-stub',0x4a3a00,696),('AMX-restore-stub',0x4a3d00,696)] and recipe['allOtherChildBytesWholeUnchanged'] is True,'only exact four AMX ranges changed before resigning')
    need(scope['currentChildPresignatureBodyWholeExceptExactAMXGuardRangesAndSignatureMetadata'] is False and scope['historicalRuntime38AMXChildVerification']['currentChildPresignatureBodyWholeExceptExactAMXGuardRangesAndSignatureMetadata'] is True and scope['currentChildImportsWholeUnchanged'] is True and scope['currentChildCodeAndImportsWholeUnchanged'] is True and scope['currentChildPresignatureBodyWholeExceptSignatureMetadata'] is True,'historical AMX four-range proof and current R38 Child whole-body signature-only delta')
    need(all(scope['amxCallerGuardContract'][k] is True for k in ('originalHostCPUCapabilitiesAndSysctlPredicateUnchanged','guardRunsOnlyAfterOriginalHostCapabilityGates','absentOnlyWithFrame958And960ZeroAndValidity1d68Zero','invalidPayload968Through1d67NeverRead','originalFrameBytesNeverWritten','presentOriginalTypedAMXCallsAndFailurePreserved','queryFailureAndNullDlsymTakeOriginalFatal','nonzeroInactiveControlsOrValidityTakeOriginalFatal','allGPRAndQ0Through31AndNZCVAndLRAndSPPreserved','allExistingSCXTReservedAndPMUGuardsWholeUnchanged','noNativeAMXStateSynthesized')),'genuine absent-only optional state omission; enabled state and real errors retained')
    scope['originalChildOnlyExactFourAMXAvailabilityGuardRangesChanged']=False
    run_source=json.loads(base.exact(scope['cpuRunReceiptDiagnosticsCandidate']).read_bytes())
    base.exact(scope['runtime38CPURunReceiptDiagnosticDeltaVerification'])
    need(run_source['cpuAMXAvailabilityCombinedCandidate']==old['cpuISAProfileCandidate']==scope['cpuISAProfileCandidate'] and len(run_source['actualChangedObjects'])==2 and len(run_source['inheritedWholeObjects'])==27 and run_source['allOther27ObjectsWholeUnchanged'] is True,'two actual bounded Run observation objects inherit complete installed R38 provider source')
    need(run_source['publicRunResultDiagnosticsContract']==scope['publicRunResultDiagnosticsContract'] and run_source['actualExports']==155 and run_source['actualNativeImports']==93 and run_source['actualLoads']==4,'actual same155/93/4 and real observation contract')
    need(all(scope['publicRunResultDiagnosticsContract'][k] is True for k in ('firstSixteenExistingInternalRunReceiptsOnly','firstEightPublicRunReturnsOnly','observesOnlyAlreadyInitializedLocalReceipts','unknownNativeValuesExplicitlyMarked','noExtraNativeCalls','noExtraCPUOrContextReads','noGuestOrCPUStateWrites','noCallsFlagsArgumentsResultsOrOutputsChanged','originalReleaseBodyInlinedWithoutChangingOneActualBorrowRelease','retainsOriginalDeferredBorrowAndStatusPriority','recordsActualReleaseStatus','preservesErrnoAcrossFormatting','logsKnownRawESRVirtualAndPhysicalAddress','logsInternalResumePublicReasonIdentityAndPoison','logsFinalPublicRunReturnAndProducerStatus','ChildBodyWholeUnchanged')),'bounded existing receipts only; original Run, release, errno, outputs and state unchanged')
    need(scope['historicalRuntime38AMXChildVerification']==old['historicalRuntime38AMXChildVerification'] and scope['historicalRuntime38AMXChildVerification']['childAMXAvailabilityGuardRecipe']==old['childAMXAvailabilityGuardRecipe'] and scope['allExistingAMXGuardCodeWholeUnchanged'] is True,'actual R38 AMX body proof retained historically and whole current R38 Child signature-only reseal')
    sys_source=json.loads(base.exact(scope['cpuSYSExceptionHandoffCandidate']).read_bytes())
    base.exact(scope['runtime39CPUSYSExceptionDeltaVerification'])
    need(sys_source['cpuRunResultDiagnosticsCandidate']==old['cpuRunReceiptDiagnosticsCandidate']==scope['cpuRunReceiptDiagnosticsCandidate'] and len(sys_source['actualChangedObjects'])==1 and len(sys_source['inheritedWholeObjects'])==28 and sys_source['allOther28ObjectsWholeUnchanged'] is True,'single exact ExitReducer object replaces actual R39 baseline; Life29/FactoryV3 whole')
    need(sys_source['ordinarySystemExitForwardingContract']==scope['ordinarySystemExitForwardingContract'] and sys_source['actualExports']==155 and sys_source['actualNativeImports']==93 and sys_source['actualLoads']==4,'actual source ordinary SYS contract and same155/93/4')
    need(all(scope['ordinarySystemExitForwardingContract'][k] is True for k in ('admitsOnlyUnhandledEC18IL1Op0AtLeast2','GICAndTimerHandlersStillRunBeforeReducer','existingMutationPoisonAndIdentityGatesUnchanged','preservesExactNativeESRVAIPAIn32BytePublicException','noGuestPCOrGPRWrites','noCPUContextReadsOrNativeCalls','noSYSGetterOrSetterSuccessFabricated','originalVMMConsumesExceptionAndAdvancesPC','HVCAndPrivateEC3FRemainUnsupported','nonRegisterSYSAndMalformedILRemainUnsupported','schemaAndExistingLinkedSymbolUnchanged','allOriginalInputValidationAndRefusalOutputPreservationUnchanged','ChildBodyWholeUnchanged','Life29FactoryV3RunDiagnosticsWholeUnchanged')),'ordinary architectural SYS exception reaches original VMM consumer; special and malformed exits still explicitly refused')
    consumer_source=json.loads(base.exact(scope['consumerStdioInheritanceCandidate']).read_bytes())
    base.exact(scope['runtime41ConsumerStdioInheritanceDeltaVerification'])
    need(consumer_source['baselineRuntimeCandidate']==json.loads(base.exact(scope['runtime41ConsumerStdioInheritanceDeltaVerification']).read_bytes())['baselineCandidate'] and len(consumer_source['actualChangedObjects'])==1 and len(consumer_source['inheritedWholeObjects'])==3 and consumer_source['allOther3ConsumerObjectsWholeUnchanged'] is True and consumer_source['all29CPUObjectsWholeUnchanged'] is True,'actual sole Consumer object replaces original while three Consumer objects and all29 CPU objects stay whole')
    need(consumer_source['stdioInheritanceContract']==scope['consumerStdioInheritanceContract'] and consumer_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True,'actual compiled Consumer standard-stream inheritance contract')
    need((scope['actualConsumerExports'],scope['actualConsumerImports'],scope['actualConsumerLoads'])==(9,80,7) and scope['actualConsumerAddedImports']==consumer_source['actualConsumerAddedImports'] and len(scope['actualConsumerAddedImports'])==6 and scope['consumerFourOwnDependencyLoadsNormalizedToBaselineLoaderPath'] is True,'Consumer own namespace is9 exports80 totalimports7loads with6 real added libSystem imports and four normalized own loadnames')
    need(runtime['consumerStdioInheritanceCandidate']==old['consumerStdioInheritanceCandidate'] and runtime['consumerStdioInheritanceContract']==old['consumerStdioInheritanceContract'] and runtime['runtime41ConsumerStdioInheritanceDeltaVerification']==old['runtime41ConsumerStdioInheritanceDeltaVerification'],'current Consumer source and its historical R42 one-object deployment proof stay whole')
    need(all(scope['consumerStdioInheritanceContract'][k] is True for k in ('onlyOwnedBundleModeV5Changed','usesPublicDarwinAddinheritNPForSTDOUTAndSTDERR','childOnlyCloseOnExecClearing','parentDescriptorAndStatusFlagsUnchanged','noNewOpenTruncateOrPathRedirection','checksRealpathFGetPathAndSameDevInode','requiresRegularUID501GID501Mode0600Nlink1AppendWritable','checksBeforeActionsAndImmediatelyBeforeActualSpawn','logsActualParentFDFlagsOncePerStream','argvEnvRegisteredPortsPermissionsAndOwnerStateUnchanged','fileActionsFailuresPreventSpawnAndDestroyInitializedActions','successfulSpawnPIDStateRetainedBeforeCleanupErrors','allStrictNativeLegacyModesUnchanged','CPUProviderAndAll29CPUObjectsWholeR41','ChildMachineBodyWholeR41')) and scope['consumerStdioInheritanceContract']['newRootPermissions'] is False,'only validated owned-log stdout/stderr descriptors reach owned Child; no parent flags, paths, permissions, owner or CPU changes')
    task_source=json.loads(base.exact(scope['cpuTaskScopedRAMV1Candidate']).read_bytes())
    base.exact(scope['runtime64CPUTaskScopedRAMV1DeltaVerification'])
    baseline_task_cpu=json.loads(base.exact(old['cpuBorrowedHostInputV1Candidate']).read_bytes())
    old_task_objects=baseline_task_cpu['actualChangedObjects']+baseline_task_cpu['inheritedWholeObjects']
    old_task_names={'modern_cpu_kernel_lifecycle_v52.o','modern_cpu_native_public_factory_startup_failure_v7.o','vm27_hv_public_vm_bootstrap_v26.o','modern_cpu_production_native_ops_v6.o'}
    new_task_names={'modern_cpu_kernel_lifecycle_v53.o','modern_cpu_native_public_factory_startup_failure_v8.o','vm27_hv_public_vm_bootstrap_v27.o','modern_cpu_production_native_ops_v7.o'}
    expected_task_whole={row['path']:row for row in old_task_objects if pathlib.Path(row['path']).name not in old_task_names}
    need(task_source['cpuBorrowedHostInputV1Candidate']==old['cpuBorrowedHostInputV1Candidate'] and len(old_task_objects)==29 and len(task_source['actualChangedObjects'])==4 and len(task_source['inheritedWholeObjects'])==25 and {row['path']:row for row in task_source['inheritedWholeObjects']}==expected_task_whole and {pathlib.Path(row['path']).name for row in task_source['actualChangedObjects']}==new_task_names and task_source['allOther25ObjectsWholeUnchanged'] is True,'exact Life53 Factory8 Bootstrap27 Production7 substitutions with25 complete whole pins')
    need(scope['factory8AndGICEngine5CurrentObjects']==[scope['factory8ActualChangedObject'],scope['gicEngine5ObjectWholeRuntime64']] and all(row in task_source['actualChangedObjects']for row in (scope['factory8ActualChangedObject'],scope['bootstrap27ActualChangedObject'],scope['production7ActualChangedObject'])) and all(row in task_source['inheritedWholeObjects']for row in (scope['gicEngine5ObjectWholeRuntime64'],scope['mandatory4ObjectWholeRuntime64'])),'Factory8 Bootstrap27 Production7 changed; Engine5 and Mandatory4 whole Runtime64')
    need(task_source['cpuTaskScopedRAMV1Contract']==scope['cpuTaskScopedRAMV1Contract'] and task_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (task_source['actualExports'],task_source['actualNativeImports'],task_source['actualLoads'])==(155,94,4) and task_source['all94NativeImportSemanticsSame'] is True and scope['all94NativeImportSemanticsPreserved'] is True,'actual155/94/4 with all existing94 native semantics whole')
    task_binding=scope['actualSameImageVCPUsExitBinding'];base.exact(task_binding['callbackAssembly'])
    need(task_binding==task_source['actualSameImageVCPUsExitBinding'] and task_binding['actualDirectBL']['targetRVA']==task_binding['ownExportRVA'] and task_binding['externalVCPUsExitImportPresent'] is False,'current own-image wake binding preserved by Runtime65 signing')
    need(task_source['sourcePlan']==scope['cpuTaskScopedRAMSourcePlan'] and task_plan['contract']==scope['cpuTaskScopedRAMV1Contract'],'actual compiled same-task RAM plan')
    for key,row in task_plan['proofs'].items():need(scope[key]==task_source[key]==row,'actual same-task RAM proof '+key);base.exact(row)
    task_contract=scope['cpuTaskScopedRAMV1Contract']
    need(all(task_contract[key]is True for key in ('actualNormal70FailureIsVMMapCreatorPthreadGuard', 'sameTaskIdentityUsesRealGetpidAndActualVMAllocationEpoch', 'additiveCreateAdoptMapOnlyUseTaskScope', 'bootstrapMapBindsInstalledBackendAndActualFactoryKernelRegistry', 'factoryTaskReadinessKeepsLiveProfileEpochRAMMembershipAndOperationExclusion', 'kernelTaskReadinessComparesOpaqueRegisteredVMBeforeDereference', 'callbackCurrentThreadStillNonzeroAndOutsideRegistryMutexes', 'productionNative3RequiresExactRealContextInstalledTaskPIDLiveVM', 'productionNative3PermitsExistingCPUsForNewDisjointMappings', 'productionNative1And2CreatorThreadChecksUnchanged', 'productionNative4And5CreatorThreadAndNoCPUChecksUnchanged', 'allCPUCreateRegisterRunDestroyOwnerAndContextChecksUnchanged', 'destructiveProtectUnmapFreeAndRAMWriteCPUAttachmentGuardsUnchanged', 'bootstrapUnmapProtectExactWholeRangeAndCreatorOwnerChecksUnchanged', 'bootstrapUnmapProtectNonzeroAtMost8GPAStatusNativeInvokedRecordsPreserveErrno', 'allBorrowedHostInputAndOutputPrivateControlGuardsPreserved', 'strictGuestIPANonoverlapWithMappedOrUncertainRangesUnchanged', 'actualNative3PacketAndReturnWithUncertainRetentionAndRealCleanupUnchanged', 'noPartialRangeOperationsAutomaticUnmapRemapOrSyntheticSuccess', 'noGuestTLBIOrCrossCPUDestructiveSafetyClaim', 'allOther25ObjectsWhole', 'all155ExportNamesAndKinds94NativeImportSemantics4LoadSemanticsUnchanged', 'noSigningDeviceProbeOrGuestBootClaim')) and task_contract['actualChangedObjects']==4,'same-task additive create adopt map only with real PID live VM epoch and existing control guards; creator/noCPU destructive and all CPU guards remain unchanged')
    borrowed_source=json.loads(base.exact(scope['cpuBorrowedHostInputV1Candidate']).read_bytes())
    base.exact(scope['runtime63CPUBorrowedHostInputV1DeltaVerification'])
    baseline_borrowed_cpu=json.loads(base.exact(old['cpuSerializedWakeV1Candidate']).read_bytes())
    old_borrowed_objects=baseline_borrowed_cpu['actualChangedObjects']+baseline_borrowed_cpu['inheritedWholeObjects']
    old_borrowed_names={'modern_cpu_kernel_lifecycle_v51.o','modern_cpu_native_public_factory_startup_failure_v6.o','vm27_hv_public_vm_bootstrap_v25.o'}
    new_borrowed_names={'modern_cpu_kernel_lifecycle_v52.o','modern_cpu_native_public_factory_startup_failure_v7.o','vm27_hv_public_vm_bootstrap_v26.o'}
    expected_borrowed_whole={row['path']:row for row in old_borrowed_objects if pathlib.Path(row['path']).name not in old_borrowed_names}
    need(borrowed_source['cpuSerializedWakeV1Candidate']==old['cpuSerializedWakeV1Candidate'] and len(old_borrowed_objects)==29 and len(borrowed_source['actualChangedObjects'])==3 and len(borrowed_source['inheritedWholeObjects'])==26 and {row['path']:row for row in borrowed_source['inheritedWholeObjects']}==expected_borrowed_whole and {pathlib.Path(row['path']).name for row in borrowed_source['actualChangedObjects']}==new_borrowed_names and borrowed_source['allOther26ObjectsWholeUnchanged'] is True,'exact Life52 Factory7 Bootstrap26 substitutions with26 complete whole pins')
    need(scope['historicalRuntime64BorrowedHostInputV1Verification']['factory7AndGICEngine5CurrentObjects']==[scope['historicalRuntime64BorrowedHostInputV1Verification']['factory7ActualChangedObject'],scope['historicalRuntime64BorrowedHostInputV1Verification']['gicEngine5ObjectWholeRuntime63']] and scope['historicalRuntime64BorrowedHostInputV1Verification']['factory7ActualChangedObject']in borrowed_source['actualChangedObjects'] and scope['historicalRuntime64BorrowedHostInputV1Verification']['bootstrap26ActualChangedObject']in borrowed_source['actualChangedObjects'] and all(row in borrowed_source['inheritedWholeObjects']for row in (scope['historicalRuntime64BorrowedHostInputV1Verification']['gicEngine5ObjectWholeRuntime63'],scope['historicalRuntime64BorrowedHostInputV1Verification']['mandatory4ObjectWholeRuntime63'])),'Factory7/Bootstrap26 changed; actual Engine5/Mandatory4 whole Runtime63')
    need(borrowed_source['cpuBorrowedHostInputV1Contract']==scope['cpuBorrowedHostInputV1Contract'] and borrowed_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (borrowed_source['actualExports'],borrowed_source['actualNativeImports'],borrowed_source['actualLoads'])==(155,94,4) and borrowed_source['all94NativeImportSemanticsSame'] is True and scope['all94NativeImportSemanticsPreserved'] is True,'actual155/94/4 with all existing94 native semantics including cond_wait whole')
    borrowed_binding=scope['historicalRuntime64BorrowedHostInputV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(borrowed_binding['callbackAssembly'])
    need(borrowed_binding==borrowed_source['actualSameImageVCPUsExitBinding'] and borrowed_binding['actualDirectBL']['targetRVA']==borrowed_binding['ownExportRVA'] and borrowed_binding['externalVCPUsExitImportPresent'] is False,'current own-image wake binding preserved by Runtime64 signing')
    need(borrowed_source['sourcePlan']==scope['cpuBorrowedHostInputSourcePlan'] and borrowed_plan['contract']==scope['cpuBorrowedHostInputV1Contract'],'actual compiled caller-borrowed host input plan')
    for key,row in borrowed_plan['proofs'].items():need(scope[key]==borrowed_source[key]==row,'actual borrowed host input proof '+key);base.exact(row)
    borrowed_contract=scope['cpuBorrowedHostInputV1Contract']
    need(all(borrowed_contract[key]is True for key in ('mappingHostInputNoLongerUsesOutputPublicationRangeGuard', 'dedicatedBootstrapFactoryAndKernelHostInputGuardsAdded', 'onlyBorrowedHostCallerOwnedAllocationDataMayAliasOtherBorrowedMappings', 'providerOwnedMmapAllocationAndItsGuardPagesRemainExcluded', 'allExistingBootstrapControlConfigMapEntryExclusionsPreserved', 'allFactoryVMRAMRecordCPUEntryExitStorageBorrowAndRegistryControlExclusionsPreserved', 'OSConfigAndGICSidecarInputExclusionsPreserved', 'kernelVMRAMRecordCPUEntryCPUAndBorrowAllocationsExcluded', 'everyActualNativeCPUContextFullTwoPage8000RangeExcluded', 'genericOutputPublicationGuardsRemainWholeUnchanged', 'outRAMReceiptAndHostCrossDisjointGuardsRemainUnchanged', 'FactoryRegistryToBootstrapMutexLockDirectionPreserved', 'KernelRegistryThenVMMutexOrderPreserved', 'ControllerSidecarChecksRemainOutsideKernelRegistryAndVMMutexes', 'noNativeOrInjectedCallbackRunsInsideThesePrivateRangeLocks', 'borrowedHostAlignmentSizeOverflowAndRealReadableSelfMappingChecksUnchanged', 'allVMOwnerPthreadNativeOwnerEpochAndLiveStateGuardsUnchanged', 'strictGuestIPANonoverlapWithMappedOrUncertainRangesRemainsUnchanged', 'realNative3MappingPacketReturnAndUncertainCleanupRulesRemainUnchanged', 'destructiveProtectUnmapFreeAndRAMWriteCPUAttachmentGuardsUnchanged', 'existingSerializedWake32FunctionsRemainWhole', 'actualRAMAdoptAndMapNonzeroReasonsLogAtMost8WithoutChangingResultOrErrno', 'actualVMMCallerDerivesHostFromBackingBasePlusRecordOffsetAndFlagsFromRealBacking', 'noGuestBootOrLiveDeviceExecutionClaimedByHostBuild', 'allOther26ObjectsWhole', 'all155ExportNamesAndKinds94NativeImportSemanticsAnd4LoadSemanticsUnchanged')) and {key:borrowed_contract[key]for key in ('actualChangedObjects',)}=={'actualChangedObjects': 3},'dedicated host input only permits caller-borrowed existing backing aliases; own allocations/guardpages/control records/all actual native CPU8000 windows remain excluded, output publication/IPA nooverlap/owners/real native failures unchanged')
    serialized_source=json.loads(base.exact(scope['cpuSerializedWakeV1Candidate']).read_bytes())
    base.exact(scope['runtime62CPUSerializedWakeV1DeltaVerification'])
    baseline_serialized_cpu=json.loads(base.exact(old['cpuOwnedMandatoryFailureV1Candidate']).read_bytes())
    old_serialized_objects=baseline_serialized_cpu['actualChangedObjects']+baseline_serialized_cpu['inheritedWholeObjects']
    expected_serialized_whole={row['path']:row for row in old_serialized_objects if pathlib.Path(row['path']).name!='modern_cpu_kernel_lifecycle_v50.o'}
    need(serialized_source['cpuOwnedMandatoryFailureV1Candidate']==old['cpuOwnedMandatoryFailureV1Candidate'] and len(old_serialized_objects)==29 and len(serialized_source['actualChangedObjects'])==1 and len(serialized_source['inheritedWholeObjects'])==28 and {row['path']:row for row in serialized_source['inheritedWholeObjects']}==expected_serialized_whole and pathlib.Path(serialized_source['actualChangedObjects'][0]['path']).name=='modern_cpu_kernel_lifecycle_v51.o' and serialized_source['allOther28ObjectsWholeUnchanged'] is True,'exact sole Life50 to51 replacement with28 complete whole pins')
    need(scope['historicalRuntime63SerializedWakeV1Verification']['factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime62']==[scope['historicalRuntime63SerializedWakeV1Verification']['factory6ObjectWholeRuntime62'],scope['historicalRuntime63SerializedWakeV1Verification']['bootstrap25ObjectWholeRuntime62'],scope['historicalRuntime63SerializedWakeV1Verification']['gicEngine5ObjectWholeRuntime62']] and all(row in serialized_source['inheritedWholeObjects']for row in scope['historicalRuntime63SerializedWakeV1Verification']['factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime62']+[scope['historicalRuntime63SerializedWakeV1Verification']['mandatory4ObjectWholeRuntime62']]),'actual Factory6 Bootstrap25 Engine5 Mandatory4 whole Runtime62')
    allowed_cond_import=[dict(ordinal=4,weak=0,name='_pthread_cond_wait',addend=0)]
    need(serialized_source['cpuSerializedWakeV1Contract']==scope['cpuSerializedWakeV1Contract'] and serialized_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (serialized_source['actualExports'],serialized_source['actualNativeImports'],serialized_source['actualLoads'])==(155,94,4) and serialized_source['all93ExistingNativeImportSemanticsSame'] is True and serialized_source['additionalNativeImports']==scope['additionalNativeImports']==allowed_cond_import and scope['all93ExistingNativeImportSemanticsPreserved'] is True,'actual155/94/4 and exact sole cond_wait addition with all prior93 native semantics unchanged')
    serialized_binding=scope['historicalRuntime63SerializedWakeV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(serialized_binding['callbackAssembly'])
    need(serialized_binding==serialized_source['actualSameImageVCPUsExitBinding'] and serialized_binding['actualDirectBL']['targetRVA']==serialized_binding['ownExportRVA'] and serialized_binding['externalVCPUsExitImportPresent'] is False,'current own-image wake binding preserved by Runtime63 signing')
    native_cond_proof=scope['additionalNativeImportStrongDefinitionProof']
    need(native_cond_proof['resolved'] is True and native_cond_proof['symbol']=='_pthread_cond_wait' and native_cond_proof['actualImport']==allowed_cond_import[0] and native_cond_proof['route'][-1]['actualExport']==dict(flags=0,address=12680),'actual captured native strong definition closes sole added cond_wait import')
    for row in scope['nativeImportClosureSources']:base.exact(row)
    need(serialized_source['sourcePlan']==scope['cpuSerializedWakeSourcePlan'] and serialized_plan['contract']==scope['cpuSerializedWakeV1Contract'] and serialized_plan['allowAdditionalNativeImports']==allowed_cond_import and serialized_plan['expectedActualNativeImports']==94,'actual compiled serialized wake plan and sole native delta')
    for key,row in serialized_plan['proofs'].items():need(scope[key]==serialized_source[key]==row,'actual serialized wake source proof '+key);base.exact(row)
    serialized_contract=scope['cpuSerializedWakeV1Contract']
    need(all(serialized_contract[key]is True for key in ('realWakeRequestsForSameOwnedTargetSerializeAcrossThreads', 'queuedAdmissionCountedBeforeLockIsDroppedForFullIdentityValidation', 'activeNativeCallAndQueuedValidationOrConditionWaitersAllPreventDrainCompletion', 'conditionWaitReleasesOwnerMutexAndChecksRealInFlightAndDrainingPredicatesAfterSpuriousWake', 'noTimedPollingOrSyntheticWakeOrNativeRunRetry', 'samePthreadRecursiveSignalAndQueueCounterOverflowStillReturnRealBUSY', 'exactCopiedIdentityCheckedBeforeQueueAndCurrentRegistryIdentityCheckedBeforeWait', 'fullOwnerEpochGenerationPublicationProfileAndActualContextVersionRecheckedAfterQueueBeforeNative10', 'realNative10WakeVersionAndWFxNotificationCallbacksAllRemainOutsideOwnerMutex', 'oneActualNative10ForEachAdmittedSignalAfterItsTurn', 'nativeSlotMaskVersionAndAllExistingForeignOwnerAndOutputRangeGuardsPreserved', 'drainingBroadcastsToQueuedCallsAndTheyReturnRealNOTLIVEWithoutNativeInvocation', 'conditionInitializationFailureReleasesInitializedMutexAndAllocation', 'conditionAndMutexDestroyFailureRetainsDrainingAllocationForRetryWithoutDoubleBorrowRelease', 'committedGICMMIOAndTrueFailurePoisonRulesUnchanged', 'originalNative9ReceiptGuestPCAndRealExitStatusNotFabricated', 'Engine5Factory6Bootstrap25Mandatory4AndAllOther28ObjectsWhole', 'onlyLifecycleObjectReplaced', 'allOther28ObjectsWhole', 'all93ExistingNativeImportSemanticsPreserved', 'onlyAddedImportIsActualSystemPthreadCondWait', 'all155PublicExportNamesAndKindsAndAll4LoadSemanticsUnchanged')) and {key:serialized_contract[key]for key in ('actualChangedObjects', 'actualNativeImports')}=={'actualChangedObjects': 1, 'actualNativeImports': 94},'real same-target cross-thread serialization with queued+active drain pins/native10 outside mutex; same-thread recursive BUSY and real failures/poison preserved without MMIO replay or synthetic wake')
    mandatory_source=json.loads(base.exact(scope['cpuOwnedMandatoryFailureV1Candidate']).read_bytes())
    base.exact(scope['runtime61CPUOwnedMandatoryFailureV1DeltaVerification'])
    baseline_mandatory_cpu=json.loads(base.exact(old['cpuAdditiveRAMV1Candidate']).read_bytes())
    old_mandatory_objects=baseline_mandatory_cpu['actualChangedObjects']+baseline_mandatory_cpu['inheritedWholeObjects']
    expected_mandatory_whole={row['path']:row for row in old_mandatory_objects if pathlib.Path(row['path']).name!='modern_vmm_mandatory_field_v3.o'}
    need(mandatory_source['cpuAdditiveRAMV1Candidate']==old['cpuAdditiveRAMV1Candidate'] and len(old_mandatory_objects)==29 and len(mandatory_source['actualChangedObjects'])==1 and len(mandatory_source['inheritedWholeObjects'])==28 and {row['path']:row for row in mandatory_source['inheritedWholeObjects']}==expected_mandatory_whole and pathlib.Path(mandatory_source['actualChangedObjects'][0]['path']).name=='modern_vmm_mandatory_field_v4.o' and mandatory_source['allOther28ObjectsWholeUnchanged'] is True,'exact sole MandatoryField3 to4 replacement and28 complete whole pins independent of old concatenation order')
    need(scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime61']==[scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['factory6ObjectWholeRuntime61'],scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['bootstrap25ObjectWholeRuntime61'],scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['gicEngine5ObjectWholeRuntime61']] and all(row in mandatory_source['inheritedWholeObjects']for row in scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime61']),'actual Factory6 Bootstrap25 Engine5 whole Runtime61')
    need(mandatory_source['cpuOwnedMandatoryFailureV1Contract']==scope['cpuOwnedMandatoryFailureV1Contract'] and mandatory_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (mandatory_source['actualExports'],mandatory_source['actualNativeImports'],mandatory_source['actualLoads'])==(155,93,4),'actual MandatoryField diagnostic source and same155/93/4 namespace')
    mandatory_binding=scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(mandatory_binding['callbackAssembly'])
    need(mandatory_binding==mandatory_source['actualSameImageVCPUsExitBinding'] and mandatory_binding['actualDirectBL']['targetRVA']==mandatory_binding['ownExportRVA'] and mandatory_binding['externalVCPUsExitImportPresent'] is False,'current actual direct own-image wake binding preserved by Runtime62 signing')
    need(mandatory_source['sourcePlan']==scope['cpuOwnedMandatoryFailureSourcePlan'] and mandatory_plan['contract']==scope['cpuOwnedMandatoryFailureV1Contract'],'actual compiled MandatoryField diagnostic plan')
    for key,row in mandatory_plan['proofs'].items():need(scope[key]==mandatory_source[key]==row,'actual MandatoryField source proof '+key);base.exact(row)
    mandatory_contract=scope['cpuOwnedMandatoryFailureV1Contract']
    need(all(mandatory_contract[key]is True for key in ('onlyMandatoryFieldImplementationObjectReplaced', 'sameActualMandatoryFieldV3AndV2ControlFlowGuardsAndReturnStatusesPreserved', 'onlyFinalTwoDefinitionsRenamedToPrivateStaticInheritedFunctions', 'privateStaticInheritedPrototypesPreventNewABIOrExports', 'publicGetAndSetWrapWholeRealOperationIncludingEarlyAdmissionNativeAndReleaseFailures', 'allNonzeroMandatoryFieldResultsShareIndependentFirst8FailureBudget', 'successfulMandatoryCallsDoNotConsumeFailureBudget', 'onlyOperationPublicCPUFieldAndRealStatusLogged', 'noFieldValuesOutputContentsOrPointersLogged', 'noAdditionalPayloadOutputMemoryNativeReadWriteOrGuestStateMutation', 'diagnosticErrnoPreserved', 'modernLogicalDebugClaim6a0UsesActualNative668U8AndBank2', 'modernLogicalACTLR410UsesActualNative3f8U64AndBank1', 'existingReserved390ZeroOwnerMetadataRouteUnchangedAndAlsoObserved', 'actualChildRestoreDebugClaimUsesLDRBU8AndACTLRUsesLDRU64', 'noSpeculativeControl7Or8Fix', 'noCurrentNormal67CrashReportClaimed', 'Life50Factory6Bootstrap25Engine5ProductionOpsAndAllOther28ObjectsWhole', 'allOther28ObjectsWhole')) and {key:mandatory_contract[key]for key in ('actualChangedObjects',)}=={'actualChangedObjects': 1},'whole original MandatoryField get/set with original early-admission/native/release results; first8 nonzero status logs only without field values/output reads/native mutations and no speculative control7/8 fix or current crash claim')
    additive_source=json.loads(base.exact(scope['cpuAdditiveRAMV1Candidate']).read_bytes())
    base.exact(scope['runtime60CPUAdditiveRAMV1DeltaVerification'])
    baseline_additive_cpu=json.loads(base.exact(old['cpuPinnedRAMReadV1Candidate']).read_bytes())
    old_additive_objects=baseline_additive_cpu['actualChangedObjects']+baseline_additive_cpu['inheritedWholeObjects']
    replaced_names={'modern_cpu_kernel_lifecycle_v49.o','modern_cpu_native_public_factory_startup_failure_v5.o','vm27_hv_public_vm_bootstrap_v24.o'}
    expected_additive_whole=[row for row in old_additive_objects if pathlib.Path(row['path']).name not in replaced_names]
    expected_new_names={'modern_cpu_kernel_lifecycle_v50.o','modern_cpu_native_public_factory_startup_failure_v6.o','vm27_hv_public_vm_bootstrap_v25.o'}
    need(additive_source['cpuPinnedRAMReadV1Candidate']==old['cpuPinnedRAMReadV1Candidate'] and len(old_additive_objects)==29 and len(additive_source['actualChangedObjects'])==3 and len(additive_source['inheritedWholeObjects'])==26 and additive_source['inheritedWholeObjects']==expected_additive_whole and {pathlib.Path(row['path']).name for row in additive_source['actualChangedObjects']}==expected_new_names and additive_source['allOther26ObjectsWholeUnchanged'] is True,'actual Life50 Factory6 Bootstrap25 substitutions, all other26 R60 CPU objects whole')
    need(scope['historicalRuntime61AdditiveRAMV1Verification']['gicEngine5ObjectWholeRuntime60']in additive_source['inheritedWholeObjects'] and scope['historicalRuntime61AdditiveRAMV1Verification']['factory6ActualChangedObject']in additive_source['actualChangedObjects'] and scope['historicalRuntime61AdditiveRAMV1Verification']['bootstrap25ActualChangedObject']in additive_source['actualChangedObjects'] and scope['historicalRuntime61AdditiveRAMV1Verification']['factory6AndGICEngine5CurrentObjects']==[scope['historicalRuntime61AdditiveRAMV1Verification']['factory6ActualChangedObject'],scope['historicalRuntime61AdditiveRAMV1Verification']['gicEngine5ObjectWholeRuntime60']],'Engine5 whole, Factory6/Bootstrap25 actually changed; no Factory5 whole current claim')
    need(additive_source['cpuAdditiveRAMV1Contract']==scope['cpuAdditiveRAMV1Contract'] and additive_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (additive_source['actualExports'],additive_source['actualNativeImports'],additive_source['actualLoads'])==(155,93,4),'actual additive RAM source and same155/93/4 namespace')
    additive_binding=scope['historicalRuntime61AdditiveRAMV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(additive_binding['callbackAssembly'])
    need(additive_binding==additive_source['actualSameImageVCPUsExitBinding'] and additive_binding['actualDirectBL']['targetRVA']==additive_binding['ownExportRVA'] and additive_binding['externalVCPUsExitImportPresent'] is False,'current actual direct own-image wake binding preserved by Runtime61 signing')
    need(additive_source['sourcePlan']==scope['cpuAdditiveRAMSourcePlan'] and additive_plan['contract']==scope['cpuAdditiveRAMV1Contract'],'actual compiled source plan contract')
    for key,row in additive_plan['proofs'].items():need(scope[key]==additive_source[key]==row,'actual additive source proof '+key);base.exact(row)
    for key,value in additive_plan.get('additionalContracts',{}).items():need(scope[key]==additive_source[key]==value,'actual bounded register/map failure diagnostic contract '+key)
    additive_contract=scope['cpuAdditiveRAMV1Contract']
    need(all(additive_contract[key]is True for key in ('CPUHandlesMayExistOnlyForCreateAdoptAndFreshDisjointMap', 'FactoryAndKernelOwnerEpochRegistryDisjointAndAdmissionPreserved', 'WriteProtectUnmapFreeStillRejectAnyCPUAttachment', 'MapRequiresUnmappedNonUncertainOwnRAMHandle', 'MapGPARangeStrictlyDisjointFromAllMappedOrUncertainRanges', 'ExistingMappedGPAHostFlagsAndBytesRemainImmutableUnderCPUAttachment', 'NewRAMRegistryLinksAndMapUncertainGuestAddressAndFinalPublicationUseVMMutex', 'Native3RemainsOutsideRegistryAndVMMutex', 'FailedNative3PreservesUncertainExactGPAAndBorrowedHostLease', 'NoNativeFailureTreatedAsNoSideEffects', 'CPUPostIdentityAndLifetimePinStillRequiredForRAMReads', 'ReaderStillHoldsRegistryThenVMMutexDuringActualUniqueOwnReadableLookupAndMachCopy', 'ReaderWaitsOnlyForItsOwnNewUncertainRAMNative3Publication', 'ReaderNeverWaitsWithRegistryMutexHeld', 'PublicationWaitReleasesVMMutexAndRechecksActualMapInFlightPredicate', 'PublicationCompletionRequiresMappedAndNonUncertainThenCompleteIdentityAndRangeRetry', 'PublicationWaitTimeoutOrNativeFailureIsExplicitContextUnreadableNeverUndefinedInjection', 'NoGuestPCAdvanceOrNativeGuestRunRetryForPublicationWait', 'PublicationCondInitDestroyFollowsActualVMLifetime', 'AllExistingPagewalkValidationDescriptorReReadActualMachCopyChecksPreserved', 'AllExistingRaw8AMXConfigAMXStateC1PACAndTrueUndefinedRoutesOtherwiseWhole', 'ActualMapFailureFirst8StageHostGPABytesStatusNativeInvokedOnly', 'MapLogPreservesErrnoAndOriginalAPIResult', 'ActualRegisterFailureFirst8AndAMXFailureFirst8PreserveResultAndErrno', 'InheritedRenamedEntryPointsHiddenBeforeDefinition', 'Other26CPUObjectsWholeR60', 'Engine5ProductionOpsV6ConsumerV6AndChildWholeR60', 'FullAMXExecutionAndAdvancedRAMProtectUnmapWithLiveCPUsRemainDeferred')) and additive_contract['DeviceExecutionProved'] is False and {key:additive_contract[key]for key in ('PublicationWaitUsesOneAbsoluteCLOCK_REALTIMEDeadlineSeconds', 'ChangedCPUObjects')}=={'PublicationWaitUsesOneAbsoluteCLOCK_REALTIMEDeadlineSeconds': 1, 'ChangedCPUObjects': 3},'strict additive-only nonoverlap RAM create/adopt/map with live CPUs; mapped bytes immutable, publication wait1s under VM condition but no Registry lock, real native3 failures/uncertain borrowed lease preserved, protect/unmap/free remain refused')
    pinned_source=json.loads(base.exact(scope['cpuPinnedRAMReadV1Candidate']).read_bytes())
    base.exact(scope['runtime59CPUPinnedRAMReadV1DeltaVerification'])
    baseline_pinned_cpu=json.loads(base.exact(old['cpuDisabledAMXStateV1Candidate']).read_bytes())
    need(pinned_source['cpuDisabledAMXStateV1Candidate']==old['cpuDisabledAMXStateV1Candidate'] and len(pinned_source['actualChangedObjects'])==1 and len(pinned_source['inheritedWholeObjects'])==28 and pinned_source['inheritedWholeObjects']==baseline_pinned_cpu['inheritedWholeObjects'] and pinned_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life49 retained-CPU RAM reader delta;28 CPU objects including Engine5 and ProductionOps whole Runtime59')
    need(len(scope['historicalRuntime60PinnedRAMReadV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime59'])==2 and all(row in pinned_source['inheritedWholeObjects']for row in scope['historicalRuntime60PinnedRAMReadV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime59']),'actual Factory5 and Engine5 whole Runtime59')
    need(pinned_source['cpuPinnedRAMReadV1Contract']==scope['cpuPinnedRAMReadV1Contract'] and pinned_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (pinned_source['actualExports'],pinned_source['actualNativeImports'],pinned_source['actualLoads'])==(155,93,4),'actual pinned RAM reader source and same155/93/4 namespace')
    pinned_binding=scope['historicalRuntime60PinnedRAMReadV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(pinned_binding['callbackAssembly'])
    need(pinned_binding==pinned_source['actualSameImageVCPUsExitBinding'] and pinned_binding['actualDirectBL']['targetRVA']==pinned_binding['ownExportRVA'] and pinned_binding['externalVCPUsExitImportPresent'] is False,'current callback targets own hv_vcpus_exit; Runtime60 signed code preserves binding')
    for key in ('actualNormal65SecondaryCPUAndRAMBusySnapshot','actualRAMCPUImmutabilitySource','originalVMOperationReadGateSource'):
        need(scope[key]==pinned_source[key],'actual pinned RAM reader source proof '+key);base.exact(scope[key])
    pinned_contract=scope['cpuPinnedRAMReadV1Contract']
    need(all(pinned_contract[key]is True for key in ('readonlyRAMLookupNoLongerContendsForGlobalVMOperation', 'onlyReaderBeginVMOperationAndEndVMOperationRemoved', 'realRetainedLiveCPUAndPostOperationPinsRAMAttachment', 'explicitCPUHandlesOrCPURegistryTruthRequiredUnderBothLocks', 'existingRegistryMutexThenVMMutexHeldThroughActualLookupAndCopy', 'allCurrentOwnCPURegistryPublishedLiveEpochGenerationOwnerPostTokenAndPoisonGuardsPreserved', 'RAMReadyV9RejectsEveryRAMMutationWhenCPUHandlesOrCPURegistryExist', 'VMFreeAndDestroyRejectCPUOrRAMAttachments', 'CPUCreateRegistersHandleAndLiveCPUBeforeExposingRun', 'uniqueCurrentEpochMappedReadableNonUncertainRegionAndOverflowGuardsPreserved', 'actualSelfMachRegionAndReadOverwriteExactCopyCountChecksPreserved', 'allPagewalkDescriptorValidationAndReReadGuardsPreserved', 'noBusyTurnedIntoUndefinedOrGuessedGuestInstruction', 'noNewBusyLoopNativeRetryOrNativeOperation', 'existingRaw8DecoderDisabledAMXStateAndConfigAndC1PACAndRealUndefinedWhole', 'originalNative9ReceiptAndRunStatusPreserved', 'existingDiagnosticPayloadBudgets192Kernel128FirmwareUnchanged', 'Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole', 'allOther28ObjectsWhole')) and {key:pinned_contract[key]for key in ('RAMReadyGuardSourceLines', 'RAMMutationGuardCallSites', 'actualChangedObjects')}=={'RAMReadyGuardSourceLines': [1262, 1268], 'RAMMutationGuardCallSites': {'create': 1290, 'adopt': 1327, 'write': 1356, 'mapProtectUnmap': 1371, 'free': 1424}, 'actualChangedObjects': 1},'read-only ownRAM is pinned by retained live CPU/post and immutable CPU-attached RAM under Registry then VM locks; all exact copy/descriptor/owner guards preserved without global VMop contention or busy/native retry')
    state_source=json.loads(base.exact(scope['cpuDisabledAMXStateV1Candidate']).read_bytes())
    base.exact(scope['runtime58CPUDisabledAMXStateV1DeltaVerification'])
    baseline_state_cpu=json.loads(base.exact(old['cpuEncodedExitV1Candidate']).read_bytes())
    need(state_source['cpuEncodedExitV1Candidate']==old['cpuEncodedExitV1Candidate'] and len(state_source['actualChangedObjects'])==1 and len(state_source['inheritedWholeObjects'])==28 and state_source['inheritedWholeObjects']==baseline_state_cpu['inheritedWholeObjects'] and state_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life48 state-read delta;28 CPU objects including Engine5 and ProductionOps whole Runtime58')
    need(len(scope['historicalRuntime59DisabledAMXStateV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime58'])==2 and all(row in state_source['inheritedWholeObjects']for row in scope['historicalRuntime59DisabledAMXStateV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime58']),'actual Factory5 and Engine5 whole Runtime58')
    need(state_source['cpuDisabledAMXStateV1Contract']==scope['cpuDisabledAMXStateV1Contract'] and state_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (state_source['actualExports'],state_source['actualNativeImports'],state_source['actualLoads'])==(155,93,4),'actual absent AMX state source and same155/93/4 namespace')
    state_binding=scope['historicalRuntime59DisabledAMXStateV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(state_binding['callbackAssembly'])
    need(state_binding==state_source['actualSameImageVCPUsExitBinding'] and state_binding['actualDirectBL']['targetRVA']==state_binding['ownExportRVA'] and state_binding['externalVCPUsExitImportPresent'] is False,'current callback targets own hv_vcpus_exit; Runtime59 signed code preserves binding')
    for key in ('actualNormal64EncodedIDAndAMXStateSnapshot','actualNativeAMXStateZeroBranchDisassembly','actualNativeAMXBank57SaveDisassembly'):
        need(scope[key]==state_source[key],'actual absent AMX state source proof '+key);base.exact(scope[key])
    state_contract=scope['cpuDisabledAMXStateV1Contract']
    need(all(state_contract[key]is True for key in ('onlyExactRaw8EncodedMRSAMXStateReceivesDisabledProfileZero', 'exactDirectionReadOneRequired', 'requiresValidatedIPadOS1611NativeISAOneOrTwoAndExactOwnerEpochGenerationPost', 'requiresImmutableProfileForbidBank57AndActual4110NoForbiddenActiveBits', 'metadataActiveReadUsesExistingGICPostFieldV20', 'requiresActualA64EL1PSTATEAndNoPCOverflow', 'actualRtZeroAndPCPlusFourWritesOnly', 'Rt31DiscardNeverWritesSP', 'noAMXStateWriteOrArithmeticOrBank57ActivationSupported', 'partialRegisterOrPCWriteFailurePoisonsCPU', 'allOtherOriginalRaw8PublicUndIDAndGICDecoderRoutesPreserved', 'allExistingC1PACDisabledAMXConfigZeroOr100AndRaw7UndefinedPreserved', 'originalNativeValuesRawReasonSyndromeAndNative9ReceiptPreserved', 'noNewNative8OrOtherNativeCall', 'noNewMetadataOrSystemAllowlistExpansion', 'firstEightRealRouteStatusActiveAndCommitLogsPreserved', 'existingDiagnosticPayloadBudgets192Kernel128FirmwareUnchanged', 'Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole', 'allOther28ObjectsWhole')) and {key:state_contract[key]for key in ('exactFieldMask', 'exactFieldMatch', 'exactSelector', 'newRouteNumber', 'nativeContextStateZeroBranchPrimaryAt', 'actualChangedObjects')}=={'exactFieldMask': '0xfffffc1f', 'exactFieldMatch': '0x00373c03', 'exactSelector': 'S3_4_C15_C1_3', 'newRouteNumber': 6, 'nativeContextStateZeroBranchPrimaryAt': '0xfffffe00080aa6a8 / 0xfffffe00080aa6c4', 'actualChangedObjects': 1},'exact AMX state selector1_3 read-only disabled0 route6 with profile/forbidden57/active/owner/post/EL1A64 guards, real Rt0 and PC4 only; existing decoder and undefined fallback preserved')
    encoded_source=json.loads(base.exact(scope['cpuEncodedExitV1Candidate']).read_bytes())
    base.exact(scope['runtime57CPUEncodedExitV1DeltaVerification'])
    baseline_encoded_cpu=json.loads(base.exact(old['cpuDisabledAMXConfigV3Candidate']).read_bytes())
    need(encoded_source['cpuDisabledAMXConfigV3Candidate']==old['cpuDisabledAMXConfigV3Candidate'] and len(encoded_source['actualChangedObjects'])==1 and len(encoded_source['inheritedWholeObjects'])==28 and encoded_source['inheritedWholeObjects']==baseline_encoded_cpu['inheritedWholeObjects'] and encoded_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life47 decoder delta;28 CPU objects including Engine5 and ProductionOps whole Runtime57')
    need(len(scope['historicalRuntime58EncodedExitV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime57'])==2 and all(row in encoded_source['inheritedWholeObjects']for row in scope['historicalRuntime58EncodedExitV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime57']),'actual Factory5 and Engine5 whole Runtime57')
    need(encoded_source['cpuEncodedExitV1Contract']==scope['cpuEncodedExitV1Contract'] and encoded_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (encoded_source['actualExports'],encoded_source['actualNativeImports'],encoded_source['actualLoads'])==(155,93,4),'actual encoded raw8 source and same155/93/4 namespace')
    encoded_binding=scope['historicalRuntime58EncodedExitV1Verification']['actualSameImageVCPUsExitBinding'];base.exact(encoded_binding['callbackAssembly'])
    need(encoded_binding==encoded_source['actualSameImageVCPUsExitBinding'] and encoded_binding['actualDirectBL']['targetRVA']==encoded_binding['ownExportRVA'] and encoded_binding['externalVCPUsExitImportPresent'] is False,'current callback targets own hv_vcpus_exit; Runtime58 signed code preserves binding')
    for key in ('actualNormal63AcceptedConfigAndRaw8Snapshot','original13EncodedExitDecoderDisassembly','actualNativeABI14EncodedExitConsumerDisassembly'):
        need(scope[key]==encoded_source[key],'actual encoded raw8 source proof '+key);base.exact(scope[key])
    encoded_contract=scope['cpuEncodedExitV1Contract']
    need(all(encoded_contract[key]is True for key in ('actualRaw8EC3FOnlyStatefulDecoder', 'exactNative4010U32MetadataReadWithOwnPostVersionOwnerEpochGenerationIdentityAndSelfMapGuards', 'noSystemGICOrGlobalMetadataAllowlistExpansion', 'metadataFreshnessBasisIsMatchingActualNativeABI14AndFourAdjacentVerifiedExitFields', 'firstEightActual4010OriginalESRDecodedESRPolicyAndRouteLoggedForActualRunValidation', 'originalNativeValuesRawReasonSyndromeAndNative9ReceiptPreserved', 'PACPolicyIs4030Bit4Mask0x10', 'privatePACMaskMatchWithPolicyTrueInjectsRealUndefinedAndResumes', 'privatePACMaskMatchWithPolicyFalsePublishesOriginalNativeESR', 'specialIDPolicyTrueWritesActualRtValue980200AndPCPlusFour', 'specialRt31DiscardedArchitecturallyNeverWritesSP', 'onlyLocalDecodedStepPassedToExistingRealGICHandlers', 'actualDecodedPublicReductionPublishedOnlyAfterSuccessfulReadAndPostGuards', 'existingFactoryPublicProducerGuardsUnchanged', 'noUnconditionalExitIgnoreOrFabricatedSuccessfulRun', 'partialRealRegisterPCOrUndefinedWriteFailurePoisonsCPU', 'raw8UndefinedInjectionDoesNotConsumeRaw7OneShotOrTryAMXEmulation', 'existingC1PACDisabledAMX01HundredAndRealUndefinedFunctionalityPreserved', 'noNewNativeCallOrGuestCodeWrite', 'existingDiagnosticPayloadBudgets192Kernel128FirmwareUnchanged', 'Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole', 'allOther28ObjectsWhole')) and encoded_contract['freshProducerWriteInstructionIndependentlyLocated'] is False and {key:encoded_contract[key]for key in ('currentAndOriginalNativeABI14Version', 'privatePACMask', 'SMCMask', 'SMCMatch', 'SMCDecodedESR', 'specialIDMask', 'specialIDMatch', 'genericDecodedESR', 'actualChangedObjects')}=={'currentAndOriginalNativeABI14Version': '0x206879700000000e', 'privatePACMask': '0x00302c00', 'SMCMask': '0x01ff0000', 'SMCMatch': '0x01c00000', 'SMCDecodedESR': '0x5e000000 | (field4010 & 0xffff)', 'specialIDMask': '0x003ffc1e', 'specialIDMatch': '0x003e4000', 'genericDecodedESR': '0x62000000 | (field4010 & 0x01ffffff)', 'actualChangedObjects': 1},'ABI14 encoded raw8 EC3f decoder with real SYS/SMC/PAC/special-ID routes; fresh producer write remains not independently located, actual owned-post4B and bounded Run logs provide runtime validation')
    config_source=json.loads(base.exact(scope['cpuDisabledAMXConfigV3Candidate']).read_bytes())
    base.exact(scope['runtime56CPUDisabledAMXConfigV3DeltaVerification'])
    baseline_config_cpu=json.loads(base.exact(old['cpuDisabledAMXConfigV2Candidate']).read_bytes())
    need(config_source['cpuDisabledAMXConfigV2Candidate']==old['cpuDisabledAMXConfigV2Candidate'] and len(config_source['actualChangedObjects'])==1 and len(config_source['inheritedWholeObjects'])==28 and config_source['inheritedWholeObjects']==baseline_config_cpu['inheritedWholeObjects'] and config_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life46 policy delta;28 CPU objects including Engine5 and ProductionOps whole Runtime56')
    need(len(scope['historicalRuntime57DisabledAMXConfigV3Verification']['factory5AndGICEngine5ObjectsWholeRuntime56'])==2 and all(row in config_source['inheritedWholeObjects']for row in scope['historicalRuntime57DisabledAMXConfigV3Verification']['factory5AndGICEngine5ObjectsWholeRuntime56']),'actual Factory5 and Engine5 whole Runtime56')
    need(config_source['cpuDisabledAMXConfigV3Contract']==scope['cpuDisabledAMXConfigV3Contract'] and config_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (config_source['actualExports'],config_source['actualNativeImports'],config_source['actualLoads'])==(155,93,4),'actual exact disabled config100 source and same155/93/4 namespace')
    config_binding=scope['historicalRuntime57DisabledAMXConfigV3Verification']['actualSameImageVCPUsExitBinding'];base.exact(config_binding['callbackAssembly'])
    need(config_binding==config_source['actualSameImageVCPUsExitBinding'] and config_binding['actualDirectBL']['targetRVA']==config_binding['ownExportRVA'] and config_binding['externalVCPUsExitImportPresent'] is False,'current callback targets own hv_vcpus_exit; Runtime57 signed code preserves binding')
    for key in ('actualNormal62Operand100Snapshot','actualNativeBootConfig100Disassembly','actualNativeContextEnable63Disassembly'):
        need(scope[key]==config_source[key],'actual config100 source proof '+key);base.exact(scope[key])
    config_contract=scope['cpuDisabledAMXConfigV3Contract']
    need(all(config_contract[key]is True for key in ('actualDisabledAMXFunctionalityPreserved', 'actualHostKernelBootMOVKSequenceZeroesEveryHigherBitThenWritesConfig100', 'nativeContextEnableBit63RemainsClearAndForbiddenBank57NeverActivated', 'virtualDisabledConfigurationRemainsReadZeroAndWritesZeroOr100Only', 'noArbitraryNonzeroOrAMXArithmeticOperationSupportClaimed', 'metadataActive4110UsesExistingGICPostFieldV20Getter', 'noSystemMetadataAllowlistExpansion', 'allExistingMSRMRSOperandRt31ProfileOwnerActiveMMUInstructionAndPartialFailureGuardsPreserved', 'actualFirstUnHandledRaw7Fault64SnapshotAfterDisabledConfigEmulationDeclines', 'successfullyEmulatedDisabledConfigDoesNotConsumeFaultOneShot', 'firstEightEligibilityAndActualOpcodeOperandAndRealPCReceiptsPreserved', 'originalNative9ReceiptAndRunStatusPreserved', 'existingGenuineBankOneSyncReusedNoAdditionalNative8', 'noAdditionalDiagnosticPayloadBytesLogged', 'noAMXBacking760OrDirtyBank57Written', 'unknownInstructionTranslationOwnershipOrOtherWriteUsesOriginalRealUndefinedFallback', 'partialEmulationWriteFailurePoisonsCPU', 'existingC1PACAndRealUndefinedFallbackPreserved', 'allExistingDescriptorUniqueOwnRAMVMOperationAndPostBoundaryGuardsPreserved', 'Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole', 'allOther28ObjectsWhole')) and config_contract['onlyAdditionalWriteValueIsExactActualNativeBootDisabledPolicy']=='0x100' and config_contract['exactSelector']=='S3_4_C15_C1_4' and (config_contract['functionalInstructionFetchBytes'],config_contract['maxKernelTotalDiagnosticPayloadBytes'],config_contract['maxFirmwareTotalDiagnosticPayloadBytes'],config_contract['actualChangedObjects'])==(4,192,128,1),'exact native boot disabled configuration0/100 read-zero only; actual bit63 clear/dirty57 untouched, unknown or other writes keep real undefined fallback')
    getter_source=json.loads(base.exact(scope['cpuDisabledAMXConfigV2Candidate']).read_bytes())
    base.exact(scope['runtime55CPUDisabledAMXConfigV2DeltaVerification'])
    baseline_getter_cpu=json.loads(base.exact(old['cpuDisabledAMXConfigCandidate']).read_bytes())
    need(getter_source['cpuDisabledAMXConfigCandidate']==old['cpuDisabledAMXConfigCandidate'] and len(getter_source['actualChangedObjects'])==1 and len(getter_source['inheritedWholeObjects'])==28 and getter_source['inheritedWholeObjects']==baseline_getter_cpu['inheritedWholeObjects'] and getter_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life45 correction; other28 CPU objects including Engine5 and ProductionOps whole Runtime55')
    need(len(scope['historicalRuntime56DisabledAMXConfigV2Verification']['factory5AndGICEngine5ObjectsWholeRuntime55'])==2 and all(row in getter_source['inheritedWholeObjects']for row in scope['historicalRuntime56DisabledAMXConfigV2Verification']['factory5AndGICEngine5ObjectsWholeRuntime55']),'actual Factory5 and Engine5 whole Runtime55')
    need(getter_source['cpuDisabledAMXConfigV2Contract']==scope['cpuDisabledAMXConfigV2Contract'] and getter_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (getter_source['actualExports'],getter_source['actualNativeImports'],getter_source['actualLoads'])==(155,93,4),'actual AMX active getter correction source and same155/93/4 namespace')
    getter_binding=scope['historicalRuntime56DisabledAMXConfigV2Verification']['actualSameImageVCPUsExitBinding'];base.exact(getter_binding['callbackAssembly'])
    need(getter_binding==getter_source['actualSameImageVCPUsExitBinding'] and getter_binding['actualDirectBL']['targetRVA']==getter_binding['ownExportRVA'] and getter_binding['externalVCPUsExitImportPresent'] is False,'current callback targets own hv_vcpus_exit; Runtime56 signed code preserves binding')
    need(scope['actualNormal61RepeatedFaultSnapshot']==getter_source['actualNormal61RepeatedFaultSnapshot'],'actual repeated fault source');base.exact(scope['actualNormal61RepeatedFaultSnapshot'])
    getter_contract=scope['cpuDisabledAMXConfigV2Contract']
    need(all(getter_contract[key]is True for key in ('actualDisabledAMXFunctionalityPreserved', 'metadataActive4110UsesExistingGICPostFieldV20Getter', 'noSystemMetadataAllowlistExpansion', 'originalFactoryProfileAndNativeISAAlreadyFilledAndExactPendingOwnedVMChecked', 'allExistingZeroOnlyMSRMRSOperandRt31ProfileOwnerActiveMMUInstructionAndPartialFailureGuardsPreserved', 'actualFirstUnHandledRaw7Fault64SnapshotAfterDisabledConfigEmulationDeclines', 'successfullyEmulatedDisabledConfigDoesNotConsumeFaultOneShot', 'firstEightEligibilityFailureLogsOnlyExistingLocalsNoAdditionalReads', 'firstEightOpcodeOperandAndRealPCEmulationReceiptsPreserved', 'originalNative9ReceiptAndRunStatusPreserved', 'existingGenuineBankOneSyncReusedNoAdditionalNative8', 'noAdditionalDiagnosticPayloadBytesLogged', 'noAMXBacking760OrDirtyBank57Written', 'noAMXNativeFeatureForcedOrArithmeticSupportClaimed', 'unknownInstructionTranslationOwnershipOrNonzeroWriteUsesOriginalRealUndefinedFallback', 'partialEmulationWriteFailurePoisonsCPU', 'existingC1PACAndRealUndefinedFallbackPreserved', 'firstUnhandledRaw7Fault64AndWakePC32Preceding32X19UpTo64DiagnosticPreserved', 'allExistingDescriptorUniqueOwnRAMVMOperationAndPostBoundaryGuardsPreserved', 'Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole', 'allOther28ObjectsWhole')) and getter_contract['exactSelector']=='S3_4_C15_C1_4' and (getter_contract['functionalInstructionFetchBytes'],getter_contract['maxKernelTotalDiagnosticPayloadBytes'],getter_contract['maxFirmwareTotalDiagnosticPayloadBytes'],getter_contract['actualChangedObjects'])==(4,192,128,1),'existing guarded GIC metadata getter4110 without allowlist expansion; preserved zero-only functionality and first-unhandled bounded diagnostics')
    disabled_source=json.loads(base.exact(scope['cpuDisabledAMXConfigCandidate']).read_bytes())
    base.exact(scope['runtime54CPUDisabledAMXConfigDeltaVerification'])
    baseline_disabled_cpu=json.loads(base.exact(old['cpuRaw7FaultOpcodeSnapshotCandidate']).read_bytes())
    need(disabled_source['cpuRaw7FaultOpcodeSnapshotCandidate']==old['cpuRaw7FaultOpcodeSnapshotCandidate'] and len(disabled_source['actualChangedObjects'])==1 and len(disabled_source['inheritedWholeObjects'])==28 and disabled_source['inheritedWholeObjects']==baseline_disabled_cpu['inheritedWholeObjects'] and disabled_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life44 functional replacement; other28 CPU objects including Engine5 and ProductionOps whole Runtime54')
    need(len(scope['historicalRuntime55DisabledAMXConfigVerification']['factory5AndGICEngine5ObjectsWholeRuntime54'])==2 and all(row in disabled_source['inheritedWholeObjects']for row in scope['historicalRuntime55DisabledAMXConfigVerification']['factory5AndGICEngine5ObjectsWholeRuntime54']),'actual Factory5 and Engine5 whole Runtime54')
    need(disabled_source['cpuDisabledAMXConfigContract']==scope['cpuDisabledAMXConfigContract'] and disabled_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (disabled_source['actualExports'],disabled_source['actualNativeImports'],disabled_source['actualLoads'])==(155,93,4),'actual disabled AMX configuration source and same155/93/4 namespace')
    disabled_binding=scope['historicalRuntime55DisabledAMXConfigVerification']['actualSameImageVCPUsExitBinding'];base.exact(disabled_binding['callbackAssembly'])
    need(disabled_binding==disabled_source['actualSameImageVCPUsExitBinding'] and disabled_binding['actualDirectBL']['targetRVA']==disabled_binding['ownExportRVA'] and disabled_binding['externalVCPUsExitImportPresent'] is False,'current actual callback targets own-image hv_vcpus_exit; Runtime55 signature preserves code')
    need(scope['actualNormal60FaultInstructionSnapshot']==disabled_source['actualNormal60FaultInstructionSnapshot'],'actual observed AMX fault instruction source');base.exact(scope['actualNormal60FaultInstructionSnapshot'])
    disabled_contract=scope['cpuDisabledAMXConfigContract']
    need(all(disabled_contract[key]is True for key in ('functionalZeroOnlyDisabledVirtualConfiguration', 'originalNative9ReceiptAndRunStatusPreserved', 'onlyActualRaw7PostOwnerPath', 'existingGenuineBankOneSyncReusedNoAdditionalNative8', 'actualInstructionFetchedAtActualPCViaExistingExactKernelTTBR1OwnRAMWalker', 'noAdditionalDiagnosticPayloadBytesLogged', 'requiresActualEL1A64AlignedPCAndNoPCOverflow', 'requiresValidatedIPadOS1611AndNativeISAOneOrTwo', 'requiresActualPendingRequestOwnerEpochGenerationAndPostBoundary', 'requiresImmutableNativeProfileForbidBank57AndActualActiveWordNoForbiddenBits', 'onlyActualZeroMSROperandAccepted', 'MSRRt31IsXZRZero', 'MRSGivesExplicitDisabledVirtualProfileZero', 'MRSRt31Discarded', 'successfulEmulationWritesRealGPRIfReadAndActualPCPlusFourOnly', 'noAMXBacking760OrDirtyBank57Written', 'noAMXNativeFeatureForcedOrArithmeticSupportClaimed', 'unknownInstructionTranslationOwnershipOrNonzeroWriteUsesOriginalRealUndefinedFallback', 'partialEmulationWriteFailurePoisonsCPU', 'firstEightActualOpcodeOperandActiveIdentityAndPCReceiptsOnly', 'existingC1PACAndRealUndefinedFallbackPreserved', 'firstRaw7Fault64AndWakePC32Preceding32X19UpTo64DiagnosticPreserved', 'allExistingDescriptorUniqueOwnRAMVMOperationAndPostBoundaryGuardsPreserved', 'Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole', 'allOther28ObjectsWhole')) and (disabled_contract['exactInstructionMask'],disabled_contract['exactMSRInstructionBase'],disabled_contract['exactMRSInstructionBase'],disabled_contract['exactSelector'])==('0xffffffe0','0xd51cf180','0xd53cf180','S3_4_C15_C1_4') and (disabled_contract['functionalInstructionFetchBytes'],disabled_contract['maxKernelTotalDiagnosticPayloadBytes'],disabled_contract['maxFirmwareTotalDiagnosticPayloadBytes'],disabled_contract['actualChangedObjects'])==(4,192,128,1),'exact zero-only disabled virtual AMX configuration; real GPR/PC+4 after owner/profile/active/ownRAM guards, unknown/nonzero retains genuine undefined fallback')
    fault_source=json.loads(base.exact(scope['cpuRaw7FaultOpcodeSnapshotCandidate']).read_bytes())
    base.exact(scope['runtime53CPURaw7FaultOpcodeSnapshotDeltaVerification'])
    baseline_fault_cpu=json.loads(base.exact(old['cpuKernelTTBR1SnapshotCandidate']).read_bytes())
    need(fault_source['cpuKernelTTBR1SnapshotCandidate']==old['cpuKernelTTBR1SnapshotCandidate'] and len(fault_source['actualChangedObjects'])==1 and len(fault_source['inheritedWholeObjects'])==28 and fault_source['inheritedWholeObjects']==baseline_fault_cpu['inheritedWholeObjects'] and fault_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life43 diagnostic replacement; other28 CPU objects including Engine5 and existing ProductionOps whole Runtime53')
    need(len(scope['historicalRuntime54Raw7FaultOpcodeSnapshotVerification']['factory5AndGICEngine5ObjectsWholeRuntime53'])==2 and all(row in fault_source['inheritedWholeObjects']for row in scope['historicalRuntime54Raw7FaultOpcodeSnapshotVerification']['factory5AndGICEngine5ObjectsWholeRuntime53']),'actual Factory5 and Engine5 whole Runtime53')
    need(fault_source['cpuRaw7FaultOpcodeSnapshotContract']==scope['cpuRaw7FaultOpcodeSnapshotContract'] and fault_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (fault_source['actualExports'],fault_source['actualNativeImports'],fault_source['actualLoads'])==(155,93,4),'actual raw7 fault-opcode snapshot source and same155/93/4 namespace')
    fault_binding=scope['historicalRuntime54Raw7FaultOpcodeSnapshotVerification']['actualSameImageVCPUsExitBinding'];base.exact(fault_binding['callbackAssembly'])
    need(fault_binding==fault_source['actualSameImageVCPUsExitBinding'] and fault_binding['actualDirectBL']['targetRVA']==fault_binding['ownExportRVA'] and fault_binding['externalVCPUsExitImportPresent'] is False,'current callback directBL targets own-image hv_vcpus_exit; signed code preserved by Runtime54 builder')
    need(scope['actualNormal59KernelPanicSnapshot']==fault_source['actualNormal59KernelPanicSnapshot'],'actual observed kernel panic snapshot source');base.exact(scope['actualNormal59KernelPanicSnapshot'])
    fault_contract=scope['cpuRaw7FaultOpcodeSnapshotContract']
    need(all(fault_contract[key]is True for key in('diagnosticOnlyFirstActualRaw7AndExistingOneShotPostWakeSample','originalNative9ReceiptAndRunStatusPreserved','actualRaw7UndefinedSixWritesAndC1PACFunctionalityPreserved','firstActualRaw7OnlyGlobalOneShotCAS','actualPreInjectionFaultPCAndPSTATEUsed','firstRaw7FaultReadAfterExistingGenuineBankOneSyncAndBeforeInjectionWrites','actualPendingRequestOwnerEpochGenerationAndPostBoundaryRequired','raw7FreshSCTLR400TCR3B0TTBR13A8ReadViaExistingGuardedGetters','noAdditionalNative8OrAnyNativeCall','firstRaw7RequiresActualEL1A64MMUOnAlignedPC','wakeKernelPC32PrecedingPC32AndActualX19PointerUpTo64','wakeX2MemoryTargetRemoved','oldExactFirmware42BitVA36BitPATTBR0ProfilePreserved','exactKernel47BitVA40BitPATTBR1ProfileAndAllExistingDescriptorGuardsPreserved','noTagStrippingOrGuessedIdentityOrUnrecognizedProfileSupport','noLRX2X27OrX28MemoryTargets','byteAlignedStringOnlyAndInstructionAlignmentStillRequired','everyDescriptorAndPayloadChunkRequiresActualUniqueMappedReadableCurrentEpochRAMAndSelfMachCopy','existingVMOperationAndRegistryThenVMMutexAndPostBoundaryGuardsPreserved','eachObservedDescriptorRereadOnceAndChangeRejectsPayload','softwareTableObservationDoesNotClaimTLB','actualPayloadBytesTableNumberDescriptorTraceAndRawHexLogged','raw7ActualIdentityPCPSTATESYSAndExtraNative8CallsZeroLogged','boundedX19PreviewMarksNULTerminationWithinActualRead','fixedInternalLabelsOnly','unknownReadsDoNotChangeRunResultAndErrnoPreserved','noNewGuestWriteOrNativeCall','Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole','allOther28ObjectsWhole'))and fault_contract['firstRaw7ExactKernelTCR']=='0x000800226511a511' and fault_contract['actualChangedObjects']==1 and (fault_contract['raw7FaultInstructionPayloadMaxBytes'],fault_contract['maxKernelTotalPayloadBytes'],fault_contract['maxWakeKernelPayloadBytes'],fault_contract['maxFirmwareTotalPayloadBytes'],fault_contract['maxPagesPerTarget'],fault_contract['maxLevelsPerPage'],fault_contract['maxDescriptorsPerTarget'])==(64,192,128,128,2,3,6),'single real raw7 faultPC64 before injection plus existing wake PC32/pre32/x1964; original descriptor/RAM/owner/status guards and no additional native calls')
    kernel_source=json.loads(base.exact(scope['cpuKernelTTBR1SnapshotCandidate']).read_bytes())
    base.exact(scope['runtime52CPUKernelTTBR1SnapshotDeltaVerification'])
    baseline_kernel_cpu=json.loads(base.exact(old['cpuRaw7UndefinedInjectionCandidate']).read_bytes())
    need(kernel_source['cpuRaw7UndefinedInjectionCandidate']==old['cpuRaw7UndefinedInjectionCandidate'] and len(kernel_source['actualChangedObjects'])==1 and len(kernel_source['inheritedWholeObjects'])==28 and kernel_source['inheritedWholeObjects']==baseline_kernel_cpu['inheritedWholeObjects'] and kernel_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life42 diagnostic replacement; other28 CPU objects including Engine5 and existing ProductionOps whole Runtime52; undeployed Life41 is not installed basis')
    need(len(scope['historicalRuntime53KernelTTBR1SnapshotVerification']['factory5AndGICEngine5ObjectsWholeRuntime52'])==2 and all(row in kernel_source['inheritedWholeObjects']for row in scope['historicalRuntime53KernelTTBR1SnapshotVerification']['factory5AndGICEngine5ObjectsWholeRuntime52']),'actual Factory5 and Engine5 whole Runtime52')
    need(kernel_source['cpuKernelTTBR1SnapshotContract']==scope['cpuKernelTTBR1SnapshotContract'] and kernel_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (kernel_source['actualExports'],kernel_source['actualNativeImports'],kernel_source['actualLoads'])==(155,93,4),'actual kernel TTBR1 snapshot source and same155/93/4 namespace')
    kernel_binding=scope['historicalRuntime53KernelTTBR1SnapshotVerification']['actualSameImageVCPUsExitBinding'];base.exact(kernel_binding['callbackAssembly'])
    need(kernel_binding==kernel_source['actualSameImageVCPUsExitBinding'] and kernel_binding['actualDirectBL']['targetRVA']==kernel_binding['ownExportRVA'] and kernel_binding['externalVCPUsExitImportPresent'] is False,'current callback directBL targets own-image hv_vcpus_exit; signed code preserved by Runtime53 builder')
    for key in('actualNormal58PostSnapshot','uninstalledKernelTTBR1SnapshotSourceHistory'):
        need(scope[key]==kernel_source[key],'kernel snapshot provenance exact '+key);base.exact(scope[key])
    kernel_contract=scope['cpuKernelTTBR1SnapshotContract']
    need(all(kernel_contract[key]is True for key in('diagnosticOnlyExistingOneShotPostWakeSample','originalNative9ReceiptAndRunStatusPreserved','Life40ActualRaw7UndefinedAndC1PACFunctionalitySourceUnchanged','actualHighCanonical47BitVARequiresTTBR1','T1SZ17TG1One16KiBIPS2FortyBitPAEPD1ZeroTBI1ZeroDSZero','L1Full11BitIndex46Through36L2Index35Through25L3Index24Through14','L1TableOnlyL2TableOr32MiBBlockL3PageOnly','allDescriptorRES0AFPAAlignmentAndActualOwnRAMGuardsPreserved','oldExactFirmware42BitVA36BitPATTBR0ProfilePreserved','noTagStrippingOrGuessedIdentityOrUnrecognizedProfileSupport','kernelSnapshotPC32PrecedingPC32AndActualX2AndX19PointersUpTo64Each','firmwareSnapshotOriginalPC64PrecedingPC64Preserved','noLRX27OrX28MemoryTargets','byteAlignedStringOnlyAndInstructionAlignmentStillRequired','everyDescriptorAndPayloadChunkRequiresActualUniqueMappedReadableCurrentEpochRAMAndSelfMachCopy','existingVMOperationAndRegistryThenVMMutexAndPostBoundaryGuardsPreserved','eachObservedDescriptorRereadOnceAndChangeRejectsPayload','softwareTableObservationDoesNotClaimTLB','actualPayloadBytesTableNumberDescriptorTraceAndRawHexLogged','boundedX2AndX19PreviewsMarkNULTerminationWithinActualRead','fixedInternalLabelsOnly','unknownReadsDoNotChangeRunResultAndErrnoPreserved','noNewNativeCallOrGuestWrites','Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole','allOther28ObjectsWhole'))and kernel_contract['onlyNewExactObservedTCR']=='0x000800226511a511' and kernel_contract['actualChangedObjects']==1 and (kernel_contract['maxKernelTotalPayloadBytes'],kernel_contract['maxFirmwareTotalPayloadBytes'],kernel_contract['maxPagesPerTarget'],kernel_contract['maxLevelsPerPage'],kernel_contract['maxDescriptorsPerTarget'])==(192,128,2,3,6),'one existing authentic post-wake kernel PC32/preceding32/x264/x1964 sample, bounded192 and firmware128 with all ownedRAM/descriptor/status guards')
    undefined_source=json.loads(base.exact(scope['cpuRaw7UndefinedInjectionCandidate']).read_bytes())
    base.exact(scope['runtime51CPURaw7UndefinedInjectionDeltaVerification'])
    baseline_undefined_cpu=json.loads(base.exact(old['cpuNativePACServiceCandidate']).read_bytes())
    need(undefined_source['cpuNativePACServiceCandidate']==old['cpuNativePACServiceCandidate'] and len(undefined_source['actualChangedObjects'])==1 and len(undefined_source['inheritedWholeObjects'])==28 and undefined_source['inheritedWholeObjects']==baseline_undefined_cpu['inheritedWholeObjects'] and undefined_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life40 replacement; other28 CPU objects including Engine5 and original ProductionOps whole Runtime51')
    need(len(scope['historicalRuntime52Raw7UndefinedInjectionVerification']['factory5AndGICEngine5ObjectsWholeRuntime51'])==2 and all(row in undefined_source['inheritedWholeObjects']for row in scope['historicalRuntime52Raw7UndefinedInjectionVerification']['factory5AndGICEngine5ObjectsWholeRuntime51']),'actual Factory5 and Engine5 whole Runtime51')
    need(undefined_source['cpuRaw7UndefinedInjectionContract']==scope['cpuRaw7UndefinedInjectionContract'] and undefined_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (undefined_source['actualExports'],undefined_source['actualNativeImports'],undefined_source['actualLoads'])==(155,93,4),'actual raw7 injection source and same155/93/4 namespace')
    undefined_binding=scope['historicalRuntime52Raw7UndefinedInjectionVerification']['actualSameImageVCPUsExitBinding'];base.exact(undefined_binding['callbackAssembly'])
    need(undefined_binding==undefined_source['actualSameImageVCPUsExitBinding'] and undefined_binding['actualDirectBL']['targetRVA']==undefined_binding['ownExportRVA'] and undefined_binding['externalVCPUsExitImportPresent'] is False,'current callback actual directBL targets own-image hv_vcpus_exit; signed code preserved by Runtime52 builder')
    for key in('original13Raw7UndefinedDisassembly','original13RunDisassembly','original13ExceptionInjectionHelper','currentKernelActualNative9Disassembly'):
        need(scope[key]==undefined_source[key],'undefined-injection source provenance exact '+key);base.exact(scope[key])
    undefined_contract=scope['cpuRaw7UndefinedInjectionContract']
    need(all(undefined_contract[key]is True for key in('onlyActualRaw7PostReturnProducerSelectsOriginal13UndefinedInjection','original13JumpTarget71f0Calls77e4ThenRealNative9','noRaw7PublicExceptionOrFabricatedRetry','actualOwnerVersionEpochGenerationAndPostTokenGuardsPreserved','onlyExistingSYSAndScalarAllowlistsAndProductionReadbackWriterUsed','realBank1ActiveAndISAForbiddenMaskValidated','realMissingReadyBankOnlyUsesExistingNative8NULL','localLifecyclePreservesOriginalNative9Receipt','AArch32IsRejectedBeforeMutation','actualSavedPC108ToRealELR3b8','realESR3c8Equals02000000UndefinedIL1','actualZeroExtendedPSTATE110ToRealSPSR410','realVBAR3e0AndActualPSTATEModeSelectArchitecturalVector','PC108ReceivesActualVectorAndNoPlus4','PSTATE110Single32BitWriteEqualsOldAndNot31Or3c5','realInjectionSuccessRequiredBeforeInternalResumeNative9','partialMutationFailurePoisonsCPUAndDoesNotClaimSuccess','atMostFirst8ActualELRSPSRESRPCPSTATEReadbackSyncAndWriteCountsLogged','noPACKeyOrVMSecretLogged','errnoPreserved','Life39C1PACAllSevenOperationsAndGuardsSourceUnchanged','Life39BoundedWakeRegisterAnd128ByteCodeSnapshotPreserved','Engine5ProductionOpsV6Factory5ConsumerV6ChildWhole','allOther28ObjectsWhole'))and undefined_contract['actualChangedObjects']==1 and undefined_contract['maxNative8CallsPerInjection']==1 and undefined_contract['vectorFormula']=='mode>3 ? VBAR+(mode&1?0x200:0) : VBAR+0x400','real raw7 undefined injection commits exact guarded bank1 ELR/SPSR/ESR/vector/PSTATE state before native9 resume, no plus4/fake retry and C1 unchanged')
    pac_source=json.loads(base.exact(scope['cpuNativePACServiceCandidate']).read_bytes())
    base.exact(scope['runtime50CPUNativePACServiceDeltaVerification'])
    baseline_pac_cpu=json.loads(base.exact(old['cpuEL1VirtualTimerPagewalkCandidate']).read_bytes())
    prior_pac_engine5=[row for row in baseline_pac_cpu['actualChangedObjects']if pathlib.Path(row['path']).name=='modern_gic_v3_engine_v5.o']
    need(len(prior_pac_engine5)==1 and len(baseline_pac_cpu['actualChangedObjects'])==2,'actual installed Life37 and Engine5 source basis')
    expected_pac_whole=baseline_pac_cpu['inheritedWholeObjects']+prior_pac_engine5
    need(pac_source['cpuEL1VirtualTimerPagewalkCandidate']==old['cpuEL1VirtualTimerPagewalkCandidate'] and len(pac_source['actualChangedObjects'])==1 and len(pac_source['inheritedWholeObjects'])==28 and {row['path']:row for row in pac_source['inheritedWholeObjects']}=={row['path']:row for row in expected_pac_whole} and pac_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life39 replacement; other28 CPU objects including Engine5 and original ProductionOps whole Runtime50')
    need(len(scope['historicalRuntime51NativePACServiceVerification']['factory5AndGICEngine5ObjectsWholeRuntime50'])==2 and all(row in pac_source['inheritedWholeObjects']for row in scope['historicalRuntime51NativePACServiceVerification']['factory5AndGICEngine5ObjectsWholeRuntime50']) and prior_pac_engine5[0]in scope['historicalRuntime51NativePACServiceVerification']['factory5AndGICEngine5ObjectsWholeRuntime50'],'actual Factory5 and Engine5 whole; no Engine4 fallback')
    need(pac_source['cpuNativePACServiceContract']==scope['cpuNativePACServiceContract'] and pac_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (pac_source['actualExports'],pac_source['actualNativeImports'],pac_source['actualLoads'])==(155,93,4),'actual native PAC service source and same155/93/4 namespace')
    pac_binding=scope['historicalRuntime51NativePACServiceVerification']['actualSameImageVCPUsExitBinding'];base.exact(pac_binding['callbackAssembly'])
    need(pac_binding==pac_source['actualSameImageVCPUsExitBinding'] and pac_binding['actualDirectBL']['targetRVA']==pac_binding['ownExportRVA'] and pac_binding['externalVCPUsExitImportPresent'] is False,'current callback actual directBL targets own-image hv_vcpus_exit; signed code preserved by Runtime51 builder')
    for key in('uninstalledPrecedingPCSourceHistory','original13PACServiceDisassembly','original13HypervisorBinary','currentKernelActualNative9Disassembly'):
        need(scope[key]==pac_source[key],'PAC source provenance exact '+key);base.exact(scope[key])
    pac_contract=scope['cpuNativePACServiceContract']
    need(all(pac_contract[key]is True for key in('onlyActualOwnedEL1HVC64EC16Imm0C1FamilyConsumed','actualPolicy4030Bit4RequiredForSuccessfulPACService','noForcedPolicyBitOrFabricatedNativeCapability','original13C1Operations0Through6AndUnsupportedResponsesPreserved','case0InitialStateAndFiveKeyPairsPlusEL0DiversifierCommittedToRealNativeFields','case1ReturnsExactOriginalProtocolDefaultPIDs','cases2And3UseRealGuestX1ForAAndBKeyFields','case4UsesRealGuestX1ForEL0Diversifier','case5UsesRealGuestX2DiversifierAndX1Mode0Clear1SetOtherUnchanged','case6UsesRealGuestX1ForGKeyFields','unsupportedOperationOrPolicyUsesZeroExtendedMOVWMinus1','onlyExistingSYSFieldAndProductionWriterAllowlistsUsed','onlyRealBank60And61AndNativeDirty748Used','realActiveBankAndISAForbiddenMaskValidatedBeforeBankMutation','realMissingReadyBankOnlyCallsExistingNative8NULL','native8OwnerVersionPostTokenRevalidatedAfterActualReturn','localLifecyclePreservesOriginalNative9ReceiptAndRunStatus','responseZeroOnlyAfterRealRequiredStateWritesSucceed','noPCWriteOrPCAdvanceAndInternalResumeUsesRealNative9','partialWriteFailurePoisonsCPUAndDoesNotClaimSuccess','modernC6AndC3000006RefusalAndOtherOrdinaryHVCPublicBehaviorPreserved','atMostFirst8ActualHVCPolicyBanksSyncStatusWriteCountResponseAndPCLogs','noPACKeyOrVMSecretLogged','errnoPreservedForDiagnosticLogs','Life37PPI27AndExactObservedPagewalkGuardsPreserved','existingSinglePostCodeBudget128BytesWithPCBeforeInsteadOfLR','Engine5AndProductionOpsV6Factory5ConsumerV6ChildWhole','allOther28ObjectsWhole'))and pac_contract['actualChangedObjects']==1 and pac_contract['maxNative8CallsPerService']==3,'true policy-gated C1 cases0..6 commit real bank60/61 state through existing guarded native8 only; no fake capability, PC advance, secret logs or changed other HVC/native9 behavior')
    pagewalk_source=json.loads(base.exact(scope['cpuEL1VirtualTimerPagewalkCandidate']).read_bytes())
    base.exact(scope['runtime49CPUEL1VirtualTimerPagewalkDeltaVerification'])
    baseline_pagewalk_cpu=json.loads(base.exact(old['cpuPostWakeRegisterCodeSnapshotCandidate']).read_bytes())
    prior_engine4=scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']['factory5AndGICEngine4ObjectsWholeRuntime48'][1]
    expected_pagewalk_whole=[row for row in baseline_pagewalk_cpu['inheritedWholeObjects']if row!=prior_engine4]
    need(pagewalk_source['cpuPostWakeRegisterCodeSnapshotCandidate']==old['cpuPostWakeRegisterCodeSnapshotCandidate'] and len(pagewalk_source['actualChangedObjects'])==2 and len(pagewalk_source['inheritedWholeObjects'])==27 and {row['path']:row for row in pagewalk_source['inheritedWholeObjects']}=={row['path']:row for row in expected_pagewalk_whole} and pagewalk_source['allOther27ObjectsWholeUnchanged'] is True,'actual Life37 and Engine5 replacements; other27 CPU objects whole Runtime49')
    need(scope['historicalRuntime50EL1VirtualTimerPagewalkVerification']['factory5ObjectWholeRuntime49']in pagewalk_source['inheritedWholeObjects'] and prior_engine4 not in pagewalk_source['inheritedWholeObjects'] and prior_engine4 not in pagewalk_source['actualChangedObjects'],'Factory5 whole; Engine4 genuinely changed to Engine5')
    need(pagewalk_source['cpuEL1VirtualTimerPagewalkContract']==scope['cpuEL1VirtualTimerPagewalkContract'] and pagewalk_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (pagewalk_source['actualExports'],pagewalk_source['actualNativeImports'],pagewalk_source['actualLoads'])==(155,93,4),'actual EL1 virtual-timer and pagewalk source with same155/93/4 namespace')
    pagewalk_binding=scope['historicalRuntime50EL1VirtualTimerPagewalkVerification']['actualSameImageVCPUsExitBinding'];base.exact(pagewalk_binding['callbackAssembly'])
    need(pagewalk_binding==pagewalk_source['actualSameImageVCPUsExitBinding'] and pagewalk_binding['actualDirectBL']['targetRVA']==pagewalk_binding['ownExportRVA'] and pagewalk_binding['externalVCPUsExitImportPresent'] is False,'current callback actual directBL targets own-image hv_vcpus_exit; signed machine code preserved by Runtime50 builder')
    need(scope['officialSDKTimerInterruptIDs']==pagewalk_source['officialSDKTimerInterruptIDs'],'actual official SDK EL1virtual27 basis')
    official_sdk=scope['officialSDKTimerInterruptIDs'];need(official_sdk['path']=='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Hypervisor.framework/Versions/A/Headers/hv_gic_types.h','only fixed official SDK timer-header external provenance')
    official_sdk_raw=pathlib.Path(official_sdk['path']).read_bytes();need(len(official_sdk_raw)==official_sdk['bytes'] and base.digest(official_sdk_raw)==official_sdk['sha256'],'actual official SDK timer-header bytes/SHA')
    pagewalk_contract=scope['cpuEL1VirtualTimerPagewalkContract']
    need(all(pagewalk_contract[key]is True for key in('actualEL1CNTV430CVAL3e8RoutesPPI27','officialMacOS27SDKDefinesEL1Virtual27EL2Physical26EL1Physical30','oldOriginalDelegate178IsEL2HypervisorPhysicalNotCNTV','physicalPPI30AndAllIdentityLevelAndEdgeGuardsPreserved','Engine5OnlyVirtualPPI26To27FunctionalDelta','Life36SingleBoundedWakeAndPostRegisterSYSGuardsPreserved','atMostOneExistingLazySystemSyncUnchanged','originalNative9ReceiptAndRunStatusPreserved','onlyActualKnownEL1MMUOnLittleEndianTTBR0Low42BitVA','actual16KiBGranuleAnd36BitOutputAddressLimit','noLPA2OrTaggedHighVAOrOtherProfileGuess','L1TableL2TableOr32MiBBlockL3PageOnly','invalidDescriptorTypeOrMissingAFOrOversizeOrMisalignedAddressIsUnknown','nonLPA2Descriptor13And12RES0ExplicitlyRequired','actualDescriptorAddressesValuesLevelsLogged','descriptorAndPayloadReadsReuseExistingVMOperationRegistryMutexVMMutexUniqueCurrentReadableRAMSelfMachReader','everyPayloadChunkFullyInsideActualOwnReadableRAM','eachObservedDescriptorRereadOnceAndChangeRejectsCode','softwareTableObservationNeverClaimsTLBObservation','MMUOffGuardedIdentityRAMReaderPreserved','noGuestWritesOrTranslationMaintenanceOrNewNativeEntry','failuresOnlyDiagnosticUnknownAndErrnoPreserved','Factory5ConsumerV6ChildWhole','allOther27ObjectsWhole'))and pagewalk_contract['actualChangedObjects']==2 and pagewalk_contract['diagnosticExactSupportedTCR']=='0x001800616556a516' and (pagewalk_contract['maxPagesPer64ByteTarget'],pagewalk_contract['maxLevelsPerPage'],pagewalk_contract['maxUniqueDescriptorObservationsPerTarget'],pagewalk_contract['maxDescriptorReadsIncludingOneRecheckEachPerTarget'],pagewalk_contract['maxCodeBytes'])==(2,3,6,12,128),'genuine EL1 CNTV PPI27 and bounded profile-limited software pagewalk; original physical30, owned RAM, status and failure guards retained')
    snapshot_source=json.loads(base.exact(scope['cpuPostWakeRegisterCodeSnapshotCandidate']).read_bytes())
    base.exact(scope['runtime48CPUPostWakeRegisterCodeSnapshotDeltaVerification'])
    baseline_snapshot_cpu=json.loads(base.exact(old['cpuVirtualTimerGICCandidate']).read_bytes())
    prior_engine4=[row for row in baseline_snapshot_cpu['actualChangedObjects']if pathlib.Path(row['path']).name=='modern_gic_v3_engine_v4.o']
    need(len(prior_engine4)==1 and len(baseline_snapshot_cpu['actualChangedObjects'])==2,'actual baseline Life35 and Engine4 object source')
    expected_snapshot_whole=baseline_snapshot_cpu['inheritedWholeObjects']+prior_engine4
    need(snapshot_source['cpuVirtualTimerGICCandidate']==old['cpuVirtualTimerGICCandidate'] and len(snapshot_source['actualChangedObjects'])==1 and len(snapshot_source['inheritedWholeObjects'])==28 and {row['path']:row for row in snapshot_source['inheritedWholeObjects']}=={row['path']:row for row in expected_snapshot_whole} and snapshot_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life36 snapshot diagnostics object replacement; other28 including actual Engine4 whole Runtime48')
    need(len(scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']['factory5AndGICEngine4ObjectsWholeRuntime48'])==2 and all(row in snapshot_source['inheritedWholeObjects']for row in scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']['factory5AndGICEngine4ObjectsWholeRuntime48']) and prior_engine4[0]in scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']['factory5AndGICEngine4ObjectsWholeRuntime48'],'actual Factory5 and Engine4 whole; no Engine3 fallback')
    need(snapshot_source['cpuPostWakeRegisterCodeSnapshotContract']==scope['cpuPostWakeRegisterCodeSnapshotContract'] and snapshot_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (snapshot_source['actualExports'],snapshot_source['actualNativeImports'],snapshot_source['actualLoads'])==(155,93,4),'actual post-wake register/code snapshot source and same155/93/4 namespace')
    snapshot_binding=scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']['actualSameImageVCPUsExitBinding'];base.exact(snapshot_binding['callbackAssembly'])
    need(snapshot_binding==snapshot_source['actualSameImageVCPUsExitBinding'] and snapshot_binding['actualDirectBL']['targetRVA']==snapshot_binding['ownExportRVA'] and snapshot_binding['externalVCPUsExitImportPresent'] is False,'actual current callback directBL targets own-image hv_vcpus_exit; signed code preserved by Runtime49 builder')
    snapshot_contract=scope['cpuPostWakeRegisterCodeSnapshotContract']
    need(all(snapshot_contract[key]is True for key in('singleExisting10SecondWakeAndActualPostReturnSampleOnly','originalNative9ReceiptAndRunStatusPreservedByLocalCopies','actualGuardedPCAndPSTATE','SYSUsesExistingTypedLookupAllowlistAndReadGuards','noDiagnosticSYSWritePort','atMostOneExistingPrepareSystemNative8OnlyOnRealTypedMissingBank','syncRequiredAttemptedInvokedStatusAndNativeReturnActuallyLogged','syncFailureDoesNotChangeRunResultOrFabricateSYS','noNewNativeEntryOrGuestRegisterWrites','codeRequiresFreshKnownEL1AndSCTLRMMUOff','MMUOnUnknownOrNonEL1CodeIsHonestUnknown','noGuessedFileOffsetOrPageTableTranslation','actualPCAndRawUnmodifiedLRAtMost64BytesEach','nonblockingExistingVMOperationPinsRAMLifecycle','registryThenVMMutexRequireCurrentRegisteredLiveEpochCPUPostTokenAndUniqueMappedReadableRAM','uncertainOverlappingUnmappedOrOverflowingRAMRejected','actualSelfMachReadChecksMappingAndCopy','adoptedHostExternalUnmapReadFailureIsUnknown','noInjectedOwnershipCallbackUnderRegistryOrVMMutex','realPostBoundaryValidatedBeforeAndAfterRAMRead','readFailureDoesNotChangeRunStatus','errnoPreserved','Life35VirtualTimerPPI26AndLife34WakeGuardsPreserved','Factory5ConsumerV6ChildAndEngine4Whole','allOther28ObjectsWhole'))and snapshot_contract['actualChangedObjects']==1 and snapshot_contract['actualGuardedGPRs']==list(range(8))+list(range(19,31)) and snapshot_contract['typedPhysicalSYSIdentifiers']==[49672,57864,49280,49410,49408,49409] and snapshot_contract['maxCodeBytes']==128,'single actual post-return register/SYS/code sample; atmost one existing bank sync, strict MMUoff and uniquely registered readableRAM guards, unknown on failure without changed Run')
    virtual_source=json.loads(base.exact(scope['cpuVirtualTimerGICCandidate']).read_bytes())
    base.exact(scope['runtime47CPUVirtualTimerGICDeltaVerification'])
    prior_cpu=json.loads(base.exact(old['cpuBoundedWakePostSnapshotCandidate']).read_bytes())
    old_gic=scope['historicalRuntime47BoundedWakePostSnapshotVerification']['factory5AndGICEngine3ObjectsWholeRuntime46'][1]
    need(virtual_source['cpuBoundedWakePostSnapshotCandidate']==old['cpuBoundedWakePostSnapshotCandidate'] and len(virtual_source['actualChangedObjects'])==2 and len(virtual_source['inheritedWholeObjects'])==27 and virtual_source['inheritedWholeObjects']==[row for row in prior_cpu['inheritedWholeObjects']if row!=old_gic] and virtual_source['allOther27ObjectsWholeUnchanged'] is True,'actual Life35 and Engine4 replacements; other27 CPU objects whole Runtime47')
    need(scope['historicalRuntime48VirtualTimerGICVerification']['factory5ObjectWholeRuntime47']in virtual_source['inheritedWholeObjects'] and old_gic not in virtual_source['inheritedWholeObjects'],'actual Factory5 whole; original Engine3 genuinely replaced')
    need(virtual_source['cpuVirtualTimerGICContract']==scope['cpuVirtualTimerGICContract'] and virtual_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (virtual_source['actualExports'],virtual_source['actualNativeImports'],virtual_source['actualLoads'])==(155,93,4),'actual genuine GIC virtual-timer source and same155/93/4 namespace')
    current_binding=scope['historicalRuntime48VirtualTimerGICVerification']['actualSameImageVCPUsExitBinding'];base.exact(current_binding['callbackAssembly'])
    need(current_binding==virtual_source['actualSameImageVCPUsExitBinding'] and current_binding['actualDirectBL']['targetRVA']==current_binding['ownExportRVA'] and current_binding['externalVCPUsExitImportPresent'] is False,'actual current callback directBL targets own-image hv_vcpus_exit with no external import; signed provider machine code preserved by Runtime48 builder')
    need(all(scope['cpuVirtualTimerGICContract'][key]is True for key in ('actualCTL430CVAL3e8AndNative6d8Only','usesActualSameOwnerPhysicalTimerReceiptCounterDomain','revalidatesRealCounterDomainAndTranslationRange','noHostElapsedGuessOrFakeTimerState','PPI26LevelFromCTLBits3Equal1AndActualCounterAtOrPastCVAL','PPI26AssertAndClearUseSameIdentityAndLevelSemanticsAsPhysical30','physicalPPI30AndAllExistingGICPathsPreserved','nativeSoftMaskOnlySuppressesDuplicateNativeTimerExits','realGuestFutureCVALOrDisabledTimerClearsSoftMaskForRearm','actualPreNative9MaskRefreshedAfterEveryRealTimerPoll','onlyExistingExactVirtualTimerPublicReason2ConsumedInternally','raw3Or4OtherCasesAndRaw2Or11Unchanged','internalTimerConsumptionDoesNotAdvancePC','virtualTimerLevelStillRoutesWithNativeSoftMaskSet','WFxFutureDeadlineIgnoresNativeSoftMask','WFxExpiredTimerRequiresActualEnabledPendingGICWork','noNewNative8OrUnboundedNativeEntryPolicy','existingCNTVReaderAndCounterValidationGuardsPreserved','partialNewVirtualMutationFailurePoisonsCPU','atMostFirst8ActualVirtualTimerStateAndConsumeLogs','Life34BoundedWakeAndPostSnapshotPreserved','Factory5ConsumerV6ChildWhole','allOther27ObjectsWhole'))and scope['cpuVirtualTimerGICContract']['actualChangedObjects']==2,'real same-owner CNTV domain drives PPI26 level and internal consumption; no fake counter/state, new native8, PC advance or changed physical30/failure guards')
    wake_source=json.loads(base.exact(scope['cpuBoundedWakePostSnapshotCandidate']).read_bytes())
    base.exact(scope['runtime46CPUBoundedWakePostSnapshotDeltaVerification'])
    baseline_cpu_source=json.loads(base.exact(old['cpuInternalRunSparseCandidate']).read_bytes())
    need(wake_source['cpuInternalRunSparseCandidate']==old['cpuInternalRunSparseCandidate'] and len(wake_source['actualChangedObjects'])==1 and wake_source['inheritedWholeObjects']==baseline_cpu_source['inheritedWholeObjects'] and len(wake_source['inheritedWholeObjects'])==28 and wake_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life34 bounded wake/post-read diagnostics object replacement and other28 whole Runtime46')
    need(wake_source['cpuBoundedWakePostSnapshotContract']==scope['cpuBoundedWakePostSnapshotContract'] and wake_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (wake_source['actualExports'],wake_source['actualNativeImports'],wake_source['actualLoads'])==(155,93,4),'actual one-shot bounded wake/post-snapshot source and same155/93/4 namespace')
    binding=scope['historicalRuntime47BoundedWakePostSnapshotVerification']['actualSameImageVCPUsExitBinding'];base.exact(binding['callbackAssembly'])
    need(binding==wake_source['actualSameImageVCPUsExitBinding'] and binding['actualDirectBL']['targetRVA']==binding['ownExportRVA'] and binding['externalVCPUsExitImportPresent'] is False,'actual callback directBL targets own-image hv_vcpus_exit export with no external import; signed provider code preserved by Runtime47 builder')
    need(all(scope['cpuBoundedWakePostSnapshotContract'][key]is True for key in ('firstActualGICPublicRunArmsOnlyOnce','targetPublicIdentityEpochGenerationCopiedByValue','noCPUVMOrGICOwnerPointerRetained','tenSecondOneShotDispatchTimer','existingDispatchImportsOnly','atMostOneExistingPublicVCPUsExitCall','publicEntryRetainsAuthenticRegisteredWakeOwner','atMostOneRealNative10ThroughExistingPublicPath','earlyDestroyedCPUUsesNormalPublicRejection','phaseFiringPublishedBeforePublicRequest','actualPublicRequestReturnLoggedSeparately','requestReturnNeverClaimsRunReturn','actualNative9PostOwnerGuardRequired','oneMatchingPostSnapshotOnly','onlyPC108AndPSTATE110Read','localAccessAndLifecycleCopiesPreserveRealRunReceipt','readFailuresNeverChangeRunStatus','rawReasonIsActualExistingNativeRead','raw2AndRaw11MayBeObservedHonestly','noNative8Added','noGuestRegisterWritesAdded','noFakeExitOrRunStatusChanges','originalCanceledAndResumePathsUnchanged','errnoPreservedOnOriginalCPUThread','timerCancelHandlerReleasesJobSourceAndQueue','Factory5ConsumerV6ChildGIC3Whole','allOther28ObjectsWhole'))and scope['cpuBoundedWakePostSnapshotContract']['actualChangedObjects']==1,'single copied-identity ten-second existing public wake and one matching genuine post-owner PC/PSTATE read only; original execution/results retained')
    internal_source=json.loads(base.exact(scope['cpuInternalRunSparseCandidate']).read_bytes())
    base.exact(scope['runtime45CPUInternalRunSparseDeltaVerification'])
    prior_cpu_source=json.loads(base.exact(old['cpuWFxCounterReaderCandidate']).read_bytes())
    need(internal_source['cpuWFxCounterReaderCandidate']==old['cpuWFxCounterReaderCandidate'] and len(internal_source['actualChangedObjects'])==1 and internal_source['inheritedWholeObjects']==prior_cpu_source['inheritedWholeObjects'] and len(internal_source['inheritedWholeObjects'])==28 and internal_source['allOther28ObjectsWholeUnchanged'] is True,'sole Life33 diagnostics object replacement and other28 whole Runtime45')
    need(internal_source['cpuInternalRunSparseContract']==scope['cpuInternalRunSparseContract'] and internal_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (internal_source['actualExports'],internal_source['actualNativeImports'],internal_source['actualLoads'])==(155,93,4),'actual internal-run sparse source and same155/93/4 namespace')
    need(len(scope['historicalRuntime47BoundedWakePostSnapshotVerification']['factory5AndGICEngine3ObjectsWholeRuntime46'])==2 and all(row in internal_source['inheritedWholeObjects']for row in scope['historicalRuntime47BoundedWakePostSnapshotVerification']['factory5AndGICEngine3ObjectsWholeRuntime46']),'actual Factory5 and GICEngine3 whole Runtime45')
    need(all(scope['cpuInternalRunSparseContract'][key]is True for key in ('reserveOrdinalExactlyOnceAtInternalStepEntry','first16AndPowerOfTwoThrough2To24Only','atMost36SelectedSteps','existingNativeReceiptFieldsOnly','alreadyReadPCOriginalBeforePlus4','alreadyDecodedRtSelectorAndSourceOnly','existingHandlerReadValueAndFlagsOnly','explicitLocalKnownBitMask','raw2AndRaw11PCRemainUnknown','noExtraCPUReadsOrWrites','noExtraNativeCalls','noGuardOrExecutionBehaviorChanges','errnoPreservedAroundFormatting','WFxCounterBindingAndNative16EntryBoundUnchanged','Factory5ConsumerV6ChildGIC3Whole','allOther28ObjectsWhole'))and scope['cpuInternalRunSparseContract']['actualChangedObjects']==1,'bounded existing-receipt and already-read-local diagnostics only; no new CPU reads, writes, native calls or execution/guard changes')
    reader_source=json.loads(base.exact(scope['cpuWFxCounterReaderCandidate']).read_bytes())
    base.exact(scope['runtime44CPUWFxCounterReaderDeltaVerification'])
    need(reader_source['cpuWFxWaitCandidate']==old['cpuWFxWaitCandidate'] and len(reader_source['actualChangedObjects'])==1 and len(reader_source['inheritedWholeObjects'])==28 and reader_source['allOther28ObjectsWholeUnchanged'] is True,'actual sole Life32 replacement and28 whole CPU objects')
    need(reader_source['cpuWFxCounterReaderContract']==scope['cpuWFxCounterReaderContract'] and reader_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (reader_source['actualExports'],reader_source['actualNativeImports'],reader_source['actualLoads'])==(155,93,4),'actual retained counter-reader source and same155/93/4 namespace')
    need(len(scope['historicalRuntime47BoundedWakePostSnapshotVerification']['factory5AndGICEngine3ObjectsWholeRuntime46'])==2 and all(row in reader_source['inheritedWholeObjects']for row in scope['historicalRuntime47BoundedWakePostSnapshotVerification']['factory5AndGICEngine3ObjectsWholeRuntime46']),'actual Factory5 and GICEngine3 whole Runtime44')
    need(all(scope['cpuWFxCounterReaderContract'][key]is True for key in('usesSameRetainedTimerOwnerActualReadCounterDomainBinding','actualBindingIsExistingV21ArchitecturalReader','directOldV19CounterReaderNoLongerUsedByCNTVWait','originalInitializationOwnedBeforeAndAfterReaderUnchanged','originalCounterDomainValidationUnchanged','noGlobalMemoryOrSYSGuardRelaxation','noExtraCPUReadsOrNativeCalls','noPCDeadlineMaskOrNativeResultChanges','onlyFirst8ActualCNTVErrorLogs','unknownBanksExplicitlyKnownZero','errnoPreservedAroundErrorFormatting','oldWFxOwnerConditionEngineAndNative16EntryBoundUnchanged','Factory5ConsumerV6AndChildWhole','allOther28ObjectsWhole'))and scope['cpuWFxCounterReaderContract']['actualChangedObjects']==1,'actual same-owner V21 counter binding and bounded existing errors preserve all domain/PC/deadline/wait/IRQ/result guards')
    wfx_source=json.loads(base.exact(scope['cpuWFxWaitCandidate']).read_bytes())
    base.exact(scope['runtime43CPUWFxWaitDeltaVerification']);base.exact(scope['historicalRuntime60PinnedRAMReadV1Verification']['factory5ObjectWholeRuntime43'])
    need(wfx_source['cpuPublicRunSparseClockCandidate']==old['cpuPublicRunSparseClockCandidate'] and len(wfx_source['actualChangedObjects'])==2 and len(wfx_source['inheritedWholeObjects'])==27 and wfx_source['allOther27ObjectsWholeUnchanged'] is True and scope['historicalRuntime60PinnedRAMReadV1Verification']['factory5ObjectWholeRuntime43'] in wfx_source['inheritedWholeObjects'],'actual Life31/GICEngine3 two-object replacement; Factory5 and27 CPU objects whole')
    need(wfx_source['cpuWFxWaitContract']==scope['cpuWFxWaitContract'] and wfx_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (wfx_source['actualExports'],wfx_source['actualNativeImports'],wfx_source['actualLoads'])==(155,93,4),'actual compiled genuine WFx candidate and unchanged155/93/4 namespace')
    need(all(scope['cpuWFxWaitContract'][key] is True for key in ('handlesEC1OnlyWithRealCreatedAttachedOwner','WFIAndWFEFollowSameOriginalModernPath','realPostLeasePCReadAdvance4AndWrite','PCOverflowAndMutationFailuresHonest','noPublicReasonZeroFabricated','noReducerOrChildChanges','independentWaitStateNotGICRWAKER','enabledPendingWakeIgnoresPMRAndPriority','IRQAndFIQInjectionStillOriginalLines','conditionGenerationClosesEarlyWakeRace','IRQDeadlineAndExitSignalRealOwnedCondition','fullIdentityVersionAndRetainedBorrowPreserved','physicalDeadlineUsesExistingRealDispatchScheduler','oneSecondMaintenanceTimeoutRevalidatesWithoutNativeEntry','CNTVActualCTL430CVAL3e8Offset6a0AndMask6d8Read','CNTVUsesExistingBank0ReadyDirtyAndRealNative8Sync','CNTVGuestCounterEqualsValidatedMachAbsoluteMinusNativeOffset','CNTVDeadlineShortensConditionTimeout','CNTVDueOnlyReturnsToRealNative9NeverSynthesizesTimerExit','noBusySpinOrAdditionalNativeRunCalls','existing16NativeEntryBoundUnchanged','noNativeReturnOrCompletionFabricated','allOther27ObjectsWhole','Factory5AndConsumerV6AndChildWhole','existing93ImportsReused')) and scope['cpuWFxWaitContract']['actualChangedObjects']==2,'real WFx PC advance/owned wait and genuine enabled-pending/physical/CNTV/exit wake, without fabricated timer/native exits or changed IRQ/FIQ lines')
    sparse_source=json.loads(base.exact(scope['cpuPublicRunSparseClockCandidate']).read_bytes())
    base.exact(scope['runtime42PublicRunSparseClockDeltaVerification'])
    need(sparse_source['cpuScratchGPRTraceCandidate']==old['cpuScratchGPRTraceCandidate'] and len(sparse_source['actualChangedObjects'])==1 and len(sparse_source['inheritedWholeObjects'])==28 and sparse_source['allOther28ObjectsWholeUnchanged'] is True,'one actual FactoryV5 observation object replaces FactoryV4; other28 CPU objects stay whole')
    need(sparse_source['publicRunSparseClockDiagnosticsContract']==scope['publicRunSparseClockDiagnosticsContract'] and sparse_source['actualIOSCompileStrictLinkAndDyldValidatePassed'] is True and (sparse_source['actualExports'],sparse_source['actualNativeImports'],sparse_source['actualLoads'])==(155,93,4) and (scope['actualCurrentCPUExports'],scope['actualCurrentCPUImports'],scope['actualCurrentCPULoads'])==(155,94,4),'historical sparse source155/93/4; actual current CPU155/94/4 with sole proven native cond_wait addition')
    need(all(scope['publicRunSparseClockDiagnosticsContract'][k] is True for k in ('recordsRunEnterBeforeActualFactoryRunProducerCall','recordsOnlyExistingInitializedProducerReceipt','recordsActualProducerReleaseAndPublicReturnStatus','clockImportAlreadyInExisting93','preservesErrnoAcrossClockAndFormatting','noNewNativeCalls','noAdditionalCPUContextOrOutputPointerReads','noCallsArgumentsFlagsResultsOrOutputsChanged','noCPUOrGuestStateWrites','originalDeferredBorrowReleaseAndFailurePriorityUnchanged','unknownNativeValuesExplicitlyKnownZero','noNativeEntryClaimFromFactoryEnter','Life29NativeOps6AndGPRTraceWholeUnchanged','ChildBodyWholeUnchanged')),'sparse clock tracing uses existing actual receipts and true statuses only, without native-entry inference, CPU reads or state changes')
    need(scope['publicRunSparseClockDiagnosticsContract']['firstPublicRunSamples']==16 and scope['publicRunSparseClockDiagnosticsContract']['maximumRegularSamples']==36 and scope['publicRunSparseClockDiagnosticsContract']['firstActualPublicProducerOrReleaseErrorSamples']==8 and scope['publicRunSparseClockDiagnosticsContract']['maximumPublicReturnLogLines']==44 and scope['publicRunSparseClockDiagnosticsContract']['clockAPI']=='mach_absolute_time' and scope['publicRunSparseClockDiagnosticsContract']['clockUnits']=='unscaled original ticks','bounded real-time first16 plus sparse Run diagnostics with first8 true errors')
    trace_source=json.loads(base.exact(scope['cpuScratchGPRTraceCandidate']).read_bytes())
    base.exact(scope['runtime40ScratchGPRTraceDeltaVerification'])
    need(runtime['cpuScratchGPRTraceCandidate']==old['cpuScratchGPRTraceCandidate'] and runtime['scratchGPRTraceContract']==old['scratchGPRTraceContract'] and runtime['runtime40ScratchGPRTraceDeltaVerification']==old['runtime40ScratchGPRTraceDeltaVerification'] and trace_source['cpuOrdinarySystemExitCandidate']==old['cpuSYSExceptionHandoffCandidate']==scope['cpuSYSExceptionHandoffCandidate'] and len(trace_source['actualChangedObjects'])==1 and len(trace_source['inheritedWholeObjects'])==28 and trace_source['allOther28ObjectsWholeUnchanged'] is True,'historical Runtime41 FactoryV4 trace source remains exact; Life29 and ExitReducerV2 whole')
    need(trace_source['scratchGPRTraceContract']==scope['scratchGPRTraceContract'] and trace_source['actualExports']==155 and trace_source['actualNativeImports']==93 and trace_source['actualLoads']==4,'actual scratch source contract and same155/93/4')
    need(all(scope['scratchGPRTraceContract'][k] is True for k in ('recordsOnlyAlreadyStagedActualPublicGetAndRequestedSetValues','noAdditionalCPUContextOrOutputPointerReads','noNativeCallsArgumentsFlagsResultsOrOutputsChanged','noPCGPRDirtyOrGuestStateWrites','actualSuccessfulRunReceiptCorrelationOnly','sameOwnerThreadTLSAndExactPublicCPUIdentityRequired','correlatesExistingRunTokenOwnerESRAndPhysicalAddress','onlyRegister31PCAndActualESRTransferRegister','clearsTagAtEveryNextPublicRunEntry','preservesErrno','initializationRegisterOperationsNotLogged','Life29AndExitReducerV2WholeObjectsInherited','ChildBodyWholeUnchanged')),'scratch trace uses only existing values and successful same-owner receipt; no additional CPU/output reads or mutation')
    need(scope['scratchGPRTraceContract']['initialSamples']==64 and scope['scratchGPRTraceContract']['firstActualGPRFailureSamples']==8 and scope['scratchGPRTraceContract']['maximumTotalLogLines']==90,'exact bounded90 scratch trace sampling')
    scope['actualOwnedOfflineInitializationExecuted']=False
    scope['actualUSBInputVerified']=False
    for name in ('runtime/parent-flat/VM27USBUnavailable.dylib',macos+'VM27USBUnavailable.dylib',macos+'MD'):
        current=next(row['local'] for row in files if row['archivePath']==name)
        prior=old_by_name[name]['local']
        need((current['bytes'],current['sha256'])==(prior['bytes'],prior['sha256']),
             'Parent USBH and current Child MD exception boundary remain whole unchanged')
    scope['originalInitializerFunctionWholeUnchanged']=True
    scope['childCodeOnlySelectedInitializerCallsiteBranchRetargeting']=False
    old_child_pg=old_by_name[macos+'ParavirtualizedGraphics27.dylib']['local']
    current_child_pg=next(row['local']for row in files if row['archivePath']==macos+'ParavirtualizedGraphics27.dylib')
    need((current_child_pg['bytes'],current_child_pg['sha256'])==(old_child_pg['bytes'],old_child_pg['sha256']),
         'all PG bytes and already successful Buffer/Heap/Detach/Shared routes remain unchanged')
    scope['originalChildAndVMMCodePreserved']=False
    scope['originalChildOnlyExactFourSCXTGuardRangesChanged']=False
    scope['originalChildOnlyExactTwelveReservedZeroAndPMUGuardRangesChanged']=False
    scope['originalErrorFunctionWholeUnchanged']=True
    scope['childCodeOnlySelectedErrorConstructorCallsiteBranchRetargeting']=False
    parentmd=next(row for row in files if row['archivePath']=='runtime/parent-flat/MD')
    need((parentmd['local']['bytes'],parentmd['local']['sha256'])==(old_by_name['runtime/parent-flat/MD']['local']['bytes'],old_by_name['runtime/parent-flat/MD']['local']['sha256']) and
         (shader['local']['bytes'],shader['local']['sha256'])==(old_by_name[shader_name]['local']['bytes'],old_by_name[shader_name]['local']['sha256']),
         'Parent MD and the actual native iOS16 shader remain whole unchanged')
    scope['ramRegionBudgetSourceCandidate']=runtime['root21Candidate']
    base.exact(scope['ramRegionBudgetSourceCandidate'])
    scope['firmwareReadonlyPermissionSourceCandidate']=runtime['root22Candidate']
    base.exact(scope['firmwareReadonlyPermissionSourceCandidate'])
    scope['vmDestroyCompatibilitySourceCandidate']=runtime['root23Candidate']
    base.exact(scope['vmDestroyCompatibilitySourceCandidate'])
    scope['startMilestonesSourceCandidate']=runtime['root24Candidate']
    base.exact(scope['startMilestonesSourceCandidate'])
    scope['cpuEmulatorDupSourceCandidate']=runtime['root25Candidate']
    base.exact(scope['cpuEmulatorDupSourceCandidate'])
    scope['childdupRouteRecipe']=runtime['childdupRouteRecipe']
    base.exact(scope['childdupRouteRecipe'])
    base.exact(scope['gicBaseAlignmentSourceCandidate'])
    scope.pop('onlyOwnMainFileUpdated',None)
    scope.pop('runtimeFilesUnchanged',None)
    scope['repeatedProductPeerReviewsOmittedAtDirectUserRequest']=True
    scope['cacheAdapterContract']=runtime['cacheAdapterContract']
    scope['ownedMutableCacheDirectories']=[dict(devicePath=q,uid=501,gid=501,mode=0o700) for q in cache_dirs]
    scope['ownedCacheDirectoryPreparationProtocolBeforeFirstReplacement']=False
    scope['ownedCacheDirectoriesActuallyPrepared']=True
    scope['existingCacheDirectoriesVerifiedAgainBeforeReplacement']=True
    scope['originalFactoryAttestationContractBodyInherited']=True
    scope['deploymentCloseSignalOutputSuppressedUntilSignalsComplete']=True
    scope['originalMainAppResourcesAllWholebytesUnchanged']=not any(row['archivePath']=='VirtualMacIndependent27.app/_CodeSignature/CodeResources' for row in changes)
    guest_helper=next(row for row in files if row['archivePath']=='VirtualMacIndependent27.app/GuestTools/vm27-guest-vsock-ssh-signed-v1')
    old_guest_helper=old_by_name[guest_helper['archivePath']]
    need((guest_helper['local']['bytes'],guest_helper['local']['sha256'],guest_helper['mode'])==(52448,'33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c',0o600) and guest_helper['local']['sha256']==old_guest_helper['local']['sha256'] and 'cdhash' not in guest_helper,'actual existing Mac guest helper whole unchanged data resource; no iPad CD or trust entry')
    scope['currentSignedMacOSGuestSSHHelperWholeUnchanged']=True
    scope['fixedOwnedLogIdentity']=LOG_IDENTITY
    scope['actualInitializerLogGeneration']=actual_generation
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
    inherited_before=fast.batch_check(template_scope)+cache_check
    missing=''.join('[ ! -e '+shlex.quote(row['devicePath'])+' ] && [ ! -L '+shlex.quote(row['devicePath'])+' ] || exit 8\n' for row in changes if row['old'] is None)
    missing+=''.join('[ ! -e '+shlex.quote(row['devicePath'])+' ] && [ ! -L '+shlex.quote(row['devicePath'])+' ] || exit 8\n' for row in new_dirs)
    missing+=cache_missing
    scripts={}
    close=prefix(0)+base.PROCESS_FUNCTIONS+'''own_close_status=0
cleanup_own >/dev/null 2>&1 || own_close_status=$?
[ "$own_close_status" = 0 ] || exit "$own_close_status"
'''+off()+"printf 'INDEPENDENT27_EXACT_CURRENT_OWN_APP_CHILD_CLOSED_NO_PRODUCT_WRITE\\n'\n"
    scripts['close-current-own']=wrap(close,0,20)
    health=base.HEALTH.read_text().replace('1791813884',str(BOOT))
    # Same reviewed Normal11 exact UI-only close, isolated from the real launch
    # PID variables. Each signal rechecks captured PID/UID/path/PPID/start.
    def close_ui_guard(current,uid):
        app_file=next(row for row in current['files'] if row['devicePath']==current['deviceAppMain'])
        close_ui=prefix(uid)+"[ -f \"$OWN_APP_MAIN\" ] && [ ! -L \"$OWN_APP_MAIN\" ] || exit 8\n[ \"$(realpath \"$OWN_APP_MAIN\")\" = \"$OWN_APP_MAIN\" ] || exit 8\n"
        close_ui+='[ \"$(stat -c %u:%g:%a:%h:%s \"$OWN_APP_MAIN\")\" = '+shlex.quote('501:501:'+format(app_file['mode'],'o')+':1:'+str(app_file['local']['bytes']))+' ] || exit 8\n'
        close_ui+='[ \"$(sha256sum \"$OWN_APP_MAIN\" | cut -d \' \' -f1)\" = '+app_file['local']['sha256']+' ] || exit 8\n'
        close_ui+=base.PROCESS_FUNCTIONS+"scan_own || exit 77\n[ -z \"$child_rows\" ] || exit 8\nsignal_own TERM \"$own_app_pid\" \"$OWN_APP_MAIN\" \"$own_app_start\" app || exit 77\nsleep 1\nsignal_own KILL \"$own_app_pid\" \"$OWN_APP_MAIN\" \"$own_app_start\" app || exit 77\n"+off()
        return "own_ui_close_status=0\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c "+shlex.quote(close_ui)+" >/dev/null 2>&1 || own_ui_close_status=$?\n[ \"$own_ui_close_status\" = 0 ] || exit \"$own_ui_close_status\"\n"
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
        temporary=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-cpu-sys-exception-v33-'+str(i)+'.pending')))
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
    scripts['stage']=wrap(stage,0,90)
    complete=stage_check+'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/stage-complete")" = 0:0:600:1:0 ]\n'
    scripts['verify']=wrap(prefix(0)+off()+complete+after+fast.cd_check(scope,native_subset)+"printf 'INDEPENDENT27_NEW_PRODUCTS_ALL_SHA_AND3_NATIVE_CD_EXACT\\n'\n",0)
    trust=prefix(0)+off()+complete+after+'(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
    for i,value in enumerate(new_cd,1):trust+='jbctl trustcache add '+value+"\nprintf 'OWN_NEW_PRODUCT_TC_ADDED "+str(i)+' '+value+"\\n'\n"
    scripts['trust']=wrap(trust+trust_check(full)+"printf 'INDEPENDENT27_ONLY_ACTUAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE\\n'\n",0)
    launch=unwrap((TEMPLATE/'launch.sh').read_text()).replace(template_scope['deviceStage'],STAGE)
    need(launch.count(close_ui_guard(template_scope,501))==1,'one inherited initial exact UI-only close')
    launch=launch.replace(close_ui_guard(template_scope,501),'',1)
    need(launch.count(inherited_before)==1,'one exact inherited full-product launch guard')
    launch=launch.replace(inherited_before,after,1)
    scripts['launch']=wrap(launch,501)
    post_script=(TEMPLATE/'post.sh').read_text().replace(template_scope['deviceStage'],STAGE)
    need(post_script.count(inherited_before.replace("'","'\"'\"'"))==1,'one inherited quoted full-product post guard')
    scripts['post']=post_script.replace(inherited_before.replace("'","'\"'\"'"),after.replace("'","'\"'\"'"),1)
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
    controller=controller.replace('1791813884',str(BOOT))
    controller=controller.replace('def off_check():','_actual_newboot_prefix=prefix\ndef prefix(uid):\n    return _actual_newboot_prefix(uid)+\'[ "$(sysctl -n kern.bootsessionuuid)" = '+BOOT_UUID+' ]\\n\'\n\n\ndef off_check():',1)
    original_prefix=prefix
    new_prefix=lambda uid:original_prefix(uid).replace('1791813884',str(BOOT))+'[ "$(sysctl -n kern.bootsessionuuid)" = '+shlex.quote(BOOT_UUID)+' ]\n'
    for action in list(scripts):
        uid=501 if action=='launch' else 0
        actual_body=unwrap(scripts[action]).replace('1791813884',str(BOOT)).replace('16777219:47534875',LOG_DEVICE_INODE)
        actual_body='[ "$(sysctl -n kern.bootsessionuuid)" = '+shlex.quote(BOOT_UUID)+' ]\n'+actual_body
        if action=='post':
            actual_body+='[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = '+shlex.quote(LOG_IDENTITY)+' ]\nprintf \'OWN_POST_ACTUAL_LOG_IDENTITY %s\\n\' "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")"\n'
        scripts[action]=new_prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(20 if action=='close-current-own' else 90 if action=='stage' else 45)+' /var/jb/bin/sh -c '+shlex.quote(actual_body)+'\n'
        need('1791813884' not in scripts[action] and '47534875' not in scripts[action], 'no historical boot or log gate in actual newboot action')
    controller=stage_transport_controller(controller)
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
    candidate=dict(schema='Actual Runtime65 same-task additive RAM mapping device packet v62',preparer=pin(__file__),
        scope=pin(out/'scope.json'),archive=pin(out/'products.tar'),controller=pin(out/'control.py'),scripts=script_rows,actions=list(scripts),
        runtimeCandidate=pin(runtime_path),appCandidate=pin(app_path),currentInstalledProductsPost=pin(POST),
        actualFullFiles=len(files),actualFullCodeDirectoryHashes=len(full),actualChangedFiles=len(changes),
        actualExistingFilesUpdated=scope['existingOwnFilesUpdated'],actualNewFilesAdded=scope['newOwnFilesAdded'],
        actualNewDirectoriesAdded=len(new_dirs),actualNewOwnedMutableCacheDirectories=0,actualNewTrustEntries=len(new_cd),actualNativeCDSubset=native_subset,
        continuingHumanAuthorization=scope['continuingHumanAuthorization'],bootSeconds=BOOT,bootSessionUUID=BOOT_UUID,
        inheritedActualSignedRuntimeCDProof=signature_pin,actualSignedAppProductProof=pin(APP_PEER),
        actualSignedRuntimeProductProof=pin(RUNTIME_PEER),actualSingleNativeTrustMembershipQueryRequired=True,
        maximumQuotedCommandBytes=max(sizes.values()),quotedCommandBytes=sizes,
        closeOwnExternalWallSeconds=20,deploymentStageExternalWallSeconds=90,deploymentStageTransportTimeoutSeconds=100,
        allOtherNonCloseNonStageRemoteActionsExternalWallSeconds=45,initializationExternalWallSeconds=45,transportTimeoutSeconds=55,
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
    pins += [scope['child15PermissionsSourceCandidate'],scope['PGResourceSourceCandidate'],scope['runtime25AddressCapabilityDeltaVerification'],scope['nativeTargetShaderCandidate'],scope['pvgBufferCapabilityCandidate'],scope['pvgAddressRangeCapabilityCandidate'],scope['pvgUnifiedStorageCandidate'],scope['pvgUnifiedStorageEvidence'],scope['runtime26UnifiedStorageDeltaVerification'],scope['childErrorReasonDiagnosticCandidate'],scope['runtime27ErrorReasonDeltaVerification'],scope['historicalChildVMInitializationDiagnosticCandidate'],scope['childVMExceptionBoundaryCandidate'],scope['runtime28VMInitializationDeltaVerification'],scope['runtime29VMExceptionBoundaryDeltaVerification'],scope['childUSBHAdapterCandidate'],scope['runtime31ChildUSBHDeltaVerification'],scope['cpuNativeDistinctSlotsCandidate'],scope['runtime32CPUSlotsDeltaVerification'],scope['cpuControlFieldsCandidate'],scope['runtime33CPUStartupDeltaVerification'],scope['cpuPublicAPIFailureDiagnosticsCandidate'],scope['cpuStartupISAR2Candidate'],scope['runtime34CPUStartupISAR2DeltaVerification'],scope['cpuSCXTFeatureGuardCandidate'],scope['childSCXTGuardRecipe'],scope['runtime34CPUStartupSCXTDeltaVerification'],scope['cpuReservedZeroCandidate'],scope['childReservedZeroRouteRecipe'],scope['runtime35CPUReservedZeroDeltaVerification'],scope['nativeRunAdmissionDiagnosticsCandidate'],scope['runtime36NativeRunAdmissionDiagnosticDeltaVerification'],scope['cpuISAProfileCandidate'],scope['runtime37CPUISAProfileDeltaVerification'],scope['cpuAMXAvailabilityChildCandidate'],scope['childAMXAvailabilityGuardRecipe'],scope['cpuRunReceiptDiagnosticsCandidate'],scope['runtime38CPURunReceiptDiagnosticDeltaVerification'],scope['cpuSYSExceptionHandoffCandidate'],scope['runtime39CPUSYSExceptionDeltaVerification'],scope['cpuScratchGPRTraceCandidate'],scope['runtime40ScratchGPRTraceDeltaVerification'],genuine['source'],genuine['actualRuntimeResource']]
    pins += [app['sourceCandidate'],app_input['sourceCandidate'],main21['source'],main21['sourceDiff'],main21['actualCompile']]
    if isinstance(main21['originalParentAndChildBasis'],dict) and 'path' in main21['originalParentAndChildBasis']:pins += [main21['originalParentAndChildBasis']]
    pins += [scope['consumerStdioInheritanceCandidate'],scope['runtime41ConsumerStdioInheritanceDeltaVerification']]
    pins += [scope['cpuPublicRunSparseClockCandidate'],scope['runtime42PublicRunSparseClockDeltaVerification']]
    pins += [scope['cpuWFxWaitCandidate'],scope['runtime43CPUWFxWaitDeltaVerification'],scope['historicalRuntime60PinnedRAMReadV1Verification']['factory5ObjectWholeRuntime43']]
    pins += [scope['cpuWFxCounterReaderCandidate'],scope['runtime44CPUWFxCounterReaderDeltaVerification']]+scope['historicalRuntime47BoundedWakePostSnapshotVerification']['factory5AndGICEngine3ObjectsWholeRuntime46']
    pins += [scope['cpuInternalRunSparseCandidate'],scope['runtime45CPUInternalRunSparseDeltaVerification']]
    pins += [scope['cpuBoundedWakePostSnapshotCandidate'],scope['runtime46CPUBoundedWakePostSnapshotDeltaVerification'],scope['actualSameImageVCPUsExitBinding']['callbackAssembly']]
    pins += [scope['cpuVirtualTimerGICCandidate'],scope['runtime47CPUVirtualTimerGICDeltaVerification']]
    pins += [scope['cpuPostWakeRegisterCodeSnapshotCandidate'],scope['runtime48CPUPostWakeRegisterCodeSnapshotDeltaVerification']]+scope['historicalRuntime49PostWakeRegisterCodeSnapshotVerification']['factory5AndGICEngine4ObjectsWholeRuntime48']
    pins += [scope['cpuEL1VirtualTimerPagewalkCandidate'],scope['runtime49CPUEL1VirtualTimerPagewalkDeltaVerification']]
    pins += [scope['cpuNativePACServiceCandidate'],scope['runtime50CPUNativePACServiceDeltaVerification'],scope['uninstalledPrecedingPCSourceHistory'],scope['original13PACServiceDisassembly'],scope['original13HypervisorBinary'],scope['currentKernelActualNative9Disassembly']]+scope['historicalRuntime51NativePACServiceVerification']['factory5AndGICEngine5ObjectsWholeRuntime50']
    pins += [scope['cpuRaw7UndefinedInjectionCandidate'],scope['runtime51CPURaw7UndefinedInjectionDeltaVerification'],scope['original13Raw7UndefinedDisassembly'],scope['original13RunDisassembly'],scope['original13ExceptionInjectionHelper'],scope['baselineDependencyProofReferencedWithoutRecursiveInline']]+scope['historicalRuntime52Raw7UndefinedInjectionVerification']['factory5AndGICEngine5ObjectsWholeRuntime51']
    pins += [scope['cpuKernelTTBR1SnapshotCandidate'],scope['runtime52CPUKernelTTBR1SnapshotDeltaVerification'],scope['actualNormal58PostSnapshot'],scope['uninstalledKernelTTBR1SnapshotSourceHistory']]+scope['historicalRuntime53KernelTTBR1SnapshotVerification']['factory5AndGICEngine5ObjectsWholeRuntime52']
    pins += [scope['cpuRaw7FaultOpcodeSnapshotCandidate'],scope['runtime53CPURaw7FaultOpcodeSnapshotDeltaVerification'],scope['actualNormal59KernelPanicSnapshot']]+scope['historicalRuntime54Raw7FaultOpcodeSnapshotVerification']['factory5AndGICEngine5ObjectsWholeRuntime53']
    pins += [scope['cpuDisabledAMXConfigCandidate'],scope['runtime54CPUDisabledAMXConfigDeltaVerification'],scope['actualNormal60FaultInstructionSnapshot']]+scope['historicalRuntime55DisabledAMXConfigVerification']['factory5AndGICEngine5ObjectsWholeRuntime54']
    pins += [scope['cpuDisabledAMXConfigV2Candidate'],scope['runtime55CPUDisabledAMXConfigV2DeltaVerification'],scope['actualNormal61RepeatedFaultSnapshot']]+scope['historicalRuntime56DisabledAMXConfigV2Verification']['factory5AndGICEngine5ObjectsWholeRuntime55']
    pins += [scope['cpuDisabledAMXConfigV3Candidate'],scope['runtime56CPUDisabledAMXConfigV3DeltaVerification'],scope['actualNormal62Operand100Snapshot'],scope['actualNativeBootConfig100Disassembly'],scope['actualNativeContextEnable63Disassembly']]+scope['historicalRuntime57DisabledAMXConfigV3Verification']['factory5AndGICEngine5ObjectsWholeRuntime56']
    pins += [scope['cpuEncodedExitV1Candidate'],scope['runtime57CPUEncodedExitV1DeltaVerification'],scope['actualNormal63AcceptedConfigAndRaw8Snapshot'],scope['original13EncodedExitDecoderDisassembly'],scope['actualNativeABI14EncodedExitConsumerDisassembly']]+scope['historicalRuntime58EncodedExitV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime57']
    pins += [scope['cpuDisabledAMXStateV1Candidate'],scope['runtime58CPUDisabledAMXStateV1DeltaVerification'],scope['actualNormal64EncodedIDAndAMXStateSnapshot'],scope['actualNativeAMXStateZeroBranchDisassembly'],scope['actualNativeAMXBank57SaveDisassembly']]+scope['historicalRuntime59DisabledAMXStateV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime58']
    pins += [scope['cpuPinnedRAMReadV1Candidate'],scope['runtime59CPUPinnedRAMReadV1DeltaVerification'],scope['actualNormal65SecondaryCPUAndRAMBusySnapshot'],scope['actualRAMCPUImmutabilitySource'],scope['originalVMOperationReadGateSource']]+scope['historicalRuntime60PinnedRAMReadV1Verification']['factory5AndGICEngine5ObjectsWholeRuntime59']
    pins += [scope['cpuAdditiveRAMV1Candidate'],scope['runtime60CPUAdditiveRAMV1DeltaVerification'],scope['cpuAdditiveRAMSourcePlan'],scope['historicalRuntime61AdditiveRAMV1Verification']['gicEngine5ObjectWholeRuntime60'],scope['historicalRuntime61AdditiveRAMV1Verification']['factory6ActualChangedObject'],scope['historicalRuntime61AdditiveRAMV1Verification']['bootstrap25ActualChangedObject']]+list(additive_plan['proofs'].values())
    pins += [scope['cpuOwnedMandatoryFailureV1Candidate'],scope['runtime61CPUOwnedMandatoryFailureV1DeltaVerification'],scope['cpuOwnedMandatoryFailureSourcePlan']]+scope['historicalRuntime62OwnedMandatoryFailureV1Verification']['factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime61']+list(mandatory_plan['proofs'].values())
    pins += [scope['cpuSerializedWakeV1Candidate'],scope['runtime62CPUSerializedWakeV1DeltaVerification'],scope['cpuSerializedWakeSourcePlan'],scope['historicalRuntime63SerializedWakeV1Verification']['mandatory4ObjectWholeRuntime62']]+scope['historicalRuntime63SerializedWakeV1Verification']['factory6AndBootstrap25AndGICEngine5ObjectsWholeRuntime62']+list(serialized_plan['proofs'].values())+scope['nativeImportClosureSources']
    pins += [scope['cpuBorrowedHostInputV1Candidate'],scope['runtime63CPUBorrowedHostInputV1DeltaVerification'],scope['cpuBorrowedHostInputSourcePlan']]+[scope['historicalRuntime64BorrowedHostInputV1Verification'][key]for key in ('factory7ActualChangedObject','bootstrap26ActualChangedObject','gicEngine5ObjectWholeRuntime63','mandatory4ObjectWholeRuntime63')]+list(borrowed_plan['proofs'].values())
    pins += [scope['cpuTaskScopedRAMV1Candidate'],scope['runtime64CPUTaskScopedRAMV1DeltaVerification'],scope['cpuTaskScopedRAMSourcePlan'],scope['factory8ActualChangedObject'],scope['bootstrap27ActualChangedObject'],scope['production7ActualChangedObject'],scope['gicEngine5ObjectWholeRuntime64'],scope['mandatory4ObjectWholeRuntime64']]+list(task_plan['proofs'].values())
    pins += [pin(B/'independent27_initializer_log_generation_v1.py'),actual_generation['initializerLaunch'],actual_generation['initializerPost'],actual_generation['actualPostStdout']]
    pins += [row['local']for row in files]+[row['old']for row in changes if row['old'] is not None]
    dump(out/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'),
        files=len(files),CDs=len(full),delta=len(changes),newTC=len(new_cd),maximumQuotedCommandBytes=max(sizes.values()))))

if __name__=='__main__':main()
