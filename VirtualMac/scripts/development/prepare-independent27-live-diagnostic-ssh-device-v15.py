#!/usr/bin/env python3
"""HOST prepare an exact GPU-only successor of an actually installed packet.

Root supplies previous packet, successful current-products post and all new SHA256
pins. Only the same existing GPU/parent/App delta paths may change. All265 paths,
146 entitlement sets, CPU29, Main33, genuine GPU192 and the inherited seven-action
backup/trust/initialization/cleanup protocol remain required. This command writes
only a fresh HOST packet; it does not sign, dispatch, make ready or boot a guest.
"""
import argparse
import copy
import difflib
import importlib.util
import io
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import struct
import sys
import tarfile

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
OLD = STAGE = base = fast = pin = dump = None
MAIN = 'VirtualMacIndependent27.app/VirtualMacIndependent27'
BOOT = 1792161311
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
MAIN32_PLAN_SHA256 = '935ba7a6209cfc0fe9d4dc12939cbb0bd595a537ed2218e9f87b55cd24ed0866'
HISTORICAL_RUNTIME86_SHA256 = 'aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
EXTENDED_VA_KEY = 'com.apple.developer.kernel.extended-virtual-addressing'
LOG_ID = '16777223:48200252'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(value, message):
    if not value:
        raise ValueError(message)


def bootstrap_pin(path):
    path=pathlib.Path(path).resolve()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def unwrap(script):
    start = script.index('/var/jb/usr/bin/timeout')
    at = script.index('/var/jb/bin/sh -c ', start)+len('/var/jb/bin/sh -c ')
    values = shlex.split(script[at:])
    need(len(values) == 1, 'one inherited bounded action')
    return values[0]


def rewrap(script, body):
    start = script.index('/var/jb/usr/bin/timeout')
    at = script.index('/var/jb/bin/sh -c ', start)+len('/var/jb/bin/sh -c ')
    need(script[at:] == shlex.quote(unwrap(script))+'\n', 'exact previous packet single quoted body/tail')
    return script[:at]+shlex.quote(body)+'\n'


def trust_check(hashes):
    # Same exact membership parser as the executed previous packet trust action.
    values = ';'.join('expected["'+value+'"]=1' for value in hashes)
    awk = ('BEGIN {'+values+'} {v=tolower($NF);if(length(v)==40 && '
           'v~/^[[:xdigit:]]+$/ && (v in expected))found[v]=1} '
           'END {for(v in found)print v}')
    return '''own_actual_trust_exit=0
own_actual_trust_info=$(jbctl trustcache info) || own_actual_trust_exit=$?
printf 'OWN_ACTUAL_TRUST_NATIVE_EXIT %s\n' "$own_actual_trust_exit"
printf '%s\n' "$own_actual_trust_info"
[ "$own_actual_trust_exit" = 0 ]
own_actual_present=$(printf '%s\n' "$own_actual_trust_info" | awk '''+shlex.quote(awk)+''' | sort)
[ "$own_actual_present" = '''+shlex.quote('\n'.join(sorted(hashes)))+''' ]
printf 'INDEPENDENT27_ACTUAL_ALL_ACTIVE_OWN_TRUST_MEMBERSHIP_EXACT\n'
'''


GPU_REL = 'gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc/Contents/MacOS/com.apple.gpusw.ParavirtualizedGraphicsGPUTask'

def gpu_off_check():
    path = '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/'+GPU_REL
    return """own_gpu_off=0
for own_gpu_wait in 1 2 3; do
 own_gpu_rows=$(ps -axo pid=,ppid=,uid=,comm=)
 if printf '%s\n' "$own_gpu_rows" | awk -v g="""+shlex.quote(path)+""" 'NF<4 {bad=1} {n++;if($4==g)bad=1} END {exit bad || !n}'; then own_gpu_off=1;break;fi
 sleep 1
done
[ "$own_gpu_off" = 1 ]
printf 'INDEPENDENT27_EXACT_NATIVE_GPU_TASK_OFF\n'
"""


def stage_body(scope, archive):
    baseline = json.loads(base.exact(scope['oldScope']).read_bytes())
    main_change = next(item for item in scope['deltaFiles'] if item['archivePath'] == MAIN)
    old_main, main_mode = main_change['old'], main_change['mode']
    prior_main = next(item['old'] for item in baseline['deltaFiles'] if item['archivePath'] == MAIN)
    original_stage = unwrap((OLD/'stage.sh').read_text())
    lead = original_stage[:original_stage.index('check_own_file() {')]
    need(lead.count(prior_main['sha256']) == 1 and
         lead.count(f'501:501:{main_mode:o}:1:{prior_main["bytes"]}') == 1,
         'one original previous packet UI-only close Main byte/metadata guard')
    lead = lead.replace(baseline['deviceStage'], STAGE).replace(prior_main['sha256'], old_main['sha256'])
    lead = lead.replace(f'501:501:{main_mode:o}:1:{prior_main["bytes"]}', f'501:501:{main_mode:o}:1:{old_main["bytes"]}')
    stage = lead+'''check_own_file() {
 [ -f "$1" ] && [ ! -L "$1" ]
 [ "$(realpath "$1")" = "$1" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$1")" = "501:501:$4:1:$3" ]
 [ "$(sha256sum "$1" | cut -d ' ' -f1)" = "$2" ]
}
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
dd of="$OWN_STAGE/products.tar" bs=65536 2>/dev/null
'''+f'''[ "$(stat -c %u:%g:%h:%s "$OWN_STAGE/products.tar")" = 0:0:1:{len(archive)} ]
[ "$(sha256sum "$OWN_STAGE/products.tar" | cut -d ' ' -f1)" = {base.digest(archive)} ]
tar -xpf "$OWN_STAGE/products.tar" -C "$OWN_STAGE"
'''
    # Exact old backups and absence markers precede all product writes.
    for row in scope['deltaFiles']:
        path = shlex.quote(row['devicePath']); old, new, mode, index = row['old'], row['new'], row['mode'], row['index']
        if old is not None:
            stage += f'''check_own_file {path} {old['sha256']} {old['bytes']} {mode:o}
cp -p {path} "$OWN_STAGE/backup-{index}"
[ "$(sha256sum "$OWN_STAGE/backup-{index}" | cut -d ' ' -f1)" = {old['sha256']} ]
'''
        else:
            stage += f'''[ ! -e {path} ] && [ ! -L {path} ]
(umask 077; set -C; : > "$OWN_STAGE/backup-new-absent-{index}")
'''
        stage += f'''[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/new-{index}")" = 0:0:600:1:{new['bytes']} ]
[ "$(sha256sum "$OWN_STAGE/new-{index}" | cut -d ' ' -f1)" = {new['sha256']} ]
'''
    stage += '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
'''+f'''[ "$(stat -c %d:%i "$OWN_LOG")" = {LOG_ID} ]
'''+'''[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
own_log_identity=$(stat -c %d:%i "$OWN_LOG")
cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
printf 'OWN_PRIOR_LOG_BACKUP metadata=%s sha256=%s\n' "$own_log_meta" "$own_log_sha"
'''
    stage += gpu_off_check()
    for directory in scope['newOwnDirectories']:
        path = shlex.quote(directory['devicePath']); parent = shlex.quote(str(pathlib.PurePosixPath(directory['devicePath']).parent))
        stage += f'''[ -d {parent} ] && [ ! -L {parent} ]
[ "$(realpath {parent})" = {parent} ]
[ ! -e {path} ] && [ ! -L {path} ]
mkdir -m {directory['mode']:o} {path}
chown 501:501 {path}
[ "$(stat -c %u:%g:%a {path})" = 501:501:{directory['mode']:o} ]
[ "$(realpath {path})" = {path} ]
'''
    for row in scope['deltaFiles']:
        path = shlex.quote(row['devicePath']); old, new, mode, index = row['old'], row['new'], row['mode'], row['index']
        pending = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-'+scope['packetName']+'-'+str(index)+'.pending')))
        stage += f'''[ ! -e {pending} ] && [ ! -L {pending} ]
cp "$OWN_STAGE/new-{index}" {pending}
chown 501:501 {pending}
chmod {mode:o} {pending}
check_own_file {pending} {new['sha256']} {new['bytes']} {mode:o}
'''
        if old is not None:
            stage += f'''check_own_file {path} {old['sha256']} {old['bytes']} {mode:o}
mv -f {pending} {path}
'''
        else:
            stage += f'''[ ! -e {path} ] && [ ! -L {path} ]
mv -n {pending} {path}
[ ! -e {pending} ] && [ ! -L {pending} ]
'''
        stage += f'''check_own_file {path} {new['sha256']} {new['bytes']} {mode:o}
printf 'OWN_EXACT_PRODUCT_UPDATED {index} {row['archivePath']}\n'
'''
    return stage+'''[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
(umask 077; set -C; : > "$OWN_STAGE/stage-complete")
printf 'INDEPENDENT27_ALL_DELTA_INSTALLED_EXACT_BACKUPS_RETAINED_NO_TRUST_OR_GUEST\n'
'''


def main():
    global OLD, STAGE, base, fast, pin, need, dump
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=pathlib.Path, required=True)
    ap.add_argument('--previous-device-packet',type=pathlib.Path,required=True)
    ap.add_argument('--expected-post-sha256',required=True)
    ap.add_argument('--app-candidate', type=pathlib.Path, required=True)
    ap.add_argument('--runtime-candidate', type=pathlib.Path, required=True)
    ap.add_argument('--current-installed-post',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate-sha256', required=True)
    ap.add_argument('--app-candidate-sha256', required=True)
    ap.add_argument('--app-source-sha256', required=True)
    ap.add_argument('--gpu-candidate-sha256', required=True)
    ap.add_argument('--gpu-source-plan-sha256', required=True)
    ap.add_argument('--gpu-expected-changed-instruction-words',type=int,default=19)
    args = ap.parse_args()
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (args.runtime_candidate_sha256,args.app_candidate_sha256,args.app_source_sha256,
          args.gpu_candidate_sha256,args.gpu_source_plan_sha256,args.expected_post_sha256)),
         'Root supplies actual post and new signed product/source SHA256 pins')
    need(args.gpu_expected_changed_instruction_words == 19,
         'actual reviewed Task192 retains exactly nineteen changed instruction words')
    need(args.gpu_source_plan_sha256 == '9b2392f32fa35bf62647de604d62f258b3d8dd943e6274f5095199d7069edabb',
         'exact reviewed Plan18 native ordinary texture Managed compatibility')
    OLD=args.previous_device_packet.resolve()
    out,app_path=args.output.resolve(),args.app_candidate.resolve()
    packet_pattern=r'independent27-gpu-[a-z0-9]+(?:-[a-z0-9]+)*-device-v[0-9]+-attempt[0-9]+'
    need(OLD.parent==N and OLD.is_dir() and re.fullmatch(packet_pattern,OLD.name) and
         out.parent==N and not out.exists() and re.fullmatch(packet_pattern,out.name) and
         len(out.name)<=120 and out!=OLD,
         'existing previous GPU packet and fresh bounded same-root successor name')
    STAGE='/private/var/mobile/Library/.VM27-'+out.name
    prior=json.loads((OLD/'candidate.json').read_bytes())
    need(prior['controller']==bootstrap_pin(OLD/'control.py') and
         prior['scope']==bootstrap_pin(OLD/'scope.json'),
         'previous candidate pins exact inherited controller and scope before import')
    base=load(OLD/'control.py','exact_previous_gpu_controller')
    fast=load(B/'independent27_device_product_verify_fast_v1.py','exact_gpu_successor_fast')
    pin,need,dump=base.pin,base.need,base.dump
    need(tuple(prior['actions'])==tuple(base.ACTIONS)==
         ('close-current-own','preflight','stage','verify','trust','launch','post'),
         'previous packet retains exact seven standard actions')
    POST=args.current_installed_post.resolve()
    need(POST.is_relative_to(N) and POST.name=='receipt.json' and
         POST.parent.name in ('post','post-recovery-v2') and pin(POST)['sha256']==args.expected_post_sha256,
         'Root exact successful actual current-products post or reviewed exact UI-only recovery receipt')
    for row in prior['scripts'].values():
        base.exact(row)
    prior_receipt_pins=[]
    for action in prior['actions']:
        path=OLD/'device-receipts'/action/'receipt.json'
        receipt=json.loads(path.read_bytes()); request=json.loads(base.exact(receipt['request']).read_bytes())
        need(receipt['transportExit']==0 and request['packetCandidate']==pin(OLD/'candidate.json') and request['script']==prior['scripts'][action], 'actual all7 previous packet phases '+action)
        base.exact(receipt['stdout']);base.exact(receipt['stderr'])
        prior_receipt_pins += [pin(path),receipt['request'],receipt['stdout'],receipt['stderr']]
    old = json.loads((OLD/'scope.json').read_bytes())
    need(old['bootSeconds'] == BOOT and old['bootSessionUUID'] == UUID and
         old['fixedOwnedLogIdentity'] == LOG_ID+':501:501:600:1', 'same current boot and owned log')
    post = json.loads(POST.read_bytes())
    text = base.exact(post['stdout']).read_text()
    base.exact(post['stderr']); base.exact(post['request'])
    post_request=json.loads(base.exact(post['request']).read_bytes())
    post_packet_pin=pin(POST.parents[2]/'candidate.json')
    need(post['action']==('post-recovery' if POST.parent.name=='post-recovery-v2' else 'post') and post['transportExit']==0 and
         post_request['packetCandidate']==post_packet_pin,
         'actual post0 binds its own exact packet candidate')
    current_post_pins=[post_packet_pin]
    if POST.parent.name=='post-recovery-v2':
        failed_path=POST.parents[2]/'device-receipts/post/receipt.json'
        failed_pin=pin(failed_path);failed=json.loads(base.exact(failed_pin).read_bytes())
        need(failed['transportExit']==8 and post_request['failedPost']==failed_pin and
             post_request['actualStop']==pin(POST.parents[2]/'device-receipts/stop/receipt.json') and
             post_request['initializer']==pin(OLD/'candidate.json') and
             post_request['expectedOnlyRelaunchedOwnedUI']==78086 and
             post_request['source']==pin(N/'root-normal128-post-recovery-v2.py') and
             base.exact(failed['stdout']).read_text().split()==
                 ['UNEXPECTED_OWN_PROCESS','78086','1','501',old['deviceAppMain']] and
             post['trustCacheOperations']==post['deviceProductWrites']==0 and
             post['guestBootRequested'] is False,
             'only exact reviewed Normal128 post8/UI78086 recovery, no products/TC writes')
        base.exact(post_request['script']);base.exact(post_request['source']);base.exact(failed['request']);base.exact(failed['stderr'])
        current_post_pins.extend([failed_pin,failed['request'],failed['stdout'],failed['stderr'],post_request['script'],post_request['source']])
    preceding_stop=None
    if post_packet_pin==pin(OLD/'candidate.json'):
        post_kind='previous-initialization-post'
        terminal='INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED'
    else:
        post_packet=json.loads(base.exact(post_packet_pin).read_bytes())
        need(post_packet['initializerCandidate']==pin(OLD/'candidate.json'),
             'normal post belongs to the same actually installed initializer')
        stop_path=POST.parents[2]/'device-receipts/stop/receipt.json'
        preceding_stop=pin(stop_path)
        normal_stop=json.loads(stop_path.read_bytes())
        need(normal_stop['action']=='stop' and normal_stop['transportExit']==0 and
             json.loads(base.exact(normal_stop['request']).read_bytes())['packetCandidate']==post_packet_pin,
             'normal current-products post follows actual stop0 of the same packet')
        base.exact(normal_stop['stdout']);base.exact(normal_stop['stderr'])
        current_post_pins.extend((preceding_stop,normal_stop['request'],normal_stop['stdout'],normal_stop['stderr']))
        post_kind='normal-post-after-stop'
        terminal='OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF'
    need(all(marker in text for marker in ('INDEPENDENT27_OWN_APP_AND_CHILD_OFF',
             'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT','PRODUCTION_6_CODE_HASHES_PRESERVED',terminal)),
         'actual same-product off/health/full-product post0 markers')
    need(prior['runtimeCandidate']==old['runtimeCandidate'] and
         prior['appCandidate']==old['appCandidate'] and STAGE!=old['deviceStage'],
         'previous scope/candidate products join and successor stage is distinct')
    base.exact(old['runtimeCandidate'])
    runtime_path = args.runtime_candidate.resolve()
    runtime_pin = pin(runtime_path)
    need(runtime_pin['sha256'] == args.runtime_candidate_sha256 and pin(app_path)['sha256'] == args.app_candidate_sha256,
         'actual installed previous runtime and Root actual signed new runtime/new App products')
    runtime = json.loads(runtime_path.read_bytes()); app = json.loads(app_path.read_bytes())
    previous_app = json.loads(base.exact(old['appCandidate']).read_bytes())
    need(app['actualCodeSigned'] is True and app['actualPrimaryPagesAndExternalSlotsVerified'] is True and
         app['runtimeCandidate'] == runtime_pin and app['runtimeRoot'] == runtime['canonicalDeviceRoot'] and
         app['actualBundleID'] == previous_app['actualBundleID'] and app['actualURLScheme'] == previous_app['actualURLScheme'],
         'actual signed new App with new runtime and unchanged application identity')
    need(app['sourceCandidate']['sha256'] == args.app_source_sha256, 'actual Root-linked new App source candidate')
    source = json.loads(base.exact(app['sourceCandidate']).read_bytes())
    inherited_source = json.loads(base.exact(source['inheritedCompiledAppCandidate']).read_bytes())
    prior_source = json.loads(base.exact(previous_app['sourceCandidate']).read_bytes())
    need(source['inheritedCompiledAppCandidate'] == previous_app['sourceCandidate'] and
         len(source['objects']) == len(source['sourceFiles']) == 35 and
         source['actualRuntimeCandidate'] == runtime_pin == old['runtimeCandidate'] and
         source['actualChangedAppObjectIndices'] == [0] and
         source['actualNewAppCompilations'] == 1 and source['actualUnchangedCompiledObjects'] == 34 and
         source['actualOnlyMainObjectChanged'] is True and
         all(source['objects'][i] == inherited_source['objects'][i] and
             source['sourceFiles'][i] == inherited_source['sourceFiles'][i]
             for i in range(35) if i != 0),
         'exact Main36 unit only; GT14 Display9 other34 objects and Runtime102 whole')
    main_key='liveDiagnosticSSHV36Contract'
    main_plan=json.loads(base.exact(source['mainSourcePlan']).read_bytes())
    need(source['mainSourceContractKey']==main_key and
         main_plan['sourceFiles']==[source['sourceFiles'][0]] and
         main_plan[main_key]==source[main_key] and
         source['actualOriginalBootArgsRestorationCodePresent'] is True and
         source['actualRuntime102AndAnchorWholeUnchanged'] is True and
         source['sourceFiles'][0]['sha256']=='6de5c286899c9d5095a6ef6a8fb5df17fff5303b5603e7be5db124994f4f44ab' and
         source['sourceFiles'][8]['sha256']=='a681e6e535b3d76b8665c90fc7998ac293fa9ac9e53fd6e10ec2576dc322a6cf' and
         source['sourceFiles'][16]['sha256']=='c4e949fda1d34f52ab3e257e0551552269e79d27acacaa06380964a75ab1e1b1',
         'actual Root-reviewed Main36 GT14 Display9 source pins')
    previous_main_plan=json.loads(base.exact(inherited_source['mainSourcePlan']).read_bytes())
    need(main_plan['baselineMain35Source']==inherited_source['sourceFiles'][0] and
         main_plan['preservedMain35ContractKey']==inherited_source['mainSourceContractKey'] and
         main_plan['preservedMain35Contract']==inherited_source[inherited_source['mainSourceContractKey']] and
         main_plan['preservedMain35Contract']==previous_main_plan[inherited_source['mainSourceContractKey']] and
         [u['index'] for u in main_plan['compileUnits']]==[0] and
         source['guestToolsSourcePlan']==inherited_source['guestToolsSourcePlan'] and
         source['guestToolsSourceContractKey']==inherited_source['guestToolsSourceContractKey'] and
         source[source['guestToolsSourceContractKey']]==inherited_source[inherited_source['guestToolsSourceContractKey']],
         'exact Main35 display contract inherited; original GT14 source plan and contract whole')
    need(runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         runtime['baselineRuntimeCandidate']['sha256'] == HISTORICAL_RUNTIME86_SHA256 and runtime['nativeGPUTaskNoContainerEntitlementActuallyPresent']is True and runtime['nativeGPUTaskCanExecuteCDHashEntitlementActuallyPresent']is True and runtime['all29CPUObjectsWholeRuntime86'] is True and
         runtime['bothSignedCPUProvidersWholeRuntime86'] is True and runtime['cpu29SourceProof'] == prior['actualCPUCurrentSource'] and
         runtime['wholeByteUnchangedSignedImages'] == 140 and runtime['existingSignedImagesResigned'] == 3 and
         runtime['nativeGPUTaskImagesPreviouslySignedAndWholeInherited'] == 2 and runtime['nativeGPUTaskImagesResigned'] == 0,
         'new runtime is assembled from historical R86 with MD/PG/VMM reseals and signed native GPU helper; all29 CPU objects and140 old signed images whole')
    need(runtime['nativeOwnedGPUTaskProduct']['sha256']==args.gpu_candidate_sha256 and
         runtime['nativeOwnedGPUTaskSourcePlan']['sha256']==args.gpu_source_plan_sha256,
         'actual Root signed GPU product and exact native event/pipeline source-plan')
    parent = runtime['ownedPGRemoteTaskParentTransportV1Contract']
    parent_observer = parent['nativeCompletionObserver']
    need(runtime['ownedGPUParentSourcePlan']['sha256'] == '3e9cbf1d3f336b63186d18300e6f85e64b51b97f2b3074ba2cbb00e9cc0b56b9' and
         runtime['callbacksInterposedButSemanticsWhole'] is True and
         runtime['scopedOnlyExactOwnedPGInstanceMethodObservation'] is True and
         runtime['noFoundationOrMetalClassMutation'] is True and
         parent['noAppleClassSwizzle'] is False and
         parent['scopedOnlyExactOwnedPGInstanceMethodObservation'] is True and
         parent['noFoundationOrMetalClassMutation'] is True and
         parent_observer['className'] == 'PGRemoteTaskDeviceDelegate' and
         parent_observer['classRVA'] == 0x84af0 and parent_observer['originalIMPRVA'] == 0x35b68 and
         parent_observer['selector'] == 'completeAsyncTokenID:success:error:' and
         parent_observer['typeEncoding'] == 'v36@0:8Q16I24@28' and
         parent_observer['PGUUID'] == '9e6a667aa77532de8dd56872ef6a53d9' and
         parent_observer['firstSixteenAndPowersOfTwoThrough'] == 1048576 and
         parent_observer['maximumFailureLogs'] == 8 and
         all(parent_observer[k] is True for k in
             ('exactImagePathUUIDClassIMPAndMethodTypesBeforeInstall',
              'installedOnlyAfterOriginalParentCallerAdmission', 'onlyOwnedVMMProcessLifetime',
              'originalIMPExactlyOnceOutsideDiagnosticCatch',
              'originalTokenUInt64ResultUInt32NSErrorAndErrnoUnchanged',
              'noEventOrStampWrites', 'noFoundationOrMetalMutation',
              'noOtherProcessOrKernelModification', 'originalExceptionsPropagate')),
         'exact owned PG callback observer; original semantics whole and no Foundation, Metal, other process or kernel mutation')
    parent_plan = json.loads(base.exact(runtime['ownedGPUParentSourcePlan']).read_bytes())
    need(parent == parent_plan['ownedPGRemoteTaskParentTransportV1Contract'],
         'runtime parent observation contract joins the actual reviewed source plan')
    gpu_source_plan=json.loads(base.exact(runtime['nativeOwnedGPUTaskSourcePlan']).read_bytes())
    base.exact(runtime['nativeOwnedGPUTaskProduct'])
    # Prior canonical main, optional capabilities, native shmem-map and typed
    # IOSurface texture contracts remain required. New exact native event and
    # bounded pipeline-error contracts are admitted from the pinned source plan.
    need(gpu_source_plan['mainImageSelection']['imageCountMaximum'] == 4096 and
         gpu_source_plan['mainImageSelection']['nameExactlyMatchesFixedCanonicalTaskPath'] is True and
         gpu_source_plan['mainImageSelection']['exactlyOneImageRequired'] is True and
         gpu_source_plan['mainImageSelection']['noDylibFallback'] is True and
         gpu_source_plan['mainImageSelection']['allOriginalMachHeaderUUIDLCMAINAndBranchGuardsPreserved'] is True,
         'canonical unique task image preserves all original execute/UUID/entry/branch guards')
    metal_features = gpu_source_plan['metalContract']['nativeFeatureQueryV2']
    need(gpu_source_plan['actualChangedCompileUnits'] == [2] and
         gpu_source_plan['inheritedWholeCompileUnits'] == [0, 1, 3, 4] and
         {row['nativeSelector'] for row in metal_features['routes']} ==
             {'supportsBufferWithAddressRanges', 'supportsHeapWithAddressRanges', 'supportsResourceDetachBacking'} and
         len(metal_features['routes']) == 3 and
         all(metal_features[key] is True for key in
             ('missingMethodReturnsFalse', 'presentNativeGetterRequiresExactTwoArgBOOLABI',
              'presentNativeGetterCalledExactlyOnce', 'noGlobalClassMutation',
              'noForcedTrueFeature', 'allowLibrariesFromOtherPlatformsNativeBLWhole')),
         'prior typed optional queries remain; only texture adapter unit rebuilt and four other objects whole')
    shmem = gpu_source_plan['metalContract']['shmemMapObservationV1']
    need(shmem['exactObservedNativeReturnRVA'] == 0x119c and
         shmem['nativeCallsPerWrapperInvocation'] == 1 and
         shmem['maxObservationsPerProcess'] == 16 and
         all(shmem[key] is True for key in
             ('allActualNativeTextCallersRequireExistingAdmission', 'nativeReturnAndOutputUnchanged',
              'nativeErrnoRestoredAfterLogging', 'expectedLengthReadOnlyAtExactCaller',
              'mappedPointerReadOnlyIfReturnPositive', 'otherNativeCallersForwardWithoutAdjacentFieldRead',
              'noNativeCompareThrowRetryMappingOrPermissionsChanged')),
         'real native map invoked once; bounded first16 observations preserve return/output/errno and original validation')
    texture = gpu_source_plan['metalContract']['nativeIOSurfaceTextureManagedToSharedV1']
    need(texture['exactNativeReturnRVAs'] == [0x4d24c, 0x4e494, 0x4ea24] and
         texture['originalAllThreeIOSurfaceCallsRouted'] is True and
         texture['actualOperationLogIncludesMatchedCallerRVA'] is True and
         texture['nativeSelector'] == 'newTextureWithDescriptor:iosurface:plane:' and
         all(texture[key] is True for key in
             ('standaloneFiveArgumentNativeABI', 'requiresActualNativeHasUnifiedMemoryTrue',
              'hasUnifiedMemoryBOrCTwoArgumentABIChecked', 'onlyManagedStorageModeOneConvertsToSharedZero',
              'callerDescriptorNotMutated', 'copiedDescriptorAllOtherFieldsRetained',
              'allOtherResourceOptionsBitsMustRemainExact', 'onlyNativeTextureAllocationOnce',
              'nativeNilOrFailureRetained', 'nativeReturnedPlusOneNoAdditionalRetain',
              'originalIOSurfaceAndPlaneUnchanged', 'noGlobalClassMutation', 'noValidationDisabled',
              'originalDeviceAndIOSurfaceValidationInstructionsWhole', 'taskEntitlementsExactlyWholeGPU12')),
         'exact native five-argument IOSurface call; only Managed-to-Shared on actual unified device; allocation/results/validation preserved')
    gpu_product=json.loads(base.exact(runtime['nativeOwnedGPUTaskProduct']).read_bytes())
    texture_call=gpu_product['nativeTaskPort']['nativeIOSurfaceTextureAllocation']
    need(gpu_product['nativeTaskPort']['exactChangedInstructionWordCount']==args.gpu_expected_changed_instruction_words and
         gpu_product['nativeTaskPort']['nativeShmemMapCallAndCompareAndThrowWhole'] is True and
         texture_call['callRVA']==0x4ea20 and texture_call['returnRVA']==0x4ea24 and
         texture_call['actualWord']=='0x94006853' and texture_call['targetCStubRVA']==0x68b6c and
         texture_call['correctStandaloneFiveArgumentABI'] is True and
         texture_call['originalNativeTextureAndSurfaceValidatorsWhole'] is True and
         texture_call['allThreeOriginalIOSurfaceAllocationCallsRouted'] is True and
         texture_call['callRVAs'] == [0x4d248, 0x4e490, 0x4ea20] and
         texture_call['returnRVAs'] == [0x4d24c, 0x4e494, 0x4ea24] and
         [(r['callRVA'], r['returnRVA'], r['actualWord']) for r in texture_call['routes']] ==
             [(0x4d248, 0x4d24c, '0x94006e49'), (0x4e490, 0x4e494, '0x940069b7'),
              (0x4ea20, 0x4ea24, '0x94006853')],
         'actual native Task bound word proof retains typed texture route; all original validators and map comparison remain whole')
    event_pipeline=gpu_source_plan['metalContract']['orderedEventAndRenderPipelineObservationV1']
    need(event_pipeline['exactScheduledSignalCallRVA']==0x2d438 and
         event_pipeline['directNativePublicSignalEventStubRVAHistoricalBeforeObserver']==0x6b200 and
         event_pipeline['signalAdapterCallsSameNativePublicSelectorOnce'] is True and
         event_pipeline['pipelineCallerReturnRVAs']==[0x41114,0x41b08] and
         event_pipeline['maxActualFailureLogs']==8 and
         event_pipeline['maxUTF16CharactersPerNSErrorField']==512 and
         event_pipeline['maxUTF8BytesPerField']==2048 and
         event_pipeline['currentTaskImportRows']==192 and
         all(event_pipeline[key] is True for key in
             ('eventValueAndOriginalCommitUnchanged', 'conservativeLaterGPUExecutionSignalNotSchedulingEquivalent',
              'exactEarlySchedulingOptimizationDeferred', 'noCPUEventValueWrite', 'noNOPOrFakeGPUCompletion',
              'singleProperSixArgumentAdapter', 'exactNativeSelectorByCaller',
              'descriptorOptionsReflectionErrorSlotsUntouched', 'nativeCallExactlyOnceAndReturnedPlusOneUnchanged',
              'nativeExceptionsStillPropagate', 'noShaderFallbackOrSuccessfulPipelineManufactured',
              'oneFreshAuthenticatedSlotAndTailStub', 'original186ImportRowsRetainedWithObserver186Sampler187Signal188',
              'taskEntitlementsExactlyWholeGPU13', 'largeNSErrorBuffersInNoInlineHelper',
              'adapterContainsNoLargeDiagnosticLocalArrays', 'exactCallerAdmissionRetained',
              'PSOAndSamplerOriginalCallStubAndImportSemanticsUnchanged',
              'PSOAuthSlotOnlyNextFieldExtendedToSamplerSlot')),
         'real later GPU signal preserves value/commit; bounded exact two-callsite six-argument pipeline observer preserves native result/error')
    sampler = gpu_source_plan['metalContract']['nativeSamplerReductionDefaultV1']
    need(sampler['exactNativeCallRVA'] == 0x44e98 and sampler['exactNativeReturnRVA'] == 0x44e9c and
         sampler['nativeSelector'] == 'setReductionMode:' and sampler['firstMaximumActualModeLogs'] == 16 and
         all(sampler[k] is True for k in ('properStandaloneThreeArgumentABI',
             'actualNativeSamplerDescriptorRequired', 'actualNativeMethodWhenPresentStrictTypedCallOnce',
             'missingSetterOnlyZeroRetainsHistoricalWeightedAverageDefault',
             'missingSetterNonzeroRaisesUnsupportedNativeException',
             'optionalExistingGetterMustReportZeroForDefaultRetention', 'noDynamicMethodAdded',
             'noFeatureAdvertisedTrue', 'noSamplerStateManufactured', 'nativeSerializedModeAndValidatorWhole',
             'nativeOtherFourteenSamplerSettersWhole', 'existingPSOAndIOSurfaceAdapterImplementationWhole')),
         'only genuine historical WeightedAverage default0 may remain implicit; all native nondefault modes require actual setter')
    sampler_route = gpu_product['nativeTaskPort']['nativeSamplerReduction']
    sampler_bind = gpu_product['nativeTaskPort']['actualAddedSamplerAuthenticatedBind']
    sampler_import = gpu_product['nativeTaskPort']['actualAddedSamplerImport']
    need(sampler_route['callRVA'] == 0x44e98 and sampler_route['returnRVA'] == 0x44e9c and
         sampler_route['stubRVA'] == 0x8e650 and sampler_route['slotRVA'] == 0x920f8 and
         sampler_route['importIndex'] == 187 and sampler_route['properThreeArgumentABI'] is True and
         sampler_route['missingSetterOnlyWeightedAverageZero'] is True and
         sampler_import['index'] == 187 and sampler_import['ordinal'] == 2 and
         sampler_import['name'] == '_VM27OwnedGPUTaskSetSamplerReductionModeV1' and
         not sampler_import['weak'] and sampler_import['addend'] == 0 and
         sampler_bind['fileoff'] == 0x920f8 and sampler_bind['index'] == 187 and
         sampler_bind['auth'] == sampler_bind['addrdiv'] == 1 and sampler_bind['key'] == 0 and
         sampler_bind['diversity'] == 0 and sampler_bind['pointerFormat'] == 12 and
         gpu_product['nativeTaskPort']['observerAuthSlotOnlyNextChangedToSampler'] is True,
         'proper new sampler Cstub and authenticated bind; old PSO auth/index remains intact except next link')
    signal = gpu_source_plan['metalContract']['nativeCommandBufferLifecycleObserverV1']
    need(signal['exactNativeCallRVA'] == 0x2d438 and signal['exactNativeReturnRVA'] == 0x2d43c and
         signal['newCStubRVA'] == 0x8e660 and signal['newSlotRVA'] == 0x92100 and
         signal['newImportIndex'] == 188 and signal['firstEightBuffersOnly'] is False and
         signal['firstEightAndPowersOfTwoThrough'] == 1048576 and
         signal['maximumDetailedLifecycleBuffers'] == 25 and
         signal['maximumActualErrorDetailedCallbacks'] == 8 and
         signal['selectedTwoSecondReadOnlySnapshotsMaximum'] == 25 and
         signal['snapshotDelayNanoseconds'] == 2000000000 and
         signal['nativePublicSignalSelector'] == 'encodeSignalEvent:value:' and
         signal['eventWrites'] == 0 and
         all(signal[k] is True for k in ('properStandaloneFourArgumentABI',
             'sameActualEventValueAndNativeCallOnce', 'originalPrivateSchedulingEquivalenceNotClaimed',
             'nativeScheduledAndCompletedCallbacksOnly', 'callbackUsesActualNativeBufferParameter',
             'actualStatusAndNSErrorAndSharedEventCounterReadOnly',
             'callbackExpectedBufferStoredAsIntegerAvoidingRetainCycle', 'noCPUCounterSignal',
             'noFakeCompletion', 'originalCommitAndCompletedHandlerAndCounterStoreWhole',
             'allDiagnosticBuffersInNoInlineHelper', 'adapterContainsNoLargeLocalArrays',
             'errnoRestoredForObserverAndActualPublicSignal', 'allBuffersHaveActualCompletedHandler',
             'unselectedSuccessfulCallbacksOnlyReadNativeStatus',
             'unselectedNonErrorCallbacksDoNotReadNSErrorOrEvent',
             'errorStatusMustBeActualNativeMTLCommandBufferStatusError',
             'errnoRestoredForEveryCompletedObserver',
             'snapshotUsesExternalDispatchBlockTemporaryRetainNoCBReferenceCycle',
             'snapshotDoesNotClaimOriginalCommitExecutionByTimerAlone')),
         'bounded real early/late native lifecycle callbacks and two-second snapshots; no event writes or fabricated completion')
    signal_route = gpu_product['nativeTaskPort']['nativeSignalLifecycleObserver']
    signal_import = gpu_product['nativeTaskPort']['actualAddedSignalImport']
    signal_bind = gpu_product['nativeTaskPort']['actualAddedSignalAuthenticatedBind']
    ordered = gpu_product['nativeTaskPort']['nativeOrderedEventSignal']
    observer_bind = gpu_product['nativeTaskPort']['actualAddedAuthenticatedBind']
    need(gpu_product['actualCurrentTaskImportRows'] == 192 and
         gpu_product['nativeTaskPort']['nativeImports'] == 192 and
         gpu_product['nativeTaskPort']['exactChangedInstructionWordCount'] == 19 and
         signal_route['callRVA'] == 0x2d438 and signal_route['returnRVA'] == 0x2d43c and
         signal_route['stubRVA'] == 0x8e660 and signal_route['slotRVA'] == 0x92100 and
         signal_route['importIndex'] == 188 and signal_route['properFourArgumentABI'] is True and
         signal_route['actualNativeSignalOnce'] is True and signal_route['eventWrites'] == 0 and
         signal_route['firstEightAndPowersOfTwoThrough'] == 1048576 and
         signal_route['maximumDetailedLifecycleBuffers'] == 25 and
         signal_route['allBuffersActualCompletedObserver'] is True and
         signal_route['maximumDetailedNativeErrors'] == 8 and
         ordered['actualTarget'] == 0x8e660 and ordered['properFourArgumentABI'] is True and
         ordered['realPublicSignalSelector'] == 'encodeSignalEvent:value:' and
         ordered['realPublicSignalCalledOnce'] is True and ordered['originalCommitWhole'] is True and
         signal_import['index'] == 188 and signal_import['ordinal'] == 2 and
         signal_import['name'] == '_VM27OwnedGPUTaskObserveSignalEventV1' and
         not signal_import['weak'] and signal_import['addend'] == 0 and
         signal_bind['fileoff'] == 0x92100 and signal_bind['index'] == 188 and
         signal_bind['auth'] == signal_bind['addrdiv'] == 1 and signal_bind['key'] == 0 and
         signal_bind['diversity'] == 0 and signal_bind['pointerFormat'] == 12 and
         signal_bind['word'] == 0xc0090000000000bc and
         sampler_bind['word'] == 0xc0090000000000bb and
         observer_bind['word'] == 0xc0090000000000ba and
         gpu_product['nativeTaskPort']['samplerAuthSlotOnlyNextChangedToSignal'] is True,
         'proper signal188 import/stub/next-to-token; existing PSO186 and sampler187 auth/index retained')
    token = gpu_source_plan['metalContract']['nativeTokenCompletionObserverV1']
    token_route = gpu_product['nativeTaskPort']['nativeTokenSendObserver']
    token_import = gpu_product['nativeTaskPort']['actualAddedTokenImport']
    token_bind = gpu_product['nativeTaskPort']['actualAddedTokenAuthenticatedBind']
    need(token['exactCallRVAs'] == [0x2d8fc, 0x2da98] and
         token['exactReturnRVAs'] == [0x2d900, 0x2da9c] and
         token['newCStubRVA'] == 0x8e670 and token['newSlotRVA'] == 0x92108 and
         token['newImportIndex'] == 189 and token['originalTailBranchRVA'] == 0x2daf4 and
         token['originalSelector'] == 'completeAsyncTokenID:success:error:' and
         token['actualNativeProtocol'] == 'ParavirtualizedGraphicsGPUDeviceProtocol' and
         token['actualProtocolMethodEncoding'] == 'v36@0:8Q16I24@28' and
         token['maxFirstOperationSamples'] == 16 and token['powersOfTwoThrough'] == 1048576 and
         token['maxDetailedSelectedSamples'] == 32 and token['maxAdditionalActualErrorSamples'] == 8 and
         token['stages'] == ['before-forward', 'after-forward'] and
         all(token[k] is True for k in
             ('properStandaloneFiveArgumentABI', 'dynamicProxyConcreteIMPNotRequired',
              'originalTailBranchWhole', 'originalNativeForwardExactlyOnce',
              'originalExceptionsPropagate', 'incomingAndNativeErrnoPreserved',
              'originalNSErrorIdentityAndTokenAndResultUnchanged',
              'largeNSErrorBuffersOnlyInNoInlineHelper', 'callerCaptureBeforeAnyLinkRequiresCompiledInspection',
              'noEventTokenStampOrCompletionWrites')) and
         token_route['callRVAs'] == [0x2d8fc, 0x2da98] and
         token_route['returnRVAs'] == [0x2d900, 0x2da9c] and
         token_route['stubRVA'] == 0x8e670 and token_route['slotRVA'] == 0x92108 and
         token_route['importIndex'] == 189 and token_route['properFiveArgumentABI'] is True and
         token_route['originalTailBranchRVA'] == 0x2daf4 and token_route['originalTailBranchWhole'] is True and
         token_route['nativeForwardOnce'] is True and
         token_import['index'] == 189 and token_import['ordinal'] == 2 and
         token_import['name'] == '_VM27OwnedGPUTaskObserveCompleteAsyncTokenV1' and
         not token_import['weak'] and token_import['addend'] == 0 and
         token_bind['fileoff'] == 0x92108 and token_bind['index'] == 189 and
         token_bind['auth'] == token_bind['addrdiv'] == 1 and token_bind['key'] == 0 and
         token_bind['diversity'] == 0 and token_bind['pointerFormat'] == 12 and
         token_bind['word'] == 0xc0090000000000bd and
         gpu_product['nativeTaskPort']['signalAuthSlotOnlyNextChangedToToken'] is True,
         'proper five-argument token189 route and next-to-paging; dynamic NSXPC protocol ABI and untouched original writeback tail')
    paging = gpu_source_plan['metalContract']['nativePagingCommandBufferObserverV1']
    paging_route = gpu_product['nativeTaskPort']['nativePagingCommitObserver']
    paging_import = gpu_product['nativeTaskPort']['actualAddedPagingImport']
    paging_bind = gpu_product['nativeTaskPort']['actualAddedPagingAuthenticatedBind']
    need(paging['exactNativeCallRVA'] == 0x2ce88 and paging['exactNativeReturnRVA'] == 0x2ce8c and
         paging['newCStubRVA'] == 0x8e680 and paging['newSlotRVA'] == 0x92110 and
         paging['newImportIndex'] == 190 and paging['originalSelector'] == 'commit' and
         paging['firstSixteenAndPowersOfTwoThrough'] == 1048576 and
         paging['maximumDetailedLifecycleBuffers'] == 32 and
         paging['maximumAdditionalActualErrorDetailedCallbacks'] == 8 and
         paging['selectedTwoSecondReadOnlySnapshotsMaximum'] == 32 and
         paging['snapshotDelayNanoseconds'] == 2000000000 and
         paging['stages'] == ['before-commit','after-commit','scheduled','completed','completed-error','after-native-commit-delay'] and
         all(paging[k] is True for k in
             ('properStandaloneTwoArgumentVoidABI', 'originalNativeCommitExactlyOnce',
              'originalNilReceiverPreserved', 'noCommandBufferManufactured',
              'originalCommandBufferCreationAndAutoreleaseOwnershipWhole',
              'originalNativeWaitEventAndValueWhole', 'originalResourceSyncEncodersWhole',
              'originalWritebackCompletedHandlerPreservedFromActualGPU20',
              'originalCompletedHandlerNotReplaced', 'originalTokenObserverAndTailRoutesWhole',
              'originalExceptionsPropagate', 'incomingAndNativeErrnoPreserved',
              'nativeScheduledAndCompletedCallbacksOnly', 'callbackUsesActualNativeBufferParameter',
              'actualNativeStatusAndNSErrorReadOnly', 'nilReceiverReportedWithoutStatusClaim',
              'callbackExpectedBufferStoredAsIntegerAvoidingRetainCycle',
              'snapshotUsesExternalDispatchBlockTemporaryRetainNoCBReferenceCycle',
              'snapshotDoesNotProveOriginalCallbackExecution', 'largeNSErrorBuffersOnlyInNoInlineHelper',
              'callerCaptureBeforeAnyLinkRequiresCompiledInspection', 'noEventTokenStampOrCompletionWrites',
              'noBlockRuntimeAdaptation')) and
         paging_route['callRVA'] == 0x2ce88 and paging_route['returnRVA'] == 0x2ce8c and
         paging_route['stubRVA'] == 0x8e680 and paging_route['slotRVA'] == 0x92110 and
         paging_route['importIndex'] == 190 and paging_route['properTwoArgumentVoidABI'] is True and
         paging_route['nativeCommitOnce'] is True and paging_route['originalNilReceiverPreserved'] is True and
         paging_route['originalCommandBufferCreationAndAutoreleaseOwnershipWhole'] is True and
         paging_route['originalWritebackCompletedHandlerWhole'] is True and
         paging_import['index'] == 190 and paging_import['ordinal'] == 2 and
         paging_import['name'] == '_VM27OwnedGPUTaskObservePagingCommitV1' and
         not paging_import['weak'] and paging_import['addend'] == 0 and
         paging_bind['fileoff'] == 0x92110 and paging_bind['index'] == 190 and
         paging_bind['auth'] == paging_bind['addrdiv'] == 1 and paging_bind['key'] == 0 and
         paging_bind['diversity'] == 0 and paging_bind['pointerFormat'] == 12 and
         paging_bind['word'] == 0xc0090000000000be and
         gpu_product['nativeTaskPort']['tokenAuthSlotOnlyNextChangedToPaging'] is True,
         'proper void two-argument paging190 observer; genuine nil/commit/creation/callback ownership preserved')
    ordinary = gpu_source_plan['metalContract']['nativeOrdinaryTextureManagedToSharedV1']
    ordinary_route = gpu_product['nativeTaskPort']['nativeOrdinaryTextureAllocation']
    ordinary_import = gpu_product['nativeTaskPort']['actualAddedOrdinaryTextureImport']
    ordinary_bind = gpu_product['nativeTaskPort']['actualAddedOrdinaryTextureAuthenticatedBind']
    need(ordinary['exactNativeCallRVAs'] == [0x47a60,0x4809c,0x4aa28,0x4af3c] and
         ordinary['exactNativeReturnRVAs'] == [0x47a64,0x480a0,0x4aa2c,0x4af40] and
         ordinary['newCStubRVA'] == 0x8e690 and ordinary['newSlotRVA'] == 0x92118 and
         ordinary['newImportIndex'] == 191 and ordinary['nativeSelector'] == 'newTextureWithDescriptor:' and
         all(ordinary[k] is True for k in ('properStandaloneThreeArgumentABI','requiresActualNativeHasUnifiedMemoryTrue','hasUnifiedMemoryBOrCTwoArgumentABIChecked','onlyManagedStorageModeOneConvertsToSharedZero','callerDescriptorNotMutated','copiedDescriptorAllOtherFieldsRetained','allOtherResourceOptionsBitsMustRemainExact','onlyNativeTextureAllocationOnce','nativeNilOrFailureRetained','nativeReturnedPlusOneNoAdditionalRetain','originalExceptionsPropagate','incomingAndNativeErrnoPreserved','noGlobalClassMutation','noValidationDisabled','allFourOriginalDirectOrdinaryCallsRouted','nativeHeapOffsetAndBufferTextureAPIsWhole','allMetal13SourceBytesWholePrefix','allPriorNativeBusinessCallsWhole','pagingAuthSlotOnlyNextChangedToOrdinary','callerCaptureBeforeAnyLinkRequiresCompiledInspection')) and
         ordinary_route['callRVAs'] == ordinary['exactNativeCallRVAs'] and
         ordinary_route['returnRVAs'] == ordinary['exactNativeReturnRVAs'] and
         ordinary_route['stubRVA'] == 0x8e690 and ordinary_route['slotRVA'] == 0x92118 and
         ordinary_route['importIndex'] == 191 and ordinary_route['properThreeArgumentABI'] is True and
         ordinary_route['nativeAllocationOnce'] is True and ordinary_route['nativeReturnedPlusOneUnchanged'] is True and
         ordinary_route['allFourOriginalDirectCallsRouted'] is True and
         ordinary_import['name'] == '_VM27OwnedGPUTaskNewTextureV1' and ordinary_import['index'] == 191 and
         ordinary_import['ordinal'] == 2 and not ordinary_import['weak'] and ordinary_import['addend'] == 0 and
         ordinary_bind['fileoff'] == 0x92118 and ordinary_bind['index'] == 191 and
         ordinary_bind['auth'] == ordinary_bind['addrdiv'] == 1 and ordinary_bind['key'] == ordinary_bind['diversity'] == 0 and
         ordinary_bind['pointerFormat'] == 12 and ordinary_bind['word'] == 0xc0010000000000bf and
         gpu_product['nativeTaskPort']['pagingAuthSlotOnlyNextChangedToOrdinary'] is True,
         'proper ordinary-texture import191: four exact native calls, real unified-memory conversion, native once/+1')
    task_raw = base.exact(gpu_product['task']).read_bytes()
    need(struct.unpack_from('<4I', task_raw, 0x8e640) == (0x90000031,0x9103c231,0xf9400230,0xd71f0a11) and
         struct.unpack_from('<4I', task_raw, 0x8e650) == (0x90000031,0x9103e231,0xf9400230,0xd71f0a11) and
         struct.unpack_from('<4I', task_raw, 0x8e660) == (0x90000031,0x91040231,0xf9400230,0xd71f0a11) and
         struct.unpack_from('<4I', task_raw, 0x8e670) == (0x90000031,0x91042231,0xf9400230,0xd71f0a11) and
         struct.unpack_from('<4I', task_raw, 0x8e680) == (0x90000031,0x91044231,0xf9400230,0xd71f0a11) and
         struct.unpack_from('<4I', task_raw, 0x8e690) == (0x90000031,0x91046231,0xf9400230,0xd71f0a11) and
         struct.unpack_from('<6Q', task_raw, 0x920f0) ==
             (0xc0090000000000ba,0xc0090000000000bb,0xc0090000000000bc,0xc0090000000000bd,0xc0090000000000be,0xc0010000000000bf) and
         struct.unpack_from('<I', task_raw, 0x2d8fc)[0] == 0x94000000 | ((0x8e670-0x2d8fc)//4) and
         struct.unpack_from('<I', task_raw, 0x2da98)[0] == 0x94000000 | ((0x8e670-0x2da98)//4) and
         struct.unpack_from('<I', task_raw, 0x2daf4)[0] == 0x1400ed63 and
         struct.unpack_from('<I', task_raw, 0x2ce88)[0] == 0x94000000 | ((0x8e680-0x2ce88)//4) and
         all(struct.unpack_from('<I',task_raw,site)[0] == 0x94000000 | ((0x8e690-site)//4) for site in (0x47a60,0x4809c,0x4aa28,0x4af3c)),
         'actual signed task distinct tail stubs and precise authenticated chain bytes')
    signature_pin = runtime['signatureVerification']
    signature = json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True, 'actual runtime signature pages and slots')
    base.exact(runtime['manifest']) # Actual runtime binary-plist anchor manifest.
    manifest_path = runtime_path.parent/'manifest.json' # Builder's signed-file metadata JSON.
    manifest = json.loads(manifest_path.read_bytes())
    cds = {'runtime/'+row['path']:row['cdhash'] for row in manifest['files'] if row['kind'] == 'mach-o'}
    signature_rows = {'runtime/'+row['relativePath']:row for row in signature['actualSignedFiles']}
    need(set(cds) == set(signature_rows) and all(signature_rows[name]['cdhash'] == value and
         signature_rows[name]['allPrimaryPagesAndSpecialSlotsVerified'] is True for name,value in cds.items()),
         'each actual new runtime manifest Mach-O joins its actual complete signature proof')
    prior_runtime=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    prior_signature=json.loads(base.exact(prior_runtime['signatureVerification']).read_bytes())
    prior_signature_rows={row['relativePath']:row for row in prior_signature['actualSignedFiles']}
    need(prior_runtime['baselineRuntimeCandidate']==runtime['baselineRuntimeCandidate'], 'new and previous runtimes both use true historical R86 assembly baseline')
    task_relative=GPU_REL
    entitlement_changes=[]
    need(set(prior_signature_rows)=={row['relativePath']for row in signature['actualSignedFiles']},
         'same actual145 runtime signed paths before exact whole-entitlement comparison')
    for row in signature['actualSignedFiles']:
        original=prior_signature_rows[row['relativePath']]
        before=original.get('embeddedEntitlements');after=row.get('embeddedEntitlements')
        need(after==before, 'every runtime image entitlement set whole installed previous runtime')
        if row['relativePath']==task_relative:
            need(isinstance(after,dict) and len(after)==9 and after.get(EXTENDED_VA_KEY)is True and
                 after.get('com.apple.private.security.no-container')is True and
                 after.get('com.apple.private.security.no-sandbox')is True and
                 after.get('com.apple.private.amfi.can-execute-cdhash')is True,
                 'actual GPU Task nine permissions including proven extended VA remain whole')
    need(entitlement_changes==[], 'no runtime entitlement change')
    sig = app['actualSignature']; old_sig = previous_app['actualSignature']
    need(re.fullmatch('[0-9a-f]{40}', sig['cdhash']) is not None and
         sig['embeddedEntitlements'] == old_sig['embeddedEntitlements'] and
         sig['actualPlatform'] == old_sig['actualPlatform'], 'one actual Main CD; no permission/platform change')
    app_root = pathlib.Path(app['app'])
    base.regular_tree(app_root)
    actual_names = {MAIN.rsplit('/', 1)[0]+'/'+p.relative_to(app_root).as_posix()
                    for p in app_root.rglob('*') if p.is_file()}
    old_rows = {row['archivePath']: row for row in old['files']}
    need(actual_names == {name for name in old_rows if name.startswith('VirtualMacIndependent27.app/')},
         'exact same104 ordinary App file paths')
    app_dirs = {'VirtualMacIndependent27.app'} | {'VirtualMacIndependent27.app/'+p.relative_to(app_root).as_posix()
                                                for p in app_root.rglob('*') if p.is_dir()}
    need(app_dirs == {name for name in old['directories'] if name == 'VirtualMacIndependent27.app' or
                     name.startswith('VirtualMacIndependent27.app/')}, 'exact existing App directories')
    files = []; changes = []; directories = dict(old['directories']); runtime_root = pathlib.Path(runtime['runtimeRoot'])
    base.regular_tree(runtime_root)
    roots = [(runtime_root,'runtime'),(app_root,'VirtualMacIndependent27.app')]
    for root, top in roots:
        for path in sorted(root.rglob('*')):
            name = top+'/'+path.relative_to(root).as_posix()
            if path.is_dir():
                directories[name] = old['directories'].get(name,0o700 if top=='runtime' else 0o755)
                continue
            original = old_rows.get(name); local = pin(path)
            mode = original['mode'] if original else 0o700 if name in cds else 0o600
            device = (old['deviceRuntime'] if top=='runtime' else old['deviceApp'])+'/'+path.relative_to(root).as_posix()
            row = dict(archivePath=name,devicePath=device,mode=mode,local=local)
            if name in cds:
                row['cdhash'] = cds[name]
                need(local == signature_rows[name]['actualSignedFile'], 'every runtime signed file joins actual signature')
            elif name == MAIN:
                need(local == sig['file'], 'actual signed Main joins signature'); row['cdhash'] = sig['cdhash']
            elif top != 'runtime':
                need(original is not None and local['bytes']==original['local']['bytes'] and local['sha256']==original['local']['sha256'], 'all103 App resources whole')
            if original is None or local['sha256'] != original['local']['sha256']:
                changes.append(dict(index=len(changes),archivePath=name,devicePath=device,mode=mode,
                    old=original['local'] if original else None,new=local,newResource=original is None))
            files.append(row)
    need(set(old_rows) <= {r['archivePath'] for r in files}, 'no installed file deletion')
    new_dirs = [dict(archivePath=name,devicePath=old['deviceRuntime']+name[len('runtime'):],mode=directories[name])
                for name in sorted(set(directories)-set(old['directories']),key=lambda n:(n.count('/'),n))]
    need(new_dirs==[] and set(old_rows)=={r['archivePath']for r in files}, 'all265 installed paths/modes/directories remain; no additions/deletions')
    change = next(row for row in changes if row['archivePath']==MAIN)
    full = sorted(row['cdhash'] for row in files if 'cdhash' in row)
    new_cd = sorted(set(full)-set(old['trustCacheCDHashes']))
    runtime_files = [row for row in files if row['archivePath'].startswith('runtime/')]
    runtime_cd_count = sum('cdhash' in row for row in runtime_files)
    manifest_rows = {row['id']:row for row in manifest['files']}
    changed_ids={'child:MD',manifest['childEntryContract']['childID'],'child-coderesources',manifest['dependencyProofID'],'gpu-task:main','gpu-task:compat','gpu-task-coderesources'}
    expected_changes={MAIN}
    need(runtime_pin == old['runtimeCandidate'], 'App-only update requires exact installed Runtime102')
    pg_name='runtime/'+manifest_rows['child:ParavirtualizedGraphics27.dylib']['path']
    need(next(row for row in files if row['archivePath']==pg_name)['local']['sha256']==old_rows[pg_name]['local']['sha256'], 'actual deterministic PG signed file whole installed previous runtime')
    need(len(manifest['files'])==160 and len(files)==265 and len(full)==len(set(full))==146 and
         runtime_cd_count==145 and len(changes)==len(expected_changes) and sig['cdhash']in new_cd and
         all(row['old']is not None for row in changes)and {row['archivePath']for row in changes}==expected_changes,
         'actual same160 runtime rows/265files/146CD; only exact diagnostic product delta paths, no new paths')
    changed_cd_names={row['archivePath']for row in changes if row['archivePath']in {f['archivePath']for f in files if 'cdhash'in f}}
    actual_new_cd_by_changed_files={row['cdhash']for row in files if row['archivePath']in changed_cd_names}-set(old['trustCacheCDHashes'])
    need(set(new_cd)==actual_new_cd_by_changed_files and len(new_cd)==len(changed_cd_names),
         'new TC membership/count derived from actual changed signed files, not predicted nine/five counts')
    old_code_names = {row['cdhash']:row['archivePath'] for row in old['files'] if 'cdhash' in row}
    new_code_hashes = {row['archivePath']:row['cdhash'] for row in files if 'cdhash' in row}
    native_subset = [new_code_hashes[old_code_names[value]] for value in old['actualNativeCDSubset']]
    scope = {key: copy.deepcopy(old[key]) for key in ('deviceRuntime', 'deviceApp', 'deviceAppMain', 'deviceChildMain',
             'directories', 'continuingHumanAuthorization', 'sandboxProfileApplied', 'nativeSandboxApplyUnavailable',
             'nativeSandboxInitSuccessFabricated', 'fixedOwnedLogIdentity', 'bootSeconds', 'bootMicroseconds', 'bootSessionUUID')
             if key in old}
    scope.update(schema='Actual exact App-only Main36 explicit live diagnostic SSH successor scope v15',packetName=out.name,
        oldScope=pin(OLD/'scope.json'), currentInstalledProductsPost=pin(POST), oldActualPost=pin(POST),
        baselinePreviousInitializationSucceeded=True,
        baselinePreviousAllSevenActionsSucceeded=True,
        baselineInstalledProductsHealthProvenByActualCurrentPost=True,
        precedingNormalStop=preceding_stop, currentInstalledPostKind=post_kind,
        baselineControllerInheritedFromPreviousPacket=True,
        deviceStage=STAGE, files=files, directories=directories, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        actualPreviousRuntimeVerification=dict(deviceCandidate=pin(OLD/'candidate.json'),scope=pin(OLD/'scope.json'),freeze=pin(OLD/'freeze.json'),runtimeCandidate=old['runtimeCandidate']),
        actualPreviousAppCandidate=old['appCandidate'], inheritedPreviousAppCompiledSource=source['inheritedCompiledAppCandidate'],
        actualAll29CPUObjectsWholeRuntime86=True, actualChangedCPUObjects=0, actualUnchangedCPUObjects=29,
        inheritedActualSignedRuntimeCDProof=signature_pin,
        actualRuntime102AndAll34OtherCompiledAppObjectsWhole=True, actualChangedAppObjectIndices=[8], actualOnlyRelinkedRuntimeAnchor=False,
        actualUnchangedCompiledObjects=34, actualNewAppCompilations=1,
        ownedPGRemoteTaskParentTransportV1Contract=runtime['ownedPGRemoteTaskParentTransportV1Contract'],
        callbacksInterposedButSemanticsWhole=True, scopedOnlyExactOwnedPGInstanceMethodObservation=True, noFoundationOrMetalClassMutation=True,
        nativeOwnedGPUTaskProduct=runtime['nativeOwnedGPUTaskProduct'],
        nativeOwnedGPUTaskSourcePlan=runtime['nativeOwnedGPUTaskSourcePlan'],
        nativeOrdinaryTextureManagedToSharedV1Contract=gpu_source_plan['metalContract']['nativeOrdinaryTextureManagedToSharedV1'],
        nativePagingCommandBufferObserverV1Contract=gpu_source_plan['metalContract']['nativePagingCommandBufferObserverV1'],
        softwareKeyboardAndOptionalQGADiagnosticV1Contract=inherited_source['softwareKeyboardAndOptionalQGADiagnosticV1Contract'],
        gpuTaskExecutableRelativePath=GPU_REL, ownGPUHelperMustBeAbsentAfterParentCleanup=True,
        trustCacheCDHashes=full, newTrustCacheCDHashes=new_cd, trustCacheRegistrationCount=len(new_cd),
        trustCacheFixedBatchCounts=[len(new_cd)], actualFullCodeDirectoryHashes=len(full),
        actualRuntimeManifestFiles=len(manifest['files']), actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count,
        deltaFiles=changes, existingOwnFilesUpdated=sum(r['old'] is not None for r in changes), actualChangedFiles=len(changes),
        unchangedFiles=len(files)-len(changes), unchangedSignedImages=len(full)-len(new_cd),
        newOwnFilesAdded=0, newOwnDirectories=new_dirs, newOwnResourceFiles=[r['archivePath'] for r in changes if r['old'] is None],
        runtimeAllWholebytesUnchanged=True, runtimeProductAndAllFilesWholeUnchanged=True,
        originalMainAppResourcesAllWholebytesUnchanged=True,
        all265ExistingDevicePathsModesAndDirectoriesSame=True, backupOldOwnFilesAndLog=True,
        missingOwnLogMayBeCreated=False, cleanupRequiresExactPIDUIDPathPPIDAndStartTimeHash=True,
        initializationExternalWallSeconds=45, currentAppCloseExternalWallSeconds=20, updateExternalWallSeconds=90,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        nonStageTransportTimeoutSeconds=55, nonStageNonCloseExternalWallSeconds=45,
        actualNativeCDSubset=native_subset, actualNativeCDSubsetCount=len(native_subset),
        actualNativeCDsQueriedThisDelta=new_cd, actualNativeCDsQueriedThisDeltaCount=len(new_cd),
        actualFullCodeTrustMembershipVerifiedAfterAddRequired=True, trustMembershipKnownBeforeDispatch=False,
        trustCacheMayRemainUntilReboot=True, perPIDKernelPrivilegeModification=False,
        deviceSystemFilesModified=False, systemSandboxFilesModified=False, noExistingImagePermissionsChanged=True, onlyGPUProductAndSignedParentPinsChanged=False, onlyAppMainChanged=True, actualRuntimeEntitlementChanges=entitlement_changes, all146RuntimeAndAppEntitlementsWholePreviousProducts=True, noNewCPUOrHVPermissions=True,
        initializationOnly=False, productInstallationPerformed=False, productUpdatesPlanned=True,
        productUpdatesPerformed=False, guestBootRequested=False, guestSSHDeferredUntilAfterBasicGuestBoot=True,
        deviceOperations=0, trustCacheOperations=0, readyForDeviceExecution=False)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for changed in changes:
            data = base.exact(changed['new']).read_bytes(); item = tarfile.TarInfo('new-'+str(changed['index']))
            item.uid = item.gid = item.mtime = 0; item.mode = 0o600; item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    archive = stream.getvalue()
    scope.update(deltaArchiveBytes=len(archive), deltaArchiveSHA256=base.digest(archive),
                 archive=dict(path=str(out/'products.tar'), bytes=len(archive), sha256=base.digest(archive)))
    base.DEVICE_STAGE = STAGE
    wrap = lambda body, uid, seconds=45: base.prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    scripts = {}; operations = {}; before = fast.batch_check(old); after = fast.batch_check(scope)
    old_before = fast.batch_check(json.loads(base.exact(old['oldScope']).read_bytes()))
    main_cd = fast.cd_check(scope, [sig['cdhash']])
    all_new_cds = fast.cd_check(scope, new_cd)

    def inherited(action):
        raw = (OLD/(action+'.sh')).read_text()
        need(old['deviceStage'] in raw, 'actual previous packet action stage identity')
        return raw.replace(old['deviceStage'], STAGE)

    def replace_once(body, before_value, after_value, reason):
        need(body.count(before_value) == 1, 'one exact previous packet block: '+reason)
        operations.setdefault(action, []).append(dict(reason=reason, beforeBytes=len(before_value.encode()),
            beforeSHA256=base.digest(before_value.encode()), afterBytes=len(after_value.encode()),
            afterSHA256=base.digest(after_value.encode())))
        return body.replace(before_value, after_value, 1)

    for action in ('close-current-own', 'preflight', 'verify', 'trust', 'launch', 'post'):
        raw = inherited(action)
        if action == 'close-current-own':
            scripts[action]=raw; operations[action]=[dict(reason='stage identity only; original precise cleanup and GPU absence gates whole')]; continue
        body = unwrap(raw)
        need(rewrap(raw, body) == raw,
             'actual previous packet outer wrapper byte-whole after stage substitution: '+action)
        # Only the nested UI-close guard changes here, never batch SHA rows.
        guard_lines = [line for line in body.splitlines()
                       if 'sha256sum "$OWN_APP_MAIN"' in line]
        expected_count = 1 if action in ('preflight', 'verify', 'trust', 'launch') else 0
        need(len(guard_lines) == expected_count, 'exact captured nested Main guard count: '+action)
        if expected_count:
            previous_main = next(item['old'] for item in old['deltaFiles'] if item['archivePath'] == MAIN)
            expected = previous_main if action == 'preflight' else old_rows[MAIN]['local']
            target = old_rows[MAIN]['local'] if action == 'preflight' else change['new']
            metadata = f'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_APP_MAIN")" = 501:501:{change["mode"]:o}:1:{expected["bytes"]} ] || exit 8'
            sha_line = guard_lines[0]
            need(sha_line.count(expected['sha256']) == 1 and
                 sha_line.endswith(' = '+expected['sha256']+' ] || exit 8'),
                 'one exact expected nested Main SHA guard: '+action)
            guard = metadata+'\n'+sha_line+'\n'
            replacement = (metadata.replace(':'+str(expected['bytes'])+' ]', ':'+str(target['bytes'])+' ]')+
                           '\n'+sha_line.replace(expected['sha256'], target['sha256'])+'\n')
            body = replace_once(body, guard, replacement, 'nested UI-close Main metadata/SHA binding only')
        body = replace_once(body, old_before if action == 'preflight' else before,
                            before if action == 'preflight' else after, 'actual full-product batch')
        if action == 'verify':
            body = replace_once(body, fast.cd_check(old, old['actualNativeCDsQueriedThisDelta']), all_new_cds,
                                'all actual changed native CD queries')
            body = body.replace('ALL_SHA_AND'+str(len(old['actualNativeCDsQueriedThisDelta']))+'_NATIVE_CD_EXACT',
                                'ALL_SHA_AND'+str(len(new_cd))+'_NATIVE_CD_EXACT')
        elif action in ('launch', 'post'):
            body = replace_once(body, fast.cd_check(old, [old_rows[MAIN]['cdhash']]), main_cd, 'new Main native CD query')
        elif action == 'trust':
            at = body.index('(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")')
            old_tail = body[at:]
            need(old_tail.count(trust_check(old['trustCacheCDHashes'])) == 1 and
                 re.findall(r'^jbctl trustcache add ([0-9a-f]{40})$', old_tail, re.M) == old['newTrustCacheCDHashes'],
                 'exact executed previous packet trust adds and whole membership parser')
            tail = '(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
            for index,value in enumerate(new_cd, 1):
                tail += 'jbctl trustcache add '+value+"\nprintf 'OWN_NEW_PRODUCT_TC_ADDED "+str(index)+' '+value+"\\n'\n"
            tail += trust_check(full)+"printf 'INDEPENDENT27_ONLY_ACTUAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE\\n'\n"
            body = replace_once(body, old_tail, tail, 'actual new trust adds and exact all146 actual membership')
        scripts[action] = rewrap(raw, body)
    scripts['stage'] = wrap(stage_body(scope, archive), 0, 90)
    actions = list(base.ACTIONS); scripts = {action: scripts[action] for action in actions}
    controller = (OLD/'control.py').read_text().replace(old['deviceStage'], STAGE)
    need(controller.replace(STAGE, old['deviceStage']) == (OLD/'control.py').read_text(),
         'previous packet controller protocol/ready/auth/once/cleanup byte-whole except stage name')
    compile(controller, str(out/'control.py'), 'exec')
    out.mkdir(mode=0o700); (out/'control.py').write_text(controller); (out/'products.tar').write_bytes(archive)
    (out/'health-root.sh').write_bytes((OLD/'health-root.sh').read_bytes()); dump(out/'scope.json', scope)
    rows = {}; sizes = {}; diff = []; unwrapped_diff = []
    for action, script in scripts.items():
        result = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True)
        need(result.returncode == 0, 'actual sh-n '+action)
        path = out/(action+'.sh'); path.write_text(script); rows[action] = pin(path)
        (out/(action+'-syntax.stderr')).write_bytes(result.stderr)
        command = ('sudo -k -S -p "" ' if action != 'launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script)
        sizes[action] = len(command.encode()); need(sizes[action]+10000 < 262144, 'ARG_MAX reserve '+action)
        diff.extend(difflib.unified_diff((OLD/(action+'.sh')).read_text().splitlines(True), script.splitlines(True),
                    fromfile=OLD.name+'/'+action+'.sh', tofile=out.name+'/'+action+'.sh'))
        unwrapped_diff.extend(difflib.unified_diff(unwrap((OLD/(action+'.sh')).read_text()).splitlines(True),
                    unwrap(script).splitlines(True), fromfile=OLD.name+'/'+action+'.body', tofile=out.name+'/'+action+'.body'))
    diff.extend(difflib.unified_diff((OLD/'control.py').read_text().splitlines(True), controller.splitlines(True),
                fromfile=OLD.name+'/control.py', tofile=out.name+'/control.py'))
    (out/'scripts-from-previous.diff').write_text(''.join(diff))
    (out/'scripts-unwrapped-from-previous.diff').write_text(''.join(unwrapped_diff))
    dump(out/'script-delta.json', dict(schema='Exact previous GPU packet to successor finite script delta v1',
         baseline=pin(OLD/'candidate.json'), baselineScope=pin(OLD/'scope.json'),
         controllerBefore=pin(OLD/'control.py'), controllerAfter=pin(out/'control.py'),
         controllerOnlyStageNameChanged=True, closeOnlyStageNameChanged=False, originalCloseSignalIdentityProtocolWhole=True,
         samePreviousTimeoutsAndProcessProtocol=True, transformations=operations,
         stageGeneratedFrom='Executed previous packet bounded stage and exact backup/pending/rename/log protocol',
         stageOnlyListedOwnedDeltaFilesAndExistingLogWritten=True,
         fullActualScriptsDiff=pin(out/'scripts-from-previous.diff'),
         fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-previous.diff'),
         scriptPairs={action:dict(before=pin(OLD/(action+'.sh')), after=rows[action]) for action in actions}))
    candidate = dict(schema='Actual exact GPU-only successor device packet v1',packetName=out.name, preparer=pin(__file__),
        scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'), scripts=rows,
        actions=actions, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        currentInstalledProductsPost=pin(POST), oldDeviceCandidate=pin(OLD/'candidate.json'),
        scriptDelta=pin(out/'script-delta.json'), fullActualScriptsDiff=pin(out/'scripts-from-previous.diff'),
        fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-previous.diff'),
        actualFullFiles=len(files), actualFullCodeDirectoryHashes=len(full), actualChangedFiles=len(changes), actualExistingFilesUpdated=sum(r['old'] is not None for r in changes),
        actualNewFilesAdded=0, actualNewDirectoriesAdded=len(new_dirs), actualNewTrustEntries=len(new_cd),
        onlyGPUProductParentIdentityAndAppAnchorChanged=False, onlyAppMainChanged=True, actualCPUCurrentSource=runtime['cpu29SourceProof'], all29CPUObjectsWholeRuntime86=True, actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count, all103AppResourcesWholeUnchanged=True,
        all265ExistingDevicePathsModesAndDirectoriesSame=True, continuingHumanAuthorization=scope['continuingHumanAuthorization'],
        bootSeconds=BOOT, bootSessionUUID=UUID, closeOwnExternalWallSeconds=20,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        allOtherRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        exactPreviousControllerOnlyStageNameChanged=True, repeatedRuntime65To66SourceAdmissionNotApplied=True,
        baselinePreviousInitializationSucceeded=True,
        baselineInstalledProductsHealthProvenByActualCurrentPost=True,
        precedingNormalStop=preceding_stop, currentInstalledPostKind=post_kind,
        newPacketRequiresAllSevenStandardActionsAndContinuingDerivedAuthorization=True,
        allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True, sameDirectoryTemporaryReplacements=True,
        originalStable2sReadinessAndProcessCleanupRetained=True, noExistingPermissionsChanged=True, onlyGPUProductAndSignedParentPinsChanged=False, noNewCPUOrHVPermissions=True,
        rootReadyAndDerivedAuthorizationNotGenerated=True, guestBootRequested=False,
        deviceOperations=0, trustCacheOperations=0, codeSigningOperations=0, readyForDeviceExecution=False)
    dump(out/'candidate.json', candidate)
    pins = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    pins += [pin(__file__), pin(B/'independent27_device_product_verify_fast_v1.py'),
             pin(OLD/'candidate.json'), pin(OLD/'scope.json'), pin(OLD/'freeze.json'), pin(OLD/'control.py'),
             pin(OLD/'health-root.sh'), old['runtimeCandidate'], old['appCandidate'],
             runtime_pin, signature_pin, pin(manifest_path),
             pin(app_path), app['sourceCandidate'], source['inheritedCompiledAppCandidate'], runtime['nativeOwnedGPUTaskProduct'], runtime['nativeOwnedGPUTaskSourcePlan'],
             scope['continuingHumanAuthorization'], pin(POST), post['request'], post['stdout'], post['stderr']]
    pins += current_post_pins + prior_receipt_pins + list(prior['scripts'].values())+[row['local'] for row in files]+[changed['old'] for changed in changes if changed['old'] is not None]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
         deviceOperations=0, codeSigningOperations=0, repeatedHistoricalSourceDeltaAdmission=False))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), scope=pin(out/'scope.json'),
         freeze=pin(out/'freeze.json'), delta=pin(out/'script-delta.json'),
         files=len(files), CDs=len(full), changedFiles=len(changes), newTC=len(new_cd), maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
