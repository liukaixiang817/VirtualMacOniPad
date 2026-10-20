#!/usr/bin/env python3
"""HOST prepare Runtime95/App115 GPU native event compatibility and pipeline error observation.

Installed baseline is actual Dev103 Runtime94/App114 and actual Normal117 post-recovery-v2=0; original post=8 is preserved.
Root alone supplies signed products and dispatches. No signing/device/ready writes.
Mature Dev103 process identity, backups, trust, initialization and controller gates
are retained; only actual listed existing files are updated; no new files or directories.
Actual recovery, GPU, Source10 and R95/App115 product pins are bound; exact CLI pins remain required.
This source was prepared without execution.
"""
import argparse
import copy
import difflib
import importlib.util
import io
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
OLD = N/'independent27-gpu-iosurface-texture-device-v103-attempt1'
EXPECTED_POST = N/'independent27-app114-normal-guest-lifecycle-v117-attempt1/device-receipts/post-recovery-v2/receipt.json'
STAGE = '/private/var/mobile/Library/.VM27-independent27-gpu-event-pipeline-stage-v105'
MAIN = 'VirtualMacIndependent27.app/VirtualMacIndependent27'
BOOT = 1792161311
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
OLD_CANDIDATE_SHA256 = 'f97f562f78dc8b318427054714bd96f5cfc0d7fbe30a3b68da9e3284724883fe'
OLD_SCOPE_SHA256 = '10e5c29db483ecae5a7f8ec7ce71e2757289bed8883a5e9eacdd1121c38c905d'
APP114_PARENT_SOURCE_SHA256 = '569bd9caab559cdead9f110fd16af3df20dc6d8f1abef9263dd9b000e031a603'
EXPECTED_POST_SHA256 = 'b9605c37ae5fc00e14e23f140d0bd6d7ab9b43e854489c64fee38b5b4c9115d9'
MAIN32_PLAN_SHA256 = '935ba7a6209cfc0fe9d4dc12939cbb0bd595a537ed2218e9f87b55cd24ed0866'
# Root supplies actual signed Runtime95/App115 and compiled App115 SHA256 pins through required CLI arguments.
INSTALLED_RUNTIME94_SHA256 = 'a6ba7667ac7753ebd5efa1cc79c843d06c23fbd2b3bef1b67e0d23a5ff82e732'
HISTORICAL_RUNTIME86_SHA256 = 'aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
RUNTIME95_CANDIDATE_SHA256 = '72eecce67a9ac0d5e25f38e9aed20f875c97f16a7631402b2a991291d6dff6e8'
APP115_CANDIDATE_SHA256 = '4f1f1eab4bc88a5ff04ca2fc0cd648460587544665452b642e6edc287b570580'
APP115_SOURCE_SHA256 = '1205dc9797769ab23a364c9a5c1d7a990d69123d20a15695600f437c59580186'
GPU_EVENT_PIPELINE_CANDIDATE_SHA256 = '01b36ebaf010d6ab1ff22e10a09da2470e277803ab08f7736dad2417acef3f5f'
GPU_EVENT_PIPELINE_SOURCE_PLAN_SHA256 = '9fbab5ab3c16014dae9e6d45b0bc3b7f3028eaf17b22a3d9935802d144cc4327'
GPU_EXPECTED_CHANGED_INSTRUCTION_WORD_COUNT = 9  # Exact Source10 native instruction proof.
EXTENDED_VA_KEY = 'com.apple.developer.kernel.extended-virtual-addressing'
LOG_ID = '16777223:48200252'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load(OLD/'control.py', 'executed_dev103_gpu_main_scope_base')
fast = load(B/'independent27_device_product_verify_fast_v1.py', 'dev103_gpu_fast')
pin, need, dump = base.pin, base.need, base.dump


def unwrap(script):
    start = script.index('/var/jb/usr/bin/timeout')
    at = script.index('/var/jb/bin/sh -c ', start)+len('/var/jb/bin/sh -c ')
    values = shlex.split(script[at:])
    need(len(values) == 1, 'one inherited bounded action')
    return values[0]


def rewrap(script, body):
    start = script.index('/var/jb/usr/bin/timeout')
    at = script.index('/var/jb/bin/sh -c ', start)+len('/var/jb/bin/sh -c ')
    need(script[at:] == shlex.quote(unwrap(script))+'\n', 'exact Dev103 single quoted body/tail')
    return script[:at]+shlex.quote(body)+'\n'


def trust_check(hashes):
    # Same exact membership parser as the executed Dev103 trust action.
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
         'one original Dev103 UI-only close Main byte/metadata guard')
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
        pending = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-gpu-event-pipeline-v105-'+str(index)+'.pending')))
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
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=pathlib.Path, required=True)
    ap.add_argument('--app-candidate', type=pathlib.Path, required=True)
    ap.add_argument('--runtime-candidate', type=pathlib.Path, required=True)
    ap.add_argument('--current-installed-post',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate-sha256', required=True)
    ap.add_argument('--app-candidate-sha256', required=True)
    ap.add_argument('--app-source-sha256', required=True)
    args = ap.parse_args()
    need(isinstance(GPU_EXPECTED_CHANGED_INSTRUCTION_WORD_COUNT, int) and
         6 <= GPU_EXPECTED_CHANGED_INSTRUCTION_WORD_COUNT <= 16,
         'Root actual native Task changed-word count must be bound before preparation')
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (RUNTIME95_CANDIDATE_SHA256, APP115_CANDIDATE_SHA256, APP115_SOURCE_SHA256,
          GPU_EVENT_PIPELINE_CANDIDATE_SHA256, GPU_EVENT_PIPELINE_SOURCE_PLAN_SHA256, EXPECTED_POST_SHA256)),
         'Root must bind actual Normal117 post and R95/App115/GPU event-pipeline/source-plan pins before preparation')
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (args.runtime_candidate_sha256, args.app_candidate_sha256, args.app_source_sha256)),
         'Root supplies actual signed Runtime95/App115 and compiled source SHA256 pins')
    need((args.runtime_candidate_sha256,args.app_candidate_sha256,args.app_source_sha256)==
         (RUNTIME95_CANDIDATE_SHA256,APP115_CANDIDATE_SHA256,APP115_SOURCE_SHA256),'exact Root signed R95/App115 and actual compiled source pins')
    POST = args.current_installed_post.resolve()
    need(POST == EXPECTED_POST.resolve() and pin(POST)['sha256'] == EXPECTED_POST_SHA256, 'only actual Normal117 post-recovery-v2 for installed Dev103 R94/App114')
    out, app_path = args.output.resolve(), args.app_candidate.resolve()
    need(out.parent == N and not out.exists(), 'fresh concrete Dev105 packet')
    need(pin(OLD/'candidate.json')['sha256'] == OLD_CANDIDATE_SHA256 and
         pin(OLD/'scope.json')['sha256'] == OLD_SCOPE_SHA256, 'exact installed Dev103 candidate/scope')
    prior = json.loads((OLD/'candidate.json').read_bytes())
    need(prior['scope'] == pin(OLD/'scope.json') and
         prior['controller'] == pin(OLD/'control.py'), 'exact executed Dev103 scope/controller')
    for row in prior['scripts'].values():
        base.exact(row)
    prior_receipt_pins=[]
    for action in prior['actions']:
        path=OLD/'device-receipts'/action/'receipt.json'
        receipt=json.loads(path.read_bytes()); request=json.loads(base.exact(receipt['request']).read_bytes())
        need(receipt['transportExit']==0 and request['packetCandidate']==pin(OLD/'candidate.json') and request['script']==prior['scripts'][action], 'actual all7 Dev103 phases '+action)
        base.exact(receipt['stdout']);base.exact(receipt['stderr'])
        prior_receipt_pins += [pin(path),receipt['request'],receipt['stdout'],receipt['stderr']]
    old = json.loads((OLD/'scope.json').read_bytes())
    need(old['bootSeconds'] == BOOT and old['bootSessionUUID'] == UUID and
         old['fixedOwnedLogIdentity'] == LOG_ID+':501:501:600:1', 'same current boot and owned log')
    post = json.loads(POST.read_bytes())
    text = base.exact(post['stdout']).read_text()
    base.exact(post['stderr']); base.exact(post['request'])
    post_request=json.loads(base.exact(post['request']).read_bytes())
    normal_packet=pin(EXPECTED_POST.parents[2]/'candidate.json')
    need(post['action']=='post-recovery' and post_request['action']=='post-recovery' and
         post_request['initializer']==pin(OLD/'candidate.json') and
         post_request['packetCandidate']==normal_packet and
         post_request['expectedOnlyRelaunchedOwnedUI']==33881 and
         post_request['externalWallSeconds']==90 and post_request['transportSeconds']==100 and
         post_request['guestBootRequested'] is False and post_request['trustCacheOperations']==0 and
         post_request['deviceProductWrites']==0 and
         post_request['source']['sha256']=='69f46c52ae9aeee38c3b03260c66d3cdc16d232a01592f41a79fe12cee5166eb',
         'actual bounded Root recovery source/request only exact self-relaunched UI33881; no product writes/guest boot')
    post_recovery_pins=[post_request['source'],post_request['script']]
    base.exact(post_request['source']);base.exact(post_request['script'])
    need(post_request['actualStop']==pin(EXPECTED_POST.parents[2]/'device-receipts/stop/receipt.json') and
         post_request['failedPost']==pin(EXPECTED_POST.parents[2]/'device-receipts/post/receipt.json'),
         'original actual stop and failed post retained without overwriting once markers')
    recovery_stop=json.loads(base.exact(post_request['actualStop']).read_bytes())
    recovery_failed=json.loads(base.exact(post_request['failedPost']).read_bytes())
    need(recovery_stop['action']=='stop' and recovery_stop['transportExit']==0 and
         recovery_failed['action']=='post' and recovery_failed['transportExit']==8,
         'actual preceding Normal117 stop0 and original post8')
    for evidence in (recovery_stop,recovery_failed):
        need(json.loads(base.exact(evidence['request']).read_bytes())['packetCandidate']==normal_packet,
             'stop and failed post bind the same actual Normal117 candidate')
        base.exact(evidence['stdout']);base.exact(evidence['stderr'])
        post_recovery_pins.extend((evidence['request'],evidence['stdout'],evidence['stderr']))
    post_recovery_pins.extend((post_request['actualStop'],post_request['failedPost']))
    need(base.exact(recovery_failed['stdout']).read_text().split()==
         ['UNEXPECTED_OWN_PROCESS','33881','1','501',old['deviceAppMain']],
         'original post8 proves only exact self-relaunched App UI33881/PPID1/UID501')
    need(post['transportExit'] == 0 and json.loads(base.exact(post['request']).read_bytes())['packetCandidate'] == pin(EXPECTED_POST.parents[2]/'candidate.json') and
         all(marker in text for marker in ('INDEPENDENT27_OWN_APP_AND_CHILD_OFF',
             'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT', 'PRODUCTION_6_CODE_HASHES_PRESERVED',
             'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF')), 'actual same-product Normal117 recovery0 baseline after retained original stop0/post8')
    base.exact(old['runtimeCandidate'])
    runtime_path = args.runtime_candidate.resolve()
    runtime_pin = pin(runtime_path)
    need(old['runtimeCandidate']['sha256'] == INSTALLED_RUNTIME94_SHA256 and
         runtime_pin['sha256'] == args.runtime_candidate_sha256 and pin(app_path)['sha256'] == args.app_candidate_sha256,
         'actual installed Runtime94 and Root actual signed Runtime95/App115 products')
    runtime = json.loads(runtime_path.read_bytes()); app = json.loads(app_path.read_bytes())
    previous_app = json.loads(base.exact(old['appCandidate']).read_bytes())
    need(app['actualCodeSigned'] is True and app['actualPrimaryPagesAndExternalSlotsVerified'] is True and
         app['runtimeCandidate'] == runtime_pin and app['runtimeRoot'] == runtime['canonicalDeviceRoot'] and
         app['actualBundleID'] == previous_app['actualBundleID'] and app['actualURLScheme'] == previous_app['actualURLScheme'],
         'actual signed App115 with Runtime95 and unchanged application identity')
    need(app['sourceCandidate']['sha256'] == args.app_source_sha256, 'actual Root-linked App115 source candidate')
    source = json.loads(base.exact(app['sourceCandidate']).read_bytes())
    need(source['inheritedCompiledAppCandidate']['sha256'] == APP114_PARENT_SOURCE_SHA256, 'actual whole App114 build is pure anchor baseline')
    inherited_source = json.loads(base.exact(source['inheritedCompiledAppCandidate']).read_bytes())
    prior_source = json.loads(base.exact(previous_app['sourceCandidate']).read_bytes())
    need(source['inheritedCompiledAppCandidate'] == previous_app['sourceCandidate'] and
         inherited_source['actualChangedAppObjectIndices'] == [34] and
         source['objects'][:34] == inherited_source['objects'][:34] and
         source['sourceFiles'][:34] == inherited_source['sourceFiles'][:34] and
         len(source['objects']) == len(source['sourceFiles']) == 35 and source['actualRuntimeCandidate'] == runtime_pin,
         'actual installed App114 retains GuestTools9/keyboard4; all34 units whole in App115 pure anchor relink')
    need(source['mainSourcePlan']['sha256'] == MAIN32_PLAN_SHA256 and
         source['mainSourceContractKey'] == 'normalBootOriginalArgsV32Contract' and
         source['sourceFiles'][0]['sha256'] == '3b3f6d3797edb88536c0609e01ec813177d64387e921e90a060b2bfdd0c6a440' and
         source['actualOriginalBootArgsRestorationCodePresent'] is True and
         source['actualChangedAppObjectIndices'] == [34] and source['actualUnchangedCompiledObjects'] == 34 and
         source['actualNewAppCompilations'] == 0 and source['all34OtherAppObjectsWholeApp114'] is True,
         'Main32 and original UART/boot arguments/display bodies remain whole; only Runtime95 anchor relinked')
    need(runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         runtime['baselineRuntimeCandidate']['sha256'] == HISTORICAL_RUNTIME86_SHA256 and runtime['nativeGPUTaskNoContainerEntitlementActuallyPresent']is True and runtime['nativeGPUTaskCanExecuteCDHashEntitlementActuallyPresent']is True and runtime['all29CPUObjectsWholeRuntime86'] is True and
         runtime['bothSignedCPUProvidersWholeRuntime86'] is True and runtime['cpu29SourceProof'] == prior['actualCPUCurrentSource'] and
         runtime['wholeByteUnchangedSignedImages'] == 140 and runtime['existingSignedImagesResigned'] == 3 and
         runtime['nativeGPUTaskImagesPreviouslySignedAndWholeInherited'] == 2 and runtime['nativeGPUTaskImagesResigned'] == 0,
         'Runtime95 is assembled from historical R86 with MD/PG/VMM reseals and signed native GPU helper; all29 CPU objects and140 old signed images whole')
    need(runtime['nativeOwnedGPUTaskProduct']['sha256']==GPU_EVENT_PIPELINE_CANDIDATE_SHA256 and
         runtime['nativeOwnedGPUTaskSourcePlan']['sha256']==GPU_EVENT_PIPELINE_SOURCE_PLAN_SHA256,
         'actual Root signed GPU product and exact native event/pipeline source-plan')
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
    need(texture['exactNativeReturnRVA'] == 0x4ea24 and
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
    need(gpu_product['nativeTaskPort']['exactChangedInstructionWordCount']==GPU_EXPECTED_CHANGED_INSTRUCTION_WORD_COUNT and
         gpu_product['nativeTaskPort']['nativeShmemMapCallAndCompareAndThrowWhole'] is True and
         texture_call['callRVA']==0x4ea20 and texture_call['returnRVA']==0x4ea24 and
         texture_call['actualWord']=='0x94006853' and texture_call['targetCStubRVA']==0x68b6c and
         texture_call['correctStandaloneFiveArgumentABI'] is True and
         texture_call['originalNativeTextureAndSurfaceValidatorsWhole'] is True,
         'actual native Task bound word proof retains typed texture route; all original validators and map comparison remain whole')
    event_pipeline=gpu_source_plan['metalContract']['orderedEventAndRenderPipelineObservationV1']
    need(event_pipeline['exactScheduledSignalCallRVA']==0x2d438 and
         event_pipeline['directNativePublicSignalEventStubRVA']==0x6b200 and
         event_pipeline['pipelineCallerReturnRVAs']==[0x41114,0x41b08] and
         event_pipeline['maxActualFailureLogs']==8 and
         event_pipeline['maxUTF16CharactersPerNSErrorField']==512 and
         event_pipeline['maxUTF8BytesPerField']==2048 and
         event_pipeline['currentTaskImportRows']==187 and
         all(event_pipeline[key] is True for key in
             ('eventValueAndOriginalCommitUnchanged', 'conservativeLaterGPUExecutionSignalNotSchedulingEquivalent',
              'exactEarlySchedulingOptimizationDeferred', 'noCPUEventValueWrite', 'noNOPOrFakeGPUCompletion',
              'singleProperSixArgumentAdapter', 'exactNativeSelectorByCaller',
              'descriptorOptionsReflectionErrorSlotsUntouched', 'nativeCallExactlyOnceAndReturnedPlusOneUnchanged',
              'nativeExceptionsStillPropagate', 'noShaderFallbackOrSuccessfulPipelineManufactured',
              'oneFreshAuthenticatedSlotAndTailStub', 'original186ImportRowsRetainedWithOneAppendedObserverImport',
              'taskEntitlementsExactlyWholeGPU13')),
         'real later GPU signal preserves value/commit; bounded exact two-callsite six-argument pipeline observer preserves native result/error')
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
         'each actual Runtime95 manifest Mach-O joins its actual complete signature proof')
    prior_runtime=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    prior_signature=json.loads(base.exact(prior_runtime['signatureVerification']).read_bytes())
    prior_signature_rows={row['relativePath']:row for row in prior_signature['actualSignedFiles']}
    need(prior_runtime['baselineRuntimeCandidate']==runtime['baselineRuntimeCandidate'], 'R95 and installed R94 both use true historical R86 assembly baseline')
    task_relative=GPU_REL
    entitlement_changes=[]
    need(set(prior_signature_rows)=={row['relativePath']for row in signature['actualSignedFiles']},
         'same actual145 runtime signed paths before exact whole-entitlement comparison')
    for row in signature['actualSignedFiles']:
        original=prior_signature_rows[row['relativePath']]
        before=original.get('embeddedEntitlements');after=row.get('embeddedEntitlements')
        need(after==before, 'every runtime image entitlement set whole installed Runtime94')
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
    expected_changes={MAIN,'runtime/'+pathlib.Path(runtime['manifest']['path']).name}|{'runtime/'+manifest_rows[i]['path']for i in changed_ids}
    pg_name='runtime/'+manifest_rows['child:ParavirtualizedGraphics27.dylib']['path']
    need(next(row for row in files if row['archivePath']==pg_name)['local']['sha256']==old_rows[pg_name]['local']['sha256'], 'actual deterministic PG signed file whole installed Runtime94')
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
    scope.update(schema='Actual Runtime95 App115 GPU native event compatibility and pipeline error observation device delta scope v105',
        oldScope=pin(OLD/'scope.json'), currentInstalledProductsPost=pin(POST), oldActualPost=pin(POST),
        baselineOriginalDev103InitializationSucceeded=True,
        baselineOriginalDev103AllSevenActionsSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal117PostRecovery=True,
        precedingNormal117Stop=post_request['actualStop'], originalNormal117FailedPost=post_request['failedPost'],
        actualRootPostRecoveryRequest=post['request'], onlyExpectedRelaunchedUI33881Recovered=True,
        baselineControllerInheritedFromOriginalDev103Packet=True,
        deviceStage=STAGE, files=files, directories=directories, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        actualInstalledRuntime94Verification=dict(deviceCandidate=pin(OLD/'candidate.json'),scope=pin(OLD/'scope.json'),freeze=pin(OLD/'freeze.json'),runtimeCandidate=old['runtimeCandidate']),
        actualInstalledApp114Candidate=old['appCandidate'], inheritedApp114CompiledSource=source['inheritedCompiledAppCandidate'],
        actualAll29CPUObjectsWholeRuntime86=True, actualChangedCPUObjects=0, actualUnchangedCPUObjects=29,
        inheritedActualSignedRuntimeCDProof=signature_pin,
        actualMain32AndOther33CompiledObjectsWholeApp114=True, actualChangedAppObjectIndices=[34], actualOnlyRelinkedRuntimeAnchor=True,
        actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
        ownedPGRemoteTaskParentTransportV1Contract=runtime['ownedPGRemoteTaskParentTransportV1Contract'],
        nativeOwnedGPUTaskProduct=runtime['nativeOwnedGPUTaskProduct'],
        nativeOwnedGPUTaskSourcePlan=runtime['nativeOwnedGPUTaskSourcePlan'],
        softwareKeyboardAndOptionalQGADiagnosticV1Contract=inherited_source['softwareKeyboardAndOptionalQGADiagnosticV1Contract'],
        gpuTaskExecutableRelativePath=GPU_REL, ownGPUHelperMustBeAbsentAfterParentCleanup=True,
        trustCacheCDHashes=full, newTrustCacheCDHashes=new_cd, trustCacheRegistrationCount=len(new_cd),
        trustCacheFixedBatchCounts=[len(new_cd)], actualFullCodeDirectoryHashes=len(full),
        actualRuntimeManifestFiles=len(manifest['files']), actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count,
        deltaFiles=changes, existingOwnFilesUpdated=sum(r['old'] is not None for r in changes), actualChangedFiles=len(changes),
        unchangedFiles=len(files)-len(changes), unchangedSignedImages=len(full)-len(new_cd),
        newOwnFilesAdded=0, newOwnDirectories=new_dirs, newOwnResourceFiles=[r['archivePath'] for r in changes if r['old'] is None],
        runtimeAllWholebytesUnchanged=False, runtimeProductAndAllFilesWholeUnchanged=False,
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
        deviceSystemFilesModified=False, systemSandboxFilesModified=False, noExistingImagePermissionsChanged=True, onlyGPUTaskEventPipelineAdapterAndSignedParentPinsChanged=True, actualRuntimeEntitlementChanges=entitlement_changes, all146RuntimeAndAppEntitlementsWholeInstalledR94App114=True, noNewCPUOrHVPermissions=True,
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
        need(old['deviceStage'] in raw, 'actual Dev103 action stage identity')
        return raw.replace(old['deviceStage'], STAGE)

    def replace_once(body, before_value, after_value, reason):
        need(body.count(before_value) == 1, 'one exact Dev103 block: '+reason)
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
             'actual Dev103 outer wrapper byte-whole after stage substitution: '+action)
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
                 'exact executed Dev103 trust adds and whole membership parser')
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
         'Dev103 controller protocol/ready/auth/once/cleanup byte-whole except stage name')
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
                    fromfile='Dev103/'+action+'.sh', tofile='Dev105/'+action+'.sh'))
        unwrapped_diff.extend(difflib.unified_diff(unwrap((OLD/(action+'.sh')).read_text()).splitlines(True),
                    unwrap(script).splitlines(True), fromfile='Dev103/'+action+'.body', tofile='Dev105/'+action+'.body'))
    diff.extend(difflib.unified_diff((OLD/'control.py').read_text().splitlines(True), controller.splitlines(True),
                fromfile='Dev103/control.py', tofile='Dev105/control.py'))
    (out/'scripts-from-device103.diff').write_text(''.join(diff))
    (out/'scripts-unwrapped-from-device103.diff').write_text(''.join(unwrapped_diff))
    dump(out/'script-delta.json', dict(schema='Exact generated Dev103 to GPU native event compatibility and pipeline error observation Runtime95/App115 Dev105 finite script delta v1',
         baseline=pin(OLD/'candidate.json'), baselineScope=pin(OLD/'scope.json'),
         controllerBefore=pin(OLD/'control.py'), controllerAfter=pin(out/'control.py'),
         controllerOnlyStageNameChanged=True, closeOnlyStageNameChanged=False, originalCloseSignalIdentityProtocolWhole=True,
         sameActualDev103TimeoutsAndProcessProtocol=True, transformations=operations,
         stageGeneratedFrom='Executed Dev103 bounded stage and exact backup/pending/rename/log protocol',
         stageOnlyListedOwnedDeltaFilesAndExistingLogWritten=True,
         fullActualScriptsDiff=pin(out/'scripts-from-device103.diff'),
         fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device103.diff'),
         scriptPairs={action:dict(before=pin(OLD/(action+'.sh')), after=rows[action]) for action in actions}))
    candidate = dict(schema='Actual Runtime95 App115 GPU native event compatibility and pipeline error observation device packet v105', preparer=pin(__file__),
        scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'), scripts=rows,
        actions=actions, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        currentInstalledProductsPost=pin(POST), oldDeviceCandidate=pin(OLD/'candidate.json'),
        scriptDelta=pin(out/'script-delta.json'), fullActualScriptsDiff=pin(out/'scripts-from-device103.diff'),
        fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device103.diff'),
        actualFullFiles=len(files), actualFullCodeDirectoryHashes=len(full), actualChangedFiles=len(changes), actualExistingFilesUpdated=sum(r['old'] is not None for r in changes),
        actualNewFilesAdded=0, actualNewDirectoriesAdded=len(new_dirs), actualNewTrustEntries=len(new_cd),
        onlyGPUTaskEventPipelineAdapterParentIdentityAndApp115AnchorChanged=True, actualCPUCurrentSource=runtime['cpu29SourceProof'], all29CPUObjectsWholeRuntime86=True, actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count, all103AppResourcesWholeUnchanged=True,
        all265ExistingDevicePathsModesAndDirectoriesSame=True, continuingHumanAuthorization=scope['continuingHumanAuthorization'],
        bootSeconds=BOOT, bootSessionUUID=UUID, closeOwnExternalWallSeconds=20,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        allOtherRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        exactDev103ControllerOnlyStageNameChanged=True, repeatedRuntime65To66SourceAdmissionNotApplied=True,
        baselineOriginalDev103InitializationSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal117PostRecovery=True,
        precedingNormal117Stop=post_request['actualStop'], originalNormal117FailedPost=post_request['failedPost'],
        actualRootPostRecoveryRequest=post['request'], onlyExpectedRelaunchedUI33881Recovered=True,
        newPacketRequiresAllSevenStandardActionsAndContinuingDerivedAuthorization=True,
        allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True, sameDirectoryTemporaryReplacements=True,
        originalStable2sReadinessAndProcessCleanupRetained=True, noExistingPermissionsChanged=True, onlyGPUTaskEventPipelineAdapterAndSignedParentPinsChanged=True, noNewCPUOrHVPermissions=True,
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
    pins += post_recovery_pins + prior_receipt_pins + list(prior['scripts'].values())+[row['local'] for row in files]+[changed['old'] for changed in changes if changed['old'] is not None]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
         deviceOperations=0, codeSigningOperations=0, repeatedHistoricalSourceDeltaAdmission=False))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), scope=pin(out/'scope.json'),
         freeze=pin(out/'freeze.json'), delta=pin(out/'script-delta.json'),
         files=len(files), CDs=len(full), changedFiles=len(changes), newTC=len(new_cd), maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
