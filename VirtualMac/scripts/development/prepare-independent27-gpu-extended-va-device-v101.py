#!/usr/bin/env python3
"""HOST prepare Runtime93/App113 GPU Task extended virtual-addressing signature delta.

Installed baseline is actual Dev99 Runtime92/App112 and actual Normal114 post0.
Root alone supplies signed products and dispatches. No signing/device/ready writes.
Mature Dev99 process identity, backups, trust, initialization and controller gates
are retained; only actual listed existing files are updated; no new files or directories.
Actual Root product and Normal114 post pins are bound; exact CLI pins remain required.
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
OLD = N/'independent27-gpu-shmem-map-device-v99-attempt1'
EXPECTED_POST = N/'independent27-app112-normal-guest-lifecycle-v114-attempt1/device-receipts/post/receipt.json'
STAGE = '/private/var/mobile/Library/.VM27-independent27-gpu-extended-va-stage-v101'
MAIN = 'VirtualMacIndependent27.app/VirtualMacIndependent27'
BOOT = 1792161311
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
OLD_CANDIDATE_SHA256 = '4d8f6e6aab658c1b6e5da090516b00b7711f142e1fa8be4b6011217aed04876b'
OLD_SCOPE_SHA256 = '7729eddfeff0bd1ca83817ec80f1d3aebd9676c0d4f69a480ade842ed558abdf'
APP112_PARENT_SOURCE_SHA256 = '4a069351b4934b37bc0ef5805f0d1469cb8fdc509b8e2da30ec11e36e0fff63e'
EXPECTED_POST_SHA256 = '65264a582107c9eb753c99021e6b22ea9fca11468a86e39ab4b2a739b85a7a83'
MAIN32_PLAN_SHA256 = '935ba7a6209cfc0fe9d4dc12939cbb0bd595a537ed2218e9f87b55cd24ed0866'
# Root supplies actual signed Runtime93/App113 and compiled App113 SHA256 pins through required CLI arguments.
INSTALLED_RUNTIME92_SHA256 = 'dfd2f45adb2aca2eddd07017bc7ac6305af6c73bf09af71c2077971b1e066961'
HISTORICAL_RUNTIME86_SHA256 = 'aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
RUNTIME93_CANDIDATE_SHA256 = '27bf64b8a69f0d5911a1ae9f57bc34683298e7ef21cdaf107e62305585f24380'
APP113_CANDIDATE_SHA256 = '36b0790b7c1eb0aa8f83ec4d812c2634b41bb0297367e2fd00e3301957173f36'
APP113_SOURCE_SHA256 = '53afdd918ebe9af7ded447a49627070e4c7fe324f29aa5e228408f67e245625d'
GPU_EXTENDED_VA_CANDIDATE_SHA256 = '096810279d6c0978f700057a99005579de08e3dfd1c21d43266913432c3e3a3d'
GPU_SHMEM_MAP_SOURCE_PLAN_SHA256 = 'e803d6fb28ed674e3117ed8d6b1bc3865b14c208b2c71126a0315c66e914d8c4'
EXTENDED_VA_KEY = 'com.apple.developer.kernel.extended-virtual-addressing'
LOG_ID = '16777223:48200252'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load(OLD/'control.py', 'executed_dev99_gpu_main_scope_base')
fast = load(B/'independent27_device_product_verify_fast_v1.py', 'dev99_gpu_fast')
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
    need(script[at:] == shlex.quote(unwrap(script))+'\n', 'exact Dev99 single quoted body/tail')
    return script[:at]+shlex.quote(body)+'\n'


def trust_check(hashes):
    # Same exact membership parser as the executed Dev99 trust action.
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
         'one original Dev99 UI-only close Main byte/metadata guard')
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
        pending = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-gpu-extended-va-v101-'+str(index)+'.pending')))
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
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (RUNTIME93_CANDIDATE_SHA256, APP113_CANDIDATE_SHA256, APP113_SOURCE_SHA256,
          GPU_EXTENDED_VA_CANDIDATE_SHA256, GPU_SHMEM_MAP_SOURCE_PLAN_SHA256, EXPECTED_POST_SHA256)),
         'Root must bind actual Normal114 post and R93/App113/extended-VA GPU product pins before preparation')
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (args.runtime_candidate_sha256, args.app_candidate_sha256, args.app_source_sha256)),
         'Root supplies actual signed Runtime93/App113 and compiled source SHA256 pins')
    need((args.runtime_candidate_sha256,args.app_candidate_sha256,args.app_source_sha256)==
         (RUNTIME93_CANDIDATE_SHA256,APP113_CANDIDATE_SHA256,APP113_SOURCE_SHA256),'exact Root signed R93/App113 and actual compiled source pins')
    POST = args.current_installed_post.resolve()
    need(POST == EXPECTED_POST.resolve() and pin(POST)['sha256'] == EXPECTED_POST_SHA256, 'only actual Normal114 same-product post for installed Dev99 R92/App112')
    out, app_path = args.output.resolve(), args.app_candidate.resolve()
    need(out.parent == N and not out.exists(), 'fresh concrete Dev101 packet')
    need(pin(OLD/'candidate.json')['sha256'] == OLD_CANDIDATE_SHA256 and
         pin(OLD/'scope.json')['sha256'] == OLD_SCOPE_SHA256, 'exact installed Dev99 candidate/scope')
    prior = json.loads((OLD/'candidate.json').read_bytes())
    need(prior['scope'] == pin(OLD/'scope.json') and
         prior['controller'] == pin(OLD/'control.py'), 'exact executed Dev99 scope/controller')
    for row in prior['scripts'].values():
        base.exact(row)
    prior_receipt_pins=[]
    for action in prior['actions']:
        path=OLD/'device-receipts'/action/'receipt.json'
        receipt=json.loads(path.read_bytes()); request=json.loads(base.exact(receipt['request']).read_bytes())
        need(receipt['transportExit']==0 and request['packetCandidate']==pin(OLD/'candidate.json') and request['script']==prior['scripts'][action], 'actual all7 Dev99 phases '+action)
        base.exact(receipt['stdout']);base.exact(receipt['stderr'])
        prior_receipt_pins += [pin(path),receipt['request'],receipt['stdout'],receipt['stderr']]
    old = json.loads((OLD/'scope.json').read_bytes())
    need(old['bootSeconds'] == BOOT and old['bootSessionUUID'] == UUID and
         old['fixedOwnedLogIdentity'] == LOG_ID+':501:501:600:1', 'same current boot and owned log')
    post = json.loads(POST.read_bytes())
    text = base.exact(post['stdout']).read_text()
    base.exact(post['stderr']); base.exact(post['request'])
    need(post['transportExit'] == 0 and json.loads(base.exact(post['request']).read_bytes())['packetCandidate'] == pin(EXPECTED_POST.parents[2]/'candidate.json') and
         all(marker in text for marker in ('INDEPENDENT27_OWN_APP_AND_CHILD_OFF',
             'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT', 'PRODUCTION_6_CODE_HASHES_PRESERVED',
             'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF')), 'actual same-product Normal114 post0 baseline')
    base.exact(old['runtimeCandidate'])
    runtime_path = args.runtime_candidate.resolve()
    runtime_pin = pin(runtime_path)
    need(old['runtimeCandidate']['sha256'] == INSTALLED_RUNTIME92_SHA256 and
         runtime_pin['sha256'] == args.runtime_candidate_sha256 and pin(app_path)['sha256'] == args.app_candidate_sha256,
         'actual installed Runtime92 and Root actual signed Runtime93/App113 products')
    runtime = json.loads(runtime_path.read_bytes()); app = json.loads(app_path.read_bytes())
    previous_app = json.loads(base.exact(old['appCandidate']).read_bytes())
    need(app['actualCodeSigned'] is True and app['actualPrimaryPagesAndExternalSlotsVerified'] is True and
         app['runtimeCandidate'] == runtime_pin and app['runtimeRoot'] == runtime['canonicalDeviceRoot'] and
         app['actualBundleID'] == previous_app['actualBundleID'] and app['actualURLScheme'] == previous_app['actualURLScheme'],
         'actual signed App113 with Runtime93 and unchanged application identity')
    need(app['sourceCandidate']['sha256'] == args.app_source_sha256, 'actual Root-linked App113 source candidate')
    source = json.loads(base.exact(app['sourceCandidate']).read_bytes())
    need(source['inheritedCompiledAppCandidate']['sha256'] == APP112_PARENT_SOURCE_SHA256, 'actual whole App112 build is pure anchor baseline')
    inherited_source = json.loads(base.exact(source['inheritedCompiledAppCandidate']).read_bytes())
    prior_source = json.loads(base.exact(previous_app['sourceCandidate']).read_bytes())
    need(source['inheritedCompiledAppCandidate'] == previous_app['sourceCandidate'] and
         inherited_source['actualChangedAppObjectIndices'] == [34] and
         source['objects'][:34] == inherited_source['objects'][:34] and
         source['sourceFiles'][:34] == inherited_source['sourceFiles'][:34] and
         len(source['objects']) == len(source['sourceFiles']) == 35 and source['actualRuntimeCandidate'] == runtime_pin,
         'actual installed App112 retains GuestTools9/keyboard4; all34 units whole in App113 pure anchor relink')
    need(source['mainSourcePlan']['sha256'] == MAIN32_PLAN_SHA256 and
         source['mainSourceContractKey'] == 'normalBootOriginalArgsV32Contract' and
         source['sourceFiles'][0]['sha256'] == '3b3f6d3797edb88536c0609e01ec813177d64387e921e90a060b2bfdd0c6a440' and
         source['actualOriginalBootArgsRestorationCodePresent'] is True and
         source['actualChangedAppObjectIndices'] == [34] and source['actualUnchangedCompiledObjects'] == 34 and
         source['actualNewAppCompilations'] == 0 and source['all34OtherAppObjectsWholeApp112'] is True,
         'Main32 and original UART/boot arguments/display bodies remain whole; only Runtime93 anchor relinked')
    need(runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         runtime['baselineRuntimeCandidate']['sha256'] == HISTORICAL_RUNTIME86_SHA256 and runtime['nativeGPUTaskNoContainerEntitlementActuallyPresent']is True and runtime['nativeGPUTaskCanExecuteCDHashEntitlementActuallyPresent']is True and runtime['all29CPUObjectsWholeRuntime86'] is True and
         runtime['bothSignedCPUProvidersWholeRuntime86'] is True and runtime['cpu29SourceProof'] == prior['actualCPUCurrentSource'] and
         runtime['wholeByteUnchangedSignedImages'] == 140 and runtime['existingSignedImagesResigned'] == 3 and
         runtime['nativeGPUTaskImagesPreviouslySignedAndWholeInherited'] == 2 and runtime['nativeGPUTaskImagesResigned'] == 0,
         'Runtime93 is assembled from historical R86 with MD/PG/VMM reseals and signed native GPU helper; all29 CPU objects and140 old signed images whole')
    need(runtime['nativeOwnedGPUTaskProduct']['sha256']==GPU_EXTENDED_VA_CANDIDATE_SHA256 and
         runtime['nativeOwnedGPUTaskSourcePlan']['sha256']==GPU_SHMEM_MAP_SOURCE_PLAN_SHA256,
         'actual Root GPU extended-VA signed product and exact native shmem-map observation source-plan')
    gpu_source_plan=json.loads(base.exact(runtime['nativeOwnedGPUTaskSourcePlan']).read_bytes())
    base.exact(runtime['nativeOwnedGPUTaskProduct'])
    gpu_product=json.loads(base.exact(runtime['nativeOwnedGPUTaskProduct']).read_bytes())
    prior_runtime_product=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    need(gpu_product['baselineCompiledAndSignedGPUProduct']==prior_runtime_product['nativeOwnedGPUTaskProduct'] and
         gpu_product['actualOnlyTaskSignatureChanged'] is True and
         gpu_product['actualCompatAndFourResourcesWhole'] is True and
         gpu_product['actualAddedEntitlements']=={EXTENDED_VA_KEY:True} and
         gpu_product['actualNewCompileOperations']==0 and gpu_product['actualNewLinkOperations']==0,
         'pure Task signature delta from actual installed GPU product; no source compilation or compat/resource edits')
    # Keep the exact historical compiled source plan and its native map observation.
    # This round changes only the GPU Task signature; no compilation is requested.
    # Native comparisons/throws, original eight permissions, CPU objects and PG stay whole.
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
         'prior typed optional queries remain; only Metal3 rebuilt and four other objects whole')
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
         'each actual Runtime93 manifest Mach-O joins its actual complete signature proof')
    prior_runtime=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    prior_signature=json.loads(base.exact(prior_runtime['signatureVerification']).read_bytes())
    prior_signature_rows={row['relativePath']:row for row in prior_signature['actualSignedFiles']}
    need(prior_runtime['baselineRuntimeCandidate']==runtime['baselineRuntimeCandidate'], 'R93 and installed R92 both use true historical R86 assembly baseline')
    task_relative=GPU_REL
    entitlement_changes=[]
    need(set(prior_signature_rows)=={row['relativePath']for row in signature['actualSignedFiles']},
         'same actual145 runtime signed paths before exact Task-only entitlement comparison')
    for row in signature['actualSignedFiles']:
        original=prior_signature_rows[row['relativePath']]
        before=original.get('embeddedEntitlements');after=row.get('embeddedEntitlements')
        if row['relativePath']==task_relative:
            need(isinstance(before,dict) and len(before)==8 and EXTENDED_VA_KEY not in before and
                 before.get('com.apple.private.security.no-container')is True and
                 before.get('com.apple.private.security.no-sandbox')is True and
                 before.get('com.apple.private.amfi.can-execute-cdhash')is True,
                 'actual eight installed GPU Task permissions without extended VA')
            expected=copy.deepcopy(before);expected[EXTENDED_VA_KEY]=True
            need(after==expected and len(after)==9,
                 'only one true extended-virtual-addressing entitlement added to exact GPU Task')
            entitlement_changes.append(dict(relativePath=task_relative,key=EXTENDED_VA_KEY,
                                             priorPresent=False,newValue=True))
        else:
            need(after==before, 'every other runtime image entitlement set whole installed Runtime92')
    need(len(entitlement_changes)==1, 'exactly one runtime entitlement addition to GPU Task only')
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
    changed_ids={'child:MD',manifest['childEntryContract']['childID'],'child-coderesources',manifest['dependencyProofID'],'gpu-task:main'}
    expected_changes={MAIN,'runtime/'+pathlib.Path(runtime['manifest']['path']).name}|{'runtime/'+manifest_rows[i]['path']for i in changed_ids}
    pg_name='runtime/'+manifest_rows['child:ParavirtualizedGraphics27.dylib']['path']
    for unchanged_gpu_id in ('gpu-task:compat','gpu-task-coderesources'):
        unchanged_gpu_name='runtime/'+manifest_rows[unchanged_gpu_id]['path']
        need(next(row for row in files if row['archivePath']==unchanged_gpu_name)['local']['sha256']==
             old_rows[unchanged_gpu_name]['local']['sha256'],
             'actual GPU compat and nested CodeResources remain whole; only Task signature changed')
    need(next(row for row in files if row['archivePath']==pg_name)['local']['sha256']==old_rows[pg_name]['local']['sha256'], 'actual deterministic PG signed file whole installed Runtime92')
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
    scope.update(schema='Actual Runtime93 App113 GPU Task extended virtual-addressing signature delta device delta scope v101',
        oldScope=pin(OLD/'scope.json'), currentInstalledProductsPost=pin(POST), oldActualPost=pin(POST),
        baselineOriginalDev99InitializationSucceeded=True,
        baselineOriginalDev99AllSevenActionsSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal114Post=True,
        baselineControllerInheritedFromOriginalDev99Packet=True,
        deviceStage=STAGE, files=files, directories=directories, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        actualInstalledRuntime92Verification=dict(deviceCandidate=pin(OLD/'candidate.json'),scope=pin(OLD/'scope.json'),freeze=pin(OLD/'freeze.json'),runtimeCandidate=old['runtimeCandidate']),
        actualInstalledApp112Candidate=old['appCandidate'], inheritedApp112CompiledSource=source['inheritedCompiledAppCandidate'],
        actualAll29CPUObjectsWholeRuntime86=True, actualChangedCPUObjects=0, actualUnchangedCPUObjects=29,
        inheritedActualSignedRuntimeCDProof=signature_pin,
        actualMain32AndOther33CompiledObjectsWholeApp112=True, actualChangedAppObjectIndices=[34], actualOnlyRelinkedRuntimeAnchor=True,
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
        deviceSystemFilesModified=False, systemSandboxFilesModified=False, noExistingImagePermissionsChanged=False, onlyGPUTaskExtendedVirtualAddressingAndSignedParentPinsChanged=True, actualRuntimeEntitlementChanges=entitlement_changes, all145OtherRuntimeAndAppEntitlementsWholeInstalledR92App112=True, onlyGPUOriginalEightEntitlementsRetainedWithOneExtendedVAAddition=True, noNewCPUOrHVPermissions=True,
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
        need(old['deviceStage'] in raw, 'actual Dev99 action stage identity')
        return raw.replace(old['deviceStage'], STAGE)

    def replace_once(body, before_value, after_value, reason):
        need(body.count(before_value) == 1, 'one exact Dev99 block: '+reason)
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
             'actual Dev99 outer wrapper byte-whole after stage substitution: '+action)
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
                 'exact executed Dev99 trust adds and whole membership parser')
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
         'Dev99 controller protocol/ready/auth/once/cleanup byte-whole except stage name')
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
                    fromfile='Dev99/'+action+'.sh', tofile='Dev101/'+action+'.sh'))
        unwrapped_diff.extend(difflib.unified_diff(unwrap((OLD/(action+'.sh')).read_text()).splitlines(True),
                    unwrap(script).splitlines(True), fromfile='Dev99/'+action+'.body', tofile='Dev101/'+action+'.body'))
    diff.extend(difflib.unified_diff((OLD/'control.py').read_text().splitlines(True), controller.splitlines(True),
                fromfile='Dev99/control.py', tofile='Dev101/control.py'))
    (out/'scripts-from-device99.diff').write_text(''.join(diff))
    (out/'scripts-unwrapped-from-device99.diff').write_text(''.join(unwrapped_diff))
    dump(out/'script-delta.json', dict(schema='Exact generated Dev99 to GPU Task extended virtual-addressing signature delta Runtime93/App113 Dev101 finite script delta v1',
         baseline=pin(OLD/'candidate.json'), baselineScope=pin(OLD/'scope.json'),
         controllerBefore=pin(OLD/'control.py'), controllerAfter=pin(out/'control.py'),
         controllerOnlyStageNameChanged=True, closeOnlyStageNameChanged=False, originalCloseSignalIdentityProtocolWhole=True,
         sameActualDev99TimeoutsAndProcessProtocol=True, transformations=operations,
         stageGeneratedFrom='Executed Dev99 bounded stage and exact backup/pending/rename/log protocol',
         stageOnlyListedOwnedDeltaFilesAndExistingLogWritten=True,
         fullActualScriptsDiff=pin(out/'scripts-from-device99.diff'),
         fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device99.diff'),
         scriptPairs={action:dict(before=pin(OLD/(action+'.sh')), after=rows[action]) for action in actions}))
    candidate = dict(schema='Actual Runtime93 App113 GPU Task extended virtual-addressing signature delta device packet v101', preparer=pin(__file__),
        scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'), scripts=rows,
        actions=actions, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        currentInstalledProductsPost=pin(POST), oldDeviceCandidate=pin(OLD/'candidate.json'),
        scriptDelta=pin(out/'script-delta.json'), fullActualScriptsDiff=pin(out/'scripts-from-device99.diff'),
        fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device99.diff'),
        actualFullFiles=len(files), actualFullCodeDirectoryHashes=len(full), actualChangedFiles=len(changes), actualExistingFilesUpdated=sum(r['old'] is not None for r in changes),
        actualNewFilesAdded=0, actualNewDirectoriesAdded=len(new_dirs), actualNewTrustEntries=len(new_cd),
        onlyGPUTaskExtendedVirtualAddressingParentIdentityAndApp113AnchorChanged=True, actualCPUCurrentSource=runtime['cpu29SourceProof'], all29CPUObjectsWholeRuntime86=True, actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count, all103AppResourcesWholeUnchanged=True,
        all265ExistingDevicePathsModesAndDirectoriesSame=True, continuingHumanAuthorization=scope['continuingHumanAuthorization'],
        bootSeconds=BOOT, bootSessionUUID=UUID, closeOwnExternalWallSeconds=20,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        allOtherRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        exactDev99ControllerOnlyStageNameChanged=True, repeatedRuntime65To66SourceAdmissionNotApplied=True,
        baselineOriginalDev99InitializationSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal114Post=True,
        newPacketRequiresAllSevenStandardActionsAndContinuingDerivedAuthorization=True,
        allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True, sameDirectoryTemporaryReplacements=True,
        originalStable2sReadinessAndProcessCleanupRetained=True, noExistingPermissionsChanged=False, onlyGPUTaskExtendedVirtualAddressingAndSignedParentPinsChanged=True, noNewCPUOrHVPermissions=True,
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
    pins += prior_receipt_pins + list(prior['scripts'].values())+[row['local'] for row in files]+[changed['old'] for changed in changes if changed['old'] is not None]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
         deviceOperations=0, codeSigningOperations=0, repeatedHistoricalSourceDeltaAdmission=False))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), scope=pin(out/'scope.json'),
         freeze=pin(out/'freeze.json'), delta=pin(out/'script-delta.json'),
         files=len(files), CDs=len(full), changedFiles=len(changes), newTC=len(new_cd), maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
