#!/usr/bin/env python3
"""HOST prepare Main33 native 2022 graphics feature profile App117 Main-only update.

Actual installed Dev107 Runtime96/App116 and Normal119 canonical stop0/post0 are
required. Runtime96, all145 runtime images and all146 entitlements stay whole.
Root supplies actual new signed App117 and compiled candidate pins by CLI.
No signing, device dispatch, ready or authorization record is generated.
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
OLD = N/'independent27-gpu-pso-caller-device-v107-attempt1'
EXPECTED_POST = N/'independent27-app116-normal-guest-lifecycle-v119-attempt1/device-receipts/post/receipt.json'
STAGE = '/private/var/mobile/Library/.VM27-independent27-gpu-feature-level-stage-v108'
MAIN = 'VirtualMacIndependent27.app/VirtualMacIndependent27'
BOOT = 1792161311
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
OLD_CANDIDATE_SHA256 = '14b31f22f47b9f0bc5fb0b196e3bf01750185d8a014d8cc9b0d7d2e83ec1b403'
OLD_SCOPE_SHA256 = '9185f12bdec47091185341e83f6b048f745f0ab6cd52f4bd41f53647943cb444'
APP116_SOURCE_SHA256 = '322dd1e9bc8dc1c139d8ec8342d864dc2a16d5b17a52be67160280caa796d6b9'
MAIN33_PLAN_SHA256 = '077a2497901f28cd45607862e5b7a4fb8030b72dd65db462f3ea445c599a1057'
EXPECTED_POST_SHA256 = 'a420e16637cf2679caacc2db5755ea8930ec801fe4e42c141700574a374c612b'
EXPECTED_STOP_SHA256 = '0e249f0059343bd300b811156fb5b7d242a3968f7e17efa57a9b81e4e1e6a23d'
# Root supplies actual new signed App117 and compiled candidate pins through required CLI arguments.
RUNTIME96_CANDIDATE_SHA256 = '8ef90753fb1ce87fff1c5a7eee54d773b2fccd663ac0741217866002eb1475b9'
LOG_ID = '16777223:48200252'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load(OLD/'control.py', 'executed_dev107_main_only_base')
fast = load(B/'independent27_device_product_verify_fast_v1.py', 'dev108_fast')
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
    need(script[at:] == shlex.quote(unwrap(script))+'\n', 'exact Dev107 single quoted body/tail')
    return script[:at]+shlex.quote(body)+'\n'


def trust_check(hashes):
    # Same exact membership parser as the executed Dev107 trust action.
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
         'one original Dev107 UI-only close Main byte/metadata guard')
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
        pending = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-gpu-feature-level-v108-'+str(index)+'.pending')))
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
    ap.add_argument('--current-installed-post-sha256', required=True)
    ap.add_argument('--app-candidate-sha256', required=True)
    ap.add_argument('--app-source-sha256', required=True)
    args = ap.parse_args()
    need(args.current_installed_post_sha256 == EXPECTED_POST_SHA256, 'exact actual Normal119 post SHA')
    APP117_CANDIDATE_SHA256 = args.app_candidate_sha256
    APP117_SOURCE_SHA256 = args.app_source_sha256
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (EXPECTED_POST_SHA256, APP117_CANDIDATE_SHA256, APP117_SOURCE_SHA256)),
         'Root must supply full actual post/signed App/source SHA256 pins')
    POST = args.current_installed_post.resolve()
    need(POST == EXPECTED_POST.resolve() and pin(POST)['sha256'] == EXPECTED_POST_SHA256, 'only actual Normal119 post for installed Dev107')
    out, app_path = args.output.resolve(), args.app_candidate.resolve()
    need(out == N/'independent27-gpu-feature-level-device-v108-attempt1' and not out.exists(), 'fresh concrete Dev108 packet')
    need(pin(OLD/'candidate.json')['sha256'] == OLD_CANDIDATE_SHA256 and
         pin(OLD/'scope.json')['sha256'] == OLD_SCOPE_SHA256, 'exact installed Dev107 candidate/scope')
    prior = json.loads((OLD/'candidate.json').read_bytes())
    need(prior['scope'] == pin(OLD/'scope.json') and
         prior['controller'] == pin(OLD/'control.py'), 'exact executed Dev107 scope/controller')
    for row in prior['scripts'].values():
        base.exact(row)
    prior_receipt_pins=[]
    for action in prior['actions']:
        path=OLD/'device-receipts'/action/'receipt.json'
        receipt=json.loads(path.read_bytes()); request=json.loads(base.exact(receipt['request']).read_bytes())
        need(receipt['transportExit']==0 and request['packetCandidate']==pin(OLD/'candidate.json') and request['script']==prior['scripts'][action], 'actual all7 Dev107 phases '+action)
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
             'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF')), 'actual same-product Normal119 post0 baseline')
    normal_path = EXPECTED_POST.parents[2]
    normal = json.loads((normal_path/'candidate.json').read_bytes())
    need(normal['initializerCandidate'] == pin(OLD/'candidate.json'), 'Normal119 belongs to actual installed Dev107')
    STOP = normal_path/'device-receipts/stop/receipt.json'
    stop = json.loads(STOP.read_bytes()); stop_request = json.loads(base.exact(stop['request']).read_bytes())
    need(pin(STOP)['sha256'] == EXPECTED_STOP_SHA256 and stop['transportExit'] == 0 and
         stop_request['packetCandidate'] == pin(normal_path/'candidate.json') and stop_request['action'] == 'stop',
         'actual same Normal119 canonical stop0 before post0')
    base.exact(stop['stdout']); base.exact(stop['stderr'])
    base.exact(old['runtimeCandidate'])
    runtime_path = args.runtime_candidate.resolve()
    runtime_pin = pin(runtime_path)
    need(runtime_pin == old['runtimeCandidate'] and runtime_pin['sha256'] == RUNTIME96_CANDIDATE_SHA256 and
         pin(app_path)['sha256'] == APP117_CANDIDATE_SHA256,
         'same actual installed Runtime96 and exact new signed App117 candidate')
    runtime = json.loads(runtime_path.read_bytes())
    app = json.loads(app_path.read_bytes())
    previous_app = json.loads(base.exact(old['appCandidate']).read_bytes())
    need(app['actualCodeSigned'] is True and app['actualPrimaryPagesAndExternalSlotsVerified'] is True and
         app['runtimeCandidate'] == runtime_pin and app['runtimeRoot'] == runtime['canonicalDeviceRoot'] and
         app['actualBundleID'] == previous_app['actualBundleID'] and
         app['actualURLScheme'] == previous_app['actualURLScheme'], 'actual signed App117, same Runtime96 and application identity')
    need(app['sourceCandidate']['sha256'] == APP117_SOURCE_SHA256, 'exact Root-compiled App117 source candidate')
    source = json.loads(base.exact(app['sourceCandidate']).read_bytes())
    prior_source = json.loads(base.exact(previous_app['sourceCandidate']).read_bytes())
    need(previous_app['sourceCandidate'] == source['inheritedCompiledAppCandidate'] and
         source['inheritedCompiledAppCandidate']['sha256'] == APP116_SOURCE_SHA256 and
         len(source['objects']) == len(source['sourceFiles']) == 35 and source['actualRuntimeCandidate'] == runtime_pin and
         all(source['objects'][i] == prior_source['objects'][i] and source['sourceFiles'][i] == prior_source['sourceFiles'][i]
             for i in range(1,35)),
         'exact App116 baseline; other34 sources/objects whole including Runtime96 anchor')
    main_plan_pin = source['mainSourcePlan']
    main_plan = json.loads(base.exact(main_plan_pin).read_bytes())
    contract_key = 'graphicsFeatureLevel2022V33Contract'
    contract = main_plan[contract_key]
    need(main_plan_pin['sha256'] == MAIN33_PLAN_SHA256 and
         source['mainSourceContractKey'] == source['graphicsFeatureLevelSourceContractKey'] == main_plan['contractKey'] == contract_key and
         source['graphicsFeatureLevelSourcePlan'] == main_plan_pin and source[contract_key] == contract and
         main_plan['baselineCompiledAppCandidate'] == previous_app['sourceCandidate'] and
         main_plan['baselineMain32Source'] == prior_source['sourceFiles'][0] and
         main_plan['baselineMain32SourcePlan'] == prior_source['mainSourcePlan'] and
         main_plan['actualRuntimeCandidate'] == runtime_pin and
         main_plan['sourceFiles'] == [source['sourceFiles'][0]] and
         main_plan['actualChangedAppObjectIndices'] == source['actualChangedAppObjectIndices'] == [0] and
         source['actualUnchangedCompiledObjects'] == 34 and source['actualNewAppCompilations'] == 1 and
         source['all34OtherAppObjectsWholeApp116'] is True and source['actualOnlyMainObjectChanged'] is True and
         source['actualRuntime96AndAnchorWholeUnchanged'] is True,
         'actual Main33 one-object build with exact original native graphics profile contract and whole other34')
    need(contract['requestedOriginalNativeDeviceFeatureLevel'] == 1 and
         contract['nativeSetterCalledExactlyOnce'] is True and contract['actualNativeGetterMustReturnOne'] is True and
         contract['actualPGCapabilityKey'] == 18 and contract['actualPGWireMaximumAtLevel1'] == '0x00020002' and
         contract['wireVersionNotAssumedEqualToPublicMTLLanguageVersionEnum'] is True and
         contract['bootArgumentsRawDiskUIKeyboardQGAAndSSHDeferralCodePreserved'] is True and
         contract['noRuntimeOrCPUOrGPUImageChanges'] is True,
         'real native conservative profile and strict readback; no public MSL version or guest-success claim')
    base.exact(source['sourceFiles'][0]); base.exact(main_plan['sourceDiff'])
    for evidence in main_plan['primaryEvidenceFiles']: base.exact(evidence)
    need(runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True,
         'same existing signed Runtime96; no runtime compilation or product delta')
    signature_pin = runtime['signatureVerification']
    signature = json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True, 'actual runtime signature pages and slots')
    base.exact(runtime['manifest']) # Actual runtime binary-plist anchor manifest.
    manifest_path = runtime_path.parent/'manifest.json' # Builder's signed-file metadata JSON.
    manifest = json.loads(manifest_path.read_bytes())
    cds = {'runtime/'+row['path']:row['cdhash'] for row in manifest['files'] if row['kind'] == 'mach-o'}
    signature_rows = {'runtime/'+row['relativePath']:row for row in signature['actualSignedFiles']}
    need(len(manifest['files']) == 160 and len(cds) == 145 and set(cds) == set(signature_rows) and all(signature_rows[name]['cdhash'] == value and
         signature_rows[name]['allPrimaryPagesAndSpecialSlotsVerified'] is True for name,value in cds.items()),
         'each actual Runtime96 manifest Mach-O joins its actual complete signature proof')
    prior_runtime=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    prior_signature=json.loads(base.exact(prior_runtime['signatureVerification']).read_bytes())
    prior_signature_rows={row['relativePath']:row for row in prior_signature['actualSignedFiles']}
    need(all(row.get('embeddedEntitlements')==prior_signature_rows[row['relativePath']].get('embeddedEntitlements')
         for row in signature['actualSignedFiles']), 'all145 runtime entitlement sets whole Runtime96')
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
    files = []; changes = []; runtime_root = pathlib.Path(runtime['runtimeRoot'])
    base.regular_tree(runtime_root)
    runtime_names = {'runtime/'+p.relative_to(runtime_root).as_posix() for p in runtime_root.rglob('*') if p.is_file()}
    need(runtime_names == {name for name in old_rows if name.startswith('runtime/')}, 'exact same runtime file paths')
    runtime_dirs = {'runtime'} | {'runtime/'+p.relative_to(runtime_root).as_posix() for p in runtime_root.rglob('*') if p.is_dir()}
    need(runtime_dirs == {name for name in old['directories'] if name == 'runtime' or name.startswith('runtime/')},
         'exact existing runtime directories')
    for original in old['files']:
        base.exact(original['local']); row = copy.deepcopy(original); name = row['archivePath']
        top, relative = name.split('/', 1)
        local = pin((runtime_root if top == 'runtime' else app_root)/relative)
        if top == 'runtime':
            need(local['sha256'] == original['local']['sha256'] and local['bytes'] == original['local']['bytes'], 'every Runtime96 file whole unchanged')
        row['local'] = local
        if name in cds:
            row['cdhash'] = cds[name]
            need(local == signature_rows[name]['actualSignedFile'], 'every runtime whole file joins signed proof')
        elif name == MAIN:
            need(local == sig['file'], 'actual new signed Main joins signature')
            row['cdhash'] = sig['cdhash']
        elif top != 'runtime':
            need(local['bytes'] == original['local']['bytes'] and local['sha256'] == original['local']['sha256'],
                 'all103 App resources whole')
        if local['sha256'] != original['local']['sha256']:
            changes.append(dict(index=len(changes), archivePath=name, devicePath=row['devicePath'],
                mode=row['mode'], old=original['local'], new=local, newResource=False))
        files.append(row)
    change = next(row for row in changes if row['archivePath'] == MAIN)
    full = sorted(row['cdhash'] for row in files if 'cdhash' in row)
    new_cd = sorted(set(full)-set(old['trustCacheCDHashes']))
    runtime_files = [row for row in files if row['archivePath'].startswith('runtime/')]
    runtime_cd_count = sum('cdhash' in row for row in runtime_files)
    need(len(files) == len(old['files']) == 265 and len(full) == len(set(full)) == 146 and
         len(runtime_files) == 161 and runtime_cd_count == 145 and len(changes) == 1 and len(new_cd) == 1 and new_cd == [sig['cdhash']] and
         changes[0]['archivePath'] == MAIN,
         'same265 paths and146 images; only Main changes and exactly one new trust entry')
    old_code_names = {row['cdhash']:row['archivePath'] for row in old['files'] if 'cdhash' in row}
    new_code_hashes = {row['archivePath']:row['cdhash'] for row in files if 'cdhash' in row}
    native_subset = [new_code_hashes[old_code_names[value]] for value in old['actualNativeCDSubset']]
    scope = {key: copy.deepcopy(old[key]) for key in ('deviceRuntime', 'deviceApp', 'deviceAppMain', 'deviceChildMain',
             'directories', 'continuingHumanAuthorization', 'sandboxProfileApplied', 'nativeSandboxApplyUnavailable',
             'nativeSandboxInitSuccessFabricated', 'fixedOwnedLogIdentity', 'bootSeconds', 'bootMicroseconds', 'bootSessionUUID')
             if key in old}
    scope.update(schema='Actual Runtime96 Main33 App117 native 2022 graphics profile device delta scope v108',
        oldScope=pin(OLD/'scope.json'), currentInstalledProductsPost=pin(POST), oldActualPost=pin(POST),
        baselineOriginalDev107InitializationSucceeded=True,
        baselineOriginalDev107AllSevenActionsSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal119Post=True,
        baselineControllerInheritedFromOriginalDev107Packet=True,
        deviceStage=STAGE, files=files, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        historicalInstalledRuntime96Verification=dict(deviceCandidate=pin(OLD/'candidate.json'),
            scope=pin(OLD/'scope.json'), freeze=pin(OLD/'freeze.json'), runtimeCandidate=old['runtimeCandidate'],
            sourceSignatureAndCPUContractsApplyToCompletedRuntime96DeploymentOnly=True),
        historicalInstalledApp116Candidate=old['appCandidate'],
        actualAll29CPUObjectsWholeRuntime96=True,
        actualChangedCPUObjects=0, actualUnchangedCPUObjects=29,
        inheritedActualSignedRuntimeCDProof=signature_pin,
        actualOther34CompiledObjectsWholeApp116=True, actualChangedAppObjectIndices=[0], actualOnlyRelinkedRuntimeAnchor=False,
        actualUnchangedCompiledObjects=34, actualNewAppCompilations=1, actualRuntime96AndAnchorWholeUnchanged=True,
        mainSourcePlan=main_plan_pin, mainSourceContractKey=contract_key,
        graphicsFeatureLevel2022V33Contract=contract,
        precedingNormal119Stop=pin(STOP), actualCanonicalNormal119StopAndPostSucceeded=True,
        nativeOwnedGPUTaskProduct=old['nativeOwnedGPUTaskProduct'],
        nativeOwnedGPUTaskSourcePlan=old['nativeOwnedGPUTaskSourcePlan'],
        gpuTaskExecutableRelativePath=old['gpuTaskExecutableRelativePath'], ownGPUHelperMustBeAbsentAfterParentCleanup=True,
        all146RuntimeAndAppEntitlementsWholeInstalledR96App116=True,
        trustCacheCDHashes=full, newTrustCacheCDHashes=new_cd, trustCacheRegistrationCount=len(new_cd),
        trustCacheFixedBatchCounts=[len(new_cd)], actualFullCodeDirectoryHashes=len(full),
        actualRuntimeManifestFiles=len(manifest['files']), actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count,
        deltaFiles=changes, existingOwnFilesUpdated=len(changes), actualChangedFiles=len(changes),
        unchangedFiles=len(files)-len(changes), unchangedSignedImages=len(full)-len(new_cd),
        newOwnFilesAdded=0, newOwnDirectories=[], newOwnResourceFiles=[],
        runtimeAllWholebytesUnchanged=True, runtimeProductAndAllFilesWholeUnchanged=True,
        originalMainAppResourcesAllWholebytesUnchanged=True,
        all265DevicePathsModesAndDirectoriesSame=True, backupOldOwnFilesAndLog=True,
        missingOwnLogMayBeCreated=False, cleanupRequiresExactPIDUIDPathPPIDAndStartTimeHash=True,
        initializationExternalWallSeconds=45, currentAppCloseExternalWallSeconds=20, updateExternalWallSeconds=90,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        nonStageTransportTimeoutSeconds=55, nonStageNonCloseExternalWallSeconds=45,
        actualNativeCDSubset=native_subset, actualNativeCDSubsetCount=len(native_subset),
        actualNativeCDsQueriedThisDelta=new_cd, actualNativeCDsQueriedThisDeltaCount=len(new_cd),
        actualFullCodeTrustMembershipVerifiedAfterAddRequired=True, trustMembershipKnownBeforeDispatch=False,
        trustCacheMayRemainUntilReboot=True, perPIDKernelPrivilegeModification=False,
        deviceSystemFilesModified=False, systemSandboxFilesModified=False, newPermissions=False,
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
        need(old['deviceStage'] in raw, 'actual Dev107 action stage identity')
        return raw.replace(old['deviceStage'], STAGE)

    def replace_once(body, before_value, after_value, reason):
        need(body.count(before_value) == 1, 'one exact Dev107 block: '+reason)
        operations.setdefault(action, []).append(dict(reason=reason, beforeBytes=len(before_value.encode()),
            beforeSHA256=base.digest(before_value.encode()), afterBytes=len(after_value.encode()),
            afterSHA256=base.digest(after_value.encode())))
        return body.replace(before_value, after_value, 1)

    for action in ('close-current-own', 'preflight', 'verify', 'trust', 'launch', 'post'):
        raw = inherited(action)
        if action == 'close-current-own':
            scripts[action] = raw; operations[action] = [dict(reason='stage-name substitution only')]; continue
        body = unwrap(raw)
        need(rewrap(raw, body) == raw,
             'actual Dev107 outer wrapper byte-whole after stage substitution: '+action)
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
                 'exact executed Dev107 trust adds and whole membership parser')
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
         'Dev107 controller protocol/ready/auth/once/cleanup byte-whole except stage name')
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
                    fromfile='Dev107/'+action+'.sh', tofile='Dev108/'+action+'.sh'))
        unwrapped_diff.extend(difflib.unified_diff(unwrap((OLD/(action+'.sh')).read_text()).splitlines(True),
                    unwrap(script).splitlines(True), fromfile='Dev107/'+action+'.body', tofile='Dev108/'+action+'.body'))
    diff.extend(difflib.unified_diff((OLD/'control.py').read_text().splitlines(True), controller.splitlines(True),
                fromfile='Dev107/control.py', tofile='Dev108/control.py'))
    (out/'scripts-from-device107.diff').write_text(''.join(diff))
    (out/'scripts-unwrapped-from-device107.diff').write_text(''.join(unwrapped_diff))
    dump(out/'script-delta.json', dict(schema='Exact generated Dev107 to Main33 native 2022 graphics profile Dev108 finite script delta v1',
         baseline=pin(OLD/'candidate.json'), baselineScope=pin(OLD/'scope.json'),
         controllerBefore=pin(OLD/'control.py'), controllerAfter=pin(out/'control.py'),
         controllerOnlyStageNameChanged=True, closeOnlyStageNameChanged=True,
         sameActualDev107TimeoutsAndProcessProtocol=True, transformations=operations,
         stageGeneratedFrom='Executed Dev107 bounded stage and exact backup/pending/rename/log protocol',
         stageOnlyListedOwnedDeltaFilesAndExistingLogWritten=True,
         fullActualScriptsDiff=pin(out/'scripts-from-device107.diff'),
         fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device107.diff'),
         scriptPairs={action:dict(before=pin(OLD/(action+'.sh')), after=rows[action]) for action in actions}))
    candidate = dict(schema='Actual Runtime96 Main33 App117 native 2022 graphics profile device packet v108', preparer=pin(__file__),
        scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'), scripts=rows,
        actions=actions, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        currentInstalledProductsPost=pin(POST), oldDeviceCandidate=pin(OLD/'candidate.json'),
        scriptDelta=pin(out/'script-delta.json'), fullActualScriptsDiff=pin(out/'scripts-from-device107.diff'),
        fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device107.diff'),
        actualFullFiles=265, actualFullCodeDirectoryHashes=146, actualChangedFiles=len(changes), actualExistingFilesUpdated=len(changes),
        actualNewFilesAdded=0, actualNewDirectoriesAdded=0, actualNewTrustEntries=len(new_cd),
        onlyMain33AppObjectChanged=True, actualCPUCurrentSource=runtime['cpu29SourceProof'], all29CPUObjectsWholeRuntime96=True, actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count, all103AppResourcesWholeUnchanged=True,
        all265DevicePathsModesAndDirectoriesSame=True, continuingHumanAuthorization=scope['continuingHumanAuthorization'],
        bootSeconds=BOOT, bootSessionUUID=UUID, closeOwnExternalWallSeconds=20,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        allOtherRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        exactDev107ControllerOnlyStageNameChanged=True, repeatedRuntime65To66SourceAdmissionNotApplied=True,
        baselineOriginalDev107InitializationSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal119Post=True,
        newPacketRequiresAllSevenStandardActionsAndContinuingDerivedAuthorization=True,
        allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True, sameDirectoryTemporaryReplacements=True,
        originalStable2sReadinessAndProcessCleanupRetained=True, noNewPermissions=True,
        rootReadyAndDerivedAuthorizationNotGenerated=True, guestBootRequested=False,
        deviceOperations=0, trustCacheOperations=0, codeSigningOperations=0, readyForDeviceExecution=False)
    dump(out/'candidate.json', candidate)
    pins = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    pins += [pin(__file__), pin(B/'independent27_device_product_verify_fast_v1.py'),
             pin(OLD/'candidate.json'), pin(OLD/'scope.json'), pin(OLD/'freeze.json'), pin(OLD/'control.py'),
             pin(OLD/'health-root.sh'), old['runtimeCandidate'], old['appCandidate'],
             runtime_pin, signature_pin, pin(manifest_path),
             pin(app_path), app['sourceCandidate'], main_plan_pin, source['sourceFiles'][0], main_plan['sourceDiff'], *main_plan['primaryEvidenceFiles'],
             scope['continuingHumanAuthorization'], pin(POST), post['request'], post['stdout'], post['stderr'],
             pin(normal_path/'candidate.json'), pin(STOP), stop['request'], stop['stdout'], stop['stderr']]
    pins += prior_receipt_pins + list(prior['scripts'].values())+[row['local'] for row in files]+[changed['old'] for changed in changes]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
         deviceOperations=0, codeSigningOperations=0, repeatedHistoricalSourceDeltaAdmission=False))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), scope=pin(out/'scope.json'),
         freeze=pin(out/'freeze.json'), delta=pin(out/'script-delta.json'),
         files=len(files), CDs=len(full), changedFiles=len(changes), newTC=len(new_cd), maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
