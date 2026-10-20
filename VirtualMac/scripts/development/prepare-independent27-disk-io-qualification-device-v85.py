#!/usr/bin/env python3
"""HOST-only Device85 source for Root-signed Runtime83/App100 disk qualification.

Inherit the original Dev84 controller and exact owned-file protocol.
Original Dev84 first five actions and post succeeded; launch returned 1.
Same-product initretry1 launch/post then succeeded with zero product/trust changes.
Normal101 post0 joins that retry and proves installed-product health/own-process-off.
The original Dev84 packet is never represented as a seven-success deployment.
New product pins are bound to Root's actual signed Runtime83/App100 artifacts.
No signing, device dispatch, ready, review or authorization record is generated.
"""
import argparse
import copy
import difflib
import importlib.util
import io
import json
import pathlib
import plistlib
import re
import shlex
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
OLD = N/'independent27-disk-io-observation-device-v84-attempt1'
EXPECTED_POST = N/'independent27-app99-normal-guest-lifecycle-v101-attempt1/device-receipts/post/receipt.json'
STAGE = '/private/var/mobile/Library/.VM27-independent27-host-capability-stage-v85'
MAIN = 'VirtualMacIndependent27.app/VirtualMacIndependent27'
BOOT = 1792161311
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
OLD_CANDIDATE_SHA256 = '0cd59406aaedbd1fa79f0a4d43e34273a76da04abf812a8c9f6db7e540bf8644'
OLD_SCOPE_SHA256 = '3cc81d5876908c87924fe6476e009a3cba641de3e36368a817d97d8e27b64adf'
EXPECTED_POST_SHA256 = 'f4b6e5ee2f3a2804b0e9623205081a63c9e150319e021948bae358545df9e699'
APP99_SOURCE_SHA256 = '3e674e324cb0c0811cc883b3847a3b94d8af9636a5b2571937becc457adeb97b'
MAIN32_PLAN_SHA256 = '935ba7a6209cfc0fe9d4dc12939cbb0bd595a537ed2218e9f87b55cd24ed0866'
# Exact installed Life65 proof and Root-verified signed Runtime83/App100 pins.
# These bind actual host artifacts; device execution remains Root-only.
CPU_LIFE65_SHA256 = '61be84de7113bb99be4a365403ab2587d3259c8c139d2930b04e56a6865cdfc0'
RUNTIME83_CANDIDATE_SHA256 = '10d87945a795f5b9d959749610edffe5c31f16a955cca0009fe4d6061dbb5452'
APP100_CANDIDATE_SHA256 = '443771717b975d39507c31c390c8b5b9ef1deacdf1c3aca0b4defc7a818696ae'
APP100_SOURCE_SHA256 = 'e49e684b97fb55a17550aa0f97701a4715de362dbcb884f6a9524c2a178a1942'
RETRY = N/'independent27-disk-io-observation-device-v84-initretry1'
RETRY_CANDIDATE_SHA256 = 'b3583625696f3175ffa3e717446eae0c29f410f2a33c1e4be977b46975382e5a'
RETRY_SCOPE_SHA256 = 'ea2ca8ef37c29bb8903a6aa99871fc08d464960671f41af024e37252410887be'
NORMAL101_CANDIDATE_SHA256 = '1bad2ac624a956b59465fd68d14a5c3056f02444d6b78b4d5fc7f29cc61a3ee5'
LOG_ID = '16777223:48200252'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load(OLD/'control.py', 'executed_dev84_normal_boot_base')
fast = load(B/'independent27_device_product_verify_fast_v1.py', 'dev85_fast')
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
    need(script[at:] == shlex.quote(unwrap(script))+'\n', 'exact Dev84 single quoted body/tail')
    return script[:at]+shlex.quote(body)+'\n'


def trust_check(hashes):
    # Same exact membership parser as the executed Dev84 trust action.
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


def stage_body(scope, archive):
    baseline = json.loads(base.exact(scope['oldScope']).read_bytes())
    main_change = next(item for item in scope['deltaFiles'] if item['archivePath'] == MAIN)
    old_main, main_mode = main_change['old'], main_change['mode']
    prior_main = next(item['old'] for item in baseline['deltaFiles'] if item['archivePath'] == MAIN)
    original_stage = unwrap((OLD/'stage.sh').read_text())
    lead = original_stage[:original_stage.index('check_own_file() {')]
    need(lead.count(prior_main['sha256']) == 1 and
         lead.count(f'501:501:{main_mode:o}:1:{prior_main["bytes"]}') == 1,
         'one original Dev84 UI-only close Main byte/metadata guard')
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
    # Back up and verify every old file before the first product replacement.
    for row in scope['deltaFiles']:
        path = shlex.quote(row['devicePath']); old, new, mode, index = row['old'], row['new'], row['mode'], row['index']
        stage += f'''check_own_file {path} {old['sha256']} {old['bytes']} {mode:o}
cp -p {path} "$OWN_STAGE/backup-{index}"
[ "$(sha256sum "$OWN_STAGE/backup-{index}" | cut -d ' ' -f1)" = {old['sha256']} ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/new-{index}")" = 0:0:600:1:{new['bytes']} ]
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
    for row in scope['deltaFiles']:
        path = shlex.quote(row['devicePath']); old, new, mode, index = row['old'], row['new'], row['mode'], row['index']
        pending = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-host-capability-v85-'+str(index)+'.pending')))
        stage += f'''[ ! -e {pending} ] && [ ! -L {pending} ]
cp "$OWN_STAGE/new-{index}" {pending}
chown 501:501 {pending}
chmod {mode:o} {pending}
check_own_file {pending} {new['sha256']} {new['bytes']} {mode:o}
check_own_file {path} {old['sha256']} {old['bytes']} {mode:o}
mv -f {pending} {path}
check_own_file {path} {new['sha256']} {new['bytes']} {mode:o}
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
    args = ap.parse_args()
    POST = args.current_installed_post.resolve()
    need(POST == EXPECTED_POST.resolve() and pin(POST)['sha256'] == EXPECTED_POST_SHA256, 'only actual Normal101 post for installed Dev84')
    out, app_path = args.output.resolve(), args.app_candidate.resolve()
    need(out == N/'independent27-disk-io-qualification-device-v85-attempt1' and not out.exists(), 'fresh concrete planned Dev85 packet')
    need(pin(OLD/'candidate.json')['sha256'] == OLD_CANDIDATE_SHA256 and
         pin(OLD/'scope.json')['sha256'] == OLD_SCOPE_SHA256, 'exact installed Dev84 candidate/scope')
    prior = json.loads((OLD/'candidate.json').read_bytes())
    need(prior['scope'] == pin(OLD/'scope.json') and
         prior['controller'] == pin(OLD/'control.py'), 'exact executed Dev84 scope/controller')
    for row in prior['scripts'].values():
        base.exact(row)
    # Preserve actual first-attempt failure; successful product initialization is separately joined below.
    prior_receipt_pins = []
    for action in prior['actions']:
        receipt_path = OLD/'device-receipts'/action/'receipt.json'
        receipt = json.loads(receipt_path.read_bytes())
        request = json.loads(base.exact(receipt['request']).read_bytes())
        expected_exit = 1 if action == 'launch' else 0
        need(receipt['transportExit'] == expected_exit and request['packetCandidate'] == pin(OLD/'candidate.json')
             and request['script'] == prior['scripts'][action], 'actual Dev84 first-attempt action status '+action)
        base.exact(receipt['stdout']); base.exact(receipt['stderr'])
        prior_receipt_pins += [pin(receipt_path), receipt['request'], receipt['stdout'], receipt['stderr']]
    old = json.loads((OLD/'scope.json').read_bytes())
    need(old['bootSeconds'] == BOOT and old['bootSessionUUID'] == UUID and
         old['fixedOwnedLogIdentity'] == LOG_ID+':501:501:600:1', 'same current boot and owned log')
    need(pin(RETRY/'candidate.json')['sha256'] == RETRY_CANDIDATE_SHA256 and
         pin(RETRY/'scope.json')['sha256'] == RETRY_SCOPE_SHA256, 'exact same-product successful initialization retry')
    retry = json.loads((RETRY/'candidate.json').read_bytes())
    retry_scope = json.loads(base.exact(retry['scope']).read_bytes())
    need(retry['oldDeviceCandidate'] == pin(OLD/'candidate.json') and
         retry_scope['sourceInstalledScope'] == pin(OLD/'scope.json') and
         retry_scope['files'] == old['files'] and retry_scope['runtimeCandidate'] == old['runtimeCandidate'] and
         retry_scope['appCandidate'] == old['appCandidate'] and
         retry['actualChangedFiles'] == retry['actualNewTrustEntries'] == retry['actualExistingFilesUpdated'] == 0 and
         retry['actions'] == ['launch','post'], 'retry inherits exact installed scope with zero product/trust delta')
    need(pin(EXPECTED_POST.parents[2]/'candidate.json')['sha256'] == NORMAL101_CANDIDATE_SHA256,
         'exact actual Normal101 packet')
    normal_packet = json.loads((EXPECTED_POST.parents[2]/'candidate.json').read_bytes())
    need(normal_packet['initializerCandidate'] == pin(RETRY/'candidate.json'),
         'actual Normal101 initializer is the successful same-product retry')
    retry_receipt_pins = []
    for action in ('launch','post'):
        path = RETRY/'device-receipts'/action/'receipt.json'
        receipt = json.loads(path.read_bytes())
        request = json.loads(base.exact(receipt['request']).read_bytes())
        need(receipt['transportExit'] == 0 and request['packetCandidate'] == pin(RETRY/'candidate.json') and
             request['script'] == retry['scripts'][action] and
             normal_packet['initializer'+action.capitalize()] == pin(path),
             'successful retry receipt joined by actual Normal101 '+action)
        base.exact(receipt['stdout']); base.exact(receipt['stderr']); base.exact(retry['scripts'][action])
        retry_receipt_pins += [pin(path),receipt['request'],receipt['stdout'],receipt['stderr'],retry['scripts'][action]]
    post = json.loads(POST.read_bytes())
    text = base.exact(post['stdout']).read_text()
    base.exact(post['stderr']); base.exact(post['request'])
    need(post['transportExit'] == 0 and json.loads(base.exact(post['request']).read_bytes())['packetCandidate'] == pin(EXPECTED_POST.parents[2]/'candidate.json') and
         all(marker in text for marker in ('INDEPENDENT27_OWN_APP_AND_CHILD_OFF',
             'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT', 'PRODUCTION_6_CODE_HASHES_PRESERVED',
             'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF')), 'actual same-product Normal101 post0 baseline')
    base.exact(old['runtimeCandidate'])
    runtime_path = args.runtime_candidate.resolve()
    need(runtime_path == (N/'independent27-signed-runtime-disk-io-qualification-product-v83-attempt1/candidate.json').resolve()
         and app_path == (N/'independent27-signed-app-disk-io-qualification-v100-attempt1/candidate.json').resolve(),
         'only planned Root Runtime83 and signed App100 candidate locations')
    runtime_pin = pin(runtime_path)
    need(all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in
             (CPU_LIFE65_SHA256, RUNTIME83_CANDIDATE_SHA256, APP100_CANDIDATE_SHA256, APP100_SOURCE_SHA256)),
         'actual bound Runtime83/signed App100/App100 source SHA256 pins; installed Life65 remains whole')
    need(isinstance(RUNTIME83_CANDIDATE_SHA256, str) and re.fullmatch('[0-9a-f]{64}', RUNTIME83_CANDIDATE_SHA256) and
         isinstance(APP100_CANDIDATE_SHA256, str) and re.fullmatch('[0-9a-f]{64}', APP100_CANDIDATE_SHA256),
         'Root must bind actual Runtime83 and signed App100 candidate SHA256 pins before preparation')
    need(runtime_pin['sha256'] == RUNTIME83_CANDIDATE_SHA256 and pin(app_path)['sha256'] == APP100_CANDIDATE_SHA256,
         'exact Root-compiled/signed Runtime83 and App100 products')
    runtime = json.loads(runtime_path.read_bytes())
    app = json.loads(app_path.read_bytes())
    previous_app = json.loads(base.exact(old['appCandidate']).read_bytes())
    need(app['actualCodeSigned'] is True and app['actualPrimaryPagesAndExternalSlotsVerified'] is True and
         app['runtimeCandidate'] == runtime_pin and app['runtimeRoot'] == runtime['canonicalDeviceRoot'] and
         app['actualBundleID'] == previous_app['actualBundleID'] and
         app['actualURLScheme'] == previous_app['actualURLScheme'], 'actual signed App100 with exact new Runtime83')
    need(app['sourceCandidate']['sha256'] == APP100_SOURCE_SHA256, 'exact Root-linked App100 pure anchor candidate')
    source = json.loads(base.exact(app['sourceCandidate']).read_bytes())
    prior_source = json.loads(base.exact(previous_app['sourceCandidate']).read_bytes())
    need(previous_app['sourceCandidate'] == source['inheritedCompiledAppCandidate'] and
         source['objects'][:34] == prior_source['objects'][:34] and
         source['sourceFiles'][:34] == prior_source['sourceFiles'][:34] and
         len(source['objects']) == len(source['sourceFiles']) == 35 and
         source['actualRuntimeCandidate'] == runtime_pin,
         'all34 Main32/other complete App99 sources and objects inherited into actual Runtime83 anchor relink')
    need(source['inheritedCompiledAppCandidate']['sha256'] == APP99_SOURCE_SHA256 and
         source['mainSourcePlan']['sha256'] == MAIN32_PLAN_SHA256 and
         source['mainSourceContractKey'] == 'normalBootOriginalArgsV32Contract' and
         source['sourceFiles'][0]['sha256'] == '3b3f6d3797edb88536c0609e01ec813177d64387e921e90a060b2bfdd0c6a440' and
         source['actualOriginalBootArgsRestorationCodePresent'] is True,
         'actual App100 anchor relink inherits exact complete App99 Main32 and original boot arguments restoration')
    need(source['actualChangedAppObjectIndices'] == [34] and
         source['actualUnchangedCompiledObjects'] == 34 and source['actualNewAppCompilations'] == 0 and
         source['actualMain32AndOther33CompiledObjectsWholeUnchanged'] is True and
         source['actualUARTAndBootArgsObjectsWholeApp99'] is True,
         'App100 Runtime83 anchor only; Main32 and other33 objects whole')
    prior_runtime = json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    need(runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         runtime['cpu29SourceProof']['sha256'] == CPU_LIFE65_SHA256 and
         runtime['cpu29SourceProof'] == prior_runtime['cpu29SourceProof'] and
         runtime['cpu29Objects'] == prior_runtime['cpu29Objects'] and len(runtime['cpu29Objects']) == 29 and
         runtime['allCPU29ObjectsAndProvidersWholeRuntime82'] is True and
         runtime['allCPUManifestEntriesWholeRuntime82'] is True and
         runtime['allParentFilesWholeRuntime82'] is True and
         runtime['actualChangedSignedRuntimeFiles'] == 2 and
         runtime['baselineRuntimeCandidate'] == old['runtimeCandidate'],
         'actual signed Runtime83 observes Child IO; all29 CPU objects/providers and all parent files whole Runtime82')
    port = json.loads(base.exact(runtime['childPortCandidate']).read_bytes())
    prior_manifest_for_child = plistlib.loads(base.exact(prior_runtime['manifest']).read_bytes())
    prior_child_row = next(row for row in prior_manifest_for_child['files']
                           if row['id'] == prior_manifest_for_child['childEntryContract']['childID'])
    prior_child_pin = pin(pathlib.Path(prior_runtime['runtimeRoot'])/prior_child_row['path'])
    need(port['baselineRuntimeCandidate'] == old['runtimeCandidate'] and
         port['originalChildMain'] == port['patchedChildMain'] == prior_child_pin and
         port['actualChildImportsChanged'] == 0 and port['actualChildImportsUnchanged'] == 1207 and
         port['actualChildWholeBytesUnchanged'] is True and port['existingFiveObserverImportRoutesWhole'] is True and
         runtime['currentChildImportsWholeUnchanged'] is True and runtime['currentChildCodeAndImportsWholeUnchanged'] is True,
         'MG implementation-only source delta; all1207 existing Child imports/code/PAC remain whole before resealing')
    for object_pin in runtime['cpu29Objects']:
        base.exact(object_pin)
    signature_pin = runtime['signatureVerification']
    signature = json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True, 'actual runtime signature pages and slots')
    manifest_path = base.exact(runtime['manifest'])
    manifest = plistlib.loads(manifest_path.read_bytes())
    prior_manifest = plistlib.loads(base.exact(prior_runtime['manifest']).read_bytes())
    need(manifest['entries'] == prior_manifest['entries'] and
         manifest['childEntryContract'] == prior_manifest['childEntryContract'],
         'every actual CPU/other manifest entry and child-entry contract whole Runtime82')
    cds = {'runtime/'+row['path']:row['cdhash'] for row in manifest['files'] if row['kind'] == 'mach-o'}
    signature_rows = {'runtime/'+row['relativePath']:row for row in signature['actualSignedFiles']}
    need(set(cds) == set(signature_rows) and all(signature_rows[name]['cdhash'] == value and
         signature_rows[name]['allPrimaryPagesAndSpecialSlotsVerified'] is True for name,value in cds.items()),
         'each actual Runtime83 manifest Mach-O joins its actual complete signature proof')
    prior_signature=json.loads(base.exact(prior_runtime['signatureVerification']).read_bytes())
    prior_signature_rows={row['relativePath']:row for row in prior_signature['actualSignedFiles']}
    need(all(row.get('embeddedEntitlements')==prior_signature_rows[row['relativePath']].get('embeddedEntitlements')
         for row in signature['actualSignedFiles']), 'all143 runtime entitlement sets whole Runtime82')
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
    need(len(files) == len(old['files']) == 259 and len(full) == len(set(full)) == 144 and
         len(changes) == 6 and len(new_cd) == 3 and sig['cdhash'] in new_cd,
         'same259 paths and144 code images; only6 changed files/3 new trust entries for Child/MG seal plus App anchor')
    manifest_rows = {row['id']:row for row in manifest['files']}
    changed_runtime_ids = (manifest['childEntryContract']['childID'],'child:VM27OwnedChildGestaltCompat.dylib',
                           'child-coderesources',manifest['dependencyProofID'])
    expected_changes = {MAIN,'runtime/'+pathlib.Path(runtime['manifest']['path']).name}
    expected_changes.update('runtime/'+manifest_rows[identity]['path']for identity in changed_runtime_ids)
    need({row['archivePath']for row in changes} == expected_changes,
         'only exact Child/MG helper/seal/graph/manifest plus Main anchor paths change; every other file whole')
    runtime_new_cd = sorted(set(cds.values()) - set(row['cdhash'] for row in old['files']
                            if row['archivePath'].startswith('runtime/') and 'cdhash' in row))
    need(len(runtime_new_cd) == 2 and runtime_new_cd == runtime['actualChangedRuntimeCDHashes'] and
         set(new_cd) == set(runtime_new_cd) | {sig['cdhash']},
         'only actual Child and MG helper CDs plus App anchor CD are newly trusted')
    for identity in ('parent:VM27HVVMProduction.dylib', 'child:VM27HVVMProduction.dylib'):
        new_row = next(row for row in manifest['files'] if row['id'] == identity)
        prior_row = next(row for row in prior_manifest['files'] if row['id'] == identity)
        need(new_row == prior_row, 'whole actual CPU provider manifest row '+identity)
    old_code_names = {row['cdhash']:row['archivePath'] for row in old['files'] if 'cdhash' in row}
    new_code_hashes = {row['archivePath']:row['cdhash'] for row in files if 'cdhash' in row}
    native_subset = [new_code_hashes[old_code_names[value]] for value in old['actualNativeCDSubset']]
    scope = {key: copy.deepcopy(old[key]) for key in ('deviceRuntime', 'deviceApp', 'deviceAppMain', 'deviceChildMain',
             'directories', 'continuingHumanAuthorization', 'sandboxProfileApplied', 'nativeSandboxApplyUnavailable',
             'nativeSandboxInitSuccessFabricated', 'fixedOwnedLogIdentity', 'bootSeconds', 'bootMicroseconds', 'bootSessionUUID')
             if key in old}
    scope.update(schema='Actual Runtime83 App100 native disk IO qualification device delta scope v85',
        oldScope=pin(OLD/'scope.json'), currentInstalledProductsPost=pin(POST), oldActualPost=pin(POST),
        baselineOriginalDev84InitializationSucceeded=False,
        baselineOriginalDev84AllSevenStandardActionsSucceeded=False,
        baselineOriginalDev84FirstFiveActionsSucceeded=True,
        baselineSuccessfulSameProductRetry=pin(RETRY/'candidate.json'),
        baselineSuccessfulSameProductRetryScope=pin(RETRY/'scope.json'),
        baselineInstalledProductsHealthProvenByActualNormal101Post=True,
        baselineControllerInheritedFromOriginalDev84Packet=True,
        deviceStage=STAGE, files=files, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        historicalInstalledRuntime82Verification=dict(deviceCandidate=pin(OLD/'candidate.json'),
            scope=pin(OLD/'scope.json'), freeze=pin(OLD/'freeze.json'), runtimeCandidate=old['runtimeCandidate'],
            sourceSignatureAndCPUContractsApplyToCompletedRuntime82DeploymentOnly=True),
        historicalInstalledApp99Candidate=old['appCandidate'],
        actualAll29CPUObjectsAndBothProvidersWholeRuntime82=True,
        actualChildCodeAndAll1207ImportsWholeRuntime82=True,
        actualOnlyMGImplementationChangedBeforeRuntimeResealing=True,
        actualChangedCPUObjects=0, actualUnchangedCPUObjects=29,
        inheritedActualSignedRuntimeCDProof=signature_pin,
        actualMain32AndOther33CompiledObjectsWholeUnchanged=True, actualUARTAndBootArgsObjectsWholeApp99=True, actualChangedAppObjectIndices=[34], actualOnlyRelinkedRuntimeAnchor=True,
        actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
        trustCacheCDHashes=full, newTrustCacheCDHashes=new_cd, trustCacheRegistrationCount=len(new_cd),
        trustCacheFixedBatchCounts=[len(new_cd)], actualFullCodeDirectoryHashes=len(full),
        actualRuntimeManifestFiles=len(manifest['files']), actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count,
        deltaFiles=changes, existingOwnFilesUpdated=len(changes), actualChangedFiles=len(changes),
        unchangedFiles=len(files)-len(changes), unchangedSignedImages=len(full)-len(new_cd),
        newOwnFilesAdded=0, newOwnDirectories=[], newOwnResourceFiles=[],
        runtimeAllWholebytesUnchanged=False, runtimeProductAndAllFilesWholeUnchanged=False,
        originalMainAppResourcesAllWholebytesUnchanged=True,
        all259DevicePathsModesAndDirectoriesSame=True, backupOldOwnFilesAndLog=True,
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
        need(old['deviceStage'] in raw, 'actual Dev84 action stage identity')
        return raw.replace(old['deviceStage'], STAGE)

    def replace_once(body, before_value, after_value, reason):
        need(body.count(before_value) == 1, 'one exact Dev84 block: '+reason)
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
             'actual Dev84 outer wrapper byte-whole after stage substitution: '+action)
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
                 'exact executed Dev84 trust adds and whole membership parser')
            tail = '(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
            for index,value in enumerate(new_cd, 1):
                tail += 'jbctl trustcache add '+value+"\nprintf 'OWN_NEW_PRODUCT_TC_ADDED "+str(index)+' '+value+"\\n'\n"
            tail += trust_check(full)+"printf 'INDEPENDENT27_ONLY_ACTUAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE\\n'\n"
            body = replace_once(body, old_tail, tail, 'actual new trust adds and exact all144 actual membership')
        scripts[action] = rewrap(raw, body)
    scripts['stage'] = wrap(stage_body(scope, archive), 0, 90)
    actions = list(base.ACTIONS); scripts = {action: scripts[action] for action in actions}
    controller = (OLD/'control.py').read_text().replace(old['deviceStage'], STAGE)
    need(controller.replace(STAGE, old['deviceStage']) == (OLD/'control.py').read_text(),
         'Dev84 controller protocol/ready/auth/once/cleanup byte-whole except stage name')
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
                    fromfile='Dev84/'+action+'.sh', tofile='Dev85/'+action+'.sh'))
        unwrapped_diff.extend(difflib.unified_diff(unwrap((OLD/(action+'.sh')).read_text()).splitlines(True),
                    unwrap(script).splitlines(True), fromfile='Dev84/'+action+'.body', tofile='Dev85/'+action+'.body'))
    diff.extend(difflib.unified_diff((OLD/'control.py').read_text().splitlines(True), controller.splitlines(True),
                fromfile='Dev84/control.py', tofile='Dev85/control.py'))
    (out/'scripts-from-device84.diff').write_text(''.join(diff))
    (out/'scripts-unwrapped-from-device84.diff').write_text(''.join(unwrapped_diff))
    dump(out/'script-delta.json', dict(schema='Exact generated Dev84 to disk IO qualification Dev85 finite script delta v1',
         baseline=pin(OLD/'candidate.json'), baselineScope=pin(OLD/'scope.json'),
         controllerBefore=pin(OLD/'control.py'), controllerAfter=pin(out/'control.py'),
         controllerOnlyStageNameChanged=True, closeOnlyStageNameChanged=True,
         sameActualDev84TimeoutsAndProcessProtocol=True, transformations=operations,
         stageGeneratedFrom='Executed Dev84 bounded stage and exact backup/pending/rename/log protocol',
         stageOnlyListedOwnedDeltaFilesAndExistingLogWritten=True,
         fullActualScriptsDiff=pin(out/'scripts-from-device84.diff'),
         fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device84.diff'),
         scriptPairs={action:dict(before=pin(OLD/(action+'.sh')), after=rows[action]) for action in actions}))
    candidate = dict(schema='Actual Runtime83 App100 native disk IO qualification device packet v85', preparer=pin(__file__),
        scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'), scripts=rows,
        actions=actions, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        currentInstalledProductsPost=pin(POST), oldDeviceCandidate=pin(OLD/'candidate.json'),
        scriptDelta=pin(out/'script-delta.json'), fullActualScriptsDiff=pin(out/'scripts-from-device84.diff'),
        fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-device84.diff'),
        actualFullFiles=259, actualFullCodeDirectoryHashes=144, actualChangedFiles=len(changes), actualExistingFilesUpdated=len(changes),
        actualNewFilesAdded=0, actualNewDirectoriesAdded=0, actualNewTrustEntries=len(new_cd),
        onlyOneLife65ObjectChanged=False, all29CPUObjectsAndBothProvidersWholeRuntime82=True, actualChildCodeAndAll1207ImportsWholeRuntime82=True, actualCPUCurrentSource=runtime['cpu29SourceProof'], actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count, all103AppResourcesWholeUnchanged=True,
        all259DevicePathsModesAndDirectoriesSame=True, continuingHumanAuthorization=scope['continuingHumanAuthorization'],
        bootSeconds=BOOT, bootSessionUUID=UUID, closeOwnExternalWallSeconds=20,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        allOtherRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        exactDev84ControllerOnlyStageNameChanged=True, repeatedRuntime65To66SourceAdmissionNotApplied=True,
        baselineOriginalDev84InitializationSucceeded=False,
        baselineOriginalDev84AllSevenStandardActionsSucceeded=False,
        baselineOriginalDev84FirstFiveActionsSucceeded=True,
        baselineSuccessfulSameProductRetry=pin(RETRY/'candidate.json'),
        baselineSuccessfulSameProductRetryLaunchPostSucceeded=True,
        baselineInstalledProductsHealthProvenByActualNormal101Post=True,
        newPacketRequiresAllSevenStandardActionsAndFreshReadyAuthorization=True,
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
             pin(app_path), app['sourceCandidate'],
             scope['continuingHumanAuthorization'], pin(POST), post['request'], post['stdout'], post['stderr']]
    pins += prior_receipt_pins + retry_receipt_pins + [pin(RETRY/'candidate.json'),pin(RETRY/'scope.json'),
         pin(EXPECTED_POST.parents[2]/'candidate.json'),runtime['childPortCandidate']] + list(prior['scripts'].values())+[row['local'] for row in files]+[changed['old'] for changed in changes]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
         deviceOperations=0, codeSigningOperations=0, repeatedHistoricalSourceDeltaAdmission=False))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), scope=pin(out/'scope.json'),
         freeze=pin(out/'freeze.json'), delta=pin(out/'script-delta.json'),
         files=len(files), CDs=len(full), changedFiles=len(changes), newTC=len(new_cd), maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
