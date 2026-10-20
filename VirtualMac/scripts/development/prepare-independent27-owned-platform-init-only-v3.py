#!/usr/bin/env python3
"""HOST prepare bounded initialization for the actually observed new boot.

All installed products remain unchanged. Trust restoration is derived only
from Root's actual complete read-only inventory for this same boot session.
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

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
OLD = N / 'independent27-owned-platform-init-only-v1-attempt1'
FACTS = N / 'init-only-current-device-facts-readonly-v1-attempt1/receipt.json'
BOOT = 1791813884
STAGE = '/private/var/mobile/Library/.VM27-independent27-init-only-v3'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = load(OLD / 'control.py', 'new_boot_owned_platform_controller_base')
previous = load(B / 'prepare-independent27-owned-platform-init-only-v1.py', 'old_readiness_source')
fast = load(B / 'independent27_device_product_verify_fast_v1.py', 'new_boot_fast_verify')
pin, need, dump = base.pin, base.need, base.dump


def wrap(body, uid, seconds=45):
    return base.prefix(uid) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 ' + str(seconds) + ' /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'


def trust_check(all_hashes, present):
    values = ';'.join('expected["' + x + '"]=1' for x in all_hashes)
    awk = 'BEGIN {' + values + '} {v=tolower($NF);if(length(v)==40 && v~/^[[:xdigit:]]+$/ && (v in expected))found[v]=1} END {for(v in found)print v}'
    return '''own_actual_trust_info=$(jbctl trustcache info)
own_actual_present=$(printf '%s\n' "$own_actual_trust_info" | awk ''' + shlex.quote(awk) + ''' | sort)
[ "$own_actual_present" = ''' + shlex.quote('\n'.join(sorted(present))) + ''' ]
printf 'INDEPENDENT27_ACTUAL_OWN_TRUST_MEMBERSHIP_EXACT\n'
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--trust-plan', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve(); plan_path = args.trust_plan.resolve()
    need(out.parent == N and not out.exists(), 'fresh new boot packet')
    for row in json.loads((OLD / 'freeze.json').read_bytes())['files']:
        base.exact(row)
    old_candidate = json.loads((OLD / 'candidate.json').read_bytes())
    old_scope = json.loads((OLD / 'scope.json').read_bytes())
    facts = json.loads(FACTS.read_bytes())
    base.exact(facts['request']); facts_text = base.exact(facts['stdout']).read_text(); base.exact(facts['stderr'])
    need(facts['transportExit'] == 0 and facts['readOnly'] is True and facts['deviceWrites'] == 0 and
         f'BOOT_TIME {{ sec = {BOOT}, usec = 70222 }}' in facts_text and
         'MODEL iPad14,6\nKERNEL 22.1.0\nBUILD 20B101\n' in facts_text and
         'OWN_CURRENT_ABSENT /tmp/VirtualMacIndependent27.log' in facts_text,
         'actual successful new boot read-only facts')
    processes = re.findall(r'^OWN_CURRENT_PROCESS\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(\S+)$', facts_text, re.M)
    need(processes == [('1673', '1', '501', base.APP_MAIN)], 'actual only current canonical own App')
    plan = json.loads(plan_path.read_bytes())
    inventory = old_scope['trustCacheCDHashes']
    need(plan['bootSeconds'] == BOOT and plan['inventoryScope'] == pin(OLD / 'scope.json') and
         plan['all140CDHashes'] == inventory and plan['readOnlyQueryPassed'] is True and
         plan['trustCacheOperations'] == 0, 'actual read-only trust plan for same boot/inventory')
    present, missing = plan['presentCDHashes'], plan['missingCDHashes']
    need(len(inventory) == len(set(inventory)) == 140 and
         len(present) == len(set(present)) and len(missing) == len(set(missing)) and
         set(present).isdisjoint(missing) and set(present) | set(missing) == set(inventory),
         'actual complete disjoint present/missing self-code inventory')
    query = json.loads(base.exact(plan['actualQueryReceipt']).read_bytes())
    base.exact(query['request']); base.exact(query['stderr'])
    need(query['transportExit'] == 0 and query['stdout'] == plan['actualQueryStdout'],
         'actual successful query stdout identity')
    base.exact(plan['actualQueryStdout'])
    old_health = base.HEALTH.read_text()
    need(old_health.count('1791354846') == 1, 'one old frozen health boot guard')
    health = old_health.replace('1791354846', str(BOOT))
    old_prefix = base.prefix
    base.DEVICE_STAGE = STAGE
    # Instance-only function substitution; no old source file is modified.
    base.prefix = lambda uid: old_prefix(uid).replace('1791354846', str(BOOT))
    scope = copy.deepcopy(old_scope)
    scope['historicalPriorBootInitializationOnly'] = dict(candidate=pin(OLD / 'candidate.json'),
        currentInstalledProductsPost=scope['currentInstalledProductsPost'], retainedCurrentLog=scope.pop('retainedCurrentLog'))
    scope.update(schema='Already installed independent27 new boot initialization scope v3',
         bootSeconds=BOOT, bootMicroseconds=70222, currentDeviceFacts=pin(FACTS),
         currentBootTrustPlan=pin(plan_path), deviceStage=STAGE,
         currentInstalledProductsPost=None, installedProductsCurrentBootVerificationRequired=True,
         oldActualPost=None, priorHistoricalInstalledProductsPost=old_scope['currentInstalledProductsPost'],
         newTrustCacheCDHashes=missing, trustCacheRegistrationCount=len(missing),
         trustCacheFixedBatchCounts=([len(missing)] if missing else []),
         restoredExistingProductCDHashes=missing, newProductCodeHashes=[],
         trustMembershipKnownBeforeDispatch=True, trustMembershipAssumedFromPriorBoot=False,
         actualOwnAppPIDObserved=1673, currentAppCloseExternalWallSeconds=20,
         missingOwnLogMayBeCreated=True, existingOwnLogMustBeBackedUpBeforeTruncation=True,
         initializationOnly=True, productInstallationPerformed=False, productUpdatesPerformed=False,
         productionBundleMutation=False, globalAutoBootMutation=False,
         diagnosticDirectoryAndOwnLogWritesOnly=True)
    all_products = fast.batch_check(scope)
    native_cd_subset = ['e43846ee132f920ab8d6fdfb3adef64184368de6',
                        '464c666df31f9853e3ff73ce6f652359fa644d72',
                        'c8e5ae89c4cdb2c197eb206fde4aa29e3be62385']
    need(set(native_cd_subset).issubset(inventory), 'exact App/child/premain actual native CD subset')
    runtime = json.loads(base.exact(scope['runtimeCandidate']).read_bytes())
    signature_proof = runtime['signatureVerification']
    signed = json.loads(base.exact(signature_proof).read_bytes())
    app_peer_path = N / 'independent27-app10-runtime8-signed-product-independent-peer-v2-attempt1/review.json'
    app_peer = json.loads(app_peer_path.read_bytes())
    need(len(signed['actualSignedFiles']) == 139 and
         signed['allCodePagesAndSpecialSlotsActuallyVerified'] is True and
         signed['allCodeDirectoriesPrimarySHA256'] is True and
         app_peer['passed'] is True and app_peer['findings'] == [] and
         app_peer['signedCandidate'] == scope['appCandidate'] and
         app_peer['runtimeCandidate'] == scope['runtimeCandidate'],
         'actual immutable full139 runtime signatures and real App product peer')
    by_hash = {row['cdhash']: row for row in scope['files'] if 'cdhash' in row}
    for row in signed['actualSignedFiles']:
        need(row['allPrimaryPagesAndSpecialSlotsVerified'] is True and
             row['actualSignedFile'] == by_hash[row['cdhash']]['local'],
             'each inherited runtime signed CD joins exact unchanged wholefile')
    scope['exactFullProductsAndSignedCDProofInherited'] = True
    scope['actualNativeCDSubset'] = native_cd_subset
    scope['actualNativeCDSubsetCount'] = 3
    scope['all140NativeCodeDirectoriesRequeried'] = False
    scope['inheritedActualSignedRuntimeCDProof'] = signature_proof
    scope['inheritedActualSignedAppPeer'] = pin(app_peer_path)
    all_cd = fast.cd_check(scope, native_cd_subset)
    stage_check = '''[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
    close = base.prefix(0) + base.PROCESS_FUNCTIONS + '''
scan_own
[ "$own_app_pid" = 0 ] || [ "$own_app_pid" = 1673 ]
cleanup_own
''' + base.off_check() + "printf 'INDEPENDENT27_CURRENT_BOOT_EXACT_OWN_APP_CHILD_CLOSED_NO_PRODUCT_OR_TC_WRITE\\n'\n"
    preflight = base.prefix(0) + base.off_check() + health + all_products + all_cd + '''
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
''' + stage_check + '''
if [ -e "$OWN_LOG" ] || [ -L "$OWN_LOG" ]; then
 [ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
 [ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
 [ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
 own_prior_log_metadata=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
 own_prior_log_hash=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
 cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
 [ "$(stat -c %u:%g:%a:%h "$OWN_STAGE/backup-app-log")" = 501:501:600:1 ]
 [ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_prior_log_hash" ]
 [ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_prior_log_metadata" ]
 [ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_prior_log_hash" ]
 printf 'OWN_PRIOR_LOG_BACKED_UP metadata=%s sha256=%s\n' "$own_prior_log_metadata" "$own_prior_log_hash"
else
 [ ! -e "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
 (umask 077; set -C; : > "$OWN_LOG")
 chown 501:501 "$OWN_LOG"
 chmod 600 "$OWN_LOG"
 [ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
 (umask 077; set -C; : > "$OWN_STAGE/prior-app-log-absent")
 printf 'OWN_NEW_EMPTY_ORDINARY_APP_LOG_CREATED_UID501_MODE600\n'
fi
(umask 077; set -C; : > "$OWN_STAGE/init-preflight-complete")
printf 'INDEPENDENT27_NEW_BOOT_INIT_PREFLIGHT_ALL253_AND3_NATIVE_CD_EXACT_NO_PRODUCT_UPDATES\n'
'''
    restore = base.prefix(0) + base.off_check() + all_products + stage_check + '''
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/init-preflight-complete")" = 0:0:600:1:0 ]
''' + trust_check(inventory, present) + '''(umask 077; set -C; : > "$OWN_STAGE/restore-trust-dispatched")
'''
    for i, value in enumerate(missing, 1):
        restore += 'jbctl trustcache add ' + value + "\nprintf 'OWN_EXISTING_PRODUCT_TC_RESTORED " + str(i) + ' ' + value + "\\n'\n"
    restore += trust_check(inventory, inventory) + "printf 'INDEPENDENT27_CURRENT_BOOT_ALL140_OWN_CODE_TRUST_PRESENT\\n'\n"
    _, launch_body = previous.unwrap((OLD / 'launch.sh').read_text())
    launch_body = launch_body.replace('1791354846', str(BOOT)).replace(old_scope['deviceStage'], STAGE)
    start = launch_body.index('[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]\n', launch_body.index(base.PROCESS_FUNCTIONS.strip()))
    stop = launch_body.index('own_log_inode=', start)
    new_log = '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_prior_log_inode=$(stat -c %d:%i "$OWN_LOG")
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_prior_log_inode" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
'''
    launch_body = launch_body[:start] + new_log + launch_body[stop:]
    need(launch_body.count(previous.READINESS) == 1 and
         launch_body.count(base.PROCESS_FUNCTIONS.strip()) == 1,
         'stable2s gate and exact process cleanup wholebyte unchanged')
    post_script = (OLD / 'post.sh').read_text().replace('1791354846', str(BOOT)).replace(old_scope['deviceStage'], STAGE)
    scripts = {'close-current-own': wrap(close, 0, 20), 'preflight': wrap(preflight, 0),
               'restore-trust': wrap(restore, 0), 'launch': wrap(launch_body, 501), 'post': post_script}
    controller = (OLD / 'control.py').read_text().replace(old_scope['deviceStage'], STAGE).replace('1791354846', str(BOOT))
    controller = controller.replace('TRUST_ACTIONS = ()', "TRUST_ACTIONS = ('restore-trust',)")
    controller = controller.replace("ACTIONS = ('preflight', 'launch', 'post')",
                                    "ACTIONS = ('close-current-own', 'preflight', 'restore-trust', 'launch', 'post')")
    gate_start = controller.index("    need(scope.get('initializationOnly') is True")
    gate_stop = controller.index('    return ready, scope', gate_start)
    controller = controller[:gate_start] + '''    plan = json.loads(exact(scope['currentBootTrustPlan']).read_bytes())
    current = json.loads(exact(scope['currentDeviceFacts']).read_bytes())
    need(current['transportExit'] == 0 and current['readOnly'] is True and
         plan['readOnlyQueryPassed'] is True and plan['bootSeconds'] == scope['bootSeconds'] == 1791813884 and
         plan['missingCDHashes'] == scope['newTrustCacheCDHashes'] and
         plan['all140CDHashes'] == scope['trustCacheCDHashes'] and
         scope['trustCacheRegistrationCount'] == len(plan['missingCDHashes']) and
         scope['initializationOnly'] is True and scope['deltaFiles'] == [] and
         scope['actualChangedFiles'] == 0 and scope['productInstallationPerformed'] is False and
         scope['productUpdatesPerformed'] is False and len(scope['files']) == 253,
         'new boot concrete init-only scope and actual missing trust inventory')
    query = json.loads(exact(plan['actualQueryReceipt']).read_bytes())
    need(query['transportExit'] == 0 and query['stdout'] == plan['actualQueryStdout'],
         'actual successful trust query')
    exact(plan['actualQueryStdout'])
''' + controller[gate_stop:]
    controller = controller.replace("    previous = {'launch': 'preflight', 'post': 'launch'}.get(args.action)",
        "    previous = {'preflight': 'close-current-own', 'restore-trust': 'preflight', 'launch': 'restore-trust', 'post': 'launch'}.get(args.action)")
    controller = controller.replace('HEALTH = N/\'cpu-owned-gic-counter-controller-v2/health-root.sh\'',
                                    "HEALTH = pathlib.Path(__file__).resolve().parent/'health-root.sh'")
    need("HEALTH = pathlib.Path(__file__).resolve().parent/'health-root.sh'" in controller,
         'new real health clone exported to readonly/normal producers')
    compile(controller, str(out / 'control.py'), 'exec')
    out.mkdir(mode=0o700)
    (out / 'health-root.sh').write_text(health)
    (out / 'control.py').write_text(controller)
    (out / 'readiness-loop.sh').write_text(previous.READINESS)
    dump(out / 'scope.json', scope)
    script_rows, sizes = {}, {}
    for action, script in scripts.items():
        result = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True)
        need(result.returncode == 0, 'actual finite shell syntax: ' + action)
        (out / (action + '-syntax.stderr')).write_bytes(result.stderr)
        (out / (action + '.sh')).write_text(script)
        script_rows[action] = pin(out / (action + '.sh'))
        command = ('sudo -k -S -p "" ' if action != 'launch' else '') + '/var/jb/bin/sh -c ' + shlex.quote(script)
        sizes[action] = len(command.encode())
        need(sizes[action] + 10000 < 262144, 'actual iPad ARG_MAX with environment reserve')
    candidate = dict(schema='Prepared already installed independent27 new boot initialization packet v3',
         preparer=pin(__file__), scope=pin(out / 'scope.json'), controller=pin(out / 'control.py'),
         scripts=script_rows, actions=list(scripts), currentDeviceFacts=pin(FACTS), currentBootTrustPlan=pin(plan_path),
         runtimeCandidate=old_candidate['runtimeCandidate'], appCandidate=old_candidate['appCandidate'],
         continuingHumanAuthorization=scope['continuingHumanAuthorization'], actualChangedFiles=0,
         actualNewTrustEntries=len(missing), restoredExistingProductCDHashes=missing,
         actualFullFiles=253, actualFullCodeDirectoryHashes=140, bootSeconds=BOOT,
         priorController=pin(OLD / 'control.py'), priorPacket=pin(OLD / 'candidate.json'),
         initializationOnly=True, health=pin(out / 'health-root.sh'), healthOnlyOneBootConstantChanged=True,
         readinessLoop=pin(out / 'readiness-loop.sh'), readinessStableParentChildSeconds=2,
         exactFullProductsAndSignedCDProofInherited=True, actualNativeCDSubset=native_cd_subset,
         actualNativeCDSubsetCount=3, inheritedActualSignedRuntimeCDProof=signature_proof,
         inheritedActualSignedAppPeer=pin(app_peer_path),
         processIdentityCleanupAndTransportFunctionsUnchanged=True,
         appRegistrationRepeated=False, closeOwnExternalWallSeconds=20,
         initializationExternalWallSeconds=45, restoreTrustExternalWallSeconds=45, transportTimeoutSeconds=55,
         productInstallationPerformed=False, productUpdatesPerformed=False,
         maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
         sandboxProfileApplied=False, nativeSandboxApplyUnavailable=45, nativeSandboxInitSuccessFabricated=False,
         actualOwnedPlatformPreparationExecuted=False, diagnosticDirectoryAndOwnLogWritesOnly=True,
         deviceOperations=0, trustCacheOperations=0, guestBootRequested=False, readyForDeviceExecution=False)
    dump(out / 'candidate.json', candidate)
    files = [pin(p) for p in out.iterdir() if p.is_file()]
    files += [pin(__file__), pin(FACTS), facts['request'], facts['stdout'], facts['stderr'], pin(plan_path),
              plan['actualQueryReceipt'], query['request'], query['stdout'], query['stderr'],
              pin(OLD / 'candidate.json'), pin(OLD / 'freeze.json'), pin(OLD / 'scope.json'),
              pin(OLD / 'control.py'), pin(OLD / 'launch.sh'), pin(OLD / 'post.sh'),
              pin(B / 'prepare-independent27-owned-platform-init-only-v1.py'), pin(base.HEALTH),
              pin(B / 'independent27_device_product_verify_fast_v1.py'), scope['continuingHumanAuthorization'],
              scope['runtimeCandidate'], scope['appCandidate']]
    files += [row['local'] for row in scope['files']]
    files += [signature_proof, pin(app_peer_path),
              pin(B / 'prepare-independent27-owned-platform-init-only-v2.py'),
              pin(N / 'independent27-owned-platform-init-only-v2-attempt1/candidate.json'),
              pin(N / 'independent27-owned-platform-init-only-v2-attempt1/freeze.json')]
    timed_out = N / 'independent27-owned-platform-init-only-v2-attempt1/device-receipts/preflight/receipt.json'
    timeout_receipt = json.loads(timed_out.read_bytes())
    need(timeout_receipt['transportExit'] == 124 and
         'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in base.exact(timeout_receipt['stdout']).read_text(),
         'true full253 pass before prior140serialCD timeout, no assumed success')
    files += [pin(timed_out), timeout_receipt['request'], timeout_receipt['stdout'], timeout_receipt['stderr']]
    dump(out / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), scope=pin(out / 'scope.json'),
                          freeze=pin(out / 'freeze.json'), restoredEntries=len(missing),
                          maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
