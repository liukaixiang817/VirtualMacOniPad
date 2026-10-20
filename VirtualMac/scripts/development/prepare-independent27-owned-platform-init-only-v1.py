#!/usr/bin/env python3
"""HOST prepare one init-only observation of the already installed 253 files.

No install archive, product replacement, trust registration or device call.
Only Root may dispatch a reviewed packet using continued human authorization.
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
OLD = N / 'independent27-owned-platform-device-v1-attempt1'
STAGE = '/private/var/mobile/Library/.VM27-independent27-init-only-v1'
PREPARED = ('VM27 owned platform launchPrepared=1 sandboxProfileApplied=0 '
            'nativeSandboxApplyUnavailable=45 nativeLastDiagnosticErrno=45 '
            'policyDeferred=1 trustedGuestOwnedProcess=1')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = load(OLD / 'control.py', 'actual_installed_owned_platform_controller')
fast = load(B / 'independent27_device_product_verify_fast_v1.py', 'init_only_fast_verify')
pin, need, dump = base.pin, base.need, base.dump


def frozen(directory):
    for row in json.loads((directory / 'freeze.json').read_bytes())['files']:
        base.exact(row)


def unwrap(script):
    start = script.index('/var/jb/usr/bin/timeout')
    where = script.index('/var/jb/bin/sh -c ', start) + len('/var/jb/bin/sh -c ')
    values = shlex.split(script[where:])
    need(len(values) == 1, 'one existing bounded shell body')
    return script[:start], values[0]


READINESS = r'''own_wait=0
own_result=none
own_stable_seconds=0
own_stable_identity=none
while [ "$own_wait" -lt 30 ]; do
 scan_own
 [ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_inode" ]
 [ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
 [ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
 own_result_count=$(awk '/^\[Independent27\] runtime-startup result=/ {n++} END {print n+0}' "$OWN_LOG")
 [ "$own_result_count" -le 1 ]
 if [ "$own_result_count" = 1 ]; then
  own_result=$(awk '/^\[Independent27\] runtime-startup result=/ {print}' "$OWN_LOG")
  [ "$own_result" = '[Independent27] runtime-startup result=1 errorDomain= errorCode=0 error=' ]
 fi
 own_prepared_count=$(awk '/^VM27 owned platform launchPrepared=/ {n++} END {print n+0}' "$OWN_LOG")
 [ "$own_prepared_count" -le 1 ]
 own_hello_count=$(awk '/^\[Independent27\] parent-hello install-factory/ {n++} END {print n+0}' "$OWN_LOG")
 [ "$own_hello_count" -le 1 ]
 own_child_prepare_count=$(awk '/^\[Independent27\] child-prepare/ {n++} END {print n+0}' "$OWN_LOG")
 [ "$own_child_prepare_count" -le 1 ]
 if [ "$own_result_count" = 1 ] && [ "$own_prepared_count" = 1 ] &&
    [ "$own_hello_count" = 1 ] && [ "$own_child_prepare_count" = 1 ] &&
    [ "$own_app_pid" -gt 1 ] && [ "$own_child_pid" -gt 1 ] &&
    [ -n "$app_rows" ] && [ -n "$child_rows" ]; then
  grep -F -x 'VM27 owned platform launchPrepared=1 sandboxProfileApplied=0 nativeSandboxApplyUnavailable=45 nativeLastDiagnosticErrno=45 policyDeferred=1 trustedGuestOwnedProcess=1' "$OWN_LOG" >/dev/null
  grep -F -x '[Independent27] parent-hello install-factory status=0 nativeDetailsAvailable=0' "$OWN_LOG" >/dev/null
  grep -F -x '[Independent27] child-prepare status=0 pid='"$own_child_pid"' ppid='"$own_app_pid"' uid=501 euid=501 acquiredOwnerReturned=1 helloReturned=1' "$OWN_LOG" >/dev/null
  if ps -p "$own_app_pid" -o stat= | awk 'NF==1 && $1 !~ /^[ZTX]/ {ok=1} END {exit !ok}' &&
     ps -p "$own_child_pid" -o stat= | awk 'NF==1 && $1 !~ /^[ZTX]/ {ok=1} END {exit !ok}'; then
   own_identity="$own_app_pid:$own_app_start:$own_child_pid:$own_child_start"
   if [ "$own_stable_identity" = "$own_identity" ]; then
    own_stable_seconds=$((own_stable_seconds+1))
   else own_stable_identity=$own_identity;own_stable_seconds=0;fi
   if [ "$own_stable_seconds" -ge 2 ]; then break;fi
  else own_stable_identity=none;own_stable_seconds=0;fi
 else own_stable_identity=none;own_stable_seconds=0;fi
 sleep 1;own_wait=$((own_wait+1))
done
printf 'OWN_ACTUAL_RUNTIME_RESULT %s\n' "$own_result"
[ "$own_result" = '[Independent27] runtime-startup result=1 errorDomain= errorCode=0 error=' ]
[ "$own_stable_seconds" -ge 2 ]
[ "$own_app_pid" -gt 1 ] && [ "$own_child_pid" -gt 1 ]
[ -n "$app_rows" ] && [ -n "$child_rows" ]
printf 'OWN_PARENT_CHILD_PREPARED_STABLE_SECONDS 2\n'
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh init-only packet')
    frozen(OLD)
    old_candidate = json.loads((OLD / 'candidate.json').read_bytes())
    old_scope = json.loads((OLD / 'scope.json').read_bytes())
    post_path = OLD / 'device-receipts/post/receipt.json'
    post = json.loads(post_path.read_bytes())
    base.exact(post['request']); text = base.exact(post['stdout']).read_text(); base.exact(post['stderr'])
    post_request = json.loads(base.exact(post['request']).read_bytes())
    need(post['transportExit'] == 0 and post_request['packetCandidate'] == pin(OLD / 'candidate.json') and
         'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in text and
         'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in text and
         'INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED' in text,
         'true prior successful off/products/health receipt')
    matches = re.findall(r'^OWN_RETAINED_LOG_BYTES ([0-9]+)$', text, re.M)
    hashes = re.findall(r'^OWN_RETAINED_LOG_SHA256 ([a-f0-9]{64})  /tmp/VirtualMacIndependent27.log$', text, re.M)
    need(matches == ['2341'] and len(hashes) == 1 and hashes[0] ==
         'f6d6da2e5fb14f3fe6fcb71c44fe06eb904f34e621b7f8dc6ac3ede64a2f2a48',
         'exact actual retained current log')
    launch_path = OLD / 'device-receipts/launch/receipt.json'
    launch = json.loads(launch_path.read_bytes())
    old_launch_text = base.exact(launch['stdout']).read_text()
    base.exact(launch['request']); base.exact(launch['stderr'])
    need(launch['transportExit'] == 1 and old_launch_text.count(PREPARED) == 1 and
         'OWN_ACTUAL_RUNTIME_RESULT [Independent27] runtime-startup result=1' in old_launch_text,
         'actual failed controller race while true owned preparation completed')
    current_log = old_launch_text.split('OWN_APP_LOG_BEGIN\n', 1)[1].split('\nOWN_APP_LOG_END', 1)[0].encode()
    need(len(current_log) == 2341 and base.digest(current_log) == hashes[0],
         'retained log exact actual launch stdout section')
    register = json.loads((OLD / 'device-receipts/launch/register-receipt.json').read_bytes())
    need(register['transportExit'] == 0, 'prior real app registration already succeeded')
    base.exact(register['stdout']); base.exact(register['stderr'])
    scope = copy.deepcopy(old_scope)
    historical = {}
    for key in ('archive', 'deltaArchiveBytes', 'deltaArchiveSHA256', 'deltaFiles', 'newOwnDirectories',
                'newOwnResourceFiles', 'trustCacheFixedBatchCounts', 'existingOwnFilesUpdated', 'newOwnFilesAdded'):
        historical[key] = scope.pop(key)
    scope['historicalInstalledOwnedPlatformDeltaOnly'] = dict(scope=pin(OLD / 'scope.json'), priorFields=historical)
    scope.update(schema='Already installed independent27 init-only finite scope v1',
         deviceStage=STAGE, oldActualPost=pin(post_path), currentInstalledProductsPost=pin(post_path),
         oldScope=pin(OLD / 'scope.json'), newTrustCacheCDHashes=[], trustCacheRegistrationCount=0,
         trustCacheFixedBatchCounts=[], deltaFiles=[], existingOwnFilesUpdated=0, newOwnFilesAdded=0,
         newOwnDirectories=[], newOwnResourceFiles=[], unchangedFiles=253, unchangedSignedImages=140,
         productInstallationPerformed=False, productUpdatesPerformed=False, actualChangedFiles=0,
         appRegistrationRepeated=False, actualFullCodeInventoryForVerificationOnly=True,
         initializationOnly=True, actualOwnedPlatformPreparationObservedInPriorLaunch=True,
         readinessRequiresExactOwnedPreparationMarker=True, readinessStableParentChildSeconds=2,
         retainedCurrentLog=dict(bytes=2341, sha256=hashes[0]),
         priorInitializationLaunch=pin(launch_path), priorAppRegistration=pin(OLD / 'device-receipts/launch/register-receipt.json'),
         backupOldOwnFilesAndLog=False, backupPriorOwnLogOnly=True,
         sameLogInodeMayBeTruncatedOnlyForNewInitialization=True)
    need(len(scope['files']) == 253 and len(scope['trustCacheCDHashes']) == 140 and
         len(set(scope['trustCacheCDHashes'])) == 140, 'same actual 253/140 installed inventory')
    for row in scope['files']:
        base.exact(row['local'])
    base.DEVICE_STAGE = STAGE
    prefix = base.prefix
    bounded = lambda body, uid: prefix(uid) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
    all_products = fast.batch_check(scope)
    stage_check = '''[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
    log_check = '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:2341 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = ''' + hashes[0] + '\n'
    preflight = prefix(0) + base.off_check() + base.HEALTH.read_text() + all_products + log_check + '''
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
''' + stage_check + '''cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/backup-app-log")" = 501:501:600:1:2341 ]
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = ''' + hashes[0] + '''
(umask 077; set -C; : > "$OWN_STAGE/init-preflight-complete")
printf 'INDEPENDENT27_INIT_ONLY_PREFLIGHT_COMPLETE_ZERO_PRODUCT_UPDATES_ZERO_TC\n'
'''
    outer, body = unwrap((OLD / 'launch.sh').read_text())
    body = body.replace(old_scope['deviceStage'], STAGE)
    need(body.count('[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]') == 1,
         'one inherited empty log guard')
    empty_log_guard = '[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]'
    body = body.replace(empty_log_guard, log_check + '''own_prior_log_inode=$(stat -c %d:%i "$OWN_LOG")
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_prior_log_inode" ]
''' + empty_log_guard, 1)
    start = body.index('own_wait=0\nown_result=none\n')
    stop = body.index('own_accept_count=', start)
    old_wait = body[start:stop]
    need('break\n' in old_wait and '[ "$own_child_pid" -gt 1 ]' in old_wait,
         'exact original premature-result wait span')
    body = body[:start] + READINESS + body[stop:]
    need(body.count(base.PROCESS_FUNCTIONS.strip()) == 1,
         'original exact process identity and cleanup functions unchanged')
    launch_script = bounded(body, 501)
    post_script = (OLD / 'post.sh').read_text().replace(old_scope['deviceStage'], STAGE)
    scripts = {'preflight': bounded(preflight, 0), 'launch': launch_script, 'post': post_script}
    source = (OLD / 'control.py').read_text()
    head = source[:source.index('\ndef ready_gate(')]
    head = head.replace(old_scope['deviceStage'], STAGE)
    head = head.replace("TRUST_ACTIONS = ('trust',)", 'TRUST_ACTIONS = ()')
    head = head.replace("ACTIONS = ('close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')",
                        "ACTIONS = ('preflight', 'launch', 'post')")
    ready = source[source.index('\ndef ready_gate('):source.index('\ndef run_remote(')]
    cut = ready.index("    raw = (packet/'products.tar').read_bytes()")
    ready = ready[:cut] + '''    need(scope.get('initializationOnly') is True and scope['newTrustCacheCDHashes'] == [] and
         scope['trustCacheRegistrationCount'] == 0 and scope['deltaFiles'] == [] and
         scope['actualChangedFiles'] == 0 and scope['productInstallationPerformed'] is False and
         scope['productUpdatesPerformed'] is False and len(scope['files']) == 253 and
         len(set(scope['trustCacheCDHashes'])) == 140, 'concrete init-only zero install/trust scope')
    current = json.loads(exact(scope['currentInstalledProductsPost']).read_bytes())
    need(current['transportExit'] == 0, 'actual already installed current post required')
    need('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in exact(current['stdout']).read_text(),
         'actual installed products verified')
    return ready, scope

'''
    tail = source[source.index('\ndef run_remote('):]
    previous_start = tail.index('    previous = ')
    previous_stop = tail.index('    if previous:', previous_start)
    tail = tail[:previous_start] + "    previous = {'launch': 'preflight', 'post': 'launch'}.get(args.action)\n" + tail[previous_stop:]
    tail = tail.replace("        data = (packet/'products.tar').read_bytes() if args.action == 'stage' else b''", "        data = b''")
    dispatch_start = tail.index("        if args.action == 'launch':\n            status, stdout, stderr, error = run_remote((packet/'register.sh')")
    dispatch_stop = tail.index('        password = None', dispatch_start)
    tail = tail[:dispatch_start] + "        status, stdout, stderr, error = run_remote(script, data, args.action != 'launch', password)\n" + tail[dispatch_stop:]
    controller = head + ready + tail
    compile(controller, str(out / 'control.py'), 'exec')
    need('jbctl trustcache add' not in controller and "packet/'products.tar'" not in controller,
         'no trust or install action remains')
    out.mkdir(mode=0o700)
    dump(out / 'scope.json', scope)
    (out / 'control.py').write_text(controller)
    (out / 'readiness-loop.sh').write_text(READINESS)
    script_rows, sizes = {}, {}
    for action, script in scripts.items():
        syntax = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True)
        need(syntax.returncode == 0, 'actual shell syntax passed: ' + action)
        (out / (action + '-syntax.stderr')).write_bytes(syntax.stderr)
        command = ('sudo -k -S -p "" ' if action != 'launch' else '') + '/var/jb/bin/sh -c ' + shlex.quote(script)
        need(len(command.encode()) + 10000 < 262144, 'actual ARG_MAX with environment reserve')
        (out / (action + '.sh')).write_text(script)
        script_rows[action] = pin(out / (action + '.sh'))
        sizes[action] = len(command.encode())
    candidate = dict(schema='Prepared already installed independent27 init-only device packet v1',
         preparer=pin(__file__), scope=pin(out / 'scope.json'), controller=pin(out / 'control.py'),
         scripts=script_rows, actions=['preflight', 'launch', 'post'], priorController=pin(OLD / 'control.py'),
         currentInstalledProductsPost=pin(post_path), runtimeCandidate=old_candidate['runtimeCandidate'],
         appCandidate=old_candidate['appCandidate'], actualChangedFiles=0, actualNewTrustEntries=0,
         actualFullFiles=253, actualFullCodeDirectoryHashes=140,
         continuingHumanAuthorization=scope['continuingHumanAuthorization'],
         initializationOnly=True, appRegistrationRepeated=False, actualOwnedPlatformPreparationExecuted=False,
         readinessLoop=pin(out / 'readiness-loop.sh'), readinessStableParentChildSeconds=2,
         oldPrematureReadinessSpanSHA256=base.digest(old_wait.encode()),
         processIdentityCleanupAndTransportFunctionsUnchanged=True,
         maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
         allRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
         sandboxProfileApplied=False, nativeSandboxApplyUnavailable=45, nativeSandboxInitSuccessFabricated=False,
         productInstallationPerformed=False, productUpdatesPerformed=False,
         priorOwnLogRetainedBeforeSameInodeInitializationTruncation=True,
         deviceOperations=0, trustCacheOperations=0, guestBootRequested=False, readyForDeviceExecution=False)
    dump(out / 'candidate.json', candidate)
    pins = [pin(p) for p in out.iterdir() if p.is_file()]
    pins += [pin(__file__), pin(OLD / 'candidate.json'), pin(OLD / 'freeze.json'), pin(OLD / 'scope.json'),
             pin(OLD / 'control.py'), pin(OLD / 'launch.sh'), pin(OLD / 'post.sh'), pin(post_path),
             post['request'], post['stdout'], post['stderr'], pin(launch_path), launch['request'], launch['stdout'],
             launch['stderr'], scope['priorAppRegistration'], register['stdout'], register['stderr'],
             scope['continuingHumanAuthorization'], scope['runtimeCandidate'], scope['appCandidate'],
             pin(base.HEALTH), pin(B / 'independent27_device_product_verify_fast_v1.py')]
    pins += [row['local'] for row in scope['files']]
    dump(out / 'freeze.json', dict(files=list({p['path']: p for p in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), scope=pin(out / 'scope.json'),
                          freeze=pin(out / 'freeze.json'), maximumQuotedCommandBytes=max(sizes.values()),
                          newTrustEntries=0, productUpdates=0)))


if __name__ == '__main__':
    main()
