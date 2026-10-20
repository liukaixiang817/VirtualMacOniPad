#!/usr/bin/env python3
"""Prepare a bounded recovery of the exact already authorized products."""
import importlib.util
import json
import pathlib
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = N / 'independent27-device-bootstrap-controller-v3-attempt1'
OUT = N / 'independent27-device-bootstrap-recovery-v4-attempt1'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


base = module('frozen3', OLD / 'control.py')
fast_path = R / 'VirtualMac/scripts/development/independent27_device_product_verify_fast_v1.py'
fast = module('fast', fast_path)
pin, need = base.pin, base.need
scope = json.loads((OLD / 'scope.json').read_bytes())
failure = OLD / 'device-receipts/stage/receipt.json'
need(json.loads(failure.read_bytes())['transportExit'] == 124, 'actual failed original transport')
need(not any((OLD / (action + '-dispatched.json')).exists() for action in base.TRUST_ACTIONS), 'no previous TC action')
read_receipt = N / 'independent27-staged-fast-verify-readonly-v1/receipt.json'
read_data = json.loads(read_receipt.read_bytes())
need(read_data['transportExit'] == 0 and read_data['deviceWrites'] == 0, 'actual completed readonly stage proof')
read_stdout = base.exact(read_data['stdout']).read_bytes()
need(b'INDEPENDENT27_STAGED_FAST_HASH_AND_FIRST10_CD_READONLY_COMPLETE\n' in read_stdout, 'true full staged proof')
old_scripts = base.make_scripts(scope, base.HEALTH.read_text())
final_fast = fast.batch_check(scope)
staged_fast = fast.batch_check(scope, staged=True)
prefix = base.prefix
off = base.off_check
wrap = lambda body, uid: prefix(uid) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
stage_identity = '''
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %d:%i:%u:%g:%a "$OWN_STAGE")" = 16777220:47302920:0:0:700 ]
'''
body = prefix(0) + off() + '''
own_old_stage_pid=$(ps -p 85402 -o pid= || true)
[ -z "$own_old_stage_pid" ]
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %d:%i:%u:%g:%a "$OWN_STAGE")" = 16777220:47302920:0:501:700 ]
[ ! -e "$OWN_RUNTIME" ] && [ ! -L "$OWN_RUNTIME" ]
[ ! -e "$OWN_APP" ] && [ ! -L "$OWN_APP" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
''' + staged_fast + '''
chown 0:0 "$OWN_STAGE"
own_runtime_identity=$(stat -c %d:%i "$OWN_STAGE/runtime")
mv "$OWN_STAGE/runtime" "$OWN_RUNTIME"
mv "$OWN_STAGE/VirtualMacIndependent27.app" "$OWN_APP"
[ "$(stat -c %d:%i "$OWN_RUNTIME")" = "$own_runtime_identity" ]
''' + stage_identity + final_fast + "printf 'INDEPENDENT27_RECOVERED_EXACT_PRODUCTS_NO_TRUST_OR_EXECUTION\\n'\n"
# Two entire path sets would exceed ARG_MAX in one shell argument. Verify the
# staged set before the move in its own read-only action, then close final bits
# in recover-stage. The earlier actual readonly SHA result also remains pinned.
staged_check_body = prefix(0) + off() + '''
own_old_stage_pid=$(ps -p 85402 -o pid= || true)
[ -z "$own_old_stage_pid" ]
[ "$(stat -c %d:%i:%u:%g:%a "$OWN_STAGE")" = 16777220:47302920:0:501:700 ]
''' + staged_fast + "printf 'INDEPENDENT27_STAGED_READONLY_RECHECK_COMPLETE\\n'\n"
body = body.replace(staged_fast, '', 1)
scripts = {'staged-recheck': wrap(staged_check_body, 0), 'recover-stage': wrap(body, 0)}
verify_actions = tuple('verify-cd-' + str(index + 1) for index in range(14))
trust_actions = tuple('trust-' + str(index + 1) for index in range(14))
for index in range(14):
    hashes = scope['trustCacheCDHashes'][index * 10:(index + 1) * 10]
    check = prefix(0) + off() + stage_identity + final_fast + fast.cd_check(scope, hashes)
    scripts[verify_actions[index]] = wrap(check + f"printf 'INDEPENDENT27_CD_PREFLIGHT_{index+1}_COMPLETE\\n'\n", 0)
    check += f'(umask 077; set -C; : > "$OWN_STAGE/{trust_actions[index]}-dispatched")\n'
    for offset, cd_hash in enumerate(hashes):
        check += f'jbctl trustcache add {cd_hash}\n'
        check += f"printf 'OWN_TC_ADDED {index*10+offset+1} {cd_hash}\\n'\n"
    check += f"printf 'INDEPENDENT27_EXACT_TRUST_BATCH_{index+1}_COMPLETE\\n'\n"
    scripts[trust_actions[index]] = wrap(check, 0)
slow_plain = base.verify_products(scope)
slow_cd = base.verify_products(scope, include_cd=True)
inside = lambda value: value.replace("'", "'\"'\"'")
need(old_scripts['launch'].count(inside(slow_plain)) == 1, 'one exact old launch verification span')
scripts['launch'] = old_scripts['launch'].replace(inside(slow_plain), inside(final_fast), 1)
for action in ('register', 'post'):
    need(old_scripts[action].count(slow_cd) == 1, 'one exact old final verification span ' + action)
    scripts[action] = wrap(old_scripts[action].replace(slow_cd, final_fast, 1), 0)
actions = ('staged-recheck', 'recover-stage', *verify_actions, *trust_actions, 'launch', 'post')
source = (OLD / 'control.py').read_text()
head = source[:source.index('\ndef make_scripts(')]
head = head.replace("TRUST_ACTIONS = tuple('trust-'+str(index+1) for index in range(7))", "TRUST_ACTIONS = tuple('trust-'+str(index+1) for index in range(14))\nVERIFY_ACTIONS = tuple('verify-cd-'+str(index+1) for index in range(14))")
head = head.replace("ACTIONS = ('health', 'stage', *TRUST_ACTIONS, 'launch', 'post')", "ACTIONS = ('staged-recheck', 'recover-stage', *VERIFY_ACTIONS, *TRUST_ACTIONS, 'launch', 'post')")
tail = source[source.index('\ndef ready_gate('):source.index('\ndef main():')]
tail = tail.replace("auth['scope'] == pin(packet/'scope.json')", "auth['scope'] == json.loads((packet/'candidate.json').read_bytes())['authorizedOriginalScope'] and\n         pin(packet/'scope.json')['sha256'] == auth['scope']['sha256'] and\n         pin(packet/'scope.json')['bytes'] == auth['scope']['bytes']")
tail = tail.replace("previous = {'stage': 'health', 'trust-1': 'stage', 'launch': 'trust-7', 'post': 'launch'}.get(args.action)", "previous = {'recover-stage': 'staged-recheck', 'verify-cd-1': 'recover-stage', 'trust-1': 'verify-cd-14', 'launch': 'trust-14', 'post': 'launch'}.get(args.action)\n    if args.action in VERIFY_ACTIONS and args.action != 'verify-cd-1':\n        previous = VERIFY_ACTIONS[VERIFY_ACTIONS.index(args.action)-1]")
tail = tail.replace("data = (packet/'products.tar').read_bytes() if args.action == 'stage' else b''", "data = b''")
main = '''
def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    selected = sub.add_parser('dispatch')
    selected.add_argument('--packet', type=pathlib.Path, required=True)
    selected.add_argument('--ready', type=pathlib.Path, required=True)
    selected.add_argument('--action', choices=ACTIONS, required=True)
    dispatch(parser.parse_args())

if __name__ == '__main__':
    main()
'''
control = head + tail + main
compile(control, str(OUT / 'control.py'), 'exec')
OUT.mkdir(mode=0o700)
(OUT / 'scope.json').write_bytes((OLD / 'scope.json').read_bytes())
shutil.copyfile(OLD / 'products.tar', OUT / 'products.tar')
(OUT / 'control.py').write_text(control)
script_rows = {}
argv_sizes = {}
for action, script in scripts.items():
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), check=True)
    # The outer ssh command and the native shell's -c argument both fit the
    # actual measured 262144-byte kernel limit, with room for the 4514B env.
    command = ('sudo -k -S -p "" ' if action != 'launch' else '') + '/var/jb/bin/sh -c ' + shlex.quote(script)
    need(len(command.encode()) + 10000 < 262144, 'actual quoted argv bound ' + action)
    path = OUT / (action + '.sh')
    path.write_text(script)
    script_rows[action] = pin(path)
    argv_sizes[action] = len(command.encode())
candidate = {
    'schema': 'Prepared exact authorized independent27 bootstrap recovery v4',
    'authorizedOriginalScope': pin(OLD / 'scope.json'),
    'scope': pin(OUT / 'scope.json'), 'archive': pin(OUT / 'products.tar'),
    'controller': pin(OUT / 'control.py'), 'scripts': script_rows,
    'actions': list(actions), 'trustCacheRegistrationCount': 140,
    'actualAppCDHash': 'ba3c7c70a71c2eb4f4ed9afebba40649e66d4a0e',
    'originalStageFailure': pin(failure), 'stagedActualReadOnlyProof': pin(read_receipt),
    'oldStagePIDMustBeAbsent': 85402, 'exactStageDeviceAndInode': '16777220:47302920',
    'ownedStageGIDCorrectionFrom': 501, 'ownedStageGIDCorrectionTo': 0,
    'CDPreflightBatches': 14, 'CDPreflightBatchSize': 10, 'trustBatches': 14,
    'allRemoteActionsExternalWallSeconds': 45, 'transportTimeoutSeconds': 55,
    'allQuotedCommandBytes': argv_sizes,
    'unchangedOriginalProcessIdentificationAndCleanup': True,
    'originalScopeAndProductsByteIdentical': True, 'guestBootRequested': False,
    'deviceOperationsByPreparer': 0, 'trustCacheOperationsByPreparer': 0,
    'readyForDeviceExecution': False, 'independentReviewRequired': True
}
base.dump(OUT / 'candidate.json', candidate)
old_freeze = json.loads((OLD / 'freeze.json').read_bytes())
rows = list(old_freeze['files'])
rows += [pin(path) for path in sorted(OUT.iterdir()) if path.is_file()]
rows += [pin(pathlib.Path(__file__).resolve()), pin(fast_path), pin(failure), pin(read_receipt), read_data['script'], read_data['stdout'], read_data['stderr']]
for row in rows:
    base.exact(row)
base.dump(OUT / 'freeze.json', {'files': list({row['path']: row for row in rows}.values()), 'deviceOperations': 0})
print(json.dumps({'candidate': pin(OUT / 'candidate.json'), 'freeze': pin(OUT / 'freeze.json'),
                  'maximumQuotedCommandBytes': max(argv_sizes.values()), 'deviceOperations': 0}))
