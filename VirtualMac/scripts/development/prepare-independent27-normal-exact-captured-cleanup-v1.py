#!/usr/bin/env python3
"""HOST prepare and explicitly dispatch one exact failed-normal cleanup.

Only the actual immutable App8613/child8640 captures may be signalled. The
Root dispatcher retains the SSH output pipes through cleanup and records each
actual response. Import/preparation never invokes a device.
"""
import argparse
import getpass
import hashlib
import importlib.util
import json
import os
import pathlib
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
R = next(p for p in pathlib.Path(__file__).resolve().parents
         if (p/'VirtualMac/scripts/development').is_dir() and (p/'DeviceDiagnostics').is_dir())
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
NORMAL = N/'independent27-app12-normal-guest-lifecycle-v6-attempt1'
INITIALIZER = N/'independent27-vm-class-app-device-v1-attempt1'
COMMON = R/'VirtualMac/scripts/development/independent27_normal_guest_common_v2.py'
AUTH = N/'independent27-continuing-human-authorization-v1/authorization.json'
NORMAL_SHA = '9cc2ea7c6b31a56181e233edbed69026fd139ebf7e6d3a98e396369db3129106'
APP_START = 'abd6e2a14d2ca29bb6ed290cd4cdb0c1e7cd828a4c693342109ab18824f471d0'
CHILD_START = '464275f6b54bd9815576cfbe56b91937a174fc1072a84da94b7a28d28b36a8af'
ACTIONS = ('exact-cleanup', 'read-own-log', 'post')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


common = load(COMMON, 'captured_cleanup_common_v1')
base = load(INITIALIZER/'control.py', 'captured_cleanup_original_process_v1')
pin, exact, need, dump = common.pin, common.exact, common.need, common.dump


def actual_failure():
    need(pin(NORMAL/'candidate.json')['sha256'] == NORMAL_SHA, 'fixed actual failed normal candidate')
    candidate = json.loads((NORMAL/'candidate.json').read_bytes())
    rows = []
    for action, status in (('start', 125), ('post', 8)):
        path = NORMAL/'device-receipts'/action/'receipt.json'
        row = json.loads(path.read_bytes())
        request = json.loads(exact(row['request']).read_bytes())
        text = exact(row['stdout']).read_text();exact(row['stderr'])
        need(row['transportExit'] == status and request['packetCandidate'] == pin(NORMAL/'candidate.json') and
             request['action'] == action, 'actual failed start/post from exact normal packet')
        need(row['handoffACKAttemptRecorded'] is False and row['handoffACKSent'] is False and
             row['handoffCommitObserved'] is False, 'actual no-ACK failure; no ownership discard')
        rows.extend((pin(path), row['request'], row['stdout'], row['stderr']))
        if action == 'start':
            identities = common.identity_rows(text, candidate['ownAppMain'], candidate['ownChildMain'])
            need(identities['APP']['pid'] == 8613 and identities['APP']['startHash'] == APP_START and
                 identities['CHILD']['pid'] == 8640 and identities['CHILD']['startHash'] == CHILD_START and
                 identities['CHILD']['ppid'] == 8613, 'actual exact captured identities, never fresh enrollment')
        else:
            need('UNEXPECTED_OWN_PROCESS  8613 ' in text and 'UNEXPECTED_OWN_PROCESS  8640 ' in text,
                 'actual post observed captured App and direct child still live')
    need(not (NORMAL/'device-receipts/start/handoff-ack.json').exists(), 'no attempted ACK ledger')
    scope_path = exact(json.loads((INITIALIZER/'candidate.json').read_bytes())['scope'])
    scope = json.loads(scope_path.read_bytes())
    need(scope['bootSeconds'] == 1791813884 and len(scope['files']) == 255 and
         candidate['ownAppMain'] == scope['deviceAppMain'] and candidate['ownChildMain'] == scope['deviceChildMain'],
         'actual installed App12/current boot complete inventory')
    return candidate, scope, scope_path, rows


def wrap(body, seconds):
    return base.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+\
        ' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'


def render(scope):
    checks = '''check_captured_code() {
 [ -f "$1" ] && [ ! -L "$1" ]
 [ "$(realpath "$1")" = "$1" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$1")" = "501:501:$4:1:$3" ]
 [ "$(sha256sum "$1" | cut -d ' ' -f1)" = "$2" ]
}
'''
    for name in (scope['deviceAppMain'], scope['deviceChildMain']):
        row = next(row for row in scope['files'] if row['devicePath'] == name)
        checks += 'check_captured_code '+shlex.quote(name)+' '+row['local']['sha256']+' '+\
            str(row['local']['bytes'])+' '+format(row['mode'], 'o')+'\n'
    # The entire existing function body is retained. Immutable seeds disable
    # its initial-capture branches; any different PID/start is rejected.
    cleanup = base.prefix(0)+checks+base.PROCESS_FUNCTIONS+\
        f'own_app_pid=8613\nown_app_start={APP_START}\nown_child_pid=8640\nown_child_start={CHILD_START}\n'+'''
# No write to the SSH stdout/stderr pipe occurs until all validated signals
# have completed. This protects TERM/KILL from a caller closing its pipe.
own_cleanup_status=0
cleanup_own >/dev/null 2>&1 || own_cleanup_status=$?
[ "$own_cleanup_status" = 0 ] || exit "$own_cleanup_status"
'''+base.off_check()+'''printf 'OWN_EXACT_CAPTURED_APP8613_CHILD8640_CLEANUP_COMPLETED\n'
'''
    read = base.prefix(0)+base.off_check()+'''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = 16777219:47534875:501:501:600:1 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
printf 'OWN_ACTUAL_LOG_META %s\nOWN_ACTUAL_LOG_SHA256 %s\nOWN_APP_LOG_BEGIN\n' "$own_log_meta" "$own_log_sha"
cat "$OWN_LOG"
printf '\nOWN_APP_LOG_END\n'
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
'''+base.off_check()+'''printf 'OWN_ACTUAL_LOG_STABLE_AFTER_EXACT_CAPTURED_CLEANUP\n'
'''
    return {'exact-cleanup': wrap(cleanup, 20), 'read-own-log': wrap(read, 20),
            'post': (NORMAL/'post.sh').read_text()}


def prepare(out):
    out = out.resolve();need(out.parent == N and not out.exists(), 'fresh exact cleanup packet')
    original, scope, scope_path, failures = actual_failure()
    for row in json.loads((NORMAL/'freeze.json').read_bytes())['files']:exact(row)
    scripts = render(scope)
    out.mkdir(mode=0o700)
    for action, script in scripts.items():
        (out/(action+'.sh')).write_text(script)
        subprocess.run(['/bin/sh', '-n', str(out/(action+'.sh'))], check=True)
        need(len(('/var/jb/bin/sh -c '+shlex.quote(script)).encode())+10000 < 262144, 'actual ARG_MAX margin')
    source = pathlib.Path(__file__).resolve()
    (out/'control.py').write_bytes(source.read_bytes())
    candidate = dict(schema='Inactive exact captured failed-normal cleanup packet v1',
        builder=pin(source), controller=pin(out/'control.py'), common=pin(COMMON),
        inheritedController=pin(INITIALIZER/'control.py'), installedScope=pin(scope_path),
        actualFailedNormalCandidate=pin(NORMAL/'candidate.json'), actualFailurePins=failures,
        originalPostScript=pin(NORMAL/'post.sh'), continuingHumanAuthorization=pin(AUTH),
        inheritedProcessFunctionsSHA256=hashlib.sha256(base.PROCESS_FUNCTIONS.encode()).hexdigest(),
        exactCapturedIdentities=dict(appPID=8613, appStartHash=APP_START, childPID=8640,
            childStartHash=CHILD_START, childPPID=8613, uid=501),
        bootSeconds=1791813884, actualInstalledProducts=255, actions={a:pin(out/(a+'.sh')) for a in ACTIONS},
        cleanupExternalSeconds=20, logReadExternalSeconds=20, postExternalSeconds=45, transportSeconds=55,
        capturedIdentityOnly=True, cannotRecaptureOtherOwnProcesses=True, signalOutputSuppressedUntilCleanupComplete=True,
        postWholebytesEqualFrozenNormal=True, newTrustCacheEntries=0, productFileWrites=0,
        ownLogWrites=0, guestFileWrites=0, deviceOperations=0, actualVisibleGuest=False,
        actualSSHAvailable=False, readyForRootSerialDispatch=False, noACKDiscarded=True)
    dump(out/'candidate.json', candidate)
    rows = [pin(source),pin(out/'control.py'),pin(out/'candidate.json'),pin(COMMON),pin(INITIALIZER/'control.py'),
        pin(scope_path),pin(NORMAL/'candidate.json'),pin(NORMAL/'post.sh'),pin(AUTH),*failures,*candidate['actions'].values()]
    dump(out/'freeze.json', dict(schema='Exact captured cleanup HOST source and packet freeze v1',
        files=list({row['path']:row for row in rows}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'))))


def dispatch(packet, ready_path):
    packet = packet.resolve();ready_path = ready_path.resolve()
    need(packet.parent == N and pathlib.Path(__file__).resolve() == packet/'control.py', 'only exact copied controller')
    candidate = json.loads((packet/'candidate.json').read_bytes())
    ready = json.loads(ready_path.read_bytes())
    for row in json.loads((packet/'freeze.json').read_bytes())['files']:exact(row)
    actual_failure()
    need(ready.get('readyForRootSerialDispatch') is True and ready.get('owningRootTask') == '/root' and
         ready.get('packetCandidate') == pin(packet/'candidate.json') and
         ready.get('packetFreeze') == pin(packet/'freeze.json') and
         ready.get('continuingHumanAuthorization') == candidate['continuingHumanAuthorization'] and
         ready.get('noNewTrustCacheEntries') is True and ready.get('independentReviews'), 'actual Root cleanup ready')
    for row in ready['independentReviews']:
        review = json.loads(exact(row).read_bytes())
        need(review.get('findings') == [] and review.get('controllerPacketCandidate') == pin(packet/'candidate.json'),
             'exact independent cleanup packet peer')
    receipts = packet/'device-receipts'
    need(not receipts.exists(), 'whole new cleanup sequence runs only once')
    lock = packet/'cleanup-dispatch.lock'
    fd = os.open(lock, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600);identity = os.fstat(fd)
    password = None
    try:
        receipts.mkdir(mode=0o700)
        password = getpass.getpass('iPad password: ')
        previous = []
        for action in ACTIONS:
            output = receipts/action;output.mkdir(mode=0o700)
            dump(packet/(action+'-dispatched.json'),dict(action=action,packetCandidate=pin(packet/'candidate.json'),startedUTC=common.utc()))
            dump(output/'request.json',dict(action=action,packetCandidate=pin(packet/'candidate.json'),ready=pin(ready_path),
                script=candidate['actions'][action],priorPins=previous,startedUTC=common.utc(),trustCacheOperations=0,
                guestBootRequested=False,exactCapturedIdentities=candidate['exactCapturedIdentities']))
            script = exact(candidate['actions'][action]).read_text()
            status,stdout,stderr,error = base.run_remote(script,b'',True,password)
            (output/'stdout').write_bytes(stdout);(output/'stderr').write_bytes(stderr)
            dump(output/'receipt.json',dict(action=action,finishedUTC=common.utc(),request=pin(output/'request.json'),
                transportExit=status,transportError=error,stdout=pin(output/'stdout'),stderr=pin(output/'stderr'),
                trustCacheOperations=0,productFileWrites=0,guestBootRequested=False,actualVisibleGuest=False,actualSSHAvailable=False))
            print(json.dumps(json.loads((output/'receipt.json').read_bytes())),flush=True)
            print(stdout.decode(errors='replace')[-16000:],flush=True)
            need(status == 0, 'actual cleanup/read/post failed; preserve actual receipt and Root cleanup obligation')
            previous.append(pin(output/'receipt.json'))
    finally:
        password = None
        live = os.lstat(lock)
        need((live.st_dev,live.st_ino) == (identity.st_dev,identity.st_ino), 'exact serial lock identity')
        os.close(fd);os.unlink(lock)


def main():
    ap = argparse.ArgumentParser()
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--output',type=pathlib.Path)
    modes.add_argument('--packet',type=pathlib.Path)
    ap.add_argument('--ready',type=pathlib.Path)
    args = ap.parse_args()
    if args.output:need(args.ready is None,'preparation no ready dispatch');prepare(args.output)
    else:need(args.ready is not None,'explicit Root ready');dispatch(args.packet,args.ready)


if __name__ == '__main__':main()
