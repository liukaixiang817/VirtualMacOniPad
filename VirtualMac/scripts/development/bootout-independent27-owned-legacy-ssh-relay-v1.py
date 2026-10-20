#!/usr/bin/env python3
"""Root-only bounded runtime removal of one previously identified owned user job.

No plist mutation, launchctl disable, direct signal, port probe, or other job.
Preparation and syntax checks do not call the device transport.
"""
import argparse
import datetime
import getpass
import hashlib
import importlib.util
import json
import pathlib
import shlex
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CONTROL = N / 'independent27-device34-stage-recovery-v35-attempt1/control.py'
CONTROL_SHA = '9042ee747f3180d7d8486781f2adcb20cce3a124bb5d7f3a9e84cf39d1c49981'
PRIOR = N / 'independent27-port22222-owned-relay-readonly-v2-attempt1/receipt.json'
PRIOR_SHA = '4558fa0dcf234c7a312165b49c731f748fbd48ac3ec1dad2a0424872ce7d8836'
PLIST_CANONICAL = ('/private/preboot/3BAC96003F990D2A2530F3FB8BF9293399970140D40FBF3A5A9A6CCCCF018C0C30F94334FCD17DF3DC7434C1EA34FC3E/'
                   'dopamine-FUG16w/procursus/Library/LaunchDaemons/com.mac.virtual.guest-ssh-proxy.plist')


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def controller():
    if pin(CONTROL)['sha256'] != CONTROL_SHA or pin(PRIOR)['sha256'] != PRIOR_SHA:
        raise ValueError('actual transport or actual owned-job readonly receipt changed')
    spec = importlib.util.spec_from_file_location('exact_recovery35_transport', CONTROL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inner_script(c):
    return c.prefix(0) + c.off_check() + '''
own_job=user/501/com.mac.virtual.guest-ssh-proxy
own_plist=/var/jb/Library/LaunchDaemons/com.mac.virtual.guest-ssh-proxy.plist
own_expected_plist=''' + shlex.quote(PLIST_CANONICAL) + '''
own_expected_meta=16777219:166730:0:0:644:1:1040:1790951510:1790951511
own_expected_sha=57ac7f8194f631b22e17bde8fcabf13a2d8bd3056c3354686f048c16efdbf6b3
own_expected_start=7cfeba8c7a9f9e896bd5372ae23b2c0049bd36778c9e1a15772e5b7a7f74aec0
own_expected_args='/var/jb/usr/bin/socat TCP4-LISTEN:22222,reuseaddr,fork EXEC:/var/jb/usr/libexec/virtualmac-guest-ssh-connect,nofork'
own_program=/var/jb/usr/bin/socat
own_pid=429
check_plist() {
 [ -f "$own_plist" ] && [ ! -L "$own_plist" ] || return 8
 [ "$(realpath "$own_plist")" = "$own_expected_plist" ] || return 8
 [ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$own_plist")" = "$own_expected_meta" ] || return 8
 [ "$(sha256sum "$own_plist" | cut -d ' ' -f1)" = "$own_expected_sha" ] || return 8
}
check_pid() {
 own_rows=$(ps -p "$own_pid" -o pid=,ppid=,uid=,stat=) || return 8
 set -- $own_rows
 [ "$#" = 4 ] && [ "$1" = "$own_pid" ] && [ "$2" = 1 ] && [ "$3" = 501 ] || return 8
 own_state=$4
 [ "$(ps -p "$own_pid" -o lstart= | sha256sum | cut -d ' ' -f1)" = "$own_expected_start" ] || return 8
 case "$own_state" in Z*) return 9;; esac
 [ "$(ps -p "$own_pid" -o args= | sed 's/^ *//;s/ *$//')" = "$own_expected_args" ] || return 8
 own_comm=$(ps -p "$own_pid" -o comm= | sed 's/^ *//;s/ *$//')
 [ "$(realpath "$own_comm")" = "$own_program_canonical" ] || return 8
}
check_job() {
 own_text=$(launchctl print "$own_job") || return 8
 [ "$(printf '%s' "$own_text" | wc -c | tr -d ' ')" -le 16384 ] || return 8
 printf '%s\n' "$own_text" | awk -v p="$own_expected_plist" '
 NR==1 {if($0!="user/501/com.mac.virtual.guest-ssh-proxy = {")bad=1}
 $1=="path" && $2=="=" {np++;if($3!=p || NF!=3)bad=1}
 $1=="program" && $2=="=" {ng++;if($3!="/var/jb/usr/bin/socat" || NF!=3)bad=1}
 $1=="pid" && $2=="=" {ni++;if($3!=429 || NF!=3)bad=1}
 $1=="state" && $2=="=" {ns++;if($3!="running" || NF!=3)bad=1}
 $1=="arguments" && $2=="=" && $3=="{" {na++;inside=1;next}
 inside && $1=="}" {inside=0;next}
 inside {i++;if((i==1 && $0!="\\t\\t/var/jb/usr/bin/socat") ||
 (i==2 && $0!="\\t\\tTCP4-LISTEN:22222,reuseaddr,fork") ||
 (i==3 && $0!="\\t\\tEXEC:/var/jb/usr/libexec/virtualmac-guest-ssh-connect,nofork") || i>3)bad=1}
 END {if(bad || np!=1 || ng!=1 || ni!=1 || ns!=1 || na!=1 || i!=3 || inside)exit 8}' || return 8
 printf 'OWN_EXACT_JOB_PREBOOTOUT_SHA256 %s\n' "$(printf '%s\n' "$own_text" | sha256sum | cut -d ' ' -f1)"
}
check_plist
[ -f "$own_program" ] && [ -x "$own_program" ] && [ ! -L "$own_program" ]
own_program_canonical=$(realpath "$own_program")
own_expected_program=${own_expected_plist%/Library/LaunchDaemons/com.mac.virtual.guest-ssh-proxy.plist}/usr/bin/socat
[ "$own_program_canonical" = "$own_expected_program" ]
check_job
check_pid
check_plist
''' + c.off_check() + '''
check_pid
printf 'OWN_EXACT_JOB_BOOTOUT_BEGIN user/501/com.mac.virtual.guest-ssh-proxy PID=429 UID=501 PPID=1\n'
launchctl bootout "$own_job"
printf 'OWN_EXACT_JOB_BOOTOUT_RETURNED_ZERO\n'
check_absent() {
own_absent_status=0
own_absent=$(launchctl print "$own_job" 2>&1) || own_absent_status=$?
[ "$own_absent_status" -ne 0 ]
own_domain=$(launchctl print user/501)
[ "$(printf '%s' "$own_domain" | wc -c | tr -d ' ')" -le 262144 ]
if printf '%s\n' "$own_domain" | grep -F 'com.mac.virtual.guest-ssh-proxy' >/dev/null;then exit 8;fi
printf 'OWN_EXACT_JOB_ABSENT printExit=%s readableDomain=user/501\n' "$own_absent_status"
}
check_absent
own_done=0
for own_attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20;do
 own_all=$(ps -axo pid=,ppid=,uid=,stat=)
 own_after=$(printf '%s\n' "$own_all" | awk -v p="$own_pid" 'NF!=4 {bad=1;next} {n++;if($1==p){hit++;row=$0}} END {if(bad || !n || hit>1)exit 8;if(hit)print row}')
 if [ -z "$own_after" ];then printf 'OWN_OLD_PID_EXITED 429\n';own_done=1;break;fi
 own_check_status=0
 check_pid || own_check_status=$?
 if [ "$own_check_status" = 9 ];then printf 'OWN_OLD_PID_SAME_IDENTITY_ZOMBIE_NO_SIGNAL 429\n';own_done=1;break;fi
 [ "$own_check_status" = 0 ] || exit 8
 sleep 1
done
[ "$own_done" = 1 ]
check_absent
check_plist
''' + c.off_check() + '''
[ "$(sysctl -n kern.bootsessionuuid)" = A3247B1A-473D-4786-8585-A99DB5B5BDA0 ]
printf 'OWN_FIXED_PLIST_UNCHANGED_SHA256 %s\n' "$own_expected_sha"
printf 'OWN_EXACT_LEGACY_SSH_JOB_RUNTIME_BOOTOUT_COMPLETE_NO_PLIST_MUTATION_NO_DIRECT_SIGNALS\n'
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--execute', action='store_true', required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    args = ap.parse_args()
    c = controller()
    output = args.output.resolve()
    if output.parent != N or output.exists() or not output.name.startswith('independent27-port22222-owned-relay-bootout-v1-attempt'):
        raise ValueError('fresh direct-child receipt directory required')
    script = 'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 40 /var/jb/bin/sh -c ' + shlex.quote(inner_script(c)) + '\n'
    output.mkdir()
    (output/'bootout-root.sh').write_text(script)
    request = dict(schema='Root exact owned legacy SSH user-job runtime bootout v1', source=pin(__file__),
                   controller=pin(CONTROL), actualPriorReadonly=pin(PRIOR), script=pin(output/'bootout-root.sh'),
                   job='user/501/com.mac.virtual.guest-ssh-proxy', pid=429, externalWallSeconds=40,
                   trustCacheOperations=0, directSignals=0, plistMutation=False, disable=False,
                   authorization='Explicit current Root instruction under continuing direct human authorization')
    (output/'request.json').write_text(json.dumps(request, indent=2)+'\n')
    password = getpass.getpass('iPad password: ')
    try:
        rc, stdout, stderr, error = c.run_remote(script, b'', True, password)
    finally:
        password = None
    (output/'stdout').write_bytes(stdout)
    (output/'stderr').write_bytes(stderr)
    completed = rc == 0 and b'OWN_EXACT_LEGACY_SSH_JOB_RUNTIME_BOOTOUT_COMPLETE_NO_PLIST_MUTATION_NO_DIRECT_SIGNALS\n' in stdout
    receipt = dict(schema='Actual one owned legacy SSH user-job runtime bootout result v1', request=pin(output/'request.json'),
                   finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), transportExit=rc,
                   transportError=error, stdout=pin(output/'stdout'), stderr=pin(output/'stderr'),
                   runtimeBootoutConfirmed=completed, trustCacheOperations=0, directSignals=0,
                   plistMutation=False, disable=False, guestBootRequested=False)
    (output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))
    if not completed:
        raise SystemExit(rc or 8)


if __name__ == '__main__':
    main()
