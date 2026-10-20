#!/usr/bin/env python3
"""Build an inactive normal guest packet only from future actual success facts.

There is no fixture admission, synthesized receipt, trust cache registration,
or device dispatch in this builder. Root reviews the resulting concrete packet.
"""
import argparse
import json
import pathlib
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import urllib.parse

sys.dont_write_bytecode = True
import independent27_normal_guest_common_v2 as common
import independent27_initializer_log_generation_v1 as generation
import independent27_boot_clock_binding_v2 as boot_clock

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

# Locale-independent source markers. Absence is not a proof of no failure.
FAILURE = (r'^\[Independent27\] (explicit action|start-vm) rejected:|'
           r'^\[Independent27\] actual runtime load failed:|'
           r'^\[VirtualMac\] (actual runtime load failed:|VM configuration validation result=0|'
           r'VM delegate didStopWithError=|VM delegate guestDidStopVirtualMachine|'
           r'direct virtual machine stop (requested state=|failed:|complete))|'
           r'^\[VirtualMac\] (Configuration failed:|Validation failed:|Virtual Mac start failed:|Virtual Mac stopped:)|'
           r'^\[Independent27DisplayCtorV3\] failed=(super-init|native-default-device|native-command-queue) nil=1([[:space:]]|$)|'
           r'^\[Independent27DisplayV4\] failed=[a-z0-9-]+([[:space:]]|$)')


LOG_FUNCTIONS = r'''
check_log() {
 [ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ] || return 79
 [ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ] || return 79
 [ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_inode" ] || return 79
 [ "$(stat -c %s "$OWN_LOG")" -le 2097152 ] || return 79
}
log_state() {
 check_log || return 79
 own_summary=$(awk '
 /^\[Independent27\] start-vm accepted path=\/private\/var\/mobile\/Media\/VirtualMac\/Tahoe3\.bundle; entering actual VM startup$/ {a++}
 /^\[VirtualMac\] VM STARTED state=1$/ {s++}
 /^\[Independent27Display\] completed actual IOSurface/ {
  if ($0 !~ /^\[Independent27Display\] completed actual IOSurface bitmap frame=[0-9]+ size=[0-9]+x[0-9]+ backend=cpu-bitmap$/) {bad=1;next}
  line=$0;sub(/^.*frame=/,"",line);split(line,v," ");n=v[1]+0
  dim=v[2];sub(/^size=/,"",dim);split(dim,d,"x")
  if(n<=0 || (f && n<=last) || d[1]<=0 || d[2]<=0 || d[1]>8192 || d[2]>8192)bad=1
  if(!f)first=n;last=n;width=d[1];height=d[2];f++
 }
 END {print a+0,s+0,f+0,first+0,last+0,width+0,height+0,bad+0}' "$OWN_LOG") || return 81
 set -- $own_summary
 [ "$#" = 8 ] && [ "$1" -le 1 ] && [ "$2" -le 1 ] && [ "$8" = 0 ] || return 81
 own_accept=$1;own_started=$2;own_frames=$3;own_first=$4;own_last=$5;own_width=$6;own_height=$7
 own_failure_status=0
 grep -E @FAILURE_REGEX@ "$OWN_LOG" || own_failure_status=$?
 [ "$own_failure_status" = 1 ] || return 81
}
finish_normal() {
 own_status=$?
 trap - EXIT TERM INT HUP
 # Logging failure must never interrupt the actual exact cleanup attempt.
 set +e
 if [ "$own_handoff" != 1 ];then
  printf 'OWN_EXACT_TERMINAL_CLEANUP_BEGIN_V7\n' || :
  /var/jb/usr/bin/timeout --signal=TERM --kill-after=1 19 /var/jb/bin/sh -c "$OWN_EXACT_CLEANUP_V4" vm27-owned-cleanup-v7 "$own_app_pid" "$own_app_start" "$own_child_pid" "$own_child_start" >/dev/null 2>&1
  own_cleanup_status=$?
  printf 'OWN_EXACT_TERMINAL_CLEANUP_STATUS_V7 rc=%s\n' "$own_cleanup_status" || :
  if [ "$own_cleanup_status" != 0 ];then
   own_status=78
   printf 'OWN_EXACT_CLEANUP_FAILED_RETAIN_OWNERSHIP\n' || :
  else
   printf 'INDEPENDENT27_OWN_TERMINAL_CLEANUP_VERIFIED_OFF_V7\n' || :
  fi
 fi
 printf 'OWN_APP_LOG_BEGIN\n' || :
 if check_log;then cat "$OWN_LOG" || own_status=79;else own_status=79;fi
 printf '\nOWN_APP_LOG_END\n' || :
 exit "$own_status"
}
'''


WALL_FUNCTIONS_V4 = r'''
wall_init_v4() {
 [ -x /var/jb/usr/bin/date ] || return 82
 own_wall_start=$(/var/jb/usr/bin/date +%s) || return 82
 case "$own_wall_start" in ''|*[!0-9]*) return 82;; esac
 [ "${#own_wall_start}" = 10 ] && [ "$own_wall_start" -lt 2000000000 ] || return 82
 own_wall_last=$own_wall_start;own_elapsed=0
}
wall_tick_v4() {
 own_wall_now=$(/var/jb/usr/bin/date +%s) || return 82
 case "$own_wall_now" in ''|*[!0-9]*) return 82;; esac
 [ "${#own_wall_now}" = 10 ] && [ "$own_wall_now" -lt 2000000000 ] || return 82
 [ "$own_wall_now" -ge "$own_wall_last" ] || return 82
 # A forward wall step can never by itself authorize a handoff: host adds
 # independent monotonic285s and after150s frame progress gates before ACK.
 [ "$((own_wall_now-own_wall_last))" -le 20 ] || return 82
 own_elapsed=$((own_wall_now-own_wall_start));own_wall_last=$own_wall_now
}
'''


def bounded_run_v4(body, controller):
    return controller.prefix(501) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=20 980 /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'


def cleanup_body_v4(controller):
    return controller.prefix(501) + controller.PROCESS_FUNCTIONS + r'''
own_app_pid=$1;own_app_start=$2;own_child_pid=$3;own_child_start=$4
cleanup_own || exit 78
scan_own || exit 78
[ -z "$app_rows" ] && [ -z "$child_rows" ] || exit 78
printf 'INDEPENDENT27_OWN_TERMINAL_CLEANUP_VERIFIED_OFF_V4\n'
'''

def log_functions():
    return LOG_FUNCTIONS.replace('@FAILURE_REGEX@', shlex.quote(FAILURE))


def render_start(controller, scope, facts, nonce):
    body = controller.prefix(501) + controller.PROCESS_FUNCTIONS + controller.off_check()
    body += 'OWN_NORMAL_NONCE=' + shlex.quote(nonce) + '\n'
    body += '[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = ' + shlex.quote(facts['priorLogMetadata']) + ' ]\n'
    body += '[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]\n'
    body += '[ "$(sha256sum "$OWN_LOG" | cut -d \' \' -f1)" = ' + facts['priorLogSHA256'] + ' ]\n'
    body += '''own_log_inode=$(stat -c %d:%i "$OWN_LOG")
own_handoff=0
'''
    body += 'OWN_EXACT_CLEANUP_V4=' + shlex.quote(cleanup_body_v4(controller)) + '\n'
    body += WALL_FUNCTIONS_V4 + log_functions()
    body += '''trap finish_normal EXIT
trap 'exit 143' TERM INT HUP
# Successful exact root preflight already backed up this generation.
: > "$OWN_LOG"
check_log
/var/jb/usr/bin/uiopen --bundleid com.mac.virtual.independent27
wall_init_v4
while [ "$own_app_pid" = 0 ];do
 wall_tick_v4
 [ "$own_elapsed" -lt 8 ] || exit 83
 scan_own || exit 77
 [ "$own_app_pid" != 0 ] || sleep 1
done
[ "$own_app_pid" -gt 1 ] && [ -n "$app_rows" ] || exit 83
'''
    url = 'virtualmac27://start-vm?path=' + urllib.parse.quote(common.GUEST, safe='')
    body += '/var/jb/usr/bin/uiopen ' + shlex.quote(url) + '\n'
    body += r'''printf 'OWN_NORMAL_START_URL_REQUESTED_ONCE\n'
wall_init_v4
printf 'OWN_OBSERVATION_CLOCK_BEGIN_V4 wallEpoch=%s source=guarded-date\n' "$own_wall_start"
own_late_baseline=0;own_late_frame=0;own_late_progress=0
while :;do
 wall_tick_v4
 [ "$own_elapsed" -lt 900 ] || break
 scan_own || exit 77
 [ -n "$app_rows" ]
 log_state || exit 81
 wall_tick_v4
 if [ "$own_elapsed" -ge 150 ] && [ "$own_late_baseline" = 0 ];then own_late_frame=$own_last;own_late_baseline=1;fi
 if [ "$own_late_baseline" = 1 ] && [ "$own_last" -gt "$own_late_frame" ];then own_late_progress=1;fi
 printf 'OWN_OBSERVE elapsed=%s accept=%s state1=%s frames=%s first=%s last=%s lateProgress=%s source=guarded-date\n' "$own_elapsed" "$own_accept" "$own_started" "$own_frames" "$own_first" "$own_last" "$own_late_progress"
 if [ "$own_elapsed" -ge 300 ] && [ "$own_accept" = 1 ] && [ "$own_started" = 1 ] && [ "$own_frames" -ge 2 ] && [ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ];then break;fi
 [ "$own_elapsed" -lt 900 ] || break
 sleep 1
done
scan_own || exit 77;log_state || exit 81
[ -n "$app_rows" ] && [ -n "$child_rows" ] && [ "$own_child_pid" -gt 1 ] || exit 83
[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] && [ "$own_frames" -ge 2 ] || exit 81
[ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ] || exit 81
printf 'OWN_HANDOFF_OFFER %s %s %s %s %s %s %s %s\n' "$OWN_NORMAL_NONCE" "$own_app_pid" "$own_app_start" "$own_child_pid" "$own_child_start" "$own_log_inode" "$own_first" "$own_last"
# A bounded read leaves time for exact cleanup if the host rejects this offer.
own_ack=$(/var/jb/usr/bin/timeout --signal=TERM --kill-after=1 15 /var/jb/bin/sh -c 'IFS= read -r own_line || exit 84; printf "%s\n" "$own_line" || exit 84') || exit 84
[ "$own_ack" = "ACK $OWN_NORMAL_NONCE" ] || exit 84
scan_own || exit 77;log_state || exit 81
[ -n "$app_rows" ] && [ -n "$child_rows" ] && [ "$own_accept" = 1 ] && [ "$own_started" = 1 ] && [ "$own_frames" -ge 2 ] || exit 81
[ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ] || exit 81
own_handoff=1
printf 'OWN_HANDOFF_COMMITTED %s\n' "$OWN_NORMAL_NONCE"
'''
    # TERM980 leaves20 seconds until the1000 hard boundary for exact cleanup.
    return bounded_run_v4(body, controller)


def render_owned(controller, action):
    body = controller.prefix(501) + controller.PROCESS_FUNCTIONS
    body += r'''
IFS=' ' read -r own_app_pid own_app_start own_child_pid own_child_start own_log_inode own_nonce
[ "$own_app_pid" -gt 1 ] && [ "$own_child_pid" -gt 1 ] || exit 83
[ "$own_nonce" = @NONCE@ ]
own_handoff=1
'''
    body += log_functions()
    # Never acquire a new process here: seeded exact captures prevent recapture.
    body += 'scan_own || exit 77\n'
    if action == 'observe':
        body += WALL_FUNCTIONS_V4 + '''check_log
wall_init_v4
while :;do
 wall_tick_v4
 [ "$own_elapsed" -lt 900 ] || break
 scan_own || exit 77
 [ -n "$app_rows" ] && [ -n "$child_rows" ] || exit 83
 log_state || exit 81
 [ "$own_accept" = 1 ] && [ "$own_started" = 1 ] || exit 81
 wall_tick_v4
 printf 'OWN_LEASE_OBSERVE elapsed=%s last=%s frames=%s source=guarded-date\\n' "$own_elapsed" "$own_last" "$own_frames"
 [ "$own_elapsed" -lt 900 ] || break
 sleep 1
done
scan_own || exit 77
[ -n "$app_rows" ] && [ -n "$child_rows" ] || exit 83
log_state || exit 81
[ "$own_accept" = 1 ] && [ "$own_started" = 1 ] || exit 81
printf 'OWN_LEASE_STILL_OWNED %s\\n' "$own_nonce"
'''
        # Observe failure retains the declared Root owner; explicit stop follows.
        body += 'printf \'OWN_APP_LOG_BEGIN\\n\';cat "$OWN_LOG";printf \'\\nOWN_APP_LOG_END\\n\'\n'
    elif action == 'stop':
        body += '''cleanup_own >/dev/null 2>&1 || exit 78
scan_own || exit 77
[ -z "$app_rows" ] && [ -z "$child_rows" ] || exit 78
printf 'INDEPENDENT27_OWN_APP_AND_CHILD_OFF\\n'
if check_log;then printf 'OWN_APP_LOG_BEGIN\\n';cat "$OWN_LOG";printf '\\nOWN_APP_LOG_END\\n';fi
'''
    else:
        raise ValueError('finite owned action')
    return bounded_run_v4(body, controller) if action == 'observe' else common.bounded(body, controller, 20, 501)


def prepare(args):
    initializer = args.initializer_candidate.resolve()
    packet, scope, _, _ = common.initializer_success(initializer, args.initializer_launch, args.initializer_post)
    actual_generation = generation.actual_post_log_generation(
        initializer, args.initializer_launch.resolve(), args.initializer_post.resolve())
    failed_path = args.prior_normal_preflight_failure.resolve()
    failed = json.loads(failed_path.read_bytes())
    failed_request = json.loads(common.exact(failed['request']).read_bytes())
    failed_text = common.exact(failed['stdout']).read_text()
    common.exact(failed['stderr'])
    common.need(failed.get('transportExit') == 8 and failed.get('handoffACKAttemptRecorded') is False and
                failed.get('owningRootTask') is None and failed_request['action'] == 'preflight' and
                failed_request['packetCandidate'] == common.pin(failed_path.parents[2] / 'candidate.json') and
                re.fullmatch(r'UNEXPECTED_OWN_PROCESS\s+5507\s+1\s+501\s+' + re.escape(scope['deviceAppMain']) + r'\s*', failed_text),
                'actual earlier preflight8 only own App5507 admission failure, not guest start')
    common.need(not (failed_path.parents[2] / 'start-dispatched.json').exists() and
                not (failed_path.parents[2] / 'device-receipts/start').exists(), 'earlier guest start genuinely never dispatched')
    facts = common.guest_success(args.guest_readonly.resolve(), args.guest_configuration.resolve(),
                                 common.pin(args.initializer_post.resolve()))
    historical_screen_pin = None
    if args.no_before_screenshot_input_free_boot:
        common.need(not args.foreground_screenshot_receipt and not args.before_screenshot_review_failure,
                    'explicit input-free boot has no current screenshot or fabricated fresh failure')
        screenshot = None
        screen_pin = None
        review_failure_pin = None
        extra_screen_inputs = []
        if args.historical_foreground_screenshot_receipt:
            historical_path = args.historical_foreground_screenshot_receipt.resolve()
            historical = json.loads(historical_path.read_bytes())
            common.need(historical.get('actualNativeUSBScreenCapture') is True and historical.get('transportExit') == 0 and
                        historical.get('actualUDID') == '00008112-001E48300207401E',
                        'historical native screenshot must be an actual successful same-device capture')
            common.exact(historical['screenshot'])
            historical_record_files = [common.exact(historical[key]) for key in ('request', 'stdout', 'stderr')]
            common.need(historical.get('finishedUTC') < json.loads(args.guest_readonly.read_bytes())['finishedUTC'],
                        'historical screenshot cannot be represented as a fresh before-guest capture')
            historical_screen_pin = common.pin(historical_path)
            extra_screen_inputs = [historical_path, common.exact(historical['screenshot']), *historical_record_files]
    else:
        common.need(not args.historical_foreground_screenshot_receipt,
                    'historical image requires explicit input-free missing-current-screen admission')
        common.need(bool(args.foreground_screenshot_receipt) != bool(args.before_screenshot_review_failure),
                    'one actual before screenshot or actual failed approval-review record required')
        screenshot = None
        screen_pin = None
        review_failure_pin = None
        extra_screen_inputs = []
        if args.foreground_screenshot_receipt:
            screenshot = json.loads(args.foreground_screenshot_receipt.read_bytes())
            common.need(screenshot.get('actualNativeUSBScreenCapture') is True and screenshot.get('transportExit') == 0 and
                        isinstance(screenshot.get('actualUDID'), str) and len(screenshot['actualUDID']) >= 20,
                        'actual native USB screen receipt, not UI coordinate or mock capture')
            common.exact(screenshot['screenshot'])
            common.need(screenshot.get('finishedUTC') >= json.loads(args.guest_readonly.read_bytes())['finishedUTC'],
                        'native foreground screenshot must follow fresh actual guest facts')
            screen_pin = common.pin(args.foreground_screenshot_receipt.resolve())
            extra_screen_inputs = [args.foreground_screenshot_receipt.resolve(), common.exact(screenshot['screenshot'])]
        else:
            failure = json.loads(args.before_screenshot_review_failure.read_bytes())
            common.need(failure.get('actualAutomaticApprovalReviewFailure') is True and
                        failure.get('requestedAction') == 'native-usb-foreground-screenshot' and
                        failure.get('actualDeviceCaptureExecuted') is False and failure.get('actualNativeScreenshotProduced') is False and
                        failure.get('outputDirectoryAbsentAtRecordTime') is True and failure.get('preGuestScreenshotNotClaimed') is True and
                        failure.get('inputCalibrationPassed') is False and failure.get('actualVisibleGuest') is False and
                        failure.get('guestDisplayAndInputAcceptanceStillRequireActualNativeScreenshot') is True and
                        failure.get('doesNotAuthorizeBypassingRejectedCapture') is True,
                        'actual approval failure recorded without executed screenshot or successful receipt')
            attempts = failure.get('attempts')
            common.need(isinstance(attempts, list) and len(attempts) == 2 and
                        all(row.get('executed') is False and row.get('failureReason') == 'automatic approval review timeout'
                            for row in attempts), 'two real automatic approval review timeouts, no executed capture')
            common.need(failure.get('recordedUTC') >= json.loads(args.guest_readonly.read_bytes())['finishedUTC'],
                        'real before-screen failure evidence follows fresh actual guest read')
            review_failure_pin = common.pin(args.before_screenshot_review_failure.resolve())
            extra_screen_inputs = [args.before_screenshot_review_failure.resolve()]
    output = args.output.resolve()
    common.need(output.parent == common.N and not output.exists(), 'fresh exclusive normal packet')
    controller_path = initializer.parent / 'control.py'
    controller = common.load_module(controller_path, 'normal_inherited_actual_controller')
    # Bind the frozen health source to the measured same-UUID current boot clock.
    health_original=controller.HEALTH.read_text()
    previous_scope=__import__('json').loads(common.exact(scope['oldScope']).read_bytes())
    common.need(previous_scope['bootSessionUUID']==actual_generation['bootSessionUUID'], 'same actual boot UUID for health clock binding')
    old_clock='= '+str(previous_scope['bootSeconds'])+' ]'
    new_clock='= '+str(actual_generation['bootSeconds'])+' ]'
    common.need(health_original.count(old_clock)==1, 'exact one historical health boot check')
    current_health_script=health_original.replace(old_clock,new_clock)
    current_health_script=boot_clock.bind(current_health_script,actual_generation)

    common.need(str(actual_generation['bootSeconds']) in controller.prefix(0) and
                actual_generation['bootSessionUUID'] in controller.prefix(0),
                'inherited controller must enforce the same actual boot and UUID')
    boot_clock.bind_controller(controller,actual_generation)
    batch_path = SCRIPT_DIR / 'independent27_device_product_verify_fast_v1.py'
    batch = common.load_module(batch_path, 'normal_actual_product_batch')
    nonce = secrets.token_hex(32)
    session_path = '/private/var/mobile/Library/.VM27-normal-guest-' + nonce
    app_file = next(row for row in scope['files'] if row['devicePath'] == scope['deviceAppMain'])
    close = controller.prefix(0) + '''[ -f "$OWN_APP_MAIN" ] && [ ! -L "$OWN_APP_MAIN" ]
[ "$(realpath "$OWN_APP_MAIN")" = "$OWN_APP_MAIN" ]
'''
    close += '[ "$(stat -c %u:%g:%a:%h:%s "$OWN_APP_MAIN")" = ' + shlex.quote('501:501:' + format(app_file['mode'], 'o') + ':1:' + str(app_file['local']['bytes'])) + ' ]\n'
    close += '[ "$(sha256sum "$OWN_APP_MAIN" | cut -d \' \' -f1)" = ' + app_file['local']['sha256'] + ' ]\n'
    close += controller.PROCESS_FUNCTIONS + '''scan_own
[ -z "$child_rows" ]
signal_own TERM "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app
sleep 1
signal_own KILL "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app
'''+controller.off_check()+"printf 'OWN_NORMAL_EXACT_SELF_APP_CLOSED_NO_CHILD_OR_FOREIGN_SIGNAL\\n'\n"
    preflight = controller.prefix(0) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c ' + shlex.quote(close) + '\n'
    preflight += controller.prefix(0) + controller.off_check() + current_health_script + batch.batch_check(scope)
    preflight += batch.cd_check(scope, scope['actualNativeCDSubset'])
    # Repeat the same exact UI-only close after the expensive product checks.
    # Guest/log snapshots and the existing backup transaction then follow it.
    preflight += controller.prefix(0) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c ' + shlex.quote(close) + '\n'
    preflight += common.guest_shell(facts)
    log_identity = actual_generation['identity']
    common.need(':'.join(facts['priorLogMetadata'].split(':')[:6]) == log_identity,
                'fresh actual readonly log identity must match the same initializer post')
    preflight += '[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = ' + shlex.quote(log_identity) + ' ]\n'
    preflight += 'own_log_stable_generation=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")\n'
    preflight += 'OWN_NORMAL_BACKUP=' + shlex.quote(session_path) + '\n'
    preflight += '''[ ! -e "$OWN_NORMAL_BACKUP" ] && [ ! -L "$OWN_NORMAL_BACKUP" ]
umask 077
mkdir "$OWN_NORMAL_BACKUP"
chown 0:0 "$OWN_NORMAL_BACKUP"
chmod 700 "$OWN_NORMAL_BACKUP"
[ "$(stat -c %u:%g:%a "$OWN_NORMAL_BACKUP")" = 0:0:700 ]
[ "$(realpath "$OWN_NORMAL_BACKUP")" = "$OWN_NORMAL_BACKUP" ]
cp -- "$OWN_LOG" "$OWN_NORMAL_BACKUP/prior.log"
chown 0:0 "$OWN_NORMAL_BACKUP/prior.log"
chmod 600 "$OWN_NORMAL_BACKUP/prior.log"
[ -f "$OWN_NORMAL_BACKUP/prior.log" ] && [ ! -L "$OWN_NORMAL_BACKUP/prior.log" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_NORMAL_BACKUP/prior.log")" = 0:0:600:1 ]
[ "$(sha256sum "$OWN_NORMAL_BACKUP/prior.log" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = "$own_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_stable_generation" ]
printf 'OWN_PRIOR_LOG_BACKED_UP %s %s\\n' "$OWN_NORMAL_BACKUP/prior.log" "$own_log_sha"
'''
    empty_log_metadata = log_identity + ':0'
    empty_sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    preflight += ': > "$OWN_LOG"\n'
    preflight += '[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = ' + shlex.quote(empty_log_metadata) + ' ]\n'
    preflight += '[ "$(sha256sum "$OWN_LOG" | cut -d \' \' -f1)" = ' + empty_sha + ' ]\n'
    preflight += "printf 'OWN_NORMAL_PREFLIGHT_CANONICAL_EMPTY_LOG " + empty_log_metadata + ' ' + empty_sha + "\\n'\n"
    preflight += controller.off_check() + "printf 'OWN_NORMAL_PREFLIGHT_COMPLETE_NO_GUEST_START\\n'\n"
    expected_start_facts = dict(facts, priorLogMetadata=empty_log_metadata, priorLogSHA256=empty_sha)
    scripts = dict(preflight=common.bounded(preflight, controller, 90, 0),
                   start=render_start(controller, scope, expected_start_facts, nonce),
                   observe=render_owned(controller, 'observe').replace('@NONCE@', shlex.quote(nonce)),
                   stop=render_owned(controller, 'stop').replace('@NONCE@', shlex.quote(nonce)))
    # Separate root post remains valid while holding the exact same ledger.
    post = controller.prefix(0) + controller.off_check() + batch.batch_check(scope) + current_health_script
    post += "printf 'OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF\\n'\n"
    scripts['post'] = common.bounded(post, controller, 45, 0)
    for action, script in scripts.items():
        common.need('1791813884' not in script and '47534875' not in script,
                    'fresh normal action must not retain historical boot or log gates')
        subprocess.run(['/bin/sh', '-n'], input=script.encode(), check=True)
        common.need(common.quoted_size(script, action in ('preflight', 'post')) + 10000 < 262144,
                    'exact normal remote argv margin')
    output.mkdir(mode=0o700)
    for action, script in scripts.items():
        (output / (action + '.sh')).write_text(script)
    runner = SCRIPT_DIR / 'independent27_normal_guest_lifecycle_v8.py'
    shutil.copyfile(runner, output / 'control.py')
    source_inputs = [pathlib.Path(boot_clock.__file__),boot_clock.PROOF,pathlib.Path(__file__).resolve(), pathlib.Path(common.__file__), runner, controller_path,
                     batch_path, controller.HEALTH, pathlib.Path(generation.__file__),
                     common.exact(actual_generation['actualPostStdout']), initializer, initializer.parent / 'freeze.json',
                     args.initializer_launch.resolve(), args.initializer_post.resolve(), args.guest_readonly.resolve(),
                     args.guest_configuration.resolve(), failed_path, common.exact(failed['request']),
                     common.exact(failed['stdout']), common.exact(failed['stderr']), *extra_screen_inputs]
    plan = dict(schema='Inactive owned normal guest actual same-boot post-derived log handoff packet v18 maximum900 minimum300 preflight90', builder=common.pin(__file__),
        common=common.pin(common.__file__), controller=common.pin(output / 'control.py'),
        inheritedController=common.pin(controller_path), inheritedProcessFunctionsSHA256=__import__('hashlib').sha256(controller.PROCESS_FUNCTIONS.encode()).hexdigest(),
        initializerCandidate=common.pin(initializer), initializerLaunch=common.pin(args.initializer_launch.resolve()),
        initializerPost=common.pin(args.initializer_post.resolve()), freshGuestReadonly=common.pin(args.guest_readonly.resolve()),
        freshGuestConfiguration=common.pin(args.guest_configuration.resolve()), foregroundUSBScreenReceipt=screen_pin,
        beforeGuestScreenshotAvailable=screenshot is not None, beforeGuestScreenshotAutoReviewFailure=review_failure_pin,
        noBeforeScreenshotInputFreeBoot=args.no_before_screenshot_input_free_boot,
        historicalForegroundUSBScreenReceipt=historical_screen_pin, historicalScreenshotUsedForCalibration=False,
        currentScreenshotAbsentForInputFreeBoot=args.no_before_screenshot_input_free_boot,
        missingCurrentScreenDoesNotEstablishActualGuestDisplay=True,
        noBeforeScreenshotClaim=screenshot is None, inputCalibrationPassed=False, noInputCalibrationPassed=True,
        guestDisplayAcceptanceRequiresActualNativeUSBScreen=True,
        guestInputAcceptanceRequiresActualNativeUSBScreenAndCalibration=True,
        priorNormalPreflightFailure=common.pin(failed_path), priorNormalPreflightFailureExit=8,
        boundedExactSelfAppCloseBeforePreflight=True, boundedExactSelfAppCloseAfterProductChecksBeforeGuestAndLogSnapshot=True, closeSelfAppSeconds=20, rejectsAnyChildBeforeClose=True,
        fixedOwnedLogIdentity=log_identity, originalReadonlyLogFactsHistoricalOnly=True,
        actualInitializerLogGeneration=actual_generation,
        logIdentityDerivedOnlyFromActualSameInitializerPost=True,
        historicalFixedLogInodeNotUsed=True,
        expectedCanonicalEmptyLogForStart=dict(metadata=empty_log_metadata, sha256=empty_sha,
            producedOnlyByActualSuccessfulPreflight=True, actualNewReadonlyReceipt=False),
        guestPath=common.GUEST, guestFacts=facts, ownLog=common.LOG, ownAppMain=scope['deviceAppMain'], ownChildMain=scope['deviceChildMain'],
        sessionNonce=nonce, backupDirectory=session_path, exclusiveOnceURL=True,
        actions={action: common.pin(output / (action + '.sh')) for action in scripts},
        remoteTERMSeconds=980, remoteKILLSeconds=1000, startTransportSeconds=1050, shortTransportSeconds=55, preflightRemoteWallSeconds=90, preflightTransportSeconds=110,
        observeSeconds=900, earliestHandoffWallSeconds=300, maximumStartObservationSeconds=900, earlyHandoffRequiresAllExistingFrameAndLateProgressGates=True, wallClockGuardSeconds=900, clockSource='guarded /var/jb/usr/bin/date wall time, not monotonic', hostMonotonicMinimumObservationSeconds=285, hostMonotonicLateProgressAfterSeconds=150, terminalCleanupSeconds=20, boundedACKReadSeconds=15, failedStartPostAdmission='independent readonly OFF-first; never prefix cleanup claim', explicitHandoffAndACKFailureGuards=True, protocolRejectionKeepsSSHOutputOpenThroughNativeCleanup=True, cleanupDiagnosticPipeCannotInterruptValidatedSignals=True, requiresActualStateRunningAndLateCPUBitmapFrameProgressForOffer=True, frameProgressBackend='cpu-bitmap', frameProgressEvidence='successful IOSurface CPU copy, CGImage publication, returned commit and CA transaction completion', frameProgressMaximumDimension=8192, frameProgressIsPhysicalScreenEvidence=False, frameProgressIsMetalGPUCompletion=False,
        ownershipTransfer='Root active goal owns fsync ledger before explicit single ACK; unresolved ACK retains that owner until exact stop',
        noACKOrStartFailureRunsInheritedExactCleanup=True, followupObserveFailureRetainsExplicitOwnerUntilStop=True,
        actualVisibleGuest=False, actualGuestStarted=False, actualSSHAvailable=False, networkAvailable=False,
        trustCacheOperations=0, nativeKernelWrites=0, deviceOperations=0, readyForRootSerialDispatch=False,
        requiresFreshIndependentConcretePacketReview=True, requiresExplicitRootReadyBinding=True)
    common.dump(output / 'candidate.json', plan)
    source_inputs += [output / 'candidate.json', output / 'control.py', *[output / (a + '.sh') for a in scripts]]
    common.dump(output / 'freeze.json', dict(files=[common.pin(p) for p in source_inputs], deviceOperations=0))
    print(json.dumps(dict(candidate=common.pin(output / 'candidate.json'), freeze=common.pin(output / 'freeze.json'))))


def main():
    parser = argparse.ArgumentParser()
    for name in ('initializer-candidate', 'initializer-launch', 'initializer-post', 'guest-readonly',
                 'guest-configuration', 'prior-normal-preflight-failure', 'output'):
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    parser.add_argument('--foreground-screenshot-receipt', type=pathlib.Path)
    parser.add_argument('--before-screenshot-review-failure', type=pathlib.Path)
    parser.add_argument('--no-before-screenshot-input-free-boot', action='store_true')
    parser.add_argument('--historical-foreground-screenshot-receipt', type=pathlib.Path)
    prepare(parser.parse_args())


def source13_duration_delta_v18(text):
    """Exact allowed script delta; all other shell bytes must equal Source13."""
    for before, after in (
        ('--kill-after=20 112 ', '--kill-after=20 980 '),
        ('[ "$own_elapsed" -lt 95 ]', '[ "$own_elapsed" -lt 900 ]'),
        ('[ "$own_elapsed" -ge 45 ]', '[ "$own_elapsed" -ge 150 ]'),
        ('--kill-after=1 5 /var/jb/bin/sh', '--kill-after=1 15 /var/jb/bin/sh'),
        ('independent monotonic90s and after45s frame progress', 'independent monotonic285s and after150s frame progress'),
    ):
        text = text.replace(before, after)
    # This double-quoted argument sequence survives shlex.quote unchanged and
    # occurs only in start, never in the follow-up OWN_LEASE_OBSERVE loop.
    text = text.replace('"$own_elapsed" "$own_accept" "$own_started" "$own_frames" "$own_first" "$own_last" "$own_late_progress"\n [ "$own_elapsed" -lt 900 ] || break', '"$own_elapsed" "$own_accept" "$own_started" "$own_frames" "$own_first" "$own_last" "$own_late_progress"\n if [ "$own_elapsed" -ge 300 ] && [ "$own_accept" = 1 ] && [ "$own_started" = 1 ] && [ "$own_frames" -ge 2 ] && [ "$own_last" -gt "$own_first" ] && [ "$own_late_progress" = 1 ];then break;fi\n [ "$own_elapsed" -lt 900 ] || break', 1)
    if 'OWN_NORMAL_PREFLIGHT_COMPLETE_NO_GUEST_START' in text:
        old_preflight_bound = '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c '
        assert text.count(old_preflight_bound) == 1, 'one exact original preflight outer45 bound'
        text = text.replace(old_preflight_bound, old_preflight_bound.replace(' 45 ', ' 90 '), 1)
    return text


if __name__ == '__main__':
    main()
