#!/usr/bin/env python3
"""HOST preparation after actual init0/post0; bind their real log generation."""
import argparse
import json
import pathlib
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import independent27_normal_guest_common_v2 as common
import independent27_initializer_log_generation_v1 as generation
import independent27_boot_clock_binding_v1 as boot_clock


UI_ONLY_GUARD = r'''
own_read_ui_pid=0
own_read_ui_start=none
check_owned_ui_child_off() {
 own_read_rows=$(ps -axo pid=,ppid=,uid=,comm=)
 printf '%s\n' "$own_read_rows" | awk 'NF<4 {bad=1} END {if(bad || NR<1)exit 8}'
 own_read_child_rows=$(printf '%s\n' "$own_read_rows" | awk -v c="$OWN_CHILD_MAIN" '$4==c {print $0}')
 [ -z "$own_read_child_rows" ]
 own_read_app_rows=$(printf '%s\n' "$own_read_rows" | awk -v a="$OWN_APP_MAIN" '$4==a {print $1,$2,$3,$4}')
 [ "$(printf '%s\n' "$own_read_app_rows" | awk 'NF {n++} END {print n+0}')" -le 1 ]
 if [ -n "$own_read_app_rows" ];then
  set -- $own_read_app_rows
  [ "$#" = 4 ] && [ "$1" -gt 1 ] && [ "$2" = 1 ] && [ "$3" = 501 ] && [ "$4" = "$OWN_APP_MAIN" ] || exit 8
  own_read_start=$(ps -p "$1" -o lstart= | sha256sum | cut -d ' ' -f1)
  if [ "$own_read_ui_pid" = 0 ];then own_read_ui_pid=$1;own_read_ui_start=$own_read_start;fi
  [ "$1" = "$own_read_ui_pid" ] && [ "$own_read_start" = "$own_read_ui_start" ] || exit 8
  ps -p "$1" -o stat= | awk 'NF==1 && $1 !~ /^[ZTX]/ {ok=1} END {exit !ok}'
  printf 'OWN_GUEST_READ_UI_APP_OBSERVED %s 1 501 %s %s\n' "$1" "$own_read_start" "$OWN_APP_MAIN"
 else
  [ "$own_read_ui_pid" = 0 ]
  printf 'OWN_GUEST_READ_UI_APP_ABSENT\n'
 fi
 printf 'INDEPENDENT27_GUEST_READ_OWN_CHILD_OFF_UI_APP_NOT_VM_EVIDENCE\n'
}
check_owned_ui_child_off
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = @ACTUAL_POST_LOG_IDENTITY@ ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_read_prior_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_read_prior_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--initializer-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--initializer-launch', type=pathlib.Path, required=True)
    parser.add_argument('--initializer-post', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    initializer = args.initializer_candidate.resolve()
    actual_generation = generation.actual_post_log_generation(
        initializer, args.initializer_launch.resolve(), args.initializer_post.resolve())
    packet = json.loads(initializer.read_bytes())
    scope = json.loads(common.exact(packet['scope']).read_bytes())
    control_path = initializer.parent / 'control.py'
    controller = common.load_module(control_path, 'guest_actual_initializer_source')
    # Bind the frozen health source to the measured same-UUID current boot clock.
    health_original=controller.HEALTH.read_text()
    previous_scope=__import__('json').loads(common.exact(scope['oldScope']).read_bytes())
    common.need(previous_scope['bootSessionUUID']==actual_generation['bootSessionUUID'], 'same actual boot UUID for health clock binding')
    old_clock='= '+str(previous_scope['bootSeconds'])+' ]'
    new_clock='= '+str(actual_generation['bootSeconds'])+' ]'
    common.need(health_original.count(old_clock)==1, 'exact one historical health boot check')
    current_health_script=health_original.replace(old_clock,new_clock)
    current_health_script=boot_clock.bind(current_health_script,actual_generation)
    boot_clock.bind_controller(controller,actual_generation)

    batch_path = pathlib.Path(__file__).with_name('independent27_device_product_verify_fast_v1.py')
    batch = common.load_module(batch_path, 'guest_exact_product_batch')
    prefix = controller.prefix(0)
    common.need(str(actual_generation['bootSeconds']) in prefix and
                actual_generation['bootSessionUUID'] in prefix,
                'inherited controller must enforce the same actual boot and UUID')
    guard = UI_ONLY_GUARD.replace('@ACTUAL_POST_LOG_IDENTITY@', shlex.quote(actual_generation['identity']))
    body = prefix + guard + current_health_script
    body += batch.batch_check(scope) + common.guest_shell() + '''
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_read_prior_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_read_prior_log_sha" ]
check_owned_ui_child_off
'''
    script = common.bounded(body, controller, 40, 0)
    common.need('1791813884' not in script and '47534875' not in script,
                'fresh readonly script must not retain historical boot or log gates')
    common.need(common.quoted_size(script, True) + 10000 < 262144, 'actual finite remote ARG_MAX margin')
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), check=True)
    output = args.output.resolve()
    common.need(output.parent == common.N and not output.exists(), 'fresh prepared readonly output')
    output.mkdir(mode=0o700)
    (output / 'read-root.sh').write_text(script)
    runner = pathlib.Path(__file__).with_name('independent27_guest_bundle_readonly_v2.py')
    shutil.copyfile(runner, output / 'read.py')
    candidate = dict(schema='Inactive prepared actual Tahoe3 same-boot post-derived log readonly packet v7', initializerCandidate=common.pin(initializer),
        controller=common.pin(control_path), common=common.pin(common.__file__), script=common.pin(output / 'read-root.sh'),
        runner=common.pin(output / 'read.py'), builder=common.pin(__file__), guestPath=common.GUEST,
        requiresActualSameInitializerLaunch0AndPost0=True, requiresIndependentReadonlyPacketReview=True,
        metadataOnlyFiles=['AuxiliaryStorage', 'Disk.img'], smallCopyAndSHA=list(common.SMALL),
        permitsOnlyExactCurrentUIApp=True, currentAppOffNotClaimed=True,
        actualOwnedChildOffRequiredBeforeAndAfter=True, ownedUIAppIdentityMustRemainStable=True,
        fixedOwnedLogBeforeAfterStableMetadataAndSHARequired=True,
        actualInitializerLogGeneration=actual_generation,
        logIdentityDerivedOnlyFromActualSameInitializerPost=True,
        historicalFixedLogInodeNotUsed=True, processSignals=0, deviceWrites=0,
        remoteWallSeconds=40, remoteKillAfterSeconds=3, transportWallSeconds=55,
        maximumRemoteCommandBytes=common.quoted_size(script, True), deviceOperations=0, readyForDeviceExecution=False,
        actualGuestReadPerformed=False, actualGuestStarted=False)
    common.dump(output / 'candidate.json', candidate)
    pins = [common.pin(p) for p in (pathlib.Path(boot_clock.__file__),boot_clock.PROOF,pathlib.Path(__file__).resolve(), pathlib.Path(common.__file__), runner,
        initializer, initializer.parent / 'freeze.json', control_path, batch_path, controller.HEALTH,
        pathlib.Path(generation.__file__), args.initializer_launch.resolve(), args.initializer_post.resolve(),
        common.exact(actual_generation['actualPostStdout']),
        output / 'read-root.sh', output / 'read.py', output / 'candidate.json')]
    common.dump(output / 'freeze.json', dict(files=pins, deviceOperations=0))
    print(json.dumps(dict(candidate=common.pin(output / 'candidate.json'), freeze=common.pin(output / 'freeze.json'))))


if __name__ == '__main__':
    main()
