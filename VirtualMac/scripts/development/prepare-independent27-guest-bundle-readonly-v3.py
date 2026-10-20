#!/usr/bin/env python3
"""HOST preparation only. Future init0/post0 are mandatory at actual dispatch."""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import independent27_normal_guest_common_v2 as common


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--initializer-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    initializer = args.initializer_candidate.resolve()
    packet = json.loads(initializer.read_bytes())
    scope = json.loads(common.exact(packet['scope']).read_bytes())
    control_path = initializer.parent / 'control.py'
    controller = common.load_module(control_path, 'guest_actual_initializer_source')
    batch_path = pathlib.Path(__file__).with_name('independent27_device_product_verify_fast_v1.py')
    batch = common.load_module(batch_path, 'guest_exact_product_batch')
    body = controller.prefix(0) + controller.off_check() + controller.HEALTH.read_text()
    body += batch.batch_check(scope) + common.guest_shell() + controller.off_check()
    script = common.bounded(body, controller, 40, 0)
    common.need(common.quoted_size(script, True) + 10000 < 262144, 'actual finite remote ARG_MAX margin')
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), check=True)
    output = args.output.resolve()
    common.need(output.parent == common.N and not output.exists(), 'fresh prepared readonly output')
    output.mkdir(mode=0o700)
    (output / 'read-root.sh').write_text(script)
    runner = pathlib.Path(__file__).with_name('independent27_guest_bundle_readonly_v2.py')
    shutil.copyfile(runner, output / 'read.py')
    candidate = dict(schema='Inactive prepared actual Tahoe3 readonly packet v3', initializerCandidate=common.pin(initializer),
        controller=common.pin(control_path), common=common.pin(common.__file__), script=common.pin(output / 'read-root.sh'),
        runner=common.pin(output / 'read.py'), builder=common.pin(__file__), guestPath=common.GUEST,
        requiresActualSameInitializerLaunch0AndPost0=True, requiresIndependentReadonlyPacketReview=True,
        metadataOnlyFiles=['AuxiliaryStorage', 'Disk.img'], smallCopyAndSHA=list(common.SMALL),
        remoteWallSeconds=40, remoteKillAfterSeconds=3, transportWallSeconds=55,
        maximumRemoteCommandBytes=common.quoted_size(script, True), deviceOperations=0, readyForDeviceExecution=False,
        actualGuestReadPerformed=False, actualGuestStarted=False)
    common.dump(output / 'candidate.json', candidate)
    pins = [common.pin(p) for p in (pathlib.Path(__file__).resolve(), pathlib.Path(common.__file__), runner,
        initializer, initializer.parent / 'freeze.json', control_path, batch_path, controller.HEALTH,
        output / 'read-root.sh', output / 'read.py', output / 'candidate.json')]
    common.dump(output / 'freeze.json', dict(files=pins, deviceOperations=0))
    print(json.dumps(dict(candidate=common.pin(output / 'candidate.json'), freeze=common.pin(output / 'freeze.json'))))


if __name__ == '__main__':
    main()
