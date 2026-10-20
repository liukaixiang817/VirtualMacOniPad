#!/usr/bin/env python3
"""Freeze HOST-only source readiness without manufacturing future admission."""
import ast
import hashlib
import json
import pathlib
import sys

sys.dont_write_bytecode = True
import independent27_normal_guest_common_v2 as common


def main():
    out = common.N / 'independent27-normal-guest-lifecycle-source-v1-attempt1'
    common.need(not out.exists(), 'fresh source-only finalization')
    source = pathlib.Path(__file__).resolve().parent
    files = [source / name for name in (
        'independent27_normal_guest_common_v2.py', 'prepare-independent27-guest-bundle-readonly-v3.py',
        'independent27_guest_bundle_readonly_v2.py', 'prepare-independent27-normal-guest-lifecycle-v1.py',
        'independent27_normal_guest_lifecycle_v1.py', 'test_independent27_normal_guest_lifecycle_v1.py',
        'finalize-independent27-normal-guest-lifecycle-source-v1.py')]
    for path in files:
        tree = ast.parse(path.read_text())
        compile(tree, str(path), 'exec')
    model_dir = common.N / 'independent27-normal-guest-lifecycle-host-wire-v1-attempt3'
    model = json.loads((model_dir / 'report.json').read_bytes())
    common.need(model.get('findings') == [] and model.get('finiteHostScopePassed') is True and
                model.get('deviceOperations') == 0 and len(model['tests']) == 6, 'actual finite HOST pipe model report')
    for row in json.loads((model_dir / 'freeze.json').read_bytes())['files']:
        common.exact(row)
    read_dir = common.N / 'independent27-guest-bundle-readonly-prepared-v3-attempt1'
    readonly = json.loads((read_dir / 'candidate.json').read_bytes())
    common.need(readonly['deviceOperations'] == 0 and readonly['readyForDeviceExecution'] is False,
                'readonly source cannot claim actual future success')
    for row in json.loads((read_dir / 'freeze.json').read_bytes())['files']:
        common.exact(row)
    actual_launch = common.N / 'independent27-owned-bundle-device-v3-attempt1/device-receipts/launch/receipt.json'
    launch = json.loads(actual_launch.read_bytes())
    common.need(launch['transportExit'] == 1, 'this finalization records the actual current failed initializer')
    blocked = False
    try:
        common.receipt(actual_launch)
    except ValueError:
        blocked = True
    common.need(blocked, 'actual failed initializer must not satisfy success admission')
    launch_text = common.exact(launch['stdout']).read_text()
    common.need('Security Assertion Hit:' in launch_text, 'preserve actual unresolved original security assertion')
    out.mkdir(mode=0o700)
    report = dict(schema='Inactive normal guest lifecycle source finalization v1',
        sourceFiles=[common.pin(p) for p in files], hostPipeModels=common.pin(model_dir / 'report.json'),
        hostPipeModelsFreeze=common.pin(model_dir / 'freeze.json'), readonlyCandidate=common.pin(read_dir / 'candidate.json'),
        readonlyFreeze=common.pin(read_dir / 'freeze.json'), currentActualInitializer=common.pin(actual_launch),
        actualInitializerExit=1, actualSecurityAssertionUnresolved=True, failedInitializerActuallyRejectedByGate=blocked,
        findings=[], finiteHOSTSourceScopePassed=True, readyForRootSerialDispatch=False,
        normalPacketProduced=False, futureInitializerSuccessSynthesized=False, futureGuestFactsSynthesized=False,
        sourceInterfaces=dict(readonlyPrepare='prepare-independent27-guest-bundle-readonly-v3.py --initializer-candidate ACTUAL_FUTURE_PACKET --output NEW_DIR',
            readonlyDispatch='read.py --packet PREPARED_DIR --initializer-launch ACTUAL_LAUNCH0 --initializer-post ACTUAL_POST0 --peer-review ACTUAL_REVIEW --output NEW_FACT_DIR',
            normalPrepare='prepare-independent27-normal-guest-lifecycle-v1.py --initializer-candidate ACTUAL_PACKET --initializer-launch ACTUAL_LAUNCH0 --initializer-post ACTUAL_POST0 --guest-readonly ACTUAL_READ0 --guest-configuration ACTUAL_CONFIG --foreground-screenshot-receipt ACTUAL_USB --output NEW_NORMAL_PACKET',
            normalDispatch='control.py --packet ACTUAL_NORMAL_PACKET --ready ROOT_REVIEWED_READY --action preflight|start|observe|stop|post',
            handoff='start --confirm-handoff; actual offer -> fsync ledger+ACK record -> single ACK -> actual commit; Root owns even uncertain attempted ACK',
            continuation='observe --lease EXACT_START_LEDGER --sequence NEW_SEQUENCE; stop --lease EXACT_START_LEDGER; post'),
        limits=dict(observeSeconds=90, remoteTerm132HardKill135=True, SSH145=True, stopTerm20Kill23SSH55=True),
        exactInheritedProcessFunctionsSHA256=model['processFunctionsSHA256'], ownURLCount=1,
        noDaemonOrCrossThreadAutomation=True, nativeKernelWrites=0, trustCacheOperations=0, deviceOperations=0,
        actualGuestStarted=False, actualGuestVisible=False, actualSSHAvailable=False,
        explicitLimitations=['HOST pipe models and sh syntax do not validate real SSH/timeout/HUP/UIKit/VZ.',
            'Future concrete packet and separate peer/Root ready must bind actual init0/post0/fresh read0/USB capture.',
            'Metal progress is genuine frame submission evidence only; visible guest requires actual USB screenshot.',
            'App current NIC0 is not SSH availability; guest TCP22222 still requires the distinct real bridge.',
            'Unexpected identity or transport ambiguity retains the declared Root obligation; never blind retry or arbitrary PID kill.'])
    common.dump(out / 'candidate.json', report)
    pins = files + [model_dir / 'report.json', model_dir / 'freeze.json', read_dir / 'candidate.json', read_dir / 'freeze.json',
                    actual_launch, common.exact(launch['request']), common.exact(launch['stdout']), common.exact(launch['stderr']), out / 'candidate.json']
    common.dump(out / 'freeze.json', dict(files=[common.pin(p) for p in pins], deviceOperations=0))
    print(json.dumps(dict(candidate=common.pin(out / 'candidate.json'), freeze=common.pin(out / 'freeze.json'))))


if __name__ == '__main__':
    main()
