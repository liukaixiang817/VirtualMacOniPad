#!/usr/bin/env python3
"""Finite HOST source/observed-failure handoff; does not execute a product."""
import argparse
import hashlib
import json
import pathlib
import re

R = pathlib.Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(path):
    path = pathlib.Path(path).resolve()
    value = path.read_bytes()
    return dict(path=str(path), bytes=len(value), sha256=hashlib.sha256(value).hexdigest())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.parent == N and not out.exists()
    checks = []
    def need(value, message):
        checks.append(dict(check=message, passed=bool(value)))
        if not value: raise ValueError(message)
    launch = N / 'independent27-child-plugin-device-v2-attempt1/device-receipts/launch/stdout'
    need(pin(launch)['bytes'] == 3015 and pin(launch)['sha256'] ==
         '3ac91a41c81eb4b54793bb74dff81cd316eeac4bb1b46df278e33e30651da221', 'exact observed failed launch')
    log = launch.read_text()
    gate = next(line for line in log.splitlines() if 'parent-config check-message' in line)
    parent = next(line for line in log.splitlines() if 'child-parent-identity' in line)
    for value in ['status=13', 'nativeResult=13', 'remote=1', 'task=1', 'entitlementsValidated=0',
                  'entitlementPresent=1', 'entitlementBoolean=1', 'entitlementValue=1', 'entitlementReadError=0',
                  'auditPID=94321', 'auditVersion=179966', 'codeHashMatched=0', 'codeStatus=00000000']:
        need(value in gate, 'actual config observation ' + value)
    flags = int(re.search(r'codeStatus=([0-9a-f]+)', parent).group(1), 16)
    need(flags == 0x36003005 and flags & 0x4000 == 0, 'parent observed status lacks native entitlement-validation bit')
    sec = N / 'xpc-lwcr-compat-v1/official-source-v1/SecTask.c'
    sec_text = sec.read_text()
    need('CS_VALID | CS_KILL | CS_ENTITLEMENTS_VALIDATED' in sec_text and
         'CS_DEBUGGED | CS_ENTITLEMENTS_VALIDATED' in sec_text and
         'csops_task(task, CS_OPS_STATUS' in sec_text, 'Apple primary native flag formula')
    flags_source = N / 'xpc-approved-code-v1/official-source-v1/cs_blobs.h'
    need(re.search(r'CS_ENTITLEMENTS_VALIDATED\s+0x00004000', flags_source.read_text()), 'Apple XNU exact bit')
    historical = N / 'xpc-approved-code-v1/native-five-verification.json'
    old = json.loads(historical.read_bytes())
    rows = {row['variant']: row for row in old['runs']}
    need(old['passed'] and old['strictPolicyUnchanged'], 'historical actual bounded owned-code evidence valid')
    need(rows['true']['summary']['accepted'] == 64 and rows['true']['summary']['rejected'] == 2 and
         rows['true']['nativeIdentity']['explicitApprovedCodeAccepted'] and
         not rows['true']['nativeIdentity']['entitlementsValidated'], 'historical true approved code is separate native-false decision')
    need(rows['true-unapproved']['summary']['accepted'] == 0 and
         rows['true-unapproved']['nativeIdentity']['nativeBooleanTrue'] and
         not rows['true-unapproved']['nativeIdentity']['codeHashMatched'], 'historical true but unapproved code still rejected')
    consumer = (S / 'modern_xpc_large_private_consumer_v5.c').read_text()
    def section(text, begin, end):
        at = text.index(begin); return text[at:text.index(end, at)]
    v3 = (S / 'modern_xpc_large_private_consumer_v3.c').read_text()
    need(section(consumer, 'int VM27LargePrivateServiceConsumerV2Create(', '/* This is a separate opt-in contract') ==
         section(v3, 'int VM27LargePrivateServiceConsumerV2Create(', 'int VM27LargePrivateServiceConsumerV2Release('),
         'original consumer modes1/2 Create source exact')
    actual_check = section(consumer, 'int VM27LargePrivateServiceConsumerV2CheckMessage(', 'int VM27LargePrivateServiceConsumerV2CopyState(')
    for value in ['!consumer->state.started', 'consumer->state.reaped', 'token.val[5] != (uint32_t)consumer->state.childPID',
                  '!token.val[7]', 'consumer->childVersion && token.val[7] != consumer->childVersion',
                  'VM27LargeServicePlanVerify(consumer->plan)', 'pthread_mutex_lock(&consumer->mutex)',
                  'VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(consumer->ownedBundleApproved, message, out)']:
        need(value in actual_check, 'actual Consumer prerequisite ' + value)
    release = section(consumer, 'int VM27LargePrivateServiceConsumerV2Release(', 'static int ReleasePorts(')
    need(release.index('VM27OwnedBundleApprovedPolicyReleaseV1') < release.index('VM27LargeServicePlanRelease'),
         'borrowed plan lives past approved policy release')
    startup = (S / 'vm27_owned_app_child_startup_v6.inc').read_text()
    need('mode != VM27LargeConsumerV2StrictNative ? EINVAL' in startup and
         'VM27OwnedBundlePrivateServiceConsumerCreateV5' in startup, 'owned composition selected before native checks, no fallback')
    transport = (S / 'modern_xpc_original_instance_transport_v9.c').read_text()
    install = section(transport, 'int VM27OriginalV9TransportInstallClientFactoryMessage(', 'void VM27OriginalV9TransportClearClient(')
    need('if (status) return status;' in install and 'gate.auditPID != (unsigned)state.childPID' in install and
         '!Hex(gate.kernelCDHash, 40)' in install and '!control' in install, 'unchanged factory install independently uses real successful code/PID/remote decision')
    inputs = [launch, sec, flags_source, historical,
        S / 'modern_xpc_large_private_consumer_v3.c', S / 'modern_xpc_large_private_consumer_v5.c',
        S / 'modern_xpc_large_private_consumer_v5.h', S / 'vm27_owned_app_child_startup_v6.c',
        S / 'vm27_owned_app_child_startup_v6.inc', S / 'modern_xpc_large_strict_identity_v2.c',
        S / 'modern_xpc_original_instance_transport_v9.c', S / 'modern_xpc_original_instance_transport_v10.c',
        S / 'vm27_owned_app_parent_identity_v1.c',
        N / 'owned-bundle-approved-policy-source-v1-attempt2/candidate.json',
        N / 'owned-bundle-approved-policy-source-v1-attempt2/freeze.json']
    record = dict(schema='Finite owned-bundle authentication boundaries review v1', checks=checks,
        originalObservedLaunch=pin(launch), inputs=[pin(path) for path in inputs],
        primarySources=[dict(url='https://raw.githubusercontent.com/apple-oss-distributions/Security/main/sectask/SecTask.c',
             localPin=pin(sec), lines=[444, 453]),
             dict(url='https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/kern/cs_blobs.h',
             localPin=pin(flags_source), lines=[50, 58])],
        decision='Explicit owned endpoint only; native validated=false/result13 remain real separate fields.',
        historicalEvidenceOnly='Old native 64 accepted/true-unapproved rejected supports read-only identity mechanism; no current VMM/Plan/bundle handshake proof.',
        exactCurrentChildKernelCDAndStatusNotYetMeasured=True,
        legitimateNativeEntitlementValidationGrantNotEstablished=True,
        kernelTrustFlagWrites=0, deviceOperations=0, actualCurrentChildHandshake=False,
        wholeBundleResourceWalkClaimed=False, CPUAuthorizationChanged=False,
        finiteSourceScopePassed=True, findings=[])
    out.mkdir(mode=0o700)
    def save(path, value): path.write_text(json.dumps(value, indent=2) + '\n')
    save(out / 'review.json', record)
    save(out / 'freeze.json', dict(files=[pin(path) for path in inputs] + [pin(__file__), pin(out / 'review.json')], deviceOperations=0))
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'), checks=len(checks))))

if __name__ == '__main__':
    main()
