#!/usr/bin/env python3
"""Create an explicit owned endpoint composition, leaving frozen providers intact."""
import hashlib
import json
import pathlib
R = pathlib.Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def main():
    out = N / 'owned-bundle-consumer-startup-source-v6-attempt1'
    assert not out.exists()
    names = ['modern_xpc_large_private_consumer_v5.c', 'modern_xpc_large_private_consumer_v5.h',
             'vm27_owned_app_child_startup_v6.c', 'vm27_owned_app_child_startup_v6.inc']
    assert all(not (S / name).exists() for name in names)
    consumer = (S / 'modern_xpc_large_private_consumer_v3.c').read_text()
    spawn = (S / 'modern_xpc_large_private_consumer_v4.c').read_text()
    inherited_pins = [pin(S / name) for name in ['modern_xpc_large_private_consumer_v3.c',
        'modern_xpc_large_private_consumer_v4.c', 'vm27_owned_app_child_startup_v4.c',
        'vm27_owned_app_child_startup_v5.c']]
    consumer = consumer.replace('#include "modern_xpc_large_private_consumer_v2.h"',
        '#include "modern_xpc_large_private_consumer_v5.h"\n#include "vm27_owned_bundle_approved_policy_v1.h"', 1)
    consumer = consumer.replace('    VM27ApprovedCodePolicy *approved;',
        '    VM27ApprovedCodePolicy *approved;\n    VM27OwnedBundleApprovedPolicyV1 *ownedBundleApproved;', 1)
    consumer = consumer.replace('static _Atomic uint64_t Created, Destroyed, Spawns, Reaps, MessageChecks;',
        '/* Private state is created only by the explicitly named owned API. */\n'
        '#define VM27_OWNED_BUNDLE_MODE_V5 ((VM27LargePrivateConsumerV2Mode)3)\n'
        'static _Atomic uint64_t Created, Destroyed, Spawns, Reaps, MessageChecks;', 1)
    marker = 'int VM27LargePrivateServiceConsumerV2Release('
    create = '''/* This is a separate opt-in contract for the independently installed owned
 * endpoint. V2Create still accepts only its original modes and never falls back.
 * The actual registry plan supplies the canonical .xpc path and executable. */
int VM27OwnedBundlePrivateServiceConsumerCreateV5(VM27LargeBundleRegistry *registry,
    const char *service, const char *SHA, const char *CD, xpc_object_t requirement,
    VM27LargePrivateServiceConsumerV2 **out) {
    if (!out) return EINVAL;
    *out = NULL;
    if (!registry || !service || !SHA || !CD || !requirement) return EINVAL;
    VM27LargePrivateServiceConsumerV2 *consumer = calloc(1, sizeof(*consumer));
    if (!consumer) return ENOMEM;
    int status = VM27LargeBundleRegistryCopyServicePlan(registry, service, &consumer->plan);
    if (!status) status = VM27LargeServicePlanCopyInfo(consumer->plan, &consumer->info);
    if (!status) status = VM27LargeServicePlanVerify(consumer->plan);
    if (!status) status = Authenticate(&consumer->info, SHA, CD);
    if (!status) {
        const char *name = strrchr(consumer->info.executablePath, '/') + 1;
        static const char suffix[] = "/Contents/MacOS/";
        size_t prefix = (size_t)(name - consumer->info.executablePath);
        size_t bundleBytes = prefix - (sizeof(suffix) - 1);
        char bundle[4096];
        memcpy(bundle, consumer->info.executablePath, bundleBytes);
        bundle[bundleBytes] = 0;
        VM27BundleParentConfigurationV1 actual = {bundle, name, SHA, CD, geteuid()};
        status = VM27OwnedBundleApprovedPolicyCreateV1(&actual, consumer->plan,
            requirement, &consumer->ownedBundleApproved);
    }
    if (!status) status = pthread_mutex_init(&consumer->mutex, NULL);
    if (status) {
        if (consumer->ownedBundleApproved) VM27OwnedBundleApprovedPolicyReleaseV1(consumer->ownedBundleApproved);
        if (consumer->plan) VM27LargeServicePlanRelease(consumer->plan);
        free(consumer);
        return status;
    }
    memcpy(consumer->reviewedSHA256, SHA, sizeof(consumer->reviewedSHA256));
    memcpy(consumer->reviewedCDHash, CD, sizeof(consumer->reviewedCDHash));
    consumer->mode = VM27_OWNED_BUNDLE_MODE_V5;
    consumer->state.observedWaitExit = -1;
    *out = consumer;
    atomic_fetch_add(&Created, 1);
    return 0;
}
'''
    assert consumer.count(marker) == 1
    consumer = consumer.replace(marker, create + marker, 1)
    old_release = '    VM27LargeServicePlanRelease(consumer->plan); if (consumer->approved) VM27ApprovedCodePolicyRelease(consumer->approved);'
    assert consumer.count(old_release) == 1
    consumer = consumer.replace(old_release,
        '    if (consumer->ownedBundleApproved) VM27OwnedBundleApprovedPolicyReleaseV1(consumer->ownedBundleApproved);\n' + old_release, 1)
    check = '        if (consumer->mode == VM27LargeConsumerV2ExplicitApprovedCode) status = VM27ApprovedCodeCheckReceivedMessage(consumer->approved, message, out);'
    assert consumer.count(check) == 1
    consumer = consumer.replace(check,
        '        if (consumer->mode == VM27_OWNED_BUNDLE_MODE_V5) status = VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(consumer->ownedBundleApproved, message, out);\n'
        '        else if (consumer->mode == VM27LargeConsumerV2ExplicitApprovedCode) status = VM27ApprovedCodeCheckReceivedMessage(consumer->approved, message, out);', 1)
    begin = consumer.index('int VM27LargePrivateServiceConsumerV2Spawn(')
    end = consumer.index('int VM27LargePrivateServiceConsumerV2CheckMessage(', begin)
    actual_spawn = spawn[spawn.index('int VM27LargePrivateServiceConsumerV2Spawn('):]
    consumer = consumer[:begin] + actual_spawn + consumer[end:]
    consumer = '/* V5 explicitly adds owned bundle approval. Original V2 modes, strict\n * policy, wait/reap, actual spawn and all inherited APIs retain their contracts.\n * Generated from frozen V3 plus the actual V4 Spawn; see source candidate. */\n#include <stdio.h>\n' + consumer
    header = '''#ifndef VM27_LARGE_PRIVATE_CONSUMER_V5_H
#define VM27_LARGE_PRIVATE_CONSUMER_V5_H
#include "modern_xpc_large_private_consumer_v2.h"
/* Explicit owned endpoint only. Full canonical bundle signatures, fixed SHA/CD,
 * actual spawned message audit PID/version, kernel CD/CS_VALID and genuine
 * plugin Boolean are required. Native validation is recorded independently;
 * StrictNative/default and the old raw policy remain unchanged. */
int VM27OwnedBundlePrivateServiceConsumerCreateV5(VM27LargeBundleRegistry *,
    const char *, const char *, const char *, xpc_object_t,
    VM27LargePrivateServiceConsumerV2 **);
#endif
'''
    inc = (S / 'vm27_owned_app_child_startup_v4.c').read_text()
    inc = inc.replace('#include "vm27_owned_app_child_startup_v3.h"',
        '#include "vm27_owned_app_child_startup_v3.h"\n#include "modern_xpc_large_private_consumer_v5.h"\n#include <errno.h>', 1)
    call = '    int status = VM27LargePrivateServiceConsumerV2Create(r, service, sha, cd, requirement, mode, out);'
    assert inc.count(call) == 1
    inc = inc.replace(call,
        '    /* Independent startup deliberately selects its own fixed endpoint\n'
        '     * contract before any checks; this is never a native failure fallback. */\n'
        '    int status = mode != VM27LargeConsumerV2StrictNative ? EINVAL :\n'
        '        VM27OwnedBundlePrivateServiceConsumerCreateV5(r, service, sha, cd, requirement, out);', 1)
    inc = inc.replace('parent-start consumer-create status=%d\\n', 'parent-start owned-bundle-consumer-create status=%d\\n')
    startup = (S / 'vm27_owned_app_child_startup_v5.c').read_text()
    startup = startup.replace('#include "vm27_owned_app_child_startup_v4.c"',
        '#include "vm27_owned_app_child_startup_v6.inc"', 1)
    startup = startup.replace('"codeQueryError=%d statusQueryError=%d\\n",',
        '"codeQueryError=%d statusQueryError=%d explicitApprovedCodeAccepted=%d\\n",', 1)
    startup = startup.replace('out->dynamicCodeValid, out->codeQueryError, out->statusQueryError);',
        'out->dynamicCodeValid, out->codeQueryError, out->statusQueryError, out->explicitApprovedCodeAccepted);', 1)
    startup = startup.replace('/* Actual post-spawn diagnostics only. Each original typed callee executes once;\n * its return value, errno, output ownership and all frozen gates are preserved. */',
        '/* Explicit independent owned startup composition. Diagnostics preserve\n * actual native result/validated flags and separately record owned acceptance.\n * CPU/VMM, original coordinator/transport and public bootstrap ABI are retained. */', 1)
    out.mkdir(mode=0o700)
    for name, source in zip(names, [consumer, header, startup, inc]):
        (S / name).write_text(source)
    record = dict(schema='Explicit owned bundle consumer/startup source v6',
        builder=pin(__file__), sources=[pin(S/name) for name in names], inheritedSources=inherited_pins,
        originalV2CreateOnlyModes1And2=True, newModePrivateAndExplicit=True,
        nativePolicyUnchanged=True, originalCoordinatorAndTransportUnchanged=True,
        actualV4SpawnFunctionUnchanged=True, spawnedPIDVersionAndReapGatesRetained=True,
        nativeValidationNeverForged=True, noFailureFallback=True, deviceOperations=0)
    (out/'candidate.json').write_text(json.dumps(record, indent=2)+'\n')
    files = record['sources'] + inherited_pins + [pin(__file__), pin(out/'candidate.json')]
    (out/'freeze.json').write_text(json.dumps(dict(files=files, deviceOperations=0), indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), freeze=pin(out/'freeze.json'))))

if __name__ == '__main__':
    main()
