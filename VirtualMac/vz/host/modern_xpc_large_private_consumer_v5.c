/* V5 explicitly adds owned bundle approval. Original V2 modes, strict
 * policy, wait/reap, actual spawn and all inherited APIs retain their contracts.
 * Generated from frozen V3 plus the actual V4 Spawn; see source candidate. */
#include <stdio.h>
/* Independent V2 result-completion scope. Frozen V1 providers stay unchanged.
 * Capacity, owned spawn/reap and exact native authorization remain unchanged. */
#include "modern_xpc_large_private_consumer_v5.h"
#include "vm27_owned_bundle_approved_policy_v1.h"
#include "vm27_bundle_child_inspection_v1.h"
#include "modern_xpc_large_strict_identity_v2.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
struct VM27LargePrivateServiceConsumerV2 {
    pthread_mutex_t mutex;
    VM27LargeServicePlan *plan;
    VM27ApprovedCodePolicy *approved;
    VM27OwnedBundleApprovedPolicyV1 *ownedBundleApproved;
    VM27LargeServiceInfo info;
    VM27LargePrivateConsumerV2State state;
    VM27LargePrivateConsumerV2Mode mode;
    char reviewedSHA256[65], reviewedCDHash[41];
    uint32_t childVersion;
    bool waiting;
};
/* Private state is created only by the explicitly named owned API. */
#define VM27_OWNED_BUNDLE_MODE_V5 ((VM27LargePrivateConsumerV2Mode)3)
static _Atomic uint64_t Created, Destroyed, Spawns, Reaps, MessageChecks;
static int Authenticate(const VM27LargeServiceInfo *info, const char *SHA, const char *CD) {
    if (strlen(SHA) != 64 || strlen(CD) != 40 || strcmp(SHA, info->executableSHA256) || info->flags != 2) return EACCES;
    const char *path = info->executablePath, *name = strrchr(path, '/');
    if (!name || !name[1]) return EINVAL;
    ++name;
    static const char suffix[] = "/Contents/MacOS/";
    size_t prefix = (size_t)(name - path), bytes = sizeof(suffix) - 1;
    if (prefix <= bytes || prefix - bytes >= 4096 ||
        memcmp(path + prefix - bytes, suffix, bytes)) return EINVAL;
    char bundle[4096]; memcpy(bundle, path, prefix - bytes); bundle[prefix - bytes] = 0;
    VM27BundleParentConfigurationV1 actual = {bundle, name, SHA, CD, geteuid()};
    VM27BundleParentInspectionV1 inspected = {0};
    int result = VM27BundleChildInspectV1(&actual, &inspected);
    if (!result && (strcmp(inspected.executableUUID, info->executableUUID) ||
        inspected.executableBytes != info->executableBytes ||
        !inspected.codePagesVerified || !inspected.embeddedSlotsVerified ||
        !inspected.externalInfoSlotVerified || !inspected.externalResourcesSlotVerified ||
        !inspected.descriptorsAndNamesStable || !inspected.infoExecutableNameMatched ||
        !inspected.codeResourcesIsDictionary)) result = EACCES;
    return result;
}
int VM27LargePrivateServiceConsumerV2Create(VM27LargeBundleRegistry *registry, const char *service,
                                    const char *SHA, const char *CD, xpc_object_t requirement,
                                    VM27LargePrivateConsumerV2Mode mode, VM27LargePrivateServiceConsumerV2 **out) {
    if (!out) return EINVAL; *out = NULL;
    if (!registry || !service || !SHA || !CD || !requirement || (mode != VM27LargeConsumerV2StrictNative && mode != VM27LargeConsumerV2ExplicitApprovedCode)) return EINVAL;
    VM27LWCRPolicy *constraint = NULL; int status = VM27LWCRPolicyCreate(requirement, &constraint);
    if (status) return status;
    VM27LWCRPolicyRelease(constraint);
    VM27LargePrivateServiceConsumerV2 *consumer = calloc(1, sizeof(*consumer)); if (!consumer) return ENOMEM;
    status = VM27LargeBundleRegistryCopyServicePlan(registry, service, &consumer->plan);
    if (!status) status = VM27LargeServicePlanCopyInfo(consumer->plan, &consumer->info);
    if (!status) status = VM27LargeServicePlanVerify(consumer->plan);
    if (!status) status = Authenticate(&consumer->info, SHA, CD);
    if (!status && mode == VM27LargeConsumerV2ExplicitApprovedCode) status = VM27ApprovedCodePolicyCreate(consumer->info.executablePath, SHA, CD, requirement, &consumer->approved);
    if (!status) status = pthread_mutex_init(&consumer->mutex, NULL);
    if (status) { if (consumer->plan) VM27LargeServicePlanRelease(consumer->plan); if (consumer->approved) VM27ApprovedCodePolicyRelease(consumer->approved); free(consumer); return status; }
    memcpy(consumer->reviewedSHA256, SHA, sizeof(consumer->reviewedSHA256));
    memcpy(consumer->reviewedCDHash, CD, sizeof(consumer->reviewedCDHash));
    consumer->mode = mode; consumer->state.observedWaitExit = -1; *out = consumer; atomic_fetch_add(&Created, 1); return 0;
}
/* This is a separate opt-in contract for the independently installed owned
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
int VM27LargePrivateServiceConsumerV2Release(VM27LargePrivateServiceConsumerV2 *consumer) {
    if (!consumer) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    if (consumer->state.started && !consumer->state.reaped) { pthread_mutex_unlock(&consumer->mutex); return EBUSY; }
    pthread_mutex_unlock(&consumer->mutex);
    if (consumer->ownedBundleApproved) VM27OwnedBundleApprovedPolicyReleaseV1(consumer->ownedBundleApproved);
    VM27LargeServicePlanRelease(consumer->plan); if (consumer->approved) VM27ApprovedCodePolicyRelease(consumer->approved);
    pthread_mutex_destroy(&consumer->mutex); free(consumer); atomic_fetch_add(&Destroyed, 1); return 0;
}
static int ReleasePorts(mach_port_array_t ports, mach_msg_type_number_t count) {
    int result = 0;
    if (!ports) return count ? EIO : 0;
    for (unsigned i = 0; i < count; ++i) if (MACH_PORT_VALID(ports[i]) && mach_port_deallocate(mach_task_self(), ports[i])) result = EIO;
    if (ports && vm_deallocate(mach_task_self(), (vm_address_t)ports, count * sizeof(mach_port_t))) result = EIO;
    return result;
}
static bool BoundedStrings(char *const values[], unsigned max, size_t length, bool environment) {
    if (!values) return false;
    for (unsigned i = 0; i < max; ++i) {
        if (!values[i]) return true;
        if (strnlen(values[i], length + 1) > length || (environment && !strncmp(values[i], "DYLD_", 5))) return false;
    }
    return false;
}
int VM27LargePrivateServiceConsumerV2Spawn(VM27LargePrivateServiceConsumerV2 *consumer, xpc_endpoint_t endpoint,
                                   char *const argv[], char *const env[], pid_t *out) {
    if (!out) return EINVAL; *out = 0;
    if (!consumer || !endpoint || !BoundedStrings(argv, 17, 4096, false) || !argv[0] || strcmp(argv[0], consumer->info.executablePath) || !BoundedStrings(env, 129, 16384, true)) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    int status = consumer->state.started ? EALREADY : VM27LargeServicePlanVerify(consumer->plan);
    mach_port_array_t before = NULL, after = NULL; mach_msg_type_number_t count = 0, afterCount = 0;
    mach_port_t inherited = MACH_PORT_NULL; posix_spawnattr_t attr; bool hasAttr = false;
    if (!status) {
        kern_return_t lookup = mach_ports_lookup(mach_task_self(), &before, &count);
        bool slot2Valid = lookup == KERN_SUCCESS && count == 3 && before && MACH_PORT_VALID(before[2]);
        fprintf(stderr, "[Independent27] consumer-spawn lookupKR=%d count=%u parentSlot2Valid=%d\n", lookup, count, slot2Valid);
        if (lookup != KERN_SUCCESS || count != 3 || !before) status = ENOTSUP;
    }
    if (!status) status = VM27PrivateEndpointCopySendRight(endpoint, &inherited);
    if (!status) { status = posix_spawnattr_init(&attr); hasAttr = !status; }
    if (!status) {
        mach_port_t registered[3] = {before[0], before[1], inherited};
        status = posix_spawnattr_set_registered_ports_np(&attr, registered, 3);
        fprintf(stderr, "[Independent27] consumer-spawn set-registered-ports status=%d\n", status);
    }
    if (!status) {
        pid_t child = 0; status = posix_spawn(&child, consumer->info.executablePath, NULL, &attr, argv, env);
        fprintf(stderr, "[Independent27] consumer-spawn posix-spawn status=%d child=%d\n", status, (int)child);
        if (!status) { consumer->state.childPID = child; consumer->state.started = true; *out = child; atomic_fetch_add(&Spawns, 1); }
    }
    if (hasAttr && posix_spawnattr_destroy(&attr) && !status) status = EIO;
    if (MACH_PORT_VALID(inherited) && mach_port_deallocate(mach_task_self(), inherited) && !status) status = EIO;
    if (before) {
        bool unchanged = !mach_ports_lookup(mach_task_self(), &after, &afterCount) && afterCount == count;
        for (unsigned i = 0; unchanged && i < count; ++i) unchanged = before[i] == after[i];
        consumer->state.parentRegisteredPortsUnchanged = unchanged;
        if (!unchanged && !status) status = EIO;
    }
    int first = ReleasePorts(before, count), second = ReleasePorts(after, afterCount);
    if (!status && (first || second)) status = EIO;
    pthread_mutex_unlock(&consumer->mutex); return status;
}
int VM27LargePrivateServiceConsumerV2CheckMessage(VM27LargePrivateServiceConsumerV2 *consumer, xpc_object_t message, VM27ApprovedCodeMessageResult *out) {
    if (!out) return EINVAL; memset(out, 0, sizeof(*out));
    if (!consumer || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return EINVAL;
    pthread_mutex_lock(&consumer->mutex); ++consumer->state.messageChecks; atomic_fetch_add(&MessageChecks, 1);
    audit_token_t token = {{0}}; xpc_dictionary_get_audit_token(message, &token);
    int status = !consumer->state.started || consumer->state.reaped || token.val[5] != (uint32_t)consumer->state.childPID || !token.val[7] || (consumer->childVersion && token.val[7] != consumer->childVersion) ? EACCES : VM27LargeServicePlanVerify(consumer->plan);
    if (!status) {
        consumer->childVersion = token.val[7];
        if (consumer->mode == VM27_OWNED_BUNDLE_MODE_V5) status = VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(consumer->ownedBundleApproved, message, out);
        else if (consumer->mode == VM27LargeConsumerV2ExplicitApprovedCode) status = VM27ApprovedCodeCheckReceivedMessage(consumer->approved, message, out);
        else status = VM27LargeStrictIdentityV2CheckReceivedMessage(consumer->plan,
            consumer->reviewedSHA256, consumer->reviewedCDHash, message, out);
    }
    out->result = status; out->auditPID = token.val[5]; out->auditPIDVersion = token.val[7];
    if (!status) ++consumer->state.messagesAccepted;
    pthread_mutex_unlock(&consumer->mutex); return status;
}
int VM27LargePrivateServiceConsumerV2CopyState(VM27LargePrivateServiceConsumerV2 *consumer, VM27LargePrivateConsumerV2State *out) {
    if (!consumer || !out) return EINVAL;
    pthread_mutex_lock(&consumer->mutex); *out = consumer->state; pthread_mutex_unlock(&consumer->mutex); return 0;
}
int VM27LargePrivateServiceConsumerV2Wait(VM27LargePrivateServiceConsumerV2 *consumer, bool block, VM27LargePrivateConsumerV2State *out) {
    if (!consumer || !out) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    if (!consumer->state.started || consumer->state.reaped || consumer->waiting) { pthread_mutex_unlock(&consumer->mutex); return EALREADY; }
    consumer->waiting = true; pid_t child = consumer->state.childPID; pthread_mutex_unlock(&consumer->mutex);
    int state = 0; pid_t actual; do { actual = waitpid(child, &state, block ? 0 : WNOHANG); } while (actual < 0 && errno == EINTR);
    int status = actual < 0 ? errno : actual == 0 ? EAGAIN : 0;
    pthread_mutex_lock(&consumer->mutex); consumer->waiting = false;
    if (!status) {
        consumer->state.reaped = actual == child; consumer->state.observedWaitExit = WIFEXITED(state) ? WEXITSTATUS(state) : -1;
        consumer->state.absent = kill(child, 0) == -1 && errno == ESRCH; atomic_fetch_add(&Reaps, 1);
    }
    *out = consumer->state; pthread_mutex_unlock(&consumer->mutex); return status;
}
void VM27LargePrivateServiceConsumerV2CopyStats(VM27LargePrivateConsumerV2Stats *out) { if (out) *out = (VM27LargePrivateConsumerV2Stats){atomic_load(&Created), atomic_load(&Destroyed), atomic_load(&Spawns), atomic_load(&Reaps), atomic_load(&MessageChecks)}; }
