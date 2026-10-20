/*
 * App-private original27 plugin LWCR policy and per-message signature gate.
 * Opcode semantics: Apple's Defining launch environment and library
 * constraints, pinned in xpc-lwcr-compat-v1/official-source-v1.
 * The typed SecTask declarations below match Apple's official sectask headers.
 * No system interposition, native registration calls or permissive fallback.
 */
#include "modern_xpc_lwcr_policy.h"
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithXPCMessage(xpc_object_t message);
extern Boolean SecTaskEntitlementsValidated(SecTaskRef task);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task,
                                               CFStringRef entitlement,
                                               CFErrorRef *error);

struct VM27LWCRPolicy {
    atomic_uint references;
    uint64_t magic;
};
#define POLICY_MAGIC UINT64_C(0x564d32374c574352)

static _Atomic uint64_t gCreated, gDestroyed, gFixture, gMessages;
static _Atomic uint64_t gTaskCreates, gTaskReleases, gCopies, gReleases;
static _Atomic uint64_t gAccepted, gRejected;
#define COUNT(variable) atomic_fetch_add_explicit(&(variable), 1, memory_order_relaxed)

static bool PolicyValid(const VM27LWCRPolicy *policy) {
    return policy && policy->magic == POLICY_MAGIC &&
        atomic_load_explicit(&policy->references, memory_order_relaxed) != 0;
}
static bool Opcode(xpc_object_t value, int64_t expected) {
    return value && xpc_get_type(value) == XPC_TYPE_INT64 &&
        xpc_int64_get_value(value) == expected;
}
int VM27LWCRPolicyCreate(xpc_object_t requirement, VM27LWCRPolicy **result) {
    if (!result) return EINVAL;
    *result = NULL;
    if (!requirement || xpc_get_type(requirement) != XPC_TYPE_DICTIONARY)
        return EINVAL;
    if (xpc_dictionary_get_count(requirement) != 1) return ENOTSUP;
    xpc_object_t entitlements = xpc_dictionary_get_value(requirement, "entitlements");
    if (!entitlements || xpc_get_type(entitlements) != XPC_TYPE_DICTIONARY)
        return EINVAL;
    if (xpc_dictionary_get_count(entitlements) != 1) return ENOTSUP;
    xpc_object_t query = xpc_dictionary_get_value(entitlements, "$query");
    if (!query || xpc_get_type(query) != XPC_TYPE_ARRAY) return EINVAL;
    if (xpc_array_get_count(query) != 2) return ENOTSUP;
    xpc_object_t select = xpc_array_get_value(query, 0);
    xpc_object_t match = xpc_array_get_value(query, 1);
    if (!select || !match || xpc_get_type(select) != XPC_TYPE_ARRAY ||
        xpc_get_type(match) != XPC_TYPE_ARRAY) return EINVAL;
    if (xpc_array_get_count(select) != 2 || xpc_array_get_count(match) != 2)
        return EINVAL;
    if (!Opcode(xpc_array_get_value(select, 0), 1) ||
        !Opcode(xpc_array_get_value(match, 0), 5)) return ENOTSUP;
    xpc_object_t key = xpc_array_get_value(select, 1);
    xpc_object_t boolean = xpc_array_get_value(match, 1);
    if (!key || !boolean || xpc_get_type(key) != XPC_TYPE_STRING ||
        xpc_get_type(boolean) != XPC_TYPE_BOOL) return EINVAL;
    if (strcmp(xpc_string_get_string_ptr(key), VM27_PLUGIN_ENTITLEMENT) ||
        !xpc_bool_get_value(boolean)) return ENOTSUP;
    VM27LWCRPolicy *policy = calloc(1, sizeof(*policy));
    if (!policy) return ENOMEM;
    atomic_init(&policy->references, 1);
    policy->magic = POLICY_MAGIC;
    COUNT(gCreated);
    *result = policy;
    return 0;
}
bool VM27LWCRPolicyRetain(VM27LWCRPolicy *policy) {
    if (!PolicyValid(policy)) return false;
    unsigned current = atomic_load_explicit(&policy->references, memory_order_relaxed);
    for (;;) {
        if (current == 0 || current == UINT_MAX) return false;
        if (atomic_compare_exchange_weak_explicit(&policy->references, &current,
                current + 1, memory_order_relaxed, memory_order_relaxed)) return true;
    }
}
void VM27LWCRPolicyRelease(VM27LWCRPolicy *policy) {
    if (!PolicyValid(policy)) abort();
    if (atomic_fetch_sub_explicit(&policy->references, 1,
                                 memory_order_acq_rel) == 1) {
        policy->magic = 0;
        COUNT(gDestroyed);
        free(policy);
    }
}
int VM27LWCRPolicyEvaluateOwnedEntitlements(const VM27LWCRPolicy *policy,
                                           xpc_object_t entitlements) {
    COUNT(gFixture);
    if (!PolicyValid(policy)) return EINVAL;
    if (!entitlements || xpc_get_type(entitlements) != XPC_TYPE_DICTIONARY)
        return EACCES;
    xpc_object_t value = xpc_dictionary_get_value(entitlements, VM27_PLUGIN_ENTITLEMENT);
    return value && xpc_get_type(value) == XPC_TYPE_BOOL &&
        xpc_bool_get_value(value) ? 0 : EACCES;
}
int VM27LWCRPolicyCheckReceivedMessage(const VM27LWCRPolicy *policy,
                                      xpc_object_t message,
                                      VM27LWCRMessageResult *result) {
    COUNT(gMessages);
    VM27LWCRMessageResult detail = {0};
    detail.result = EACCES;
    if (!PolicyValid(policy)) { detail.result = EINVAL; goto finish; }
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) goto finish;
    detail.hasRemoteConnection = xpc_dictionary_get_remote_connection(message) != NULL;
    if (!detail.hasRemoteConnection) goto finish;
    SecTaskRef task = SecTaskCreateWithXPCMessage(message);
    detail.taskCreated = task != NULL;
    if (!task) { detail.result = EIO; goto finish; }
    COUNT(gTaskCreates);
    detail.entitlementsValidated = SecTaskEntitlementsValidated(task);
    CFErrorRef error = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(task,
        CFSTR(VM27_PLUGIN_ENTITLEMENT), &error);
    detail.entitlementReadError = error != NULL;
    detail.entitlementPresent = value != NULL;
    if (value) {
        COUNT(gCopies);
        detail.entitlementIsBoolean = CFGetTypeID(value) == CFBooleanGetTypeID();
        if (detail.entitlementIsBoolean)
            detail.entitlementValue = CFBooleanGetValue((CFBooleanRef)value);
        CFRelease(value);
        COUNT(gReleases);
    }
    if (error) CFRelease(error);
    CFRelease(task);
    COUNT(gTaskReleases);
    if (detail.entitlementReadError) detail.result = EIO;
    else if (detail.entitlementsValidated && detail.entitlementIsBoolean &&
             detail.entitlementValue) detail.result = 0;
finish:
    if (detail.result == 0) COUNT(gAccepted);
    else COUNT(gRejected);
    if (result) *result = detail;
    return detail.result;
}
void VM27LWCRCopyStats(VM27LWCRStats *result) {
    if (!result) return;
#define LOAD(field, variable) result->field = atomic_load_explicit(&(variable), memory_order_relaxed)
    LOAD(policiesCreated, gCreated); LOAD(policiesDestroyed, gDestroyed);
    LOAD(fixtureChecks, gFixture); LOAD(messageChecks, gMessages);
    LOAD(taskCreates, gTaskCreates); LOAD(taskReleases, gTaskReleases);
    LOAD(entitlementCopies, gCopies); LOAD(entitlementReleases, gReleases);
    LOAD(acceptedMessages, gAccepted); LOAD(rejectedMessages, gRejected);
#undef LOAD
}
