#ifndef VM27_MODERN_XPC_LWCR_POLICY_H
#define VM27_MODERN_XPC_LWCR_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM27LWCRPolicy VM27LWCRPolicy;

/* Original27 VMM's non-system plugin constraint, not a general LWCR engine. */
#define VM27_PLUGIN_ENTITLEMENT "com.apple.private.virtualization.plugin"

typedef struct {
    uint64_t policiesCreated;
    uint64_t policiesDestroyed;
    uint64_t fixtureChecks;
    uint64_t messageChecks;
    uint64_t taskCreates;
    uint64_t taskReleases;
    uint64_t entitlementCopies;
    uint64_t entitlementReleases;
    uint64_t acceptedMessages;
    uint64_t rejectedMessages;
} VM27LWCRStats;

typedef struct {
    bool hasRemoteConnection;
    bool taskCreated;
    bool entitlementsValidated;
    bool entitlementPresent;
    bool entitlementIsBoolean;
    bool entitlementValue;
    bool entitlementReadError;
    int32_t result;
} VM27LWCRMessageResult;

/*
 * Only accepts the exact original27 shape:
 * {"entitlements":{"$query":[[1,VM27_PLUGIN_ENTITLEMENT],[5,true]]}}.
 * Extra facts/operations are rejected, not ignored. A successful policy owns
 * an immutable typed snapshot; later mutation of the caller's XPC graph does
 * not alter it. Returns an errno value and NULL on malformed/unsupported data.
 */
int VM27LWCRPolicyCreate(xpc_object_t requirement, VM27LWCRPolicy **result);
bool VM27LWCRPolicyRetain(VM27LWCRPolicy *policy);
void VM27LWCRPolicyRelease(VM27LWCRPolicy *policy);

/* Pure owned-dictionary fixture; no signature authenticity is implied. */
int VM27LWCRPolicyEvaluateOwnedEntitlements(const VM27LWCRPolicy *policy,
                                           xpc_object_t entitlements);

/*
 * Must be called for each received XPC dictionary before forwarding it to a
 * service handler. SecTaskCreateWithXPCMessage uses that message's kernel
 * audit token, not a cached PID/connection identity. Both trustworthy native
 * entitlements and a genuine CFBoolean true are required. Local dictionaries,
 * missing/false/integer entitlements and failed signature reads fail closed.
 * This checks received messages; it does not register a bundle with launchd.
 */
int VM27LWCRPolicyCheckReceivedMessage(const VM27LWCRPolicy *policy,
                                      xpc_object_t message,
                                      VM27LWCRMessageResult *result);
void VM27LWCRCopyStats(VM27LWCRStats *result);

#ifdef __cplusplus
}
#endif
#endif
