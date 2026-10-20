#ifndef VM27_OWNED_BUNDLE_APPROVED_POLICY_V1_H
#define VM27_OWNED_BUNDLE_APPROVED_POLICY_V1_H
#include "modern_xpc_approved_code.h"
#include "modern_xpc_large_bundle_registry.h"
#include "vm27_bundle_child_inspection_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM27OwnedBundleApprovedPolicyV1 VM27OwnedBundleApprovedPolicyV1;

/* Explicit authorization for the one inspected, caller-owned child bundle.
 * expected SHA/CD must come from the approving product manifest, never from
 * a peer message. actualPlan is borrowed from the Consumer's retained plan
 * and must remain alive through the last Check. Release does not use it.
 * Calls are serialized by the actual Consumer owner; no concurrent Release.
 * All old raw/StrictNative/default behavior remains separate and unchanged.
 */
__attribute__((visibility("hidden")))
int VM27OwnedBundleApprovedPolicyCreateV1(
    const VM27BundleParentConfigurationV1 *actualChild,
    const VM27LargeServicePlan *actualPlan,
    xpc_object_t immutableRequirement,
    VM27OwnedBundleApprovedPolicyV1 **result);

__attribute__((visibility("hidden")))
void VM27OwnedBundleApprovedPolicyReleaseV1(VM27OwnedBundleApprovedPolicyV1 *policy);

/* The Consumer must first validate actual started/not-reaped child PID and
 * its sticky PIDVersion against this received dictionary's real audit token.
 * This function independently checks Plan/file pins, required external 1/3,
 * every page and embedded 2/5/7, actual SecTask Boolean true and same-token
 * kernel CD/CS_VALID. It invokes the original native LWCR exactly once and
 * preserves its result and entitlementsValidated value. Own acceptance is
 * explicitApprovedCodeAccepted; it is never Apple entitlement validation.
 * Query/file failure has no fallback. result is optional caller-owned output,
 * must not alias policy storage, and is written only after all reads finish.
 */
__attribute__((visibility("hidden")))
int VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(
    const VM27OwnedBundleApprovedPolicyV1 *policy,
    xpc_object_t actualReceivedMessage,
    VM27ApprovedCodeMessageResult *result);

#ifdef __cplusplus
}
#endif
#endif
