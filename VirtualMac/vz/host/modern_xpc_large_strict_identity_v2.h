#ifndef VM27_LARGE_STRICT_IDENTITY_V2_H
#define VM27_LARGE_STRICT_IDENTITY_V2_H
#include "modern_xpc_large_bundle_registry.h"
#include "modern_xpc_approved_code.h"

/* Strict result completion for a plan already authenticated by V2 Create.
 * Calls the unchanged strict native gate first. Any native refusal is returned
 * unchanged; no ExplicitApprovedCode policy is created or used. On success,
 * only the same received dictionary's kernel audit token authorizes the two
 * real csops_audittoken queries. The SHA is compared to the immutable plan
 * whose actual file pins the native gate has just reverified; CDHash must
 * match the creation-time reviewed value and CS_VALID must be set.
 * No caller-supplied validated/permission Boolean and no signature synthesis.
 * This helper does not prove child ownership: V2 CheckMessage preserves the
 * existing spawned PID/PIDversion/reaped guards before calling it. */
int VM27LargeStrictIdentityV2CheckReceivedMessage(
    const VM27LargeServicePlan *authenticatedPlan,
    const char *creationReviewedSHA256, const char *creationReviewedCDHash,
    xpc_object_t receivedDictionary, VM27ApprovedCodeMessageResult *result);
#endif
