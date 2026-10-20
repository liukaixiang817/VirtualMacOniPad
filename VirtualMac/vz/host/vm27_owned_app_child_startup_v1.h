#ifndef VM27_OWNED_APP_CHILD_STARTUP_V1_H
#define VM27_OWNED_APP_CHILD_STARTUP_V1_H
#include "vm27_owned_startup_coordinator_v3.h"
#include "modern_xpc_large_bundle_registry.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VM27OwnedAppParentV1 VM27OwnedAppParentV1;
typedef struct VM27OwnedAppChildV1 VM27OwnedAppChildV1;
typedef struct {
 const char *actualRegistryRoot;
 const char *actualImmediateBundlePath;
 const char *actualServiceIdentifier;
 const char *reviewedChildSHA256;
 const char *reviewedChildCDHash;
 xpc_object_t originalImmutableRequirement;
 char *const *actualArgv;
 char *const *actualEnvironment;
 uint64_t bootstrapNonce;
 VM27BundleParentConfigurationV1 actualParentBundle;
} VM27OwnedAppParentConfigurationV1;
typedef struct {
 pid_t ownerPID, childPID;
 int startupStatus, controlStatus;
 bool spawned, helloInstalled, controlFinalInvalid, listenerFinalInvalid;
 bool originalClientFinalInvalidObserved;
} VM27OwnedAppParentStateV1;
/* Trusted source caller passes actual finalized product paths/policy. No
 * message-body hash, PID or Boolean substitutes for Large2's native gate.
 * Calls actual registry/Create/Spawn and accepts only the real received hello.
 * Waits <=20 seconds off its own serial queue. Once allocated, *owner remains
 * caller-owned even on failure, including a child spawned before late failure.
 * This version retains the installed factory for the process lifetime: it has
 * no proof of the original VZ connection's final INVALID event, and will not
 * clear its factory or free the borrowed consumer prematurely. */
int VM27OwnedAppParentStartV1(const VM27OwnedAppParentConfigurationV1 *,
 VM27OwnedAppParentV1 **owner);
/* New owned app-private plugin policy with the existing exact LWCR opcode
 * shape. The actual VM27LWCRPolicyCreate parser must accept it before output.
 * It is a constraint, not a native entitlement or an Apple vendor identity. */
int VM27OwnedAppCreateScopedPluginRequirementV1(xpc_object_t *ownedRequirement);
int VM27OwnedAppParentCopyStateV1(VM27OwnedAppParentV1 *,VM27OwnedAppParentStateV1 *);
/* Cancel/drain only the adapter's actual control/listener, <=2s off queue.
 * Never kills the child or clears the original client; running/installed
 * ownership is retained. Release succeeds only before any child was spawned
 * and before a factory was installed, after both actual INVALID events. */
int VM27OwnedAppParentDrainV1(VM27OwnedAppParentV1 *);
int VM27OwnedAppParentReleaseV1(VM27OwnedAppParentV1 **);
/* Actual trusted pre-Main source entry. FlatBundle only; expectedParentPID
 * must equal current getppid(). Performs true V3 Prepare and connects the
 * inherited actual registered slot2 on the returned real control queue.
 * The hello ack sequences startup only: it is not a native authorization or
 * permission to execute a VM. V10 still checks the original peer before the
 * original handler, and Root installs NativeOps only on VM setup's pthread.
 * No argv/environment configuration parser, constructor, DYLD mutation,
 * native CPU operation, original Main/handler or fabricated endpoint exists.
 * The caller must link/call this entry from its actual product pre-Main unit. */
int VM27OwnedAppChildPrepareBeforeMainV1(const VM27OwnedStartupConfigurationV3 *,
 VM27OwnedAppChildV1 **owner);
/* Genuine product pre-Main entry without body-derived authorization. It first
 * connects actual registered slot2, authenticates the received configuration
 * against the parent's current kernel token/CD/CS_VALID/dual native Booleans,
 * then performs the same exact V3 FlatBundle preparation. The received file
 * hash is an inspection expectation only; it must not grant a native right. */
int VM27OwnedAppChildBootstrapBeforeMainV2(VM27OwnedAppChildV1 **owner);
/* Off actual control queue, closes V3 service, cancels/drains true control.
 * Any failure retains owner/storage and may be retried; successful release
 * follows both actual control INVALID and completed V3 Stop. */
int VM27OwnedAppChildDrainV1(VM27OwnedAppChildV1 *);
int VM27OwnedAppChildReleaseV1(VM27OwnedAppChildV1 **);
#ifdef __cplusplus
}
#endif
#endif
