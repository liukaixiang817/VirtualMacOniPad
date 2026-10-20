/* Independent V3 coordinator for the exact typed V2 consumer; old V2 stays frozen. */
#ifndef VM27_OWNED_STARTUP_COORDINATOR_V3_H
#define VM27_OWNED_STARTUP_COORDINATOR_V3_H
#include "modern_xpc_original_instance_transport_v10.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM27OwnedStartupChildV3 VM27OwnedStartupChildV3;
typedef enum {
    VM27OwnedStartupPreparingV3 = 1,
    VM27OwnedStartupPreparedV3 = 2,
    VM27OwnedStartupClosingV3 = 3,
    VM27OwnedStartupStoppedV3 = 4
} VM27OwnedStartupPhaseV3;
typedef struct {
    VM27OriginalV10ParentConfiguration parent;
    uint64_t bootstrapNonce;
} VM27OwnedStartupConfigurationV3;
typedef struct {
    VM27OwnedStartupPhaseV3 phase;
    pid_t ownerPID, expectedParentPID;
    uint64_t bootstrapNonce;
    bool privateCheckInVerified, transportCreated, registryConfigured, helloReturned;
    unsigned activeControlCalls;
    uint64_t controlMessages, registrationRoutes, bindingRoutes, refusedControlMessages;
    int preparationStatus, cleanupStatus, lastControlStatus;
} VM27OwnedStartupStateV3;

/* Standalone ordinary-user-space preparation, not an original VMM launcher.
 * Both output slots must initially be NULL. A valid call reserves this process
 * once, even on failure; a different attempt requires a fresh process.
 * Uses the real main CFBundle info and the SAME private CheckIn provider that
 * the eventual original import must use. Creates its own actual serial queue.
 * On any post-allocation failure *child remains owned for CopyState/Stop/Release;
 * *ownedHello remains NULL. A returned context is never an execution permission.
 * The nested typed parent configuration and all selected borrowed strings must
 * remain stable/live throughout this synchronous call. V10 performs the real
 * inspection: flat-bundle requires explicit owner and real external slots; the
 * 2 MiB code-only reader is diagnostic-only. No caller validation result exists.
 * Genuine native gates remain; no StartServer/Main/handler/VM/CPU/GPU call. */
int VM27OwnedStartupChildPrepareV3(const VM27OwnedStartupConfigurationV3 *,
    VM27OwnedStartupChildV3 **child, xpc_object_t *ownedHello);

/* Returns one retained actual serial queue. The caller must use this queue for
 * its existing private control connection and dispatch_release the copy. */
int VM27OwnedStartupChildCopyControlQueueV3(VM27OwnedStartupChildV3 *,
    dispatch_queue_t *ownedQueue);

/* Call only on the copied actual queue with the ORIGINAL received dictionary.
 * Exact registration/bind method only; returns the unchanged transport's status
 * and owned reply, including a reply on some refusal paths. No claimed body
 * PID/CD/token becomes authority. Caller sends the reply over that dictionary's
 * same actual remote connection and releases it. Unknown methods are refused;
 * this is not an application-protocol dispatcher or original handler wrapper. */
int VM27OwnedStartupChildReceiveControlV3(VM27OwnedStartupChildV3 *,
    xpc_object_t actualReceivedMessage, xpc_object_t *ownedReply);
int VM27OwnedStartupChildCopyStateV3(VM27OwnedStartupChildV3 *, VM27OwnedStartupStateV3 *);

/* Off the actual control/server queue only. Closes admission before calling
 * unchanged bounded StopServer. EBUSY/ETIMEDOUT/EDEADLK retain the context,
 * endpoint and queue for a later off-queue retry. Success means only that the
 * V10 service listener drained; it does NOT prove external control IPC drained. */
int VM27OwnedStartupChildStopV3(VM27OwnedStartupChildV3 *);

/* Off queue, after successful Stop AND after the caller's external control
 * connection delivered final INVALID and its callback queue was drained.
 * That external lifetime is a caller precondition, not a supplied Boolean.
 * No existing, pending, future or concurrent API/callback may borrow this context.
 * Clears *child on success.
 * Does not erase the process-lifetime CheckIn/registration singleton. */
int VM27OwnedStartupChildReleaseV3(VM27OwnedStartupChildV3 **child);

/* Three-field hello shape guard followed by unchanged InstallClientFactory's
 * real registered-consumer/native identity gate. Consumer remains caller-owned.
 * The actual Large consumer has an 8 MiB child-code limit; no small opaque cast
 * or weaker policy is introduced. Its strict-mode actual kernel-CDHash result
 * is populated only after the unchanged native gate succeeds; refusal still
 * fails closed. ClearClient remains owned by the original frontend's
 * handler/activate/final-INVALID lifetime. */
int VM27OwnedStartupParentInstallFactoryV3(VM27LargePrivateServiceConsumerV2 *,
    xpc_object_t actualChildMessage, uint64_t expectedNonce);

#ifdef __cplusplus
}
#endif
#endif
