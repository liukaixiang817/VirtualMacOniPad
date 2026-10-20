#ifndef VM27_OWNED_STARTUP_COORDINATOR_V2_H
#define VM27_OWNED_STARTUP_COORDINATOR_V2_H
#include "modern_xpc_original_instance_transport_v9.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM27OwnedStartupChildV2 VM27OwnedStartupChildV2;
typedef enum {
    VM27OwnedStartupPreparingV2 = 1,
    VM27OwnedStartupPreparedV2 = 2,
    VM27OwnedStartupClosingV2 = 3,
    VM27OwnedStartupStoppedV2 = 4
} VM27OwnedStartupPhaseV2;
typedef struct {
    VM27OriginalV9ParentConfiguration parent;
    uint64_t bootstrapNonce;
} VM27OwnedStartupConfigurationV2;
typedef struct {
    VM27OwnedStartupPhaseV2 phase;
    pid_t ownerPID, expectedParentPID;
    uint64_t bootstrapNonce;
    bool privateCheckInVerified, transportCreated, registryConfigured, helloReturned;
    unsigned activeControlCalls;
    uint64_t controlMessages, registrationRoutes, bindingRoutes, refusedControlMessages;
    int preparationStatus, cleanupStatus, lastControlStatus;
} VM27OwnedStartupStateV2;

/* Standalone ordinary-user-space preparation, not an original VMM launcher.
 * Both output slots must initially be NULL. A valid call reserves this process
 * once, even on failure; a different attempt requires a fresh process.
 * Uses the real main CFBundle info and the SAME private CheckIn provider that
 * the eventual original import must use. Creates its own actual serial queue.
 * On any post-allocation failure *child remains owned for CopyState/Stop/Release;
 * *ownedHello remains NULL. A returned context is never an execution permission.
 * The nested typed parent configuration and all selected borrowed strings must
 * remain stable/live throughout this synchronous call. V9 performs the real
 * inspection: flat-bundle requires explicit owner and real external slots; the
 * 2 MiB code-only reader is diagnostic-only. No caller validation result exists.
 * Genuine native gates remain; no StartServer/Main/handler/VM/CPU/GPU call. */
int VM27OwnedStartupChildPrepareV2(const VM27OwnedStartupConfigurationV2 *,
    VM27OwnedStartupChildV2 **child, xpc_object_t *ownedHello);

/* Returns one retained actual serial queue. The caller must use this queue for
 * its existing private control connection and dispatch_release the copy. */
int VM27OwnedStartupChildCopyControlQueueV2(VM27OwnedStartupChildV2 *,
    dispatch_queue_t *ownedQueue);

/* Call only on the copied actual queue with the ORIGINAL received dictionary.
 * Exact registration/bind method only; returns the unchanged transport's status
 * and owned reply, including a reply on some refusal paths. No claimed body
 * PID/CD/token becomes authority. Caller sends the reply over that dictionary's
 * same actual remote connection and releases it. Unknown methods are refused;
 * this is not an application-protocol dispatcher or original handler wrapper. */
int VM27OwnedStartupChildReceiveControlV2(VM27OwnedStartupChildV2 *,
    xpc_object_t actualReceivedMessage, xpc_object_t *ownedReply);
int VM27OwnedStartupChildCopyStateV2(VM27OwnedStartupChildV2 *, VM27OwnedStartupStateV2 *);

/* Off the actual control/server queue only. Closes admission before calling
 * unchanged bounded StopServer. EBUSY/ETIMEDOUT/EDEADLK retain the context,
 * endpoint and queue for a later off-queue retry. Success means only that the
 * V9 service listener drained; it does NOT prove external control IPC drained. */
int VM27OwnedStartupChildStopV2(VM27OwnedStartupChildV2 *);

/* Off queue, after successful Stop AND after the caller's external control
 * connection delivered final INVALID and its callback queue was drained.
 * That external lifetime is a caller precondition, not a supplied Boolean.
 * No existing, pending, future or concurrent API/callback may borrow this context.
 * Clears *child on success.
 * Does not erase the process-lifetime CheckIn/registration singleton. */
int VM27OwnedStartupChildReleaseV2(VM27OwnedStartupChildV2 **child);

/* Three-field hello shape guard followed by unchanged InstallClientFactory's
 * real registered-consumer/native identity gate. Consumer remains caller-owned.
 * The actual Large consumer has an 8 MiB child-code limit; no small opaque cast
 * or weaker policy is introduced. Its strict-mode missing kernel-CDHash result
 * still fails closed in V9. ClearClient remains owned by
 * the original frontend's handler/activate/final-INVALID lifetime. */
int VM27OwnedStartupParentInstallFactoryV2(VM27LargePrivateServiceConsumer *,
    xpc_object_t actualChildMessage, uint64_t expectedNonce);

#ifdef __cplusplus
}
#endif
#endif
