#ifndef VM27_OWNED_STARTUP_COORDINATOR_V1_H
#define VM27_OWNED_STARTUP_COORDINATOR_V1_H
#include "modern_xpc_original_instance_transport_v8.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM27OwnedStartupChildV1 VM27OwnedStartupChildV1;
typedef enum {
    VM27OwnedStartupPreparingV1 = 1,
    VM27OwnedStartupPreparedV1 = 2,
    VM27OwnedStartupClosingV1 = 3,
    VM27OwnedStartupStoppedV1 = 4
} VM27OwnedStartupPhaseV1;
typedef struct {
    const char *actualParentCodePath;
    const char *reviewedParentSHA256;
    const char *reviewedParentCDHash;
    pid_t expectedParentPID;
    uint64_t bootstrapNonce;
} VM27OwnedStartupConfigurationV1;
typedef struct {
    VM27OwnedStartupPhaseV1 phase;
    pid_t ownerPID, expectedParentPID;
    uint64_t bootstrapNonce;
    bool privateCheckInVerified, transportCreated, registryConfigured, helloReturned;
    unsigned activeControlCalls;
    uint64_t controlMessages, registrationRoutes, bindingRoutes, refusedControlMessages;
    int preparationStatus, cleanupStatus, lastControlStatus;
} VM27OwnedStartupStateV1;

/* Standalone ordinary-user-space preparation, not an original VMM launcher.
 * Both output slots must initially be NULL. A valid call reserves this process
 * once, even on failure; a different attempt requires a fresh process.
 * Uses the real main CFBundle info and the SAME private CheckIn provider that
 * the eventual original import must use. Creates its own actual serial queue.
 * On any post-allocation failure *child remains owned for CopyState/Stop/Release;
 * *ownedHello remains NULL. A returned context is never an execution permission.
 * The unchanged V8 parent inspector's 2 MiB bound and native identity gates
 * remain mandatory. No StartServer/Main/handler/VM/CPU/GPU is called here. */
int VM27OwnedStartupChildPrepareV1(const VM27OwnedStartupConfigurationV1 *,
    VM27OwnedStartupChildV1 **child, xpc_object_t *ownedHello);

/* Returns one retained actual serial queue. The caller must use this queue for
 * its existing private control connection and dispatch_release the copy. */
int VM27OwnedStartupChildCopyControlQueueV1(VM27OwnedStartupChildV1 *,
    dispatch_queue_t *ownedQueue);

/* Call only on the copied actual queue with the ORIGINAL received dictionary.
 * Exact registration/bind method only; returns the unchanged transport's status
 * and owned reply, including a reply on some refusal paths. No claimed body
 * PID/CD/token becomes authority. Caller sends the reply over that dictionary's
 * same actual remote connection and releases it. Unknown methods are refused;
 * this is not an application-protocol dispatcher or original handler wrapper. */
int VM27OwnedStartupChildReceiveControlV1(VM27OwnedStartupChildV1 *,
    xpc_object_t actualReceivedMessage, xpc_object_t *ownedReply);
int VM27OwnedStartupChildCopyStateV1(VM27OwnedStartupChildV1 *, VM27OwnedStartupStateV1 *);

/* Off the actual control/server queue only. Closes admission before calling
 * unchanged bounded StopServer. EBUSY/ETIMEDOUT/EDEADLK retain the context,
 * endpoint and queue for a later off-queue retry. Success means only that the
 * V8 service listener drained; it does NOT prove external control IPC drained. */
int VM27OwnedStartupChildStopV1(VM27OwnedStartupChildV1 *);

/* Off queue, after successful Stop AND after the caller's external control
 * connection delivered final INVALID and its callback queue was drained.
 * That external lifetime is a caller precondition, not a supplied Boolean.
 * No existing, pending, future or concurrent API/callback may borrow this context.
 * Clears *child on success.
 * Does not erase the process-lifetime CheckIn/registration singleton. */
int VM27OwnedStartupChildReleaseV1(VM27OwnedStartupChildV1 **child);

/* Three-field hello shape guard followed by unchanged InstallClientFactory's
 * real registered-consumer/native identity gate. Consumer remains caller-owned.
 * This covers only the existing small-consumer interface/capacity; no large-code
 * adapter or weaker security policy is introduced. ClearClient remains owned by
 * the original frontend's handler/activate/final-INVALID lifetime. */
int VM27OwnedStartupParentInstallFactoryV1(VM27PrivateServiceConsumer *,
    xpc_object_t actualChildMessage, uint64_t expectedNonce);

#ifdef __cplusplus
}
#endif
#endif
