#ifndef VM27_ORIGINAL_XPC_TRANSPORT_H
#define VM27_ORIGINAL_XPC_TRANSPORT_H
#include "modern_xpc_private_consumer.h"
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <sys/types.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM27_ORIGINAL_VM_SERVICE "com.apple.Virtualization.VirtualMachine"
typedef void (*VM27OriginalServiceHandler)(xpc_connection_t peer);
typedef struct {
    char providerUUID[33], securityUUID[33];
    uintptr_t nativeCreateRVA, nativeMainRVA, auditGetterRVA, entitlementGetterRVA;
    uintptr_t secTaskCreateRVA, secTaskCopyRVA, secTaskValidatedRVA;
    bool exactSystemProvider, exactGetterCode, exactSecurityProvider;
} VM27OriginalTransportABI;
typedef struct {
    uint64_t clientMessagesInstalled, privateConnectionsCreated, nativeConnectionsForwarded;
    uint64_t listenersCreated, listenersDestroyed, peersReceived, peersAccepted, peersDenied;
    uint64_t originalMainCalls, originalHandlerCalls, tasksCreated, tasksReleased, kernelCodeQueries;
    uint32_t lastAuditPID, lastAuditPIDVersion, lastBaseCapabilityMask;
    bool lastNativeEntitlementsValidated;
    int lastPeerError;
} VM27OriginalTransportStats;

/* No new process or system service registration. Copies only an actual native
 * endpoint in a received dictionary from this consumer's exact spawned child.
 * Requires the existing native/explicit-approved consumer gate, immutable
 * nonce UINT64 and exact service string. One connection per installed factory.
 * The caller owns the consumer/process lifetime and must clear before release. */
int VM27OriginalTransportInstallClientFactoryMessage(VM27PrivateServiceConsumer *,
    xpc_object_t actualChildMessage, uint64_t nonce);
void VM27OriginalTransportClearClient(void);
int VM27OriginalTransportCopyABI(VM27OriginalTransportABI *);
void VM27OriginalTransportCopyStats(VM27OriginalTransportStats *);

/* Authenticates actual reviewed parent file pages/CodeDirectory with the
 * existing bounded inspector (2MiB stays unchanged). Creates only an own
 * anonymous listener and returns an owned endpoint. The accepted connection
 * must match actual expectedPID + kernel CDHash/CS_VALID and BOTH SecTask's
 * genuine Boolean and native connection Boolean for either original VM key.
 * Original SecTaskEntitlementsValidated remains a separate reported field;
 * explicit reviewed-code authorization never changes it to true. */
int VM27OriginalTransportCreateServer(const char *actualParentCode,
    const char *reviewedSHA256, const char *reviewedCDHash, pid_t expectedParentPID,
    dispatch_queue_t actualServerQueue, xpc_endpoint_t *ownedEndpoint);
/* A typed lifecycle helper for bounded tests. The original ABI below uses this
 * same real listener/handler path and then dispatch_main(), never returns. */
int VM27OriginalTransportStartServer(VM27OriginalServiceHandler originalHandler);
/* Must be called off the listener queue; rejects EDEADLK/active callback.
 * Waits <=2s for the real final INVALID event, then drains and releases refs.
 * ETIMEDOUT retains own storage safely; a later off-queue retry is permitted. */
int VM27OriginalTransportStopServer(void);

/* Exact original C ABI exports. Forward other identifiers/anonymous creation
 * to the pinned real libxpc provider. Matching VM identifier fails closed if
 * its actual child factory was not installed. The returned native connection
 * remains inactive so the original caller can set its one-shot UUID, target
 * queue and original event handler before activation. No generic stub. */
xpc_connection_t VM27OriginalTransportConnectionCreate(const char *, dispatch_queue_t)
    __asm__("_xpc_connection_create");
__attribute__((noreturn)) void VM27OriginalTransportMain(VM27OriginalServiceHandler)
    __asm__("_xpc_main");

#ifdef __cplusplus
}
#endif
#endif
