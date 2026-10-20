#ifndef VM27_LARGE_ORIGINAL_XPC_INSTANCE_TRANSPORT_H
#define VM27_LARGE_ORIGINAL_XPC_INSTANCE_TRANSPORT_H
#include "modern_xpc_large_private_consumer.h"
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <sys/types.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM27_ORIGINAL_VM_SERVICE "com.apple.Virtualization.VirtualMachine"
typedef void (*VM27LargeOriginalServiceHandler)(xpc_connection_t peer);
typedef struct {
    char providerUUID[33], securityUUID[33];
    uintptr_t nativeCreateRVA, nativeMainRVA, auditGetterRVA, entitlementGetterRVA;
    uintptr_t secTaskCreateRVA, secTaskCopyRVA, secTaskValidatedRVA;
    bool exactSystemProvider, exactGetterCode, exactSecurityProvider;
    uintptr_t oneShotRVA, instanceSetRVA, instanceGetRVA;
    bool exactInstanceCode;
} VM27LargeOriginalTransportABI;
typedef struct {
    uint64_t clientMessagesInstalled, privateConnectionsCreated, nativeConnectionsForwarded;
    uint64_t listenersCreated, listenersDestroyed, peersReceived, peersAccepted, peersDenied;
    uint64_t originalMainCalls, originalHandlerCalls, tasksCreated, tasksReleased, kernelCodeQueries;
    uint32_t lastAuditPID, lastAuditPIDVersion, lastBaseCapabilityMask;
    bool lastNativeEntitlementsValidated;
    int lastPeerError;
    uint64_t instanceRequests, instanceReplies, instanceCallbacks, instancesCommitted, serverInstancesBound, instancesCopied, pendingInstanceRequests;
    int lastInstanceStatus;
    char lastKernelCDHash[41];
    uint32_t lastCodeStatus;
    int lastCodeQueryResult, lastStatusQueryResult;
    uint64_t rollbackListenersStarted, rollbackListenersReleased, rollbackFinalInvalidEvents;
    uint64_t parentFileInspections, largeParentFileInspections;
} VM27LargeOriginalTransportStats;

/* No new process or system service registration. Copies only an actual native
 * endpoint in a received dictionary from this consumer's exact spawned child.
 * Requires the existing native/explicit-approved consumer gate, immutable
 * nonce UINT64 and exact service string. One connection per installed factory.
 * The caller owns the consumer/process lifetime and must clear before release. */
int VM27LargeOriginalTransportInstallClientFactoryMessage(VM27LargePrivateServiceConsumer *,
    xpc_object_t actualChildMessage, uint64_t nonce);
/* The original consumer must complete its real handler+activate sequence,
 * including a setter-refused/cancelled connection, and drain final INVALID
 * before this final owned retain is released. Cancellation does not resume a
 * native suspended connection. This helper does not guess private state. */
void VM27LargeOriginalTransportClearClient(void);
int VM27LargeOriginalTransportCopyABI(VM27LargeOriginalTransportABI *);
void VM27LargeOriginalTransportCopyStats(VM27LargeOriginalTransportStats *);

/* Authenticates actual reviewed parent file pages/CodeDirectory with the
 * new fixed8MiB typed inspector (separate from the unchanged old2MiB provider). Creates only an own
 * anonymous listener and returns an owned endpoint. The accepted connection
 * must match actual expectedPID + kernel CDHash/CS_VALID and BOTH SecTask's
 * genuine Boolean and native connection Boolean for either original VM key.
 * Original SecTaskEntitlementsValidated remains a separate reported field;
 * explicit reviewed-code authorization never changes it to true. */
int VM27LargeOriginalTransportCreateServer(const char *actualParentCode,
    const char *reviewedSHA256, const char *reviewedCDHash, pid_t expectedParentPID,
    dispatch_queue_t actualServerQueue, xpc_endpoint_t *ownedEndpoint);
/* A typed lifecycle helper for bounded tests. The original ABI below uses this
 * same real listener/handler path and then dispatch_main(), never returns. */
int VM27LargeOriginalTransportStartServer(VM27LargeOriginalServiceHandler originalHandler);
/* Must be called off the listener queue; rejects EDEADLK/active callback.
 * Waits <=2s for the real final INVALID event, then drains and releases refs.
 * ETIMEDOUT retains own storage safely; a later off-queue retry is permitted. */
int VM27LargeOriginalTransportStopServer(void);

/* Exact original C ABI exports. Forward other identifiers/anonymous creation
 * to the pinned real libxpc provider. Matching VM identifier fails closed if
 * its actual child factory was not installed. The returned native connection
 * has an inactive user handler. Its private one-shot UUID is authenticated
 * on the real child factory channel before the original handler is activated. No generic stub. */
xpc_connection_t VM27LargeOriginalTransportConnectionCreate(const char *, dispatch_queue_t)
    __asm__("_xpc_connection_create");
__attribute__((noreturn)) void VM27LargeOriginalTransportMain(VM27LargeOriginalServiceHandler)
    __asm__("_xpc_main");

/* Establish the required per-process, per-service one-shot instance before
 * peer delivery. These are private bootstrap control messages, never original
 * application wire messages. Must be invoked on the actual child control queue.
 * The caller must return the owned reply through that same actual connection. */
int VM27LargeOriginalTransportRequireServerInstance(uint64_t nonce);
int VM27LargeOriginalTransportBindServerInstanceMessage(xpc_object_t actualMessage,
    xpc_object_t *ownedReply);
int VM27LargeOriginalTransportCopyServerInstance(unsigned char outUUID[16]);
#if VM27_ENABLE_DIAGNOSTIC_ENDPOINT_FAILURE
/* One failed endpoint allocation for an own just-created listener only. Never
 * changes native libxpc, registration, messages or the success path. */
void VM27LargeOriginalTransportInjectEndpointFailureOnceForDiagnostic(void);
#endif
/* Exact original void ABIs. Private matching connection binds one immutable
 * nonzero UUID to the actual spawned process, requiring an authenticated ack.
 * Failure cancels it and reports errno/lastInstanceStatus, never fake success.
 * Calls for other connections forward only to pinned native code. Getter copies
 * 16 bytes; it does NOT return a pointer. No setters touch libxpc object fields. */
void VM27LargeOriginalTransportSetOneShotInstance(xpc_connection_t, const unsigned char *)
    __asm__("_xpc_connection_set_oneshot_instance");
void VM27LargeOriginalTransportGetInstance(xpc_connection_t, unsigned char *)
    __asm__("_xpc_connection_get_instance");
#ifdef __cplusplus
}
#endif
#endif
