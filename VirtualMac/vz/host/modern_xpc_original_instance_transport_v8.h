#ifndef VM27_ORIGINAL_XPC_INSTANCE_TRANSPORT_V8_H
#define VM27_ORIGINAL_XPC_INSTANCE_TRANSPORT_V8_H
#include "modern_xpc_private_consumer.h"
#include <dispatch/dispatch.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <sys/types.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM27_ORIGINAL_VM_SERVICE "com.apple.Virtualization.VirtualMachine"
typedef void (*VM27OriginalV8ServiceHandler)(xpc_connection_t peer);
typedef struct {
    char providerUUID[33], securityUUID[33];
    uintptr_t nativeCreateRVA, nativeMainRVA, auditGetterRVA, entitlementGetterRVA;
    uintptr_t secTaskCreateRVA, secTaskCopyRVA, secTaskValidatedRVA;
    bool exactSystemProvider, exactGetterCode, exactSecurityProvider;
    uintptr_t oneShotRVA, instanceSetRVA, instanceGetRVA;
    bool exactInstanceCode;
} VM27OriginalV8TransportABI;
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
} VM27OriginalV8TransportStats;

/* New separate output, never appended to or overlaid on the old stats ABI. */
typedef struct {
    uint64_t serverConfigurations, registrationMessages, registrationCommits;
    uint64_t registrationIdempotentMessages, registrationDeniedMessages;
    uint64_t clientRequests, clientReplies, clientCallbacks, clientCommits;
    uint64_t pendingClientRequests, bundleTitleCopies, serverTitleCopies;
    uint64_t peersDeniedBeforeRegistration;
    int32_t lastServerStatus, lastClientStatus;
    bool serverConfigured, serverRegistered, clientRegistered;
} VM27OriginalV8TransportRegistrationStats;
void VM27OriginalV8TransportCopyRegistrationStats(VM27OriginalV8TransportRegistrationStats *);
/* Both actual native gates precede the unchanged registry's message/token/CD
 * gate. Requires actual serial server control queue. Owned exact typed reply. */
int VM27OriginalV8TransportReceiveServerClientRegistrationMessage(xpc_object_t actualMessage,
    xpc_object_t *ownedReply);
/* Actual main CFBundle DisplayName, or actual Name only if DisplayName absent.
 * No hard default. A competing in-flight caller returns local EALREADY without
 * cancelling its owner. Actual metadata/request/reply error or timeout cancels
 * the private connection and fails; cleanup owns its captured epoch/tag. */
int VM27OriginalV8TransportRegisterClientDisplayNameFromMainBundle(xpc_connection_t exactPrivateConnection);
/* Retained live actual registered parent name; unregistered/reaped peer fails.
 * Initializes only this typed8-byte output to NULL. */
int VM27OriginalV8TransportCopyServerRegisteredClientDisplayName(CFStringRef *ownedName);

/* No new process or system service registration. Copies only an actual native
 * endpoint in a received dictionary from this consumer's exact spawned child.
 * Requires the existing native/explicit-approved consumer gate, immutable
 * nonce UINT64 and exact service string. One connection per installed factory.
 * The caller owns the consumer/process lifetime and must clear before release. */
int VM27OriginalV8TransportInstallClientFactoryMessage(VM27PrivateServiceConsumer *,
    xpc_object_t actualChildMessage, uint64_t nonce);
/* The original consumer must complete its real handler+activate sequence,
 * including a setter-refused/cancelled connection, and drain final INVALID
 * before this final owned retain is released. Cancellation does not resume a
 * native suspended connection. This helper does not guess private state. */
void VM27OriginalV8TransportClearClient(void);
int VM27OriginalV8TransportCopyABI(VM27OriginalV8TransportABI *);
void VM27OriginalV8TransportCopyStats(VM27OriginalV8TransportStats *);

/* One configured server/peer per process. Stop cannot reset the immutable
 * registry: Create after configuration requires a fresh process (EALREADY).
 * Authenticates actual reviewed parent file pages/CodeDirectory with the
 * existing bounded inspector (2MiB stays unchanged). Creates only an own
 * anonymous listener and returns an owned endpoint. The accepted connection
 * must match actual expectedPID + kernel CDHash/CS_VALID and BOTH SecTask's
 * genuine Boolean and native connection Boolean for either original VM key.
 * Original SecTaskEntitlementsValidated remains a separate reported field;
 * explicit reviewed-code authorization never changes it to true. */
int VM27OriginalV8TransportCreateServer(const char *actualParentCode,
    const char *reviewedSHA256, const char *reviewedCDHash, pid_t expectedParentPID,
    dispatch_queue_t actualServerQueue, xpc_endpoint_t *ownedEndpoint);
/* Requires successful immutable registry configuration first. A typed
 * lifecycle helper for bounded tests. The original ABI uses this same real
 * listener/handler path and then dispatch_main(), never returns. */
int VM27OriginalV8TransportStartServer(VM27OriginalV8ServiceHandler originalHandler);
/* Must be called off the listener queue; rejects EDEADLK/active callback.
 * Waits <=2s for the real final INVALID event, then drains and releases refs.
 * ETIMEDOUT retains own storage safely; a later off-queue retry is permitted. */
int VM27OriginalV8TransportStopServer(void);

/* Exact original C ABI exports. ConnectionCreate forwards other identifiers/anonymous creation
 * to the pinned real libxpc provider. Matching VM identifier fails closed if
 * its actual child factory was not installed. The returned native connection
 * has an inactive user handler. Its private one-shot UUID is authenticated
 * on the real child factory channel before the original handler is activated.
 * Main requires an owned prepared server; absent state exits78 without system
 * bootstrap registration. No generic stub. */
xpc_connection_t VM27OriginalV8TransportConnectionCreate(const char *, dispatch_queue_t)
    __asm__("_xpc_connection_create");
__attribute__((noreturn)) void VM27OriginalV8TransportMain(VM27OriginalV8ServiceHandler)
    __asm__("_xpc_main");

/* Establish the required per-process, per-service one-shot instance before
 * peer delivery. These are private bootstrap control messages, never original
 * application wire messages. Must be invoked on the actual child control queue.
 * The caller must return the owned reply through that same actual connection. */
/* Before starting the listener, also configures the registry from this
 * server's immutable actual expected parent PID/CD and the same nonce. */
int VM27OriginalV8TransportRequireServerInstance(uint64_t nonce);
int VM27OriginalV8TransportBindServerInstanceMessage(xpc_object_t actualMessage,
    xpc_object_t *ownedReply);
int VM27OriginalV8TransportCopyServerInstance(unsigned char outUUID[16]);
#if VM27_ENABLE_DIAGNOSTIC_ENDPOINT_FAILURE
/* One failed endpoint allocation for an own just-created listener only. Never
 * changes native libxpc, registration, messages or the success path. */
void VM27OriginalV8TransportInjectEndpointFailureOnceForDiagnostic(void);
#endif
/* Exact original void ABIs. Private matching connection binds one immutable
 * nonzero UUID to the actual spawned process, requiring an authenticated ack.
 * Zero UUID returns EINVAL without sending; an already bound/in-flight
 * instance returns EALREADY without cancelling the prior real state. Actual
 * registration/transmitted request/reply failure or timeout invalidates the
 * frontend epoch, cancels it and reports errno/lastInstanceStatus, never fake success.
 * Calls for other connections forward only to pinned native code. Getter copies
 * 16 bytes; it does NOT return a pointer. No setters touch libxpc object fields. */
void VM27OriginalV8TransportSetOneShotInstance(xpc_connection_t, const unsigned char *)
    __asm__("_xpc_connection_set_oneshot_instance");
void VM27OriginalV8TransportGetInstance(xpc_connection_t, unsigned char *)
    __asm__("_xpc_connection_get_instance");
#ifdef __cplusplus
}
#endif
#endif
