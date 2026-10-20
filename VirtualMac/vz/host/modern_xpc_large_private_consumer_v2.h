/* Independent V2 result-completion scope. Frozen V1 providers stay unchanged.
 * Capacity, owned spawn/reap and exact native authorization remain unchanged. */
#ifndef VM27_LARGE_PRIVATE_SERVICE_CONSUMER_V2_H
#define VM27_LARGE_PRIVATE_SERVICE_CONSUMER_V2_H
#include "modern_xpc_large_bundle_registry.h"
#include "modern_xpc_approved_code.h"
#include "modern_xpc_private_endpoint.h"
#include <sys/types.h>

typedef struct VM27LargePrivateServiceConsumerV2 VM27LargePrivateServiceConsumerV2;
typedef enum { VM27LargeConsumerV2StrictNative = 1, VM27LargeConsumerV2ExplicitApprovedCode = 2 } VM27LargePrivateConsumerV2Mode;
typedef struct {
    pid_t childPID;
    bool started, reaped, absent, parentRegisteredPortsUnchanged;
    int observedWaitExit;
    uint64_t messageChecks, messagesAccepted;
} VM27LargePrivateConsumerV2State;
typedef struct { uint64_t created, destroyed, spawns, reaps, messageChecks; } VM27LargePrivateConsumerV2Stats;

/* Copies a real registry plan. Both reviewed expected hashes are mandatory.
 * The full actual executable CodeDirectory/pages/slots are authenticated;
 * flags2 and original27's precise non-null requirement remain mandatory.
 * Approved mode additionally requires its signed plugin Boolean true.
 * Strict mode keeps the exact original native gate, with no fallback. After
 * that gate succeeds, it completes the actual received-message identity
 * using csops_audittoken CDHash and CS_VALID, requiring both reviewed pins. */
int VM27LargePrivateServiceConsumerV2Create(VM27LargeBundleRegistry *registry, const char *service,
                                    const char *expectedSHA256, const char *expectedCDHash,
                                    xpc_object_t originalRequirement,
                                    VM27LargePrivateConsumerV2Mode mode,
                                    VM27LargePrivateServiceConsumerV2 **result);
/* Returns EBUSY without destroying an active, unreaped owned child. Caller
 * must drain its message queue before release. No implicit kill or orphan. */
int VM27LargePrivateServiceConsumerV2Release(VM27LargePrivateServiceConsumerV2 *consumer);
/* One actual registered service executable; argv[0] must be that pinned path.
 * No DYLD_* environment overrides; bounded args/environment. Copies the own
 * native endpoint send capability into child registered slot2 only. */
int VM27LargePrivateServiceConsumerV2Spawn(VM27LargePrivateServiceConsumerV2 *consumer,
                                   xpc_endpoint_t ownEndpoint,
                                   char *const arguments[], char *const environment[],
                                   pid_t *ownedChildPID);
/* Each received dictionary rechecks actual registry file pins and only the
 * real kernel audit identity of this actual spawned child, before the chosen
 * native/explicit-approved gate. Message body claims are not authority. */
int VM27LargePrivateServiceConsumerV2CheckMessage(VM27LargePrivateServiceConsumerV2 *consumer,
                                          xpc_object_t message,
                                          VM27ApprovedCodeMessageResult *result);
/* Actual waitpid only; nonblocking returns EAGAIN while running. The caller
 * bounds a blocking wait (the fixture uses CPU5/wall15 and child alarm15). */
int VM27LargePrivateServiceConsumerV2Wait(VM27LargePrivateServiceConsumerV2 *consumer, bool block,
                                  VM27LargePrivateConsumerV2State *result);
int VM27LargePrivateServiceConsumerV2CopyState(VM27LargePrivateServiceConsumerV2 *consumer,
                                       VM27LargePrivateConsumerV2State *result);
void VM27LargePrivateServiceConsumerV2CopyStats(VM27LargePrivateConsumerV2Stats *result);
#endif
