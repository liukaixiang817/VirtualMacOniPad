/* Independent fixed8MiB app-private capacity scope; old2MiB source/providers
 * stay unchanged. Info.plist still64KiB. Real SHA/UUID/owner/FD paths retained. */
#ifndef VM27_LARGE_PRIVATE_SERVICE_CONSUMER_H
#define VM27_LARGE_PRIVATE_SERVICE_CONSUMER_H
#include "modern_xpc_large_bundle_registry.h"
#include "modern_xpc_approved_code.h"
#include "modern_xpc_private_endpoint.h"
#include <sys/types.h>

typedef struct VM27LargePrivateServiceConsumer VM27LargePrivateServiceConsumer;
typedef enum { VM27LargeConsumerStrictNative = 1, VM27LargeConsumerExplicitApprovedCode = 2 } VM27LargePrivateConsumerMode;
typedef struct {
    pid_t childPID;
    bool started, reaped, absent, parentRegisteredPortsUnchanged;
    int observedWaitExit;
    uint64_t messageChecks, messagesAccepted;
} VM27LargePrivateConsumerState;
typedef struct { uint64_t created, destroyed, spawns, reaps, messageChecks; } VM27LargePrivateConsumerStats;

/* Copies a real registry plan. Both reviewed expected hashes are mandatory.
 * The full actual executable CodeDirectory/pages/slots are authenticated;
 * flags2 and original27's precise non-null requirement remain mandatory.
 * Approved mode additionally requires its signed plugin Boolean true.
 * Strict mode keeps the exact original native gate, with no fallback. */
int VM27LargePrivateServiceConsumerCreate(VM27LargeBundleRegistry *registry, const char *service,
                                    const char *expectedSHA256, const char *expectedCDHash,
                                    xpc_object_t originalRequirement,
                                    VM27LargePrivateConsumerMode mode,
                                    VM27LargePrivateServiceConsumer **result);
/* Returns EBUSY without destroying an active, unreaped owned child. Caller
 * must drain its message queue before release. No implicit kill or orphan. */
int VM27LargePrivateServiceConsumerRelease(VM27LargePrivateServiceConsumer *consumer);
/* One actual registered service executable; argv[0] must be that pinned path.
 * No DYLD_* environment overrides; bounded args/environment. Copies the own
 * native endpoint send capability into child registered slot2 only. */
int VM27LargePrivateServiceConsumerSpawn(VM27LargePrivateServiceConsumer *consumer,
                                   xpc_endpoint_t ownEndpoint,
                                   char *const arguments[], char *const environment[],
                                   pid_t *ownedChildPID);
/* Each received dictionary rechecks actual registry file pins and only the
 * real kernel audit identity of this actual spawned child, before the chosen
 * native/explicit-approved gate. Message body claims are not authority. */
int VM27LargePrivateServiceConsumerCheckMessage(VM27LargePrivateServiceConsumer *consumer,
                                          xpc_object_t message,
                                          VM27ApprovedCodeMessageResult *result);
/* Actual waitpid only; nonblocking returns EAGAIN while running. The caller
 * bounds a blocking wait (the fixture uses CPU5/wall15 and child alarm15). */
int VM27LargePrivateServiceConsumerWait(VM27LargePrivateServiceConsumer *consumer, bool block,
                                  VM27LargePrivateConsumerState *result);
int VM27LargePrivateServiceConsumerCopyState(VM27LargePrivateServiceConsumer *consumer,
                                       VM27LargePrivateConsumerState *result);
void VM27LargePrivateServiceConsumerCopyStats(VM27LargePrivateConsumerStats *result);
#endif
