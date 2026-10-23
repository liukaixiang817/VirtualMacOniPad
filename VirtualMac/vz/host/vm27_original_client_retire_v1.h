#ifndef VM27_ORIGINAL_CLIENT_RETIRE_V1_H
#define VM27_ORIGINAL_CLIENT_RETIRE_V1_H
#include "modern_xpc_large_private_consumer_v2.h"

/* No process is signalled. Retirement requires the consumer's actual waitpid
 * result and, if created, completion of the original client's real INVALID
 * callback. A busy operation leaves all factory references retained. */
int VM27OriginalClientRetireAfterExitV1(VM27LargePrivateServiceConsumerV2 *, uint64_t nonce);
typedef struct {
    uint64_t generation, callbacks;
    bool handlerInstalled, finalInvalidObserved;
} VM27OriginalClientLifecycleV1;
void VM27OriginalClientCopyLifecycleV1(VM27OriginalClientLifecycleV1 *);
#endif
