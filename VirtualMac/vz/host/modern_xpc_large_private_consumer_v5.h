#ifndef VM27_LARGE_PRIVATE_CONSUMER_V5_H
#define VM27_LARGE_PRIVATE_CONSUMER_V5_H
#include "modern_xpc_large_private_consumer_v2.h"
/* Explicit owned endpoint only. Full canonical bundle signatures, fixed SHA/CD,
 * actual spawned message audit PID/version, kernel CD/CS_VALID and genuine
 * plugin Boolean are required. Native validation is recorded independently;
 * StrictNative/default and the old raw policy remain unchanged. */
int VM27OwnedBundlePrivateServiceConsumerCreateV5(VM27LargeBundleRegistry *,
    const char *, const char *, const char *, xpc_object_t,
    VM27LargePrivateServiceConsumerV2 **);
#endif
