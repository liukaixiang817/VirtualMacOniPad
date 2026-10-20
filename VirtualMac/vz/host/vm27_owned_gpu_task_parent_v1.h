#ifndef VM27_OWNED_GPU_TASK_PARENT_V1_H
#define VM27_OWNED_GPU_TASK_PARENT_V1_H
#import <Foundation/Foundation.h>
#include "vm27_owned_gpu_task_transport_v1.h"

/* Root emits this immutable profile after signing the separate GPU task.
 * There is no reverse parent-hash dependency and no environment authority. */
typedef struct {
    uint32_t version;
    uid_t ownerUID;
    const char *canonicalRegistryRoot;
    const char *canonicalBundlePath;
    const char *canonicalExecutablePath;
    const char *signedExecutableSHA256;
    const char *signedExecutableCDHash;
    const char *executableUUID;
} VM27OwnedGPUTaskParentProfileV1;
extern const VM27OwnedGPUTaskParentProfileV1 VM27OwnedGPUTaskPinnedParentProfileV1;

/* Only PG's exact original initWithServiceName: call may enter. Its allocated
 * connection is consumed with the same init-family +1/nil ownership contract. */
__attribute__((visibility("default"), ns_returns_retained))
id VM27OwnedGPUTaskConnectionInitV1(id allocatedConnection, SEL originalSelector,
                                  NSString *serviceName);
#endif
