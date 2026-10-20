#ifndef VM27_MODERN_XPC_BUNDLE_REGISTRY_H
#define VM27_MODERN_XPC_BUNDLE_REGISTRY_H
#include "modern_xpc_lwcr_policy.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM27BundleRegistry VM27BundleRegistry;
typedef struct VM27PrivateServicePlan VM27PrivateServicePlan;
typedef struct {
    char bundleIdentifier[161];
    char serviceIdentifier[161];
    char executablePath[4096];
    char executableSHA256[65];
    char executableUUID[33];
    uint64_t executableBytes;
    uint64_t flags;
} VM27PrivateServiceInfo;
typedef struct {
    uint64_t registrations;
    uint64_t registeredServices;
    uint64_t plansCreated;
    uint64_t plansDestroyed;
    uint64_t verificationCalls;
    uint64_t messageChecks;
} VM27BundleRegistryStats;

/* Root is an existing, caller-owned mode0700 directory; no following symlinks. */
int VM27BundleRegistryCreate(const char *root, VM27BundleRegistry **result);
void VM27BundleRegistryRelease(VM27BundleRegistry *registry);

/*
 * Actual private table registration, not a launchd/xpc_add_bundle replacement.
 * Only immediate .bundle children under the immutable canonical root, flags2,
 * and original27's exact non-null plugin policy are supported. Reads real
 * Contents/Info.plist, each XPCServices service's Contents/Info.plist and the
 * actual arm64 executable identity/embedded-signature bounds. Stages all
 * records before atomic commit; native signature authenticity is separate.
 * No empty registration, replacement, symlink, path escape or unowned code.
 */
int VM27BundleRegistryRegister(VM27BundleRegistry *registry,
                              const char *absoluteBundlePath, uint64_t flags,
                              xpc_object_t immutableRequirement);
int VM27BundleRegistryCopyServicePlan(VM27BundleRegistry *registry,
                                     const char *identifier,
                                     VM27PrivateServicePlan **result);
void VM27PrivateServicePlanRelease(VM27PrivateServicePlan *plan);
int VM27PrivateServicePlanCopyInfo(const VM27PrivateServicePlan *plan,
                                 VM27PrivateServiceInfo *result);

/* Reopen each registered file beneath the retained root FD and recheck pins. */
int VM27PrivateServicePlanVerify(const VM27PrivateServicePlan *plan);
/* Received messages are checked against pins and the real strict native gate. */
int VM27PrivateServicePlanCheckReceivedMessage(const VM27PrivateServicePlan *plan,
                                             xpc_object_t message,
                                             VM27LWCRMessageResult *result);
void VM27BundleRegistryCopyStats(VM27BundleRegistryStats *result);

/* No process launcher or original xpc_add_bundle_with_lwcr export yet. */
#ifdef __cplusplus
}
#endif
#endif
