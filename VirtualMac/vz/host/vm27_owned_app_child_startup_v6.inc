/* Actual startup diagnostics only; public V2 parent / V3 bootstrap ABI and
 * every frozen owner, received-identity, native and cleanup gate remain. */
#include "vm27_owned_app_child_startup_v3.h"
#include "modern_xpc_large_private_consumer_v5.h"
#include <errno.h>
#include <stdio.h>
static int RegistryCreateDiagnosticV4(const char *root, VM27LargeBundleRegistry **out) {
    int status = VM27LargeBundleRegistryCreate(root, out);
    fprintf(stderr, "[Independent27] parent-start registry-create status=%d\n", status);
    return status;
}
static int RegistryRegisterDiagnosticV4(VM27LargeBundleRegistry *r, const char *path,
                                       uint64_t flags, xpc_object_t requirement) {
    int status = VM27LargeBundleRegistryRegister(r, path, flags, requirement);
    fprintf(stderr, "[Independent27] parent-start registry-register status=%d\n", status);
    return status;
}
static int ConsumerCreateDiagnosticV4(VM27LargeBundleRegistry *r, const char *service,
    const char *sha, const char *cd, xpc_object_t requirement,
    VM27LargePrivateConsumerV2Mode mode, VM27LargePrivateServiceConsumerV2 **out) {
    /* Independent startup deliberately selects its own fixed endpoint
     * contract before any checks; this is never a native failure fallback. */
    int status = mode != VM27LargeConsumerV2StrictNative ? EINVAL :
        VM27OwnedBundlePrivateServiceConsumerCreateV5(r, service, sha, cd, requirement, out);
    fprintf(stderr, "[Independent27] parent-start owned-bundle-consumer-create status=%d\n", status);
    return status;
}
static int ConsumerSpawnDiagnosticV4(VM27LargePrivateServiceConsumerV2 *consumer,
    xpc_endpoint_t endpoint, char *const arguments[], char *const environment[], pid_t *child) {
    int status = VM27LargePrivateServiceConsumerV2Spawn(consumer, endpoint, arguments, environment, child);
    fprintf(stderr, "[Independent27] parent-start consumer-spawn status=%d child=%d\n", status, child ? (int)*child : 0);
    return status;
}
#define VM27LargeBundleRegistryCreate RegistryCreateDiagnosticV4
#define VM27LargeBundleRegistryRegister RegistryRegisterDiagnosticV4
#define VM27LargePrivateServiceConsumerV2Create ConsumerCreateDiagnosticV4
#define VM27LargePrivateServiceConsumerV2Spawn ConsumerSpawnDiagnosticV4
#include "vm27_owned_app_child_startup_v3.c"
#undef VM27LargeBundleRegistryCreate
#undef VM27LargeBundleRegistryRegister
#undef VM27LargePrivateServiceConsumerV2Create
#undef VM27LargePrivateServiceConsumerV2Spawn
