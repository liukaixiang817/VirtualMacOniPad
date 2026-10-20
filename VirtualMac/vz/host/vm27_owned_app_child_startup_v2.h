#ifndef VM27_OWNED_APP_CHILD_STARTUP_V2_H
#define VM27_OWNED_APP_CHILD_STARTUP_V2_H
#include "vm27_owned_app_child_startup_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
/* ARC callers never construct/release an xpc +1 out parameter. Requirement
 * must initially be NULL; this actual C owner creates the scoped policy,
 * calls the inherited strict native parent start and releases its own policy.
 * The returned process/consumer owner follows the unchanged v1 retention. */
int VM27OwnedAppParentStartWithScopedPolicyV2(const VM27OwnedAppParentConfigurationV1 *,
 VM27OwnedAppParentV1 **owner);
#ifdef __cplusplus
}
#endif
#endif
