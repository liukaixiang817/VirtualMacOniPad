#ifndef VM27_BUNDLE_CHILD_INSPECTION_V1_H
#define VM27_BUNDLE_CHILD_INSPECTION_V1_H
#include "vm27_bundle_parent_inspection_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Actual canonical .xpc/Contents layout only. The existing configuration
 * supplies the real .xpc path/name, reviewed SHA/CD and exact file owner.
 * Same frozen page/embedded/external-slot parser as ParentInspectV1;
 * child code <=8MiB, Info<=64KiB, CodeResources<=1MiB. Every ancestor/name/FD
 * is retained and checked. No whole-resource walk or native trust assertion.
 * This hidden helper belongs inside the one ConsumerV2 provider image. */
__attribute__((visibility("hidden")))
int VM27BundleChildInspectV1(const VM27BundleParentConfigurationV1 *,
                            VM27BundleParentInspectionV1 *);
#ifdef __cplusplus
}
#endif
#endif
