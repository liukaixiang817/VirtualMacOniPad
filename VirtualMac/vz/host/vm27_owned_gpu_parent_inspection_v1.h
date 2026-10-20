#ifndef VM27_OWNED_GPU_PARENT_INSPECTION_V1_H
#define VM27_OWNED_GPU_PARENT_INSPECTION_V1_H
#include "vm27_bundle_parent_inspection_v1.h"
/* Read-only identity completion for the actual slot2 capability owner. The
 * actual kernel CDHash has already been obtained from an authenticated parent
 * message. This checks complete file pages and embedded/external slots at the
 * fixed canonical parent .xpc, requiring its computed CD to equal that kernel
 * identity. The returned SHA is an actual observation, not a preapproved pin.
 * No native/Apple trust or whole-resource validation is fabricated. */
__attribute__((visibility("hidden")))
int VM27OwnedGPUInspectActualParentV1(const char *canonicalBundlePath,
    const char *executableName, uid_t ownerUID, const char *actualKernelCDHash,
    VM27BundleParentInspectionV1 *result);
#endif
