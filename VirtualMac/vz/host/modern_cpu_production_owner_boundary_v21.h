#ifndef VM27_PRODUCTION_OWNER_BOUNDARY_V21_H
#define VM27_PRODUCTION_OWNER_BOUNDARY_V21_H
#include "modern_cpu_kernel_lifecycle.h"
/* Pure identity comparison: these concrete callbacks cannot reenter lifecycle
 * mutation while the current CPU's operation guard is held. */
__attribute__((visibility("hidden"))) bool
VM27ProductionOwnerBoundaryEligibleV21(const VZKernelLifecycleOps *);
#endif
