#include "modern_cpu_production_native_ops_v20_control0.c"
#include "modern_cpu_production_owner_boundary_v21.h"
bool VM27ProductionOwnerBoundaryEligibleV21(const VZKernelLifecycleOps *ops) {
 return ops && ops->context==&ProductionV1 && ops->currentThread==ProductionThreadV1 &&
  ops->readMemory==ProductionReadV1 && ops->nativeTrap==ProductionNativeV1;
}
