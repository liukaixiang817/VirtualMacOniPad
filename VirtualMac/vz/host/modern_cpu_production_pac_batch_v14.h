#ifndef VM27_PRODUCTION_PAC_BATCH_V14_H
#define VM27_PRODUCTION_PAC_BATCH_V14_H
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_kernel_initialization_private.h"
typedef struct { unsigned ok,attempted,completed; } VM27PACBatchResultV14;
__attribute__((visibility("hidden"))) bool VM27ProductionPACBatchEligibleV14(
 const VZKernelLifecycleOps *,const VZKernelInitWriter *);
__attribute__((visibility("hidden"))) VM27PACBatchResultV14 VM27ProductionPACBatchWriteV14(
 uintptr_t,uint64_t,const uint64_t *,unsigned);
#endif
