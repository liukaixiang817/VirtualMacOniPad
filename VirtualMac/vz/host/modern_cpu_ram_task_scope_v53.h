#ifndef VM27_RAM_TASK_SCOPE_V53_H
#define VM27_RAM_TASK_SCOPE_V53_H
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_native_public_factory_v2.h"
// Same-image task/registry lookups only; no thread-owner bypass for CPU APIs.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelRAMTaskScopeV53(VZKernelVM *,uint64_t);
__attribute__((visibility("hidden"))) VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMTaskScopeV8(VM27CPUFactoryVMV2 *);
#endif
