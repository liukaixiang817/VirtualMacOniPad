#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V9_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V9_H
#include "modern_cpu_native_public_factory_v8.h"
#include "modern_cpu_kernel_lifecycle_v11.h"
#ifdef __cplusplus
extern "C" {
#endif
// The caller owns and retains this actual self-task host range. This handle
// never munmaps it. Whole-range native changes use the same CPU/VM registry;
// an uncertain native change retains the handle until successful unmap.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMAdoptHostV9(VM27CPUFactoryVMV2 *,
 void *hostAddress,uint64_t bytes,VM27CPUFactoryRAMV5 **,VZKernelRAMResultV9 *);
#ifdef __cplusplus
}
#endif
#endif
