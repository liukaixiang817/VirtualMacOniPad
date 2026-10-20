#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V5_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V5_H
#include "modern_cpu_native_public_factory_v4.h"
#include "modern_cpu_kernel_lifecycle_v9.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VM27CPUFactoryRAMV5 VM27CPUFactoryRAMV5;
// SAME factory VM/owner/epoch/nativeOps as CPU. The returned address is a
// borrowed view of own backing; caller may not free/reprotect it. Whole range
// native3/5/4, no CPU handles during writes or mapping changes. Keep RAM mapped
// through CPU lifetime, then destroy CPU before unmap/free. Native failures
// preserve real backing and cleanup handles; VM destroy/free refuses RAM.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMCreateV5(VM27CPUFactoryVMV2 *,
 uint64_t bytes, VM27CPUFactoryRAMV5 **, void **hostAddress, VZKernelRAMResultV9 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMWriteV5(VM27CPUFactoryRAMV5 *,
 uint64_t offset, const void *, size_t, VZKernelRAMResultV9 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMMapV5(VM27CPUFactoryRAMV5 *,
 uint64_t guestAddress, uint64_t flags, VZKernelRAMResultV9 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMProtectV5(VM27CPUFactoryRAMV5 *,
 uint64_t flags, VZKernelRAMResultV9 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMUnmapV5(VM27CPUFactoryRAMV5 *, VZKernelRAMResultV9 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMFreeV5(VM27CPUFactoryRAMV5 *);
#ifdef __cplusplus
}
#endif
#endif
