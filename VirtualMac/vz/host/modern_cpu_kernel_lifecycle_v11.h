#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V11_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V11_H
#include "modern_cpu_kernel_lifecycle_v10.h"
// Real public mapping borrows a caller-owned self-task host range. No host
// allocation is copied or freed by this handle. The caller must keep the range
// alive through successful unmap, including uncertain failed native changes.
// The same VM registry, owner, epoch and exclusion as own RAM apply. Whole
// ranges only; CPU handles must be absent during changes. No foreign VM token.
VZKernelStatus VZKernelRAMAdoptHostRangeV11(VZKernelVM *, void *hostAddress,
 uint64_t bytes,VZKernelRAMV9 **outRAM,VZKernelRAMResultV9 *);
#endif
