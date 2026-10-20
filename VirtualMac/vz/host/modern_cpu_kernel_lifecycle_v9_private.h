#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V9_PRIVATE_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V9_PRIVATE_H
#include "modern_cpu_kernel_lifecycle_v9.h"
// Hidden registry range guard for higher Factory/OS output admission. No
// callbacks. Nested order Factory->KernelRegistry->VMmutex; no inverse call.
bool VZKernelRAMOutputRangeDisjointV9(const void *,size_t);
#endif
