#ifndef VZ_CPU_KERNEL_INITIALIZATION_V3_PRIVATE_H
#define VZ_CPU_KERNEL_INITIALIZATION_V3_PRIVATE_H
#include "modern_cpu_kernel_initialization_private.h"
// q.low/high are an actual own config snapshot, not historical/default values.
VZKernelStatus VZKernelInitApplyCreationConfigV3(const VZKernelInitRequest *,
    const VZKernelInitAccess *, VZKernelInitReceipt *);
#endif
