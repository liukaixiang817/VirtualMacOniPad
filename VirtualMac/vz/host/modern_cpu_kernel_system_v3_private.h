#ifndef VZ_MODERN_CPU_KERNEL_SYSTEM_V3_PRIVATE_H
#define VZ_MODERN_CPU_KERNEL_SYSTEM_V3_PRIVATE_H
#include "modern_cpu_kernel_system_private.h"
// Invoked only for the original missing decoded readiness mask, under the
// actual lifecycle CPU guard. Boolean reports invocation, never a fake token.
typedef VZKernelStatus (*VZKernelSysPrepareV3)(void *, bool *);
VZKernelStatus VZKernelSysApplyVerifiedRouteV3(const VZKernelSysRequest *,
    const VZKernelInitAccess *, VZKernelSysFeatureCache *, uint64_t *,
    VZKernelSysReceipt *, VZKernelSysPrepareV3);
#endif
