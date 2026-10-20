#ifndef VZ_MODERN_CPU_KERNEL_SYSTEM_PRIVATE_H
#define VZ_MODERN_CPU_KERNEL_SYSTEM_PRIVATE_H
#include "modern_cpu_kernel_system.h"
#include "modern_cpu_kernel_initialization_private.h"

// Application-private requested-value cache; never passed to Apple code.
typedef struct { uint64_t values[9]; uint16_t valid; } VZKernelSysFeatureCache;
bool VZKernelSysNativeFieldAllowed(uint32_t offset, size_t bytes);
VZKernelStatus VZKernelSysApplyVerifiedRoute(const VZKernelSysRequest *,
    const VZKernelInitAccess *, VZKernelSysFeatureCache *, uint64_t *, VZKernelSysReceipt *);
#endif
