#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V6_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V6_H
// Link this alternative source instead of immutable V5. V5 remains unchanged.
#include "modern_cpu_kernel_lifecycle_v5.h"
#include "modern_cpu_kernel_initialization.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t schemaVersion, fineGrainedTraps, trapTLBISW;
    uint32_t supportKnown, supportSupported;
    uint64_t keyLow, keyHigh, sourceConfigGeneration;
} VZKernelCreationConfigV6;
// Apply only the closed native0e creation key/policy slice, before publication.
// Boolean fields are retained in own state. They are not op6 flags and do not
// prove a USER feature cache, native TLBI application, reset or native Run.
// The same owner/TLS/VM epoch/CPU generation guard covers every read/write.
// Failed partial writes poison the CPU and preserve its actual cleanup handle.
VZKernelStatus VZKernelCPUApplyCreationConfigV6(VZKernelCPU *,
    const VZKernelCreationConfigV6 *, const VZKernelInitWriter *,
    VZKernelInitReceipt *, VZKernelLifecycleResult *);
VZKernelStatus VZKernelCPUCopyCreationConfigV6(VZKernelCPU *, VZKernelCreationConfigV6 *);
#ifdef __cplusplus
}
#endif
#endif
