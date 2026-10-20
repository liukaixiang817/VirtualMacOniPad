#ifndef VM27_CPU_KERNEL_LIFECYCLE_V28_PRIVATE_H
#define VM27_CPU_KERNEL_LIFECYCLE_V28_PRIVATE_H
#include "modern_cpu_kernel_lifecycle_v27.h"
typedef struct {
    uint64_t identity, vmEpoch, cpuGeneration, ownerThread, returnedSlotWord;
    uint32_t nativeHVISA, reserved;
} VZKernelAMXAvailabilityIdentityV28;
/* Query metadata only. Neither value claims that an AMX operation succeeded. */
enum { VM27_AMX_ABSENT_V1 = 0, VM27_AMX_PRESENT_V1 = 1 };
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUGetAMXAvailabilityV28(VZKernelCPU *,
    const VZKernelAMXAvailabilityIdentityV28 *, const void *publicationTarget, uint32_t *);
#endif
