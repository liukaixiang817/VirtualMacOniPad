#ifndef VZ_MODERN_CPU_KERNEL_WAKE_OWNER_V17_H
#define VZ_MODERN_CPU_KERNEL_WAKE_OWNER_V17_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VZKernelCPUWakeOwnerV17 VZKernelCPUWakeOwnerV17;
typedef struct {
 VZKernelStatus status;
 uint64_t nativeSlotMask;
 VZKernelHVReturn nativeReturn;
 bool nativeInvoked,versionVerified,identityVerified,callbackDraining;
} VZKernelCPUWakeReceiptV17;
// Create/release on the real CPU owner thread. Holds its actual V5 borrow.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUWakeOwnerCreateV17(
 const VZKernelRunPendingRequestV14 *,VZKernelCPUWakeOwnerV17 **);
// Async allowed: exact registered slot only, even while that CPU is in Run.
// The controller must pin this token for the entire callback and drain its
// scheduler before destroy. No arbitrary masks or owner-thread substitution.
// Calls nativeTrap(context,10,(void *)(uintptr_t)mask): op10 x1 is an integer
// bitmask, not a pointer to a packet. This wakes/cancels; it does not inject IRQ.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUWakeOwnerSignalV17(
 VZKernelCPUWakeOwnerV17 *,const VZKernelRunPendingRequestV14 *,VZKernelCPUWakeReceiptV17 *);
// Closing the signal gate is permanent. BUSY retains token/borrow, allowing an
// owner-thread retry after the scheduler and its in-flight callbacks drain.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUWakeOwnerDrainV17(VZKernelCPUWakeOwnerV17 *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUWakeOwnerDestroyV17(VZKernelCPUWakeOwnerV17 *);
// Raw architectural frequency, paired with CNTPCT_EL0. Offline compilation
// alone does not prove EL0 access or its relationship to mach_absolute_time.
__attribute__((visibility("hidden"))) bool VZKernelReadPhysicalCounterFrequencyV17(void *,uint64_t *);
#ifdef __cplusplus
}
#endif
#endif
