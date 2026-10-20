#ifndef VZ_MODERN_CPU_KERNEL_PHYSICAL_TIMER_V16_H
#define VZ_MODERN_CPU_KERNEL_PHYSICAL_TIMER_V16_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VZKernelPhysicalTimerOwnerV16 VZKernelPhysicalTimerOwnerV16;
typedef enum {VZ_KERNEL_PHYSICAL_TIMER_READ_V16=1,
 VZ_KERNEL_PHYSICAL_TIMER_WRITE_V16=2,VZ_KERNEL_PHYSICAL_TIMER_POLL_V16=3}
 VZKernelPhysicalTimerActionV16;
#define VZ_KERNEL_PHYSICAL_TIMER_CTL_V16 UINT32_C(0xdf11)
#define VZ_KERNEL_PHYSICAL_TIMER_CVAL_V16 UINT32_C(0xdf12)
// This is a private, native-CNTPCT finite profile. It is not the SDK GIC API.
// The true GIC registry must validate its actual allocation and this identity.
// routePhysicalTimer updates its timer PPI level and returns the IRQ after
// arbitration over all real sources. A timer level is not itself an IRQ.
// A deadline hook must arm/cancel a real wake source, not a success cache.
typedef struct {
 void *nativeContext,*gicOwner;
 bool (*readPhysicalCounter)(void *,uint64_t *);
 VZKernelStatus (*validateGICOwner)(void *,const VZKernelRunPendingRequestV14 *);
 VZKernelStatus (*routePhysicalTimer)(void *,const VZKernelRunPendingRequestV14 *,bool,bool *);
 VZKernelStatus (*updatePhysicalDeadline)(void *,const VZKernelRunPendingRequestV14 *,bool,uint64_t);
 // Same owner cleanup, including a withdrawn/draining CPU: cancel and drain
 // the wake source and detach its PPI before the real CPU borrow is released.
 VZKernelStatus (*quiescePhysicalTimer)(void *,const VZKernelRunPendingRequestV14 *);
} VZKernelPhysicalTimerBindingV16;
typedef struct {
 VZKernelStatus status;
 uint32_t attemptedReads,attemptedWrites,completedWrites,failedNativeOffset;
 uint64_t nativeControl,nativeCVAL,nativeCounter;
 bool nativeOp8Required,nativeOp8Invoked,physicalStateRead,counterSampled;
 bool physicalTimerAsserted,aggregateIRQ,irqRouteAttempted,irqRouteComplete;
 bool deadlineAttempted,deadlineComplete,deadlineArmed;
 bool mutationPoisoned,identityWithdrawn;
} VZKernelPhysicalTimerReceiptV16;
// Holds an actual V5 borrow for its entire lifetime, including mutation failure.
// Binding functions execute under this CPU's real owner/version/operation guard.
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelPhysicalTimerOwnerCreateV16(const VZKernelRunPendingRequestV14 *,
 const VZKernelPhysicalTimerBindingV16 *,const VZKernelInitWriter *,
 VZKernelPhysicalTimerOwnerV16 **);
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelPhysicalTimerOwnerAccessV16(VZKernelPhysicalTimerOwnerV16 *,
 VZKernelPhysicalTimerActionV16,uint32_t,uint64_t,uint64_t *,
 VZKernelPhysicalTimerReceiptV16 *,VZKernelLifecycleResult *);
// Failed borrow release retains the owner and its cleanup handle; never free it.
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelPhysicalTimerOwnerDestroyV16(VZKernelPhysicalTimerOwnerV16 *);
// Exact CNTPCT_EL0 sample. No software clock substitution; non-arm64 refuses.
// This is compiled offline here. Its EL0 availability still needs device proof.
__attribute__((visibility("hidden"))) bool
VZKernelReadPhysicalCounterV16(void *,uint64_t *);
#ifdef __cplusplus
}
#endif
#endif
