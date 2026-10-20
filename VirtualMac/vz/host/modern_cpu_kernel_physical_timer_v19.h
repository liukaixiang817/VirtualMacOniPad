#ifndef VZ_MODERN_CPU_KERNEL_PHYSICAL_TIMER_V19_H
#define VZ_MODERN_CPU_KERNEL_PHYSICAL_TIMER_V19_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#include "modern_cpu_kernel_counter_domain_v19.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VZKernelPhysicalTimerOwnerV19 VZKernelPhysicalTimerOwnerV19;
typedef enum {VZ_KERNEL_PHYSICAL_TIMER_READ_V19=1,
 VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19=2,VZ_KERNEL_PHYSICAL_TIMER_POLL_V19=3}
 VZKernelPhysicalTimerActionV19;
#define VZ_KERNEL_PHYSICAL_TIMER_CTL_V19 UINT32_C(0xdf11)
#define VZ_KERNEL_PHYSICAL_TIMER_CVAL_V19 UINT32_C(0xdf12)
// Private sampled Mach/physical-counter profile. Nonzero guest offset and
// actual stable commpage bias translate through native physical CVAL.
// This is a private, native-CNTPCT finite profile. It is not the SDK GIC API.
// The true GIC registry must validate its actual allocation and this identity.
// routePhysicalTimer updates its timer PPI level and returns the IRQ after
// arbitration over all real sources. A timer level is not itself an IRQ.
// A deadline hook must arm/cancel a real wake source, not a success cache.
typedef struct {
 void *nativeContext,*gicOwner;
 bool (*readCounterDomain)(void *,VZKernelCounterDomainSampleV19 *);
 VZKernelStatus (*validateGICOwner)(void *,const VZKernelRunPendingRequestV14 *);
 VZKernelStatus (*routePhysicalTimer)(void *,const VZKernelRunPendingRequestV14 *,bool,bool *);
 VZKernelStatus (*updatePhysicalDeadline)(void *,const VZKernelRunPendingRequestV14 *,bool,uint64_t);
 // Same owner cleanup, including a withdrawn/draining CPU: cancel and drain
 // the wake source and detach its PPI before the real CPU borrow is released.
 VZKernelStatus (*quiescePhysicalTimer)(void *,const VZKernelRunPendingRequestV14 *);
} VZKernelPhysicalTimerBindingV19;
typedef struct {
 VZKernelStatus status;
 uint32_t attemptedReads,attemptedWrites,completedWrites,failedNativeOffset;
 uint64_t nativeControl,nativeCVAL,nativeCounter;
 uint64_t logicalCVAL,vtimerOffset,hostCounterBias,physicalOffset,previousPhysicalOffset;
 VZKernelCounterDomainSampleV19 counterDomain;
 VZKernelCounterDomainResultV19 domainResult;
 bool domainValidated,offsetRebased;
 bool nativeOp8Required,nativeOp8Invoked,physicalStateRead,counterSampled;
 bool physicalTimerAsserted,aggregateIRQ,irqRouteAttempted,irqRouteComplete;
 bool deadlineAttempted,deadlineComplete,deadlineArmed;
 bool mutationPoisoned,identityWithdrawn;
} VZKernelPhysicalTimerReceiptV19;
// Holds an actual V5 borrow for its entire lifetime, including mutation failure.
// Binding functions execute under this CPU's real owner/version/operation guard.
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelPhysicalTimerOwnerCreateV19(const VZKernelRunPendingRequestV14 *,
 const VZKernelPhysicalTimerBindingV19 *,const VZKernelInitWriter *,
 VZKernelPhysicalTimerOwnerV19 **);
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelPhysicalTimerOwnerAccessV19(VZKernelPhysicalTimerOwnerV19 *,
 VZKernelPhysicalTimerActionV19,uint32_t,uint64_t,uint64_t *,
 VZKernelPhysicalTimerReceiptV19 *,VZKernelLifecycleResult *);
// Failed borrow release retains the owner and its cleanup handle; never free it.
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelPhysicalTimerOwnerDestroyV19(VZKernelPhysicalTimerOwnerV19 *);
#ifdef __cplusplus
}
#endif
#endif
