#ifndef VM27_MODERN_CPU_KERNEL_LIFECYCLE_V18_H
#define VM27_MODERN_CPU_KERNEL_LIFECYCLE_V18_H
#include "modern_cpu_kernel_lifecycle_v16.h"
#include "modern_cpu_kernel_physical_timer_v16.h"
#include "modern_cpu_kernel_wake_owner_v17.h"
#include "modern_gic_v3_engine_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VZKernelCPUGICOwnerV18 VZKernelCPUGICOwnerV18;
// The engine must already have retained this exact CPU in its own attachment.
// This owner additionally holds its actual V5 CPU borrow and real Timer16 owner.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerCreateV18(
 const VZKernelRunPendingRequestV14 *,VM27GICV3V1 *,const VZKernelInitWriter *,VZKernelCPUGICOwnerV18 **);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerDestroyV18(VZKernelCPUGICOwnerV18 *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerSetAffinityV18(
 VZKernelCPUGICOwnerV18 *,uint64_t);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerAccessV18(
 VZKernelCPUGICOwnerV18 *,uint32_t action,uint32_t selector,uint64_t value,uint64_t *,VZKernelPhysicalTimerReceiptV16 *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerPoisonV18(VZKernelCPUGICOwnerV18 *);
// Failure to authenticate or acquire the owner is a status, never poison state.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerPoisonedV18(VZKernelCPUGICOwnerV18 *,bool *);
// Actual factory Run routes here. Without a GIC attachment it preserves Life14
// exactly. With one, handled traps resume only while the true post token is live.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPURunGICPendingV18(
 VZKernelCPU *,const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,VZKernelRunPendingReceiptV14 *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPURunGICPendingBoundedV18(
 VZKernelCPU *,const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,uint64_t maxSteps,VZKernelRunPendingReceiptV14 *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerRequestExitV18(VZKernelCPUGICOwnerV18 *,bool *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUGICOwnerTakeExitV18(VZKernelCPUGICOwnerV18 *,bool *);
__attribute__((visibility("hidden"))) bool VZKernelCPUControllerOutputRangeDisjointV18(const void *,size_t);
__attribute__((visibility("hidden"))) bool VZKernelCPUWakeRangeDisjointV18(
 VZKernelCPUWakeOwnerV17 *,const void *,size_t);
#ifdef __cplusplus
}
#endif
#endif
