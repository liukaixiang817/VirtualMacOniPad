#ifndef VM27_MODERN_CPU_KERNEL_VTIMER_MASK_V20_H
#define VM27_MODERN_CPU_KERNEL_VTIMER_MASK_V20_H
#include "modern_cpu_kernel_lifecycle_v18.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
 VZKernelStatus status;
 uint32_t attemptedReads,attemptedWrites,completedWrites;
 uint64_t initialNativeValue,requestedNativeValue;
 bool initialMask,requestedMask,mutationPoisoned,identityWithdrawn;
} VZKernelVtimerMaskReceiptV20;
// Private producer only: the actual factory borrow supplies CPU and identity.
// Reads/writes the proved old 6d8 full64 field, changing only architectural bit0.
// This does not classify a native exit, route an IRQ, or invoke native8/9/10.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUAccessVtimerMaskV20(
 VZKernelCPU *,const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,
 bool write,bool mask,bool *,VZKernelVtimerMaskReceiptV20 *,VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
