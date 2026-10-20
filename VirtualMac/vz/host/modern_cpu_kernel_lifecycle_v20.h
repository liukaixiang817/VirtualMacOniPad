#ifndef VM27_MODERN_CPU_KERNEL_LIFECYCLE_V20_H
#define VM27_MODERN_CPU_KERNEL_LIFECYCLE_V20_H
#include "modern_cpu_kernel_lifecycle_v18.h"
#include "modern_cpu_kernel_vtimer_mask_v20.h"
#include "modern_cpu_kernel_physical_timer_v19.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
 VZKernelRunPendingReceiptV14 pending;
 VZCPUDecodedPublicExceptionV1 publicExit;
 uint64_t nativeCNTVControl;
 uint64_t entryActiveBanks,returnReadyBanks;
 uint64_t nativeHVCX0;
 uint32_t nativeHVCCPSR;
 uint32_t autoMaskWritesAttempted,autoMaskWritesCompleted;
 bool publicExitProduced,initialVtimerMaskKnown,initialVtimerMask;
 bool nativeCNTVControlRead,autoMaskCommitted;
 bool entryActiveBanksRead,returnReadyBanksRead,nativeCNTVControlFresh;
 bool runStateMutationAttempted;
 bool ordinaryHVCProduced,nativeHVCX0Read,nativeHVCCPSRRead;
} VZKernelRunPublicReceiptV20;
// Keeps the inherited V18 private ownership ABI, with actual Timer19 owners.
// Public exit publication consumes this exact producer receipt, never a caller
// manufactured numeric reason or a fabricated exception/reduction flag.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPURunGICPublicV20(
 VZKernelCPU *,const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,VZKernelRunPublicReceiptV20 *);
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPURunGICPublicBoundedV20(
 VZKernelCPU *,const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,uint64_t,VZKernelRunPublicReceiptV20 *);
// Private factory producer uses its actual retained lower borrow and q.
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelCPUProducerPoisonV20(
 VZKernelCPU *,const VZKernelRunPendingRequestV14 *);
#ifdef __cplusplus
}
#endif
#endif
