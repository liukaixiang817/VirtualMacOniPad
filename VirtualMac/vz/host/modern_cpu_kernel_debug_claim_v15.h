#ifndef VM27_CPU_KERNEL_DEBUG_CLAIM_V15_H
#define VM27_CPU_KERNEL_DEBUG_CLAIM_V15_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
// Private physical state port. This is not a public DBGCLAIM MSR emulation:
// caller supplies an already computed raw 8-bit claim state for frame restore.
typedef enum {VZ_KERNEL_DEBUG_CLAIM_READ_V15=1,VZ_KERNEL_DEBUG_CLAIM_WRITE_V15=2}
 VZKernelDebugClaimActionV15;
typedef struct {
 VZKernelRunPendingRequestV14 identity;
 VZKernelDebugClaimActionV15 action;
 uint32_t reserved;
 uint64_t value;
} VZKernelDebugClaimRequestV15;
typedef struct {
 VZKernelStatus status;
 uint32_t attemptedReads,attemptedWrites,completedWrites,failedNativeOffset;
 bool nativeOp8Required,nativeOp8Invoked,mutationPoisoned,cpuCleanupRequired;
 bool actualClaimStateRead,actualClaimStateWritten;
 bool completeModernSYSContract,runAllowed;
} VZKernelDebugClaimReceiptV15;
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUAccessPhysicalDebugClaimV15(VZKernelCPU *,
 const VZKernelDebugClaimRequestV15 *,const VZKernelInitWriter *,uint64_t *,
 VZKernelDebugClaimReceiptV15 *,VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
