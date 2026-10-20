#ifndef VM27_CPU_KERNEL_ACTLR_V16_H
#define VM27_CPU_KERNEL_ACTLR_V16_H
#include "modern_cpu_kernel_lifecycle_v15.h"
#ifdef __cplusplus
extern "C" {
#endif
// Private full64 physical ACTLR state port for modern mandatory frame5f8.
// Public ACTLR EnTSO feature filtering is a separate operation. The raw frame
// preserves all original bits and uses true current-kernel native group1.
typedef enum {VZ_KERNEL_ACTLR_READ_V16=1,VZ_KERNEL_ACTLR_WRITE_V16=2}
 VZKernelACTLRActionV16;
typedef struct {
 VZKernelRunPendingRequestV14 identity;
 VZKernelACTLRActionV16 action;
 uint32_t reserved;
 uint64_t value;
} VZKernelACTLRRequestV16;
typedef struct {
 VZKernelStatus status;
 uint32_t attemptedReads,attemptedWrites,completedWrites,failedNativeOffset;
 bool nativeOp8Required,nativeOp8Invoked,mutationPoisoned,cpuCleanupRequired;
 bool actualACTLRStateRead,actualACTLRStateWritten;
 bool completeModernSYSContract,runAllowed;
} VZKernelACTLRReceiptV16;
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUAccessPhysicalACTLRV16(VZKernelCPU *,
 const VZKernelACTLRRequestV16 *,const VZKernelInitWriter *,uint64_t *,
 VZKernelACTLRReceiptV16 *,VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
