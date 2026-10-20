#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V14_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V14_H
#include "modern_cpu_kernel_lifecycle_v13.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
 uint32_t schemaVersion,validatedKernelProfile,nativeHVISA,reserved;
 uint64_t expectedVMEpoch,expectedPublicIdentity,expectedOwnerThread;
 uint64_t expectedCPUGeneration,expectedReturnedSlotWord;
} VZKernelRunPendingRequestV14;
typedef struct {
 VZKernelRunStepReceiptV7 step;
 VZKernelInitReceipt entryControl,returnControl;
 VZKernelStatus runStatusBeforeCleanup,cleanupStatus;
 uint64_t entryPendingMask;
 bool entryControlComplete,pendingCleared,returnControlComplete;
 bool mutationPoisoned,identityWithdrawn;
} VZKernelRunPendingReceiptV14;
typedef enum {VZ_KERNEL_PENDING_READ_V14=1,VZ_KERNEL_PENDING_WRITE_V14=2}
 VZKernelPendingActionV14;
// Real own pending state, with the same published identity/owner/version
// contract as Run. No Apple USER object or native register is a pending store.
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUAccessPendingInterruptV14(VZKernelCPU *,
 const VZKernelRunPendingRequestV14 *,VZKernelPendingActionV14,
 uint32_t,bool,bool *);
// One actual operation9 only. Pending !=0 adds the exact original old C0
// slices before/after the call, including cleanup on nonzero native status.
// Initial cancellation, automatic retry, full timer/GIC/VIEW and complete
// public Run equivalence remain unimplemented.
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPURunOwnedPendingStepV14(VZKernelCPU *,
 const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,
 VZKernelRunPendingReceiptV14 *);
#ifdef __cplusplus
}
#endif
#endif
