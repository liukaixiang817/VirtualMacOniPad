#ifndef VM27_CPU_KERNEL_LIFECYCLE_V23_H
#define VM27_CPU_KERNEL_LIFECYCLE_V23_H
#include "modern_cpu_kernel_lifecycle_v22.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
 VZ_KERNEL_DTR_READ_PAIR_V23=1,VZ_KERNEL_DTR_READ_RX_V23=2,
 VZ_KERNEL_DTR_WRITE_PAIR_V23=3,VZ_KERNEL_DTR_WRITE_TX_V23=4
} VZKernelDTRActionV23;
typedef struct {
 VZKernelRunPendingRequestV14 identity;
 VZKernelDTRActionV23 action;
 uint32_t reserved;
 uint64_t value;
} VZKernelDTRRequestV23;
typedef struct {
 VZKernelStatus status;
 VZKernelDTRActionV23 action;
 uint64_t rxValue,txValue,firstTXValue,finalTXValue;
 uint32_t actualSoftwareWrites;
 bool ownResetZeroPolicy,mutationPoisoned;
} VZKernelDTRReceiptV23;
/* Own per-CPU debug-transfer state. No native field is projected into a
 * modern context; there is no hardware debugger/host RX producer claim. */
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUAccessDTRV23(VZKernelCPU *,const VZKernelDTRRequestV23 *,
 uint64_t *,VZKernelDTRReceiptV23 *,VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
