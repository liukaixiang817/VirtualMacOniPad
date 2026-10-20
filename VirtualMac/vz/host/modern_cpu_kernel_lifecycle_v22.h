#ifndef VM27_CPU_KERNEL_LIFECYCLE_V22_H
#define VM27_CPU_KERNEL_LIFECYCLE_V22_H
#include "modern_cpu_kernel_lifecycle_v21.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {VZ_KERNEL_CONTROL_READ_V22=1,VZ_KERNEL_CONTROL_WRITE_V22=2} VZKernelControlActionV22;
typedef struct {
 VZKernelRunPendingRequestV14 identity;
 VZKernelControlActionV22 action;
 uint32_t identifier;
 uint64_t value;
} VZKernelControlRequestV22;
/* Closed actual original27 callers: CONTROL2,7,8. Each maps to the genuine
 * old context688,6e0,6e8; this is never a modern context view. */
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUAccessControlV22(VZKernelCPU *,
 const VZKernelControlRequestV22 *,const VZKernelInitWriter *,uint64_t *,
 VZKernelInitReceipt *,VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
