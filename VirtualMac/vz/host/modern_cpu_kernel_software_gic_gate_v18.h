#ifndef VZ_MODERN_CPU_KERNEL_SOFTWARE_GIC_GATE_V18_H
#define VZ_MODERN_CPU_KERNEL_SOFTWARE_GIC_GATE_V18_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
 VZKernelStatus status;
 uint32_t attemptedReads,failedNativeOffset;
 uint64_t requestedICHControl,effectiveICHControl;
 bool actualFieldsRead,commonAndBothGroupTrapsEnabled,nativeGICDisabled;
 // A native control check is not an execution oracle for ICC_SRE/CNTP.
 bool actualSRETrapProved,actualPhysicalTimerTrapProved,fullRunAllowed;
} VZKernelSoftwareGICTrapReceiptV18;
// Caller retains this real CPU handle for the entire call. The strict V14
// registry identity and full native version are rechecked on every boundary.
// Read-only: no native operation8/9, no shadow fields, no native setter.
__attribute__((visibility("hidden"))) VZKernelStatus
VZKernelCPUCheckSoftwareGICTrapV18(VZKernelCPU *,
 const VZKernelRunPendingRequestV14 *,VZKernelSoftwareGICTrapReceiptV18 *,
 VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
