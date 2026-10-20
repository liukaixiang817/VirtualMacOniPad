#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V12_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V12_H
#include "modern_cpu_kernel_lifecycle_v11.h"
#ifdef __cplusplus
extern "C" {
#endif
// This packet describes the retained CPU; it never accepts a native address.
// Only the validated old native profile is implemented. Modern object fields
// and its clock compensation path are not represented by this packet.
typedef struct {
 uint32_t schemaVersion, validatedKernelProfile, nativeHVISA, reserved;
 uint64_t expectedVMEpoch, expectedPublicIdentity, expectedOwnerThread;
 uint64_t expectedCPUGeneration, expectedReturnedSlotWord, vtimerOffset;
} VZKernelVtimerRequestV12;
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUSetVtimerOffsetV12(VZKernelCPU *,
 const VZKernelVtimerRequestV12 *,const VZKernelInitWriter *,
 VZKernelInitReceipt *,VZKernelLifecycleResult *);
// Include actual native contexts as well as own retained allocations. This
// guard performs no memory callback or native operation and publishes no data.
__attribute__((visibility("hidden")))
bool VZKernelCPUOutputRangeDisjointV12(const void *,size_t);
#ifdef __cplusplus
}
#endif
#endif
