#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V13_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V13_H
#include "modern_cpu_kernel_lifecycle_v12.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum { VZ_KERNEL_DEBUG_EXCEPTIONS_V13=1,
 VZ_KERNEL_DEBUG_REGISTER_ACCESSES_V13=2 } VZKernelDebugKindV13;
typedef struct {
 uint32_t schemaVersion,validatedKernelProfile,nativeHVISA,reserved;
 uint64_t expectedVMEpoch,expectedPublicIdentity,expectedOwnerThread;
 uint64_t expectedCPUGeneration,expectedReturnedSlotWord;
 VZKernelDebugKindV13 kind;
 bool value;
 uint8_t reservedBytes[3];
} VZKernelDebugRequestV13;
// Modern full64 bit clear/set semantics, translated to the real compatible
// old native CONTROL2 field and its original synchronization sequence.
__attribute__((visibility("hidden")))
VZKernelStatus VZKernelCPUSetDebugTrapV13(VZKernelCPU *,
 const VZKernelDebugRequestV13 *,const VZKernelInitWriter *,
 VZKernelInitReceipt *,VZKernelLifecycleResult *);
#ifdef __cplusplus
}
#endif
#endif
