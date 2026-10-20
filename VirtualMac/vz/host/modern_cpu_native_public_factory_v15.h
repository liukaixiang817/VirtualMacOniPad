#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V15_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V15_H
#include "modern_cpu_native_public_factory_v14.h"
#include "modern_cpu_kernel_lifecycle_v18.h"
#ifdef __cplusplus
extern "C" {
#endif
// Exact SDK signature, also visible with the iOS SDK's Hypervisor fallback.
hv_return_t hv_vcpus_exit(hv_vcpu_t *,uint32_t);
typedef struct {
 uint32_t schemaVersion,nativeHVISA,validatedKernelProfile,liveCPUCount;
 uint64_t vmEpoch;
 bool live,gicInstalled;
} VM27CPUFactoryVMGICDescriptionV15;
typedef struct {
 void *context;
 VZKernelStatus (*scheduleDeadline)(void *,const VZKernelRunPendingRequestV14 *,bool,uint64_t);
 VZKernelStatus (*drainDeadline)(void *,const VZKernelRunPendingRequestV14 *);
} VM27CPUFactoryGICSchedulerV15;
typedef enum {
 VM27_FACTORY_GIC_DISTRIBUTOR_READ_V15=1,
 VM27_FACTORY_GIC_DISTRIBUTOR_WRITE_V15=2,
 VM27_FACTORY_GIC_SPI_LEVEL_V15=3,
 VM27_FACTORY_GIC_MSI_V15=4,VM27_FACTORY_GIC_RESET_V15=5
} VM27CPUFactoryVMGICActionV15;
typedef enum {
 VM27_FACTORY_GIC_ICC_READ_V15=1,VM27_FACTORY_GIC_ICC_WRITE_V15=2,
 VM27_FACTORY_GIC_REDISTRIBUTOR_READ_V15=3,VM27_FACTORY_GIC_REDISTRIBUTOR_WRITE_V15=4,
 VM27_FACTORY_GIC_REDISTRIBUTOR_BASE_V15=5,
 VM27_FACTORY_GIC_PHYSICAL_TIMER_READ_V15=6,VM27_FACTORY_GIC_PHYSICAL_TIMER_WRITE_V15=7
} VM27CPUFactoryCPUGICActionV15;
// Every VM operation compares the opaque pointer against the actual registry
// before dereference. Installation is owner-only, on a live VM before any CPU.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICDescribeV15(
 VM27CPUFactoryVMV2 *,VM27CPUFactoryVMGICDescriptionV15 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICInstallV15(
 VM27CPUFactoryVMV2 *,const VM27GICConfigV1 *,const VM27CPUFactoryGICSchedulerV15 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICTeardownV15(VM27CPUFactoryVMV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICAccessV15(
 VM27CPUFactoryVMV2 *,VM27CPUFactoryVMGICActionV15,uint64_t selector,uint64_t value,uint64_t *);
// Uses the real retained factory borrow to construct the CPU identity. A caller
// cannot provide a numeric q or select an unrelated CPU/native slot.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowGICAccessV15(
 VM27CPUFactoryBorrowV2 *,VM27CPUFactoryCPUGICActionV15,uint32_t selector,uint64_t value,uint64_t *);
// Async scheduler wake authenticates q against an actual retained attachment.
// It invokes only native10; it does not change pending IRQ/FIQ or inject state.
__attribute__((visibility("hidden"))) VZKernelStatus VM27CPUFactoryGICSignalWakeV15(
 VM27CPUFactoryVMV2 *,const VZKernelRunPendingRequestV14 *);
// A Root ACK producer may fail after the actual retained attachment committed.
// Numeric expectations only narrow the real registered owner; they grant no lease.
__attribute__((visibility("hidden"))) VM27CPUFactoryMachStatusV2 VM27CPUFactoryPoisonGICCPUV15(
 VM27CPUFactoryIDV2,uint64_t expectedVMEpoch,uint64_t expectedCPUGeneration);
// Root's private range guard also excludes controller/attachment allocations.
__attribute__((visibility("hidden"))) bool VM27CPUFactoryGICOutputRangeDisjointV15(const void *,size_t);
#ifdef __cplusplus
}
#endif
#endif
