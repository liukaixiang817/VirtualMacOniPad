#ifndef VM27_MODERN_GIC_V3_ENGINE_V1_H
#define VM27_MODERN_GIC_V3_ENGINE_V1_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif

// A software GICv3 for the independent, non-nested native CPU profile. These
// are controller state and execution operations, not a foreign HV context.
#define VM27_GIC_CPUS_V1 64u
#define VM27_GIC_INTIDS_V1 1020u
#define VM27_GIC_DIST_BYTES_V1 UINT64_C(0x10000)
#define VM27_GIC_REDIST_BYTES_V1 UINT64_C(0x20000)
#define VM27_GIC_MSI_BYTES_V1 UINT64_C(0x10000)
#define VM27_GIC_PHYSICAL_TIMER_INTID_V1 30u
typedef struct VM27GICV3V1 VM27GICV3V1;
typedef struct {
 uint32_t schemaVersion,maxCPUs,ipaBits,reserved;
 uint64_t vmEpoch,distributorBase,redistributorBase,msiBase;
 uint32_t msiFirst,msiCount;
 bool msiConfigured;
} VM27GICConfigV1;
typedef struct {
 void *context;
 // retainCPU must acquire the actual factory/kernel borrow before publishing
 // this attachment. Its lifetime pins CPU, VM and mapped backing. A numeric
 // identity and a nonnull token alone do not establish that implementation.
 VZKernelStatus (*retainCPU)(void *,const VZKernelRunPendingRequestV14 *,void **);
 VZKernelStatus (*releaseCPU)(void *,void *);
 // Wakes the validated, still retained native slot; never injects an IRQ.
 VZKernelStatus (*wakeCPU)(void *,const VZKernelRunPendingRequestV14 *);
 // Real scheduler arm/cancel/drain hooks. Drain success guarantees no later
 // callback can dereference this CPU or use its native slot.
 VZKernelStatus (*scheduleDeadline)(void *,const VZKernelRunPendingRequestV14 *,bool,uint64_t);
 VZKernelStatus (*drainDeadline)(void *,const VZKernelRunPendingRequestV14 *);
} VM27GICBindingsV1;
typedef struct {bool irq,fiq;uint32_t highestGroup0,highestGroup1;} VM27GICLinesV1;
typedef struct {
 bool handled,write,signExtend,is64Bit,controllerStateCommitted;
 uint32_t registerIndex,bytes;
 uint64_t readValue;
} VM27GICTrapResultV1;

__attribute__((visibility("hidden"))) VZKernelStatus VM27GICCreateV1(
 const VM27GICConfigV1 *,const VM27GICBindingsV1 *,VM27GICV3V1 **);
// Teardown refuses live attachments and in-flight callbacks; errors retain it.
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDestroyV1(VM27GICV3V1 *);
__attribute__((visibility("hidden"))) bool VM27GICOutputRangeDisjointV1(VM27GICV3V1 *,const void *,size_t);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICAttachCPUV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint64_t mpidr);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICSetAffinityV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint64_t mpidr);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICBeginRunV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICEndRunV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICResetV1(VM27GICV3V1 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDetachCPUV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICGetLinesV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,VM27GICLinesV1 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICSetSPIV1(VM27GICV3V1 *,uint32_t,bool);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICSendMSIV1(VM27GICV3V1 *,uint64_t,uint32_t);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDistributorRegV1(
 VM27GICV3V1 *,uint16_t,bool,uint64_t,uint64_t *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICRedistributorRegV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint32_t,bool,uint64_t,uint64_t *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICRedistributorBaseV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint64_t *);
// Guest MMIO uses architectural register write semantics (W1S/W1C included).
// Caller must have validated the actual returned native Run token. Only a
// handled result permits committing the real target register and advancing PC.
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICMMIOV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint64_t ipa,uint32_t bytes,
 bool write,uint64_t value,uint64_t *out);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICICCRegV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint16_t,bool,uint64_t,uint64_t *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICHandleAbortV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint32_t esr,uint64_t ipa,
 uint64_t sourceRegister,VM27GICTrapResultV1 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICHandleSystemV1(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,uint32_t esr,
 uint64_t sourceRegister,VM27GICTrapResultV1 *);
// Directly shaped for the Timer16 binding, with exact registered identity.
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICValidateTimerOwnerV1(
 void *,const VZKernelRunPendingRequestV14 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICRoutePhysicalTimerV1(
 void *,const VZKernelRunPendingRequestV14 *,bool,bool *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICUpdatePhysicalDeadlineV1(
 void *,const VZKernelRunPendingRequestV14 *,bool,uint64_t);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICQuiescePhysicalTimerV1(
 void *,const VZKernelRunPendingRequestV14 *);
#ifdef __cplusplus
}
#endif
#endif
