#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V7_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V7_H
#include "modern_cpu_kernel_lifecycle_v6.h"
#include "modern_cpu_native_exit_reducer_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    VZKernelStatus status;
    VZKernelLifecycleResult lifecycle;
    uint64_t vmEpoch, cpuGeneration, ownerThread, runToken;
    VZCPUNativeExitValuesV1 nativeValues;
    VZCPUExitReductionV1 reduction;
    bool postReturnIdentityValidated, reductionValid, publicExceptionProduced;
    bool fullPublicRunEquivalent, architecturalResetComplete, memoryBindingComplete;
} VZKernelRunStepReceiptV7;
// Application-owned explicit single native9 primitive, not hv_vcpu_run.
// Same live owner/TLS/epoch/gen exclusion covers call and every post-return
// read, reduction and output. No retry, initial cancel, C0 submission, native
// pending write, or USER/VIEW is performed. Nonzero pending and unsupported
// FGT/TLBI execution policy are refused before invoking native9.
// raw2/11 -> internalRetry/BUSY, never a public exit. Only the original closed
// exception lane is produced. Raw0 and emulation classes remain UNSUPPORTED.
// This source does not establish guest reset, mapped backing or full Run.
// It may block in native9: any later execution needs separate external bounds
// and recovery review. Mac fixtures inject mocks; iOS compilation is inert.
VZKernelStatus VZKernelCPURunOwnedStepV7(VZKernelCPU *, VZKernelRunStepReceiptV7 *);
#ifdef __cplusplus
}
#endif
#endif
