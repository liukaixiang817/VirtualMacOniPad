#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V3_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V3_H
#include "modern_cpu_native_public_factory_v2.h"
#include "modern_cpu_kernel_lifecycle_v7.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    VM27CPUFactoryDiagnosticV2 factory;
    VZKernelRunStepReceiptV7 step;
    bool exitStoragePublished;
} VM27CPUFactoryRunDiagnosticV3;
// Link alternative factoryV3 + lifecycleV7 + OSv4. All V2 own signatures stay
// available. This explicit one-step API adds the genuine native9 expression;
// it is not an Apple public-run interpose or completed VMM worker integration.
// Factory/borrow/CPU guards retain the same exit allocation through reduction.
// Before each attempt, prior exit validity is revoked. Refusals preserve all
// 32 storage bytes. Successful exception publication copies the typed32B value
// into that original allocation; zeroed creation storage is never valid.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRunOwnedStepV3(
    VM27CPUFactoryBorrowV2 *, VM27CPUFactoryRunDiagnosticV3 *);
#ifdef __cplusplus
}
#endif
#endif
