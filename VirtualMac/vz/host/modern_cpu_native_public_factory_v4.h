#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V4_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V4_H
#include "modern_cpu_native_public_factory_v3.h"
#include "modern_cpu_kernel_lifecycle_v8.h"
#ifdef __cplusplus
extern "C" {
#endif
// Application-owned SYS entry. Uses the immutable writer bound at VMCreate;
// output storage must be owned/disjoint. No actual Apple hv_* export is made.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessSystemV4(
    VM27CPUFactoryBorrowV2 *, VZKernelSysAction, uint32_t identifier,
    uint64_t writeValue, uint64_t *readOutput, VZKernelSysReceipt *,
    VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
