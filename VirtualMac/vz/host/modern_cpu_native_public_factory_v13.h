#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V13_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V13_H
#include "modern_cpu_native_public_factory_v12.h"
#include "modern_cpu_kernel_lifecycle_v15.h"
#ifdef __cplusplus
extern "C" {
#endif
// Retained private frame-state operation. Public SYS register set/clear
// semantics stay separate; WRITE accepts only a computed 8-bit raw state.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13(
 VM27CPUFactoryBorrowV2 *,VZKernelDebugClaimActionV15,uint64_t,uint64_t *,
 VZKernelDebugClaimReceiptV15 *,VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
