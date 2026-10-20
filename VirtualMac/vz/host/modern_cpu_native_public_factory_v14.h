#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V14_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V14_H
#include "modern_cpu_native_public_factory_v13.h"
#include "modern_cpu_kernel_lifecycle_v16.h"
#ifdef __cplusplus
extern "C" {
#endif
// Retained private full64 ACTLR frame-state operation. Public EnTSO feature
// filtering remains separate and cannot discard raw mandatory frame bits.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessPhysicalACTLRV14(
 VM27CPUFactoryBorrowV2 *,VZKernelACTLRActionV16,uint64_t,uint64_t *,
 VZKernelACTLRReceiptV16 *,VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
