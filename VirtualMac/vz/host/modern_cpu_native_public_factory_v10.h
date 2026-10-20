#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V10_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V10_H
#include "modern_cpu_native_public_factory_v9.h"
#include "modern_cpu_kernel_lifecycle_v12.h"
#ifdef __cplusplus
extern "C" {
#endif
// Actual Mac27 SDK signature; iOS uses the existing exact public ABI typedefs.
hv_return_t hv_vcpu_set_vtimer_offset(hv_vcpu_t,uint64_t);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowSetVtimerOffsetV10(
 VM27CPUFactoryBorrowV2 *,uint64_t,VZKernelInitReceipt *,VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
