#ifndef VM27_CPU_NATIVE_PUBLIC_FACTORY_V18_H
#define VM27_CPU_NATIVE_PUBLIC_FACTORY_V18_H
#include "modern_cpu_native_public_factory_v17.h"
#include "modern_cpu_kernel_lifecycle_v22.h"
#ifdef __cplusplus
extern "C" {
#endif
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessControlV18(
 VM27CPUFactoryBorrowV2 *,VZKernelControlActionV22,uint32_t,uint64_t,uint64_t *,
 VZKernelInitReceipt *,VM27CPUFactoryDiagnosticV2 *);
/* Actual private exported Mach-O symbols have two leading underscores. */
hv_return_t _hv_vcpu_get_control_field(hv_vcpu_t,uint32_t,uint64_t *);
hv_return_t _hv_vcpu_set_control_field(hv_vcpu_t,uint32_t,uint64_t);
#ifdef __cplusplus
}
#endif
#endif
