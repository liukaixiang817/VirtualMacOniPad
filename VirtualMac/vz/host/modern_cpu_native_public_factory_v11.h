#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V11_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V11_H
#include "modern_cpu_native_public_factory_v10.h"
#include "modern_cpu_kernel_lifecycle_v13.h"
#ifdef __cplusplus
extern "C" {
#endif
hv_return_t hv_vcpu_set_trap_debug_exceptions(hv_vcpu_t,bool);
hv_return_t hv_vcpu_set_trap_debug_reg_accesses(hv_vcpu_t,bool);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowSetDebugTrapV11(
 VM27CPUFactoryBorrowV2 *,VZKernelDebugKindV13,bool,
 VZKernelInitReceipt *,VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
