#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V12_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V12_H
#include "modern_cpu_hv_public_abi_v3.h"
#include "modern_cpu_native_public_factory_v11.h"
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
hv_return_t hv_vcpu_get_pending_interrupt(hv_vcpu_t,hv_interrupt_type_t,bool *);
hv_return_t hv_vcpu_set_pending_interrupt(hv_vcpu_t,hv_interrupt_type_t,bool);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowPendingInterruptV12(
 VM27CPUFactoryBorrowV2 *,VZKernelPendingActionV14,hv_interrupt_type_t,bool,bool *,
 VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
