#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V16_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V16_H
#include "modern_cpu_native_public_factory_v15.h"
#include "modern_cpu_kernel_lifecycle_v20.h"
#ifdef __cplusplus
extern "C" {
#endif
hv_return_t hv_vcpu_get_vtimer_mask(hv_vcpu_t,bool *);
hv_return_t hv_vcpu_set_vtimer_mask(hv_vcpu_t,bool);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessVtimerMaskV16(
 VM27CPUFactoryBorrowV2 *,bool write,bool mask,bool *,VZKernelVtimerMaskReceiptV20 *);
#ifdef __cplusplus
}
#endif
#endif
