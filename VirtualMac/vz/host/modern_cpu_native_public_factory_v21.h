#ifndef VM27_CPU_NATIVE_PUBLIC_FACTORY_V21_H
#define VM27_CPU_NATIVE_PUBLIC_FACTORY_V21_H
#include "modern_cpu_native_public_factory_v20.h"
#include "modern_cpu_kernel_lifecycle_v23.h"
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("hidden")))
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessDTRV21(VM27CPUFactoryBorrowV2 *,
 VZKernelDTRActionV23,uint64_t,uint64_t *,VZKernelDTRReceiptV23 *,VM27CPUFactoryDiagnosticV2 *);
/* Private own architectural bank, never an SDK host SYS implementation. */
hv_return_t VM27CPUFactoryAccessDTRV21(hv_vcpu_t,VZKernelDTRActionV23,uint64_t,uint64_t *);
#ifdef __cplusplus
}
#endif
#endif
