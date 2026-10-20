#ifndef VM27_HV_PUBLIC_VM_BOOTSTRAP_V9_H
#define VM27_HV_PUBLIC_VM_BOOTSTRAP_V9_H
#include "vm27_hv_public_vm_bootstrap_v8.h"
#include "modern_cpu_native_public_factory_v15.h"
#include "modern_gic_public_abi_v1.h"
#include "modern_gic_deadline_scheduler_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("hidden"))) hv_return_t VM27HVDrainGICBorrowV9(void);
#ifdef __cplusplus
}
#endif
#endif
