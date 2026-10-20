#ifndef VM27_HV_PUBLIC_VM_BOOTSTRAP_V5_H
#define VM27_HV_PUBLIC_VM_BOOTSTRAP_V5_H
#include "modern_cpu_native_public_factory_v11.h"
#include "vm27_hv_public_vm_bootstrap_v4.h"
#ifdef __cplusplus
extern "C" {
#endif
// Exact genuine framework upper-bound ABI: uint32 output64 and signed32
// success. This is not a measurement of iPad native CPU capacity.
hv_return_t hv_vm_get_max_vcpu_count(uint32_t *);
#ifdef __cplusplus
}
#endif
#endif
