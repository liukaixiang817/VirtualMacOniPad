#ifndef VM27_VMM_DTR_V1_H
#define VM27_VMM_DTR_V1_H
#include "modern_cpu_native_public_factory_v21.h"
#include "modern_vmm_private_cpu_scalar_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
uint64_t VM27VMMReadDTRV1(hv_vcpu_t,uint32_t,VM27VMMScalarFailureV1);
void VM27VMMWriteDTRV1(hv_vcpu_t,uint32_t,uint64_t,VM27VMMScalarFailureV1);
#ifdef __cplusplus
}
#endif
#endif
