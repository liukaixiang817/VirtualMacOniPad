#ifndef VM27_VMM_PRIVATE_CPU_SCALAR_V1_H
#define VM27_VMM_PRIVATE_CPU_SCALAR_V1_H
#include "modern_vmm_mandatory_field_v2.h"
#ifdef __cplusplus
extern "C" {
#endif
// The caller supplies the original VMM's no-return error helper. A real
// operation failure never becomes a scalar zero or a successful void return.
typedef void (*VM27VMMScalarFailureV1)(VM27CPUFactoryMachStatusV2);
uint64_t VM27VMMReadCPUScalarV1(hv_vcpu_t actualCPU,uint32_t originalSelector,
 VM27VMMScalarFailureV1 originalFailure);
void VM27VMMWriteCPUScalarV1(hv_vcpu_t actualCPU,uint32_t originalSelector,
 uint64_t originalValue,VM27VMMScalarFailureV1 originalFailure);
// Original job306564 obtains its CPU from argument+18, then CPU+d8, and
// replaces ACTLR bit1 with bit0 of the job's genuine byte flag.
void VM27VMMUpdateACTLRBit1V1(hv_vcpu_t actualCPU,uint32_t originalByteFlag,
 VM27VMMScalarFailureV1 originalFailure);
#ifdef __cplusplus
}
#endif
#endif
