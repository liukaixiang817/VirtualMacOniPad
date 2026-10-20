#ifndef VM27_VMM_MANDATORY_FIELD_V2_H
#define VM27_VMM_MANDATORY_FIELD_V2_H
#include "modern_cpu_native_public_factory_v15.h"
#ifdef __cplusplus
extern "C" {
#endif
// Private caller ABI for the two genuine mandatory modern frame fields.
// These selectors are original physical field offsets, not public SYS IDs.
enum {VM27_VMM_FIELD_DEBUG_CLAIM_V2=0x6a0, VM27_VMM_FIELD_ACTLR_V2=0x410};
// identity is the original hv_vcpu_t loaded by VMM. Claim output has width
// one byte; ACTLR output has width eight bytes. Failure does not publish a read.
VM27CPUFactoryMachStatusV2 VM27VMMGetMandatoryFieldV2(hv_vcpu_t identity,
 uint32_t field,void *actualFrameField);
VM27CPUFactoryMachStatusV2 VM27VMMSetMandatoryFieldV2(hv_vcpu_t identity,
 uint32_t field,uint64_t actualFrameValue);
// A failed release retains the exact borrow on this owner thread. Drain only
// retries releasing that borrow; it never repeats the physical operation.
VM27CPUFactoryMachStatusV2 VM27VMMDrainMandatoryFieldBorrowV2(void);
#ifdef __cplusplus
}
#endif
#endif
