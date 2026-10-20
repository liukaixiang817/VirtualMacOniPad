#include "modern_vmm_private_cpu_scalar_v1.h"
#include <stddef.h>
// These are the actual 53 original VMM fields with already-reviewed SYS
// routes. No unsupported field is represented by a projected context word.
static const hv_sys_reg_t ScalarSYSV1[]={
 0x8010,0xe7ed,0xe7ec,0xe7ef,0xe7ee,0xe7fc,0xe7f9,0xe793,0xe794,
 0xe78f,0xe78e,0xe795,0xe792,0xf78a,0xf7c1,0xf7c2,0xf78b,0xf788,
 0xf799,0xf78e,0xf7a2,0xf7a3,0xf7a4,0xf7a5,0xf7a6,0xf7a7,0xf7a8,
 0xf798,0xf78d,0xf79b,0xf79c,0xf79d,0xf79e,0xf79f,0xf7a0,0xf7a1,
 0xf781,0xf7d4,0xf7d6,0xf7d5,0xf7d7,0xf7d0,0xf7d3,0xf7d1,0xf7d2,
 0xe78c,0xe7e0,0xf795,0xe784,0xf7c3,0xe788,0xe789,0xe78a
};
static bool ScalarIsSYSV1(uint32_t selector) {
 for(size_t i=0;i<sizeof(ScalarSYSV1)/sizeof(*ScalarSYSV1);++i)
  if(selector==(uint32_t)ScalarSYSV1[i])return true;
 return false;
}
static _Noreturn void ScalarFailV1(int32_t status,VM27VMMScalarFailureV1 failure) {
 if(failure)failure(status);
 // The original helper ends in _os_crash/BRK. Returning from an untrusted
 // callback cannot turn a failed owner operation into a successful method.
 __builtin_trap();
}
static int32_t ScalarReadV1(hv_vcpu_t cpu,uint32_t selector,uint64_t *value) {
 if(ScalarIsSYSV1(selector))return (int32_t)hv_vcpu_get_sys_reg(cpu,(hv_sys_reg_t)selector,value);
 if(selector==VM27_VMM_FIELD_DEBUG_CLAIM_V2) {
  uint8_t byte=0;int32_t status=VM27VMMGetMandatoryFieldV2(cpu,selector,&byte);
  if(!status)*value=byte;
  return status;
 }
 if(selector==VM27_VMM_FIELD_ACTLR_V2)return VM27VMMGetMandatoryFieldV2(cpu,selector,value);
 return (int32_t)UINT32_C(0xfae94003);
}
static int32_t ScalarWriteV1(hv_vcpu_t cpu,uint32_t selector,uint64_t value) {
 if(ScalarIsSYSV1(selector))return (int32_t)hv_vcpu_set_sys_reg(cpu,(hv_sys_reg_t)selector,value);
 if(selector==VM27_VMM_FIELD_DEBUG_CLAIM_V2 || selector==VM27_VMM_FIELD_ACTLR_V2)
  return VM27VMMSetMandatoryFieldV2(cpu,selector,value);
 return (int32_t)UINT32_C(0xfae94003);
}
uint64_t VM27VMMReadCPUScalarV1(hv_vcpu_t cpu,uint32_t selector,VM27VMMScalarFailureV1 failure) {
 if(!failure)__builtin_trap();
 uint64_t actual=0;int32_t status=ScalarReadV1(cpu,selector,&actual);
 if(status)ScalarFailV1(status,failure);
 return actual;
}
void VM27VMMWriteCPUScalarV1(hv_vcpu_t cpu,uint32_t selector,uint64_t value,VM27VMMScalarFailureV1 failure) {
 if(!failure)__builtin_trap();
 int32_t status=ScalarWriteV1(cpu,selector,value);
 if(status)ScalarFailV1(status,failure);
}
void VM27VMMUpdateACTLRBit1V1(hv_vcpu_t cpu,uint32_t flag,VM27VMMScalarFailureV1 failure) {
 if(!failure)__builtin_trap();
 uint64_t actual=0;int32_t status=ScalarReadV1(cpu,VM27_VMM_FIELD_ACTLR_V2,&actual);
 if(!status)status=ScalarWriteV1(cpu,VM27_VMM_FIELD_ACTLR_V2,
  (actual&~UINT64_C(2))|((uint64_t)(flag&1)<<1));
 if(status)ScalarFailV1(status,failure);
}
