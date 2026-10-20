#include "modern_vmm_dtr_v1.h"
static _Noreturn void DTRFailureV1(hv_return_t status,VM27VMMScalarFailureV1 failure) {
 if(failure)failure((int32_t)status);__builtin_trap();
}
uint64_t VM27VMMReadDTRV1(hv_vcpu_t cpu,uint32_t selector,VM27VMMScalarFailureV1 failure) {
 if(!failure)__builtin_trap();uint64_t actual=0;
 VZKernelDTRActionV23 action=selector==0x9820?VZ_KERNEL_DTR_READ_PAIR_V23:
  selector==0x9828?VZ_KERNEL_DTR_READ_RX_V23:(VZKernelDTRActionV23)0;
 hv_return_t status=VM27CPUFactoryAccessDTRV21(cpu,action,0,&actual);
 if(status)DTRFailureV1(status,failure);return actual;
}
void VM27VMMWriteDTRV1(hv_vcpu_t cpu,uint32_t selector,uint64_t value,VM27VMMScalarFailureV1 failure) {
 if(!failure)__builtin_trap();
 VZKernelDTRActionV23 action=selector==0x9820?VZ_KERNEL_DTR_WRITE_PAIR_V23:
  selector==0x9828?VZ_KERNEL_DTR_WRITE_TX_V23:(VZKernelDTRActionV23)0;
 hv_return_t status=VM27CPUFactoryAccessDTRV21(cpu,action,value,NULL);
 if(status)DTRFailureV1(status,failure);
}
