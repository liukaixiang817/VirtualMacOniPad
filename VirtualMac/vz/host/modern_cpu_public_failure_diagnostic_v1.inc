#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
static _Atomic unsigned VM27PublicFailureLogCountV1;
static void VM27LogPublicFailureV1(const char *operation,uint32_t selector,
    uint64_t requestedValue,hv_return_t result) {
 if(!result)return;
 int savedErrno=errno;
 unsigned sequence=atomic_load_explicit(&VM27PublicFailureLogCountV1,memory_order_relaxed);
 while(sequence<8 && !atomic_compare_exchange_weak_explicit(&VM27PublicFailureLogCountV1,
  &sequence,sequence+1,memory_order_relaxed,memory_order_relaxed)){}
 if(sequence<8)dprintf(2,"[Independent27HV] failed stage=public-api sequence=%u operation=%s selector=0x%08x requestedValue=0x%016llx status=0x%08x\n",
  sequence+1,operation,selector,(unsigned long long)requestedValue,(unsigned)result);
 errno=savedErrno;
}
hv_return_t _hv_vcpu_get_control_field(hv_vcpu_t cpu,uint32_t selector,uint64_t *out) {
 hv_return_t result=VM27InheritedGetControlFailureV1(cpu,selector,out);
 VM27LogPublicFailureV1("get-control",selector,0,result);return result;
}
hv_return_t _hv_vcpu_set_control_field(hv_vcpu_t cpu,uint32_t selector,uint64_t value) {
 hv_return_t result=VM27InheritedSetControlFailureV1(cpu,selector,value);
 VM27LogPublicFailureV1("set-control",selector,value,result);return result;
}
hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t cpu,hv_sys_reg_t selector,uint64_t *out) {
 hv_return_t result=VM27InheritedGetSYSFailureV1(cpu,selector,out);
 VM27LogPublicFailureV1("get-sys",(uint32_t)selector,0,result);return result;
}
hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t cpu,hv_sys_reg_t selector,uint64_t value) {
 hv_return_t result=VM27InheritedSetSYSFailureV1(cpu,selector,value);
 VM27LogPublicFailureV1("set-sys",(uint32_t)selector,value,result);return result;
}
