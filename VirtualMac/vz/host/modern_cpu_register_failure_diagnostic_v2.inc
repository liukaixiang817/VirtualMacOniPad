#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>

/* Include after the inherited GPR/SIMD/AMX names have been undefined.
 * The wrappers observe the actual complete public call, including admission
 * and release failures. Successful calls consume neither failure budget. */
static _Atomic unsigned VM27RegisterFailureLogCountV2;
static _Atomic unsigned VM27AMXAvailabilityFailureLogCountV2;

static void VM27LogRegisterFailureV2(const char *operation,hv_vcpu_t cpu,
    uint32_t reg,hv_return_t result) {
 if(!result)return;
 int savedErrno=errno;
 unsigned sequence=atomic_load_explicit(&VM27RegisterFailureLogCountV2,memory_order_relaxed);
 while(sequence<8 && !atomic_compare_exchange_weak_explicit(&VM27RegisterFailureLogCountV2,
  &sequence,sequence+1,memory_order_relaxed,memory_order_relaxed)){}
 if(sequence<8)dprintf(2,"[Independent27HV] failed stage=register-api sequence=%u operation=%s cpu=%llu reg=%u status=0x%08x\n",
  sequence+1,operation,(unsigned long long)cpu,reg,(unsigned)result);
 errno=savedErrno;
}

hv_return_t hv_vcpu_get_reg(hv_vcpu_t cpu,hv_reg_t reg,uint64_t *out) {
 hv_return_t result=VM27InheritedGetRegisterFailureV2(cpu,reg,out);
 VM27LogRegisterFailureV2("get-reg",cpu,(uint32_t)reg,result);return result;
}
hv_return_t hv_vcpu_set_reg(hv_vcpu_t cpu,hv_reg_t reg,uint64_t value) {
 hv_return_t result=VM27InheritedSetRegisterFailureV2(cpu,reg,value);
 VM27LogRegisterFailureV2("set-reg",cpu,(uint32_t)reg,result);return result;
}
hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t cpu,hv_simd_fp_reg_t reg,
    hv_simd_fp_uchar16_t *out) {
 hv_return_t result=VM27InheritedGetSIMDRegisterFailureV2(cpu,reg,out);
 VM27LogRegisterFailureV2("get-simd",cpu,(uint32_t)reg,result);return result;
}
hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t cpu,hv_simd_fp_reg_t reg,
    hv_simd_fp_uchar16_t value) {
 hv_return_t result=VM27InheritedSetSIMDRegisterFailureV2(cpu,reg,value);
 VM27LogRegisterFailureV2("set-simd",cpu,(uint32_t)reg,result);return result;
}

VM27CPUFactoryMachStatusV2 VM27VMMGetAMXAvailabilityV1(hv_vcpu_t cpu,uint32_t *out) {
 VM27CPUFactoryMachStatusV2 result=VM27InheritedGetAMXAvailabilityFailureV2(cpu,out);
 if(result) {
  int savedErrno=errno;
  unsigned sequence=atomic_load_explicit(&VM27AMXAvailabilityFailureLogCountV2,memory_order_relaxed);
  while(sequence<8 && !atomic_compare_exchange_weak_explicit(&VM27AMXAvailabilityFailureLogCountV2,
   &sequence,sequence+1,memory_order_relaxed,memory_order_relaxed)){}
  if(sequence<8)dprintf(2,"[Independent27HV] failed stage=amx-availability sequence=%u operation=get-amx-availability cpu=%llu status=0x%08x\n",
   sequence+1,(unsigned long long)cpu,(unsigned)result);
  errno=savedErrno;
 }
 return result;
}
