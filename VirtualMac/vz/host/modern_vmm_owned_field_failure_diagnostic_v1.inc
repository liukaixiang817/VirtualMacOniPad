#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>

/* The versioned mandatory-field implementation supplies the two inherited
 * functions below. Observe its whole result, including early admission and
 * retained-lease failures, without reading the caller's output or field value. */
static _Atomic unsigned VM27OwnedFieldFailureLogCountV1;
static void VM27LogOwnedFieldFailureV1(const char *operation,hv_vcpu_t cpu,
    uint32_t field,VM27CPUFactoryMachStatusV2 result) {
 if(!result)return;
 int savedErrno=errno;
 unsigned sequence=atomic_load_explicit(&VM27OwnedFieldFailureLogCountV1,memory_order_relaxed);
 while(sequence<8 && !atomic_compare_exchange_weak_explicit(&VM27OwnedFieldFailureLogCountV1,
  &sequence,sequence+1,memory_order_relaxed,memory_order_relaxed)){}
 if(sequence<8)dprintf(2,"[Independent27HV] failed stage=owned-mandatory-field sequence=%u operation=%s cpu=%llu field=0x%08x status=0x%08x\n",
  sequence+1,operation,(unsigned long long)cpu,field,(unsigned)result);
 errno=savedErrno;
}
VM27CPUFactoryMachStatusV2 VM27VMMGetMandatoryFieldV2(hv_vcpu_t cpu,
    uint32_t field,void *out) {
 VM27CPUFactoryMachStatusV2 result=VM27VMMInheritedGetMandatoryFailureV1(cpu,field,out);
 VM27LogOwnedFieldFailureV1("get-mandatory",cpu,field,result);return result;
}
VM27CPUFactoryMachStatusV2 VM27VMMSetMandatoryFieldV2(hv_vcpu_t cpu,
    uint32_t field,uint64_t value) {
 VM27CPUFactoryMachStatusV2 result=VM27VMMInheritedSetMandatoryFailureV1(cpu,field,value);
 VM27LogOwnedFieldFailureV1("set-mandatory",cpu,field,result);return result;
}
