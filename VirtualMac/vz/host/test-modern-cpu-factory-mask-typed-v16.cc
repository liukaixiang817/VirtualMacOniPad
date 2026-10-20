#include "modern_cpu_native_public_factory_v16.h"
#include <type_traits>
static_assert(std::is_same<decltype(&hv_vcpu_get_vtimer_mask),hv_return_t (*)(hv_vcpu_t,bool *)>::value);
static_assert(std::is_same<decltype(&hv_vcpu_set_vtimer_mask),hv_return_t (*)(hv_vcpu_t,bool)>::value);
extern "C" hv_return_t VM27TypedPublicMaskV16(hv_vcpu_t cpu,bool *mask,bool value) {
 hv_return_t s=hv_vcpu_get_vtimer_mask(cpu,mask);
 if(!s)s=hv_vcpu_set_vtimer_mask(cpu,value);
 return s?s:hv_vcpu_run(cpu);
}
extern "C" VZKernelStatus VM27TypedPrivateRunV20(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,VZKernelRunPublicReceiptV20 *out) {
 return VZKernelCPURunGICPublicV20(cpu,q,writer,out);
}
