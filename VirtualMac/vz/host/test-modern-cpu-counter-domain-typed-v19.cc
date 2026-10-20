#include "modern_cpu_kernel_physical_timer_v19.h"
#include <type_traits>
using ValidateType=VZKernelCounterDomainResultV19 (*)(const VZKernelCounterDomainSampleV19 *);
using SampleType=bool (*)(void *,VZKernelCounterDomainSampleV19 *);
static_assert(std::is_same<decltype(&VZKernelValidateCounterDomainV19),ValidateType>::value,"exact validator ABI");
static_assert(std::is_same<decltype(&VZKernelReadCounterDomainSampleV19),SampleType>::value,"exact sampler ABI");
extern "C" int VM27CounterTypedCallerV19(void *context,VZKernelCounterDomainSampleV19 *sample) {
 return VZKernelReadCounterDomainSampleV19(context,sample)?
  (int)VZKernelValidateCounterDomainV19(sample):-1;
}
