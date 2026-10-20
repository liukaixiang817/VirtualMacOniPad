#ifndef VZ_KERNEL_COUNTER_DOMAIN_V19_H
#define VZ_KERNEL_COUNTER_DOMAIN_V19_H
#include <stdbool.h>
#include <stdint.h>
// This evidence is sampled from the actual current process. It is not a
// caller-supplied assertion that Mach and architectural counter domains agree.
typedef struct {
 uint64_t physicalBefore,machAbsolute,physicalAfter,counterFrequency;
 uint64_t commpageBaseBefore,commpageBaseAfter;
 uint32_t timebaseNumer,timebaseDenom;
 uint16_t commpageVersionBefore,commpageVersionAfter;
 uint8_t userTimebaseBefore,userTimebaseAfter;
} VZKernelCounterDomainSampleV19;
typedef enum {
 VZ_COUNTER_DOMAIN_VALID_V19=0,VZ_COUNTER_DOMAIN_UNSTABLE_V19=1,
 VZ_COUNTER_DOMAIN_FREQUENCY_V19=2,VZ_COUNTER_DOMAIN_EPOCH_V19=3,
 VZ_COUNTER_DOMAIN_TRANSLATION_RANGE_V19=4,VZ_COUNTER_DOMAIN_COMMPAGE_V19=5
} VZKernelCounterDomainResultV19;
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("hidden"))) VZKernelCounterDomainResultV19
VZKernelValidateCounterDomainV19(const VZKernelCounterDomainSampleV19 *);
// Actual CNTPCT_EL0/CNTFRQ_EL0, mach_absolute_time/timebase_info and mapped
// commpage reads. This function has not yet executed on the target device.
__attribute__((visibility("hidden"))) bool
VZKernelReadCounterDomainSampleV19(void *,VZKernelCounterDomainSampleV19 *);
#ifdef __cplusplus
}
#endif
#endif
