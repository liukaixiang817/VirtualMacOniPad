#ifndef VM27_COUNTER_DOMAIN_READER_V21_H
#define VM27_COUNTER_DOMAIN_READER_V21_H
#include "modern_cpu_kernel_counter_domain_v19.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <mach/mach_time.h>
#ifdef __cplusplus
extern "C" {
#endif
// Only this audited current iPad profile may use architectural commpage loads.
// The three fields are fixed by XNU's LP64 commpage ABI and the captured kernel;
// this is not an alternative general-purpose memory reader.
#define VZ_COUNTER_COMMPAGE_BASE_V21 UINT64_C(0x0000000fffffc000)
typedef enum {
 VZ_COUNTER_SAMPLE_COMPLETE_V21=0,VZ_COUNTER_SAMPLE_ARGUMENT_V21=1,
 VZ_COUNTER_SAMPLE_PROFILE_V21=2,VZ_COUNTER_SAMPLE_TIMEBASE_V21=3,
 VZ_COUNTER_SAMPLE_FIELD_V21=4,VZ_COUNTER_SAMPLE_ARCH_UNAVAILABLE_V21=5
} VZKernelCounterSampleStageV21;
typedef struct {
 uint32_t offset,bytes;
 VM27CPUSelfMappedReceiptV1 mapped;
 int32_t copyStatus;
 uint64_t copied,value;
 bool mapChecked,copyAttempted,copyComplete,architecturalAttempted,completed;
} VZKernelCounterFieldReceiptV21;
typedef struct {
 uint32_t schemaVersion,attemptedFields,completedFields,failedFieldOrdinal;
 VZKernelCounterSampleStageV21 stage;
 int32_t timebaseStatus;
 bool targetProfileChecked,targetProfileMatched,timebaseAttempted;
 bool countersRead,completed,domainValidationAttempted;
 VZKernelCounterDomainResultV19 domainResult;
 VZKernelCounterDomainSampleV19 sample;
 VZKernelCounterFieldReceiptV21 fields[6];
} VZKernelCounterSampleReceiptV21;
// Boolean preserves the V19 callback contract: a complete actual sample was
// read. Validation remains separate; an invalid complete sample is not success.
__attribute__((visibility("hidden"))) bool
VZKernelReadCounterDomainSampleV21(void *,VZKernelCounterDomainSampleV19 *);
__attribute__((visibility("hidden"))) bool
VZKernelReadCounterDomainSampleDetailedV21(void *,VZKernelCounterDomainSampleV19 *,
 VZKernelCounterSampleReceiptV21 *);
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
// Hooks exist solely in local finite fixtures. Device builds reject this macro.
typedef struct {
 bool (*profileString)(const char *,const char *);
 bool (*mappedRange)(const void *,size_t,bool,VM27CPUSelfMappedReceiptV1 *);
 int32_t (*copy)(uintptr_t,size_t,void *,uint64_t *);
 bool (*architecturalField)(uint32_t,uint32_t,uint64_t *);
 int32_t (*timebase)(mach_timebase_info_data_t *);
 uint64_t (*frequency)(void),(*physical)(void),(*machAbsolute)(void);
} VZKernelCounterDomainTestHooksV21;
extern const VZKernelCounterDomainTestHooksV21 VM27CounterDomainTestHooksV21;
#endif
#ifdef __cplusplus
}
#endif
#endif
