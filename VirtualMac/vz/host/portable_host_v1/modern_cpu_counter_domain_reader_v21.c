#include "modern_cpu_counter_domain_reader_v21.h"
#include <mach/mach.h>
#include <string.h>
#include <sys/sysctl.h>
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21) && defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#error "Counter domain fixture hooks must never be compiled for iOS"
#endif
#include "vm_host_profile_read_v1.h"
static bool CounterTargetProfileV21(void) {
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 return VM27CounterDomainTestHooksV21.profileString("hw.machine","iPad14,6") &&
  VM27CounterDomainTestHooksV21.profileString("kern.osrelease","22.1.0") &&
  VM27CounterDomainTestHooksV21.profileString("kern.osversion","20B101");
#else
 return VM27HostCurrentABI20B101MatchesV1();
#endif
}
static bool CounterArchitecturalFieldV21(uint32_t offset,uint32_t bytes,uint64_t *value) {
 // Exact width is checked before either a production LDR or a fixture hook.
 if(!value || !((offset==0x1e && bytes==2) || (offset==0x88 && bytes==8) ||
  (offset==0x90 && bytes==1)))return false;
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 return VM27CounterDomainTestHooksV21.architecturalField(offset,bytes,value);
#elif defined(__aarch64__)
 uintptr_t address=VZ_COUNTER_COMMPAGE_BASE_V21+offset;
 __asm__ volatile("dmb ishld":::"memory");
 if(bytes==2)*value=*(const volatile uint16_t *)address;
 else if(bytes==8)*value=*(const volatile uint64_t *)address;
 else *value=*(const volatile uint8_t *)address;
 __asm__ volatile("dmb ishld":::"memory");
 return true;
#else
 (void)offset;(void)bytes;return false;
#endif
}
static bool CounterFixedFieldV21(uint32_t offset,uint32_t bytes,
 VZKernelCounterFieldReceiptV21 *r) {
 *r=(VZKernelCounterFieldReceiptV21){0};r->offset=offset;r->bytes=bytes;
 if(!((offset==0x1e && bytes==2) || (offset==0x88 && bytes==8) ||
  (offset==0x90 && bytes==1)))return false;
 const uintptr_t address=VZ_COUNTER_COMMPAGE_BASE_V21+offset;
 r->mapChecked=true;
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 (void)VM27CounterDomainTestHooksV21.mappedRange((const void *)address,bytes,false,&r->mapped);
#else
 (void)VM27CPUSelfMappedRangeV1((const void *)address,bytes,false,&r->mapped);
#endif
 // A commpage can be installed in shared page tables without an ordinary
 // readable vm_map entry. Record the query, then try the true Mach copy itself.
 // A failed object-port release remains a resource error, not permission to
 // disregard ownership of a port returned by that query.
 if(r->mapped.portReleaseStatus!=KERN_SUCCESS)return false;
 r->copyAttempted=true;uint64_t value=0;
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 r->copyStatus=VM27CounterDomainTestHooksV21.copy(address,bytes,&value,&r->copied);
#else
 vm_size_t copied=0;r->copyStatus=vm_read_overwrite(mach_task_self(),
  (vm_address_t)address,bytes,(vm_address_t)&value,&copied);r->copied=copied;
#endif
 r->copyComplete=r->copyStatus==KERN_SUCCESS && r->copied==bytes;
 if(!r->copyComplete) {
  r->architecturalAttempted=true;
  if(!CounterArchitecturalFieldV21(offset,bytes,&value))return false;
 }
 r->value=value;r->completed=true;return true;
}
bool VZKernelReadCounterDomainSampleDetailedV21(void *context,
 VZKernelCounterDomainSampleV19 *out,VZKernelCounterSampleReceiptV21 *receipt) {
 (void)context;VZKernelCounterSampleReceiptV21 r={0};r.schemaVersion=1;
 r.stage=VZ_COUNTER_SAMPLE_ARGUMENT_V21;
 VZKernelCounterDomainSampleV19 s={0};mach_timebase_info_data_t t={0};
 if(!out)goto finish;
 r.stage=VZ_COUNTER_SAMPLE_PROFILE_V21;r.targetProfileChecked=true;
 r.targetProfileMatched=CounterTargetProfileV21();if(!r.targetProfileMatched)goto finish;
#if !defined(__aarch64__) && !defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 r.stage=VZ_COUNTER_SAMPLE_ARCH_UNAVAILABLE_V21;goto finish;
#else
 r.stage=VZ_COUNTER_SAMPLE_TIMEBASE_V21;r.timebaseAttempted=true;
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 r.timebaseStatus=VM27CounterDomainTestHooksV21.timebase(&t);
#else
 r.timebaseStatus=mach_timebase_info(&t);
#endif
 if(r.timebaseStatus!=KERN_SUCCESS)goto finish;
 s.timebaseNumer=t.numer;s.timebaseDenom=t.denom;
 const uint32_t offsets[6]={0x1e,0x90,0x88,0x88,0x90,0x1e};
 const uint32_t widths[6]={2,1,8,8,1,2};
 for(unsigned i=0;i<6;++i) {
  r.stage=VZ_COUNTER_SAMPLE_FIELD_V21;r.failedFieldOrdinal=i+1;++r.attemptedFields;
  if(!CounterFixedFieldV21(offsets[i],widths[i],&r.fields[i]))goto finish;
  ++r.completedFields;uint64_t value=r.fields[i].value;
  switch(i) {
   case 0:s.commpageVersionBefore=(uint16_t)value;break;
   case 1:s.userTimebaseBefore=(uint8_t)value;break;
   case 2:s.commpageBaseBefore=value;break;
   case 3:s.commpageBaseAfter=value;break;
   case 4:s.userTimebaseAfter=(uint8_t)value;break;
   case 5:s.commpageVersionAfter=(uint16_t)value;break;
  }
  if(i==2) {
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
   s.counterFrequency=VM27CounterDomainTestHooksV21.frequency();
   s.physicalBefore=VM27CounterDomainTestHooksV21.physical();
   s.machAbsolute=VM27CounterDomainTestHooksV21.machAbsolute();
   s.physicalAfter=VM27CounterDomainTestHooksV21.physical();
#else
   __asm__ volatile("isb\n\tmrs %0, cntfrq_el0":"=r"(s.counterFrequency)::"memory");
   __asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(s.physicalBefore)::"memory");
   s.machAbsolute=mach_absolute_time();
   __asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(s.physicalAfter)::"memory");
#endif
   r.countersRead=true;
  }
 }
 r.failedFieldOrdinal=0;r.stage=VZ_COUNTER_SAMPLE_COMPLETE_V21;r.completed=true;
 r.domainValidationAttempted=true;r.domainResult=VZKernelValidateCounterDomainV19(&s);
 *out=s;
#endif
finish:
 r.sample=s;if(receipt)*receipt=r;return r.completed;
}
bool VZKernelReadCounterDomainSampleV21(void *context,VZKernelCounterDomainSampleV19 *out) {
 return VZKernelReadCounterDomainSampleDetailedV21(context,out,NULL);
}
