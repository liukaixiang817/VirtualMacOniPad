/* Production counter sampling uses the same actual architectural fields as
 * V21's existing fallback. Only hardware/kernel identity and the immutable
 * Mach conversion ratio are cached within this process. All six shared-page
 * fields, CNTFRQ, both CNTPCT samples and mach_absolute_time remain fresh.
 * The detailed diagnostic entry retains V21's genuine Mach/port receipts. */
#define VZKernelReadCounterDomainSampleV21 VM27CounterOriginalSampleV22
#include "modern_cpu_counter_domain_reader_v21.c"
#undef VZKernelReadCounterDomainSampleV21
#include <stdatomic.h>

static _Atomic unsigned CounterProfileStateV22;
static mach_timebase_info_data_t CounterTimebaseV22;

static bool CounterReadyV22(void) {
 unsigned state=atomic_load_explicit(&CounterProfileStateV22,memory_order_acquire);
 if(state==2)return true;
 unsigned expected=0;
 if(!atomic_compare_exchange_strong_explicit(&CounterProfileStateV22,&expected,1,
    memory_order_acq_rel,memory_order_acquire))return false;
 mach_timebase_info_data_t timebase={0};
 bool valid=CounterTargetProfileV21();
 if(valid) {
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
  valid=VM27CounterDomainTestHooksV21.timebase(&timebase)==KERN_SUCCESS;
#else
  valid=mach_timebase_info(&timebase)==KERN_SUCCESS;
#endif
 }
 valid=valid && timebase.numer && timebase.denom;
 if(valid)CounterTimebaseV22=timebase;
 /* Failed/transient initialization is never a permanent synthetic result.
  * Another call may retry; a competing initializer uses the original path. */
 atomic_store_explicit(&CounterProfileStateV22,valid?2:0,memory_order_release);
 return valid;
}

__attribute__((visibility("hidden"))) bool
VZKernelReadCounterDomainSampleV21(void *context,VZKernelCounterDomainSampleV19 *out) {
#if defined(__aarch64__) || defined(VM27_COUNTER_DOMAIN_TESTING_V21)
 if(out && CounterReadyV22()) {
  VZKernelCounterDomainSampleV19 sample={0};
  sample.timebaseNumer=CounterTimebaseV22.numer;
  sample.timebaseDenom=CounterTimebaseV22.denom;
  const uint32_t offsets[6]={0x1e,0x90,0x88,0x88,0x90,0x1e};
  const uint32_t widths[6]={2,1,8,8,1,2};
  for(unsigned i=0;i<6;++i) {
   uint64_t value=0;
   if(!CounterArchitecturalFieldV21(offsets[i],widths[i],&value))return false;
   switch(i) {
    case 0:sample.commpageVersionBefore=(uint16_t)value;break;
    case 1:sample.userTimebaseBefore=(uint8_t)value;break;
    case 2:sample.commpageBaseBefore=value;break;
    case 3:sample.commpageBaseAfter=value;break;
    case 4:sample.userTimebaseAfter=(uint8_t)value;break;
    case 5:sample.commpageVersionAfter=(uint16_t)value;break;
   }
   if(i==2) {
#if defined(VM27_COUNTER_DOMAIN_TESTING_V21)
    sample.counterFrequency=VM27CounterDomainTestHooksV21.frequency();
    sample.physicalBefore=VM27CounterDomainTestHooksV21.physical();
    sample.machAbsolute=VM27CounterDomainTestHooksV21.machAbsolute();
    sample.physicalAfter=VM27CounterDomainTestHooksV21.physical();
#else
    __asm__ volatile("isb\n\tmrs %0, cntfrq_el0":"=r"(sample.counterFrequency)::"memory");
    __asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(sample.physicalBefore)::"memory");
    sample.machAbsolute=mach_absolute_time();
    __asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(sample.physicalAfter)::"memory");
#endif
   }
  }
  /* Preserve V19's complete-sample contract. Consumers still validate the
   * actual before/after version, bias, timebase and counter relationships. */
  *out=sample;
  return true;
 }
#endif
 return VZKernelReadCounterDomainSampleDetailedV21(context,out,NULL);
}
