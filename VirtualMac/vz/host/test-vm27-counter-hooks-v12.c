// Local integration hooks only. The production reader rejects these on iOS.
#include "modern_cpu_counter_domain_reader_v21.h"
#include <string.h>
static unsigned FieldsV12,PhysicalV12;
static bool ProfileV12(const char *name,const char *expected) {
 return (!strcmp(name,"hw.machine") && !strcmp(expected,"iPad14,6")) ||
  (!strcmp(name,"kern.osrelease") && !strcmp(expected,"22.1.0")) ||
  (!strcmp(name,"kern.osversion") && !strcmp(expected,"20B101"));
}
static bool MappedV12(const void *p,size_t n,bool writable,VM27CPUSelfMappedReceiptV1 *r) {
 (void)p;(void)n;(void)writable;
 *r=(VM27CPUSelfMappedReceiptV1){.queries=1,.queryStatus=KERN_INVALID_ADDRESS,
  .portReleaseStatus=KERN_SUCCESS};return false;
}
static int32_t CopyV12(uintptr_t p,size_t n,void *out,uint64_t *copied) {
 (void)p;const uint64_t values[]={3,3,20,20,3,3};
 uint64_t v=values[FieldsV12++%6];memcpy(out,&v,n);*copied=n;return KERN_SUCCESS;
}
static bool ArchV12(uint32_t offset,uint32_t n,uint64_t *out) {
 (void)offset;(void)n;(void)out;return false;
}
static int32_t TimebaseV12(mach_timebase_info_data_t *t){t->numer=125;t->denom=3;return 0;}
static uint64_t FrequencyV12(void){return 24000000;}
static uint64_t PhysicalCounterV12(void){return PhysicalV12++%2?120:100;}
static uint64_t MachV12(void){return 130;}
const VZKernelCounterDomainTestHooksV21 VM27CounterDomainTestHooksV21={
 ProfileV12,MappedV12,CopyV12,ArchV12,TimebaseV12,FrequencyV12,PhysicalCounterV12,MachV12};
