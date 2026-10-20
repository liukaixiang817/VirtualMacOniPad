#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
static int32_t VM27NativeTrapWithMilestoneV4(uint64_t,void *);
#define VM27ProductionNativeTrapV1 VM27NativeTrapWithMilestoneV4
#include "modern_cpu_production_native_ops_slot_v5.inc"
#undef VM27ProductionNativeTrapV1
extern int32_t VM27ProductionNativeTrapV1(uint64_t,void *);
static _Atomic unsigned VM27NativeMilestonesV4;
static int32_t VM27NativeTrapWithMilestoneV4(uint64_t operation,void *arguments) {
 unsigned sequence=atomic_load_explicit(&VM27NativeMilestonesV4,memory_order_relaxed);
 while(sequence<16 && !atomic_compare_exchange_weak_explicit(&VM27NativeMilestonesV4,&sequence,sequence+1,memory_order_relaxed,memory_order_relaxed)){}
 bool traced=sequence<16;
 if(traced)dprintf(2,"[Independent27HV] milestone stage=native-enter sequence=%u operation=%llu\n",sequence+1,(unsigned long long)operation);
 int32_t result=VM27ProductionNativeTrapV1(operation,arguments);
 if(traced)dprintf(2,"[Independent27HV] milestone stage=native-return sequence=%u operation=%llu nativeReturn=%d raw=0x%08x\n",sequence+1,(unsigned long long)operation,result,(unsigned)result);
 if(result)dprintf(2,"[Independent27HV] failed stage=native-trap operation=%llu nativeReturn=%d raw=0x%08x\n",(unsigned long long)operation,result,(unsigned)result);
 return result;
}
