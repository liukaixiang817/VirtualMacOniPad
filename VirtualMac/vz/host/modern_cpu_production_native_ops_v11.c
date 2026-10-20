#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <errno.h>
static int32_t VM27NativeTrapWithMilestoneV6(uint64_t,void *);
#define VM27ProductionNativeTrapV1 VM27NativeTrapWithMilestoneV6
#include "modern_cpu_production_native_ops_slot_v11.inc"
#undef VM27ProductionNativeTrapV1
extern int32_t VM27ProductionNativeTrapV1(uint64_t,void *);
static _Atomic unsigned VM27NativeMilestonesV6;
static _Atomic unsigned VM27NativeRunSnapshotsV6;
static _Atomic uint32_t VM27ObservedNativeISAV6;

// Only inspect this provider's actual current CPU shared mapping. These four
// words have genuine create/run producers in the pinned current kernel.
// No kernel pointer is followed, and no word is changed or synthesized.
static void VM27RunAdmissionSnapshotV6(void) {
 unsigned ordinal=atomic_load_explicit(&VM27NativeRunSnapshotsV6,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&VM27NativeRunSnapshotsV6,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal>=8)return;
 const int savedErrno=errno;
 uint64_t version=0,dirty=0,ready=0,inactive=0,active=0,slot=UINT64_MAX;
 unsigned known=0;
 const uint64_t thread=ProductionThreadV1(NULL);
 LockProductionV1();
 ProductionCPUV1 *cpu=CurrentCPUProductionV1(thread);
 bool own=thread && ProductionV1.installed && ProductionV1.vmLive && cpu &&
  cpu->live && cpu->usable && !cpu->destroying && !cpu->writeFailed;
 if(own && CopyProductionV1((void *)(cpu->nativeContext+0x4000),8,&version) &&
  version==VZ_KERNEL_NATIVE_CONTEXT_VERSION) {
  known=1;slot=cpu->slot;
  if(CopyProductionV1((void *)(cpu->nativeContext+0x748),8,&dirty))known|=2;
  if(CopyProductionV1((void *)(cpu->nativeContext+0x4100),8,&ready))known|=4;
  if(CopyProductionV1((void *)(cpu->nativeContext+0x4108),8,&inactive))known|=8;
  if(CopyProductionV1((void *)(cpu->nativeContext+0x4110),8,&active))known|=16;
 }
 UnlockProductionV1();
 dprintf(2,"[Independent27HV] run-admission ordinal=%u nativeISA=%u ownCPU=%u known=0x%x slot=%llu version=0x%llx dirty748=0x%016llx ready4100=0x%016llx inactive4108=0x%016llx active4110=0x%016llx\n",ordinal+1,atomic_load_explicit(&VM27ObservedNativeISAV6,memory_order_relaxed),own,known,(unsigned long long)slot,(unsigned long long)version,(unsigned long long)dirty,(unsigned long long)ready,(unsigned long long)inactive,(unsigned long long)active);
 errno=savedErrno;
}
static int32_t VM27NativeTrapWithMilestoneV6(uint64_t operation,void *arguments) {
 unsigned sequence=atomic_load_explicit(&VM27NativeMilestonesV6,memory_order_relaxed);
 while(sequence<16 && !atomic_compare_exchange_weak_explicit(&VM27NativeMilestonesV6,&sequence,sequence+1,memory_order_relaxed,memory_order_relaxed)){}
 bool traced=sequence<16;
 if(traced)dprintf(2,"[Independent27HV] milestone stage=native-enter sequence=%u operation=%llu\n",sequence+1,(unsigned long long)operation);
 if(operation==9)VM27RunAdmissionSnapshotV6();
 // ProductionNativeV1 already verified this own exact32-byte VM packet.
 uint32_t requestedISA=operation==1 && arguments?((VZKernelNativeVMConfig *)arguments)->nativeHVISA:0;
 int32_t result=VM27ProductionNativeTrapV1(operation,arguments);
 if(operation==1 && !result)atomic_store_explicit(&VM27ObservedNativeISAV6,requestedISA,memory_order_relaxed);
 if(operation==2 && !result)atomic_store_explicit(&VM27ObservedNativeISAV6,0,memory_order_relaxed);
 if(traced)dprintf(2,"[Independent27HV] milestone stage=native-return sequence=%u operation=%llu nativeReturn=%d raw=0x%08x\n",sequence+1,(unsigned long long)operation,result,(unsigned)result);
 if(result)dprintf(2,"[Independent27HV] failed stage=native-trap operation=%llu nativeReturn=%d raw=0x%08x\n",(unsigned long long)operation,result,(unsigned)result);
 return result;
}
