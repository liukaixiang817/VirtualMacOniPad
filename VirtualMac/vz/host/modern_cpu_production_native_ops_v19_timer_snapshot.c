/* Production18 is whole. Snapshot only actual immutable-owner native fields
 * while its synchronous CPU operation pins the native6 mapping. Each group
 * checks the mapping epoch, actual version and live owner before and after;
 * it calls no registry, callback, native trap or write. Unadmitted/failure
 * results select the original sequential reads in the lifecycle caller. */
#include "modern_cpu_production_native_ops_v18_owner_pac.c"
#include "modern_cpu_production_timer_snapshot_v19.h"
VM27NativeTimerSnapshotV19 VM27ProductionTimerSnapshotV19(uintptr_t context,unsigned kind) {
 VM27NativeTimerSnapshotV19 r={0};VM27OwnedNativeAdmissionV7 a={0};
 if(kind>2 || !context || !VM27CPUOwnedNativeAdmissionV7(&a))return r;
 ProductionCPUV1 *cpu=(ProductionCPUV1 *)a.token;
 if(!cpu || a.context!=context || cpu->nativeContext!=context ||
    a.version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION || !cpu->live || !cpu->usable ||
    cpu->destroying || cpu->writeFailed || !pthread_equal(cpu->pthread,pthread_self()))return r;
 const uint32_t fields[3][3]={{0x6a0,0x748,0x4100},{0x438,0x3f0,0},{0x430,0x3e8,0x6d8}};
 unsigned count=kind==1?2:3;
 for(unsigned i=0;i<count;++i)if(!ContextRangeProductionV10(cpu,(void *)(context+fields[kind][i]),8,false))return r;
 uint64_t words[3]={0};
 for(unsigned i=0;i<count;++i)NativeLoadOwnerPACV18((void *)(context+fields[kind][i]),8,&words[i]);
 VM27OwnedNativeAdmissionV7 after={0};
 if(!VM27CPUOwnedNativeAdmissionV7(&after) || after.token!=a.token || after.context!=context ||
    after.version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION || !cpu->live || !cpu->usable || cpu->destroying || cpu->writeFailed)return r;
 r.first=words[0];r.second=words[1];r.third=words[2];r.valid=true;
 static _Atomic unsigned observations;
 unsigned ordinal=atomic_load_explicit(&observations,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&observations,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal<8){int saved=errno;dprintf(2,"[Independent27TimerSnapshot19] sample=%u kind=%u fields=%u actualNativeOwner=1 nativeVersionBeforeAfter=1 writes=0 nativeCalls=0\n",ordinal+1,kind,count);errno=saved;}
 return r;
}
