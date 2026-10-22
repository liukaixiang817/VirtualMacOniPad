/* All Production19 behavior remains. Only the internal pending-control0
 * transaction uses the actual initialization engine without the shared mutex.
 * A live native6 mapping pins its CPU token and pages until this same pthread
 * executes native7. No foreign callback, native entry or registry mutation
 * occurs inside this finite transaction. */
#include "modern_cpu_production_native_ops_v19_timer_snapshot.c"
#include "modern_cpu_production_control0_v20.h"
#include "modern_cpu_kernel_profile_v2.h"

static bool Control0OwnerV20(ProductionCPUV1 *cpu) {
 VM27OwnedNativeAdmissionV7 a={0};
 return VM27CPUOwnedNativeAdmissionV7(&a) && a.token==(uintptr_t)cpu &&
  a.context==cpu->nativeContext && a.version==VZ_KERNEL_NATIVE_CONTEXT_VERSION &&
  cpu->live && cpu->usable && !cpu->destroying && !cpu->writeFailed &&
  pthread_equal(cpu->pthread,pthread_self());
}
static bool Control0FieldV20(uint32_t offset,size_t bytes) {
 return bytes==8 && (offset==0x670 || offset==0x678 || offset==0x748);
}
static bool Control0ReadV20(void *opaque,uint32_t offset,size_t bytes,void *out) {
 ProductionCPUV1 *cpu=opaque;
 if(!Control0FieldV20(offset,bytes) || !Control0OwnerV20(cpu))return false;
 NativeLoadOwnerPACV18((void *)(cpu->nativeContext+offset),bytes,out);
 return Control0OwnerV20(cpu);
}
static bool Control0WriteV20(void *opaque,uint32_t offset,size_t bytes,const void *value) {
 ProductionCPUV1 *cpu=opaque;
 if(!Control0FieldV20(offset,bytes) || !Control0OwnerV20(cpu))return false;
 /* Only the original offset-only engine invokes these private callbacks;
  * its source is its own request or local Modify value, never a client buffer. */
 uint64_t staged,readback;memcpy(&staged,value,8);
 NativeStoreOwnerPACV18((void *)(cpu->nativeContext+offset),8,&staged);
 NativeLoadOwnerPACV18((void *)(cpu->nativeContext+offset),8,&readback);
 bool ok=staged==readback && Control0OwnerV20(cpu);
 if(!ok)cpu->writeFailed=true;
 CountProductionV10(&cpu->fastWrites);return ok;
}
VM27Control0ResultV20 VM27ProductionControl0V20(uintptr_t context,uint32_t nativeISA,uint64_t value) {
 VM27Control0ResultV20 r={0};VM27OwnedNativeAdmissionV7 a={0};
 if(!context || !VZKernelNativeISAHasValidatedContextV2(nativeISA) ||
    !VM27CPUOwnedNativeAdmissionV7(&a) || a.context!=context ||
    a.version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION)return r;
 ProductionCPUV1 *cpu=(ProductionCPUV1 *)a.token;
 if(!cpu || !Control0OwnerV20(cpu))return r;
 const uint32_t fields[]={0x670,0x678,0x748};
 for(unsigned i=0;i<3;++i)
  if(!ContextRangeProductionV10(cpu,(void *)(context+fields[i]),8,false) ||
     !ContextRangeProductionV10(cpu,(void *)(context+fields[i]),8,true))return r;
 r.handled=true;r.receipt.failedWriteOrdinal=r.receipt.failedNativeOffset=UINT32_MAX;
 VZKernelInitRequest q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,cpu->thread,0,cpu->slot,
  nativeISA,VZ_KERNEL_INIT_CONTROL,0,value,0};
 VZKernelInitAccess access={cpu,Control0ReadV20,Control0WriteV20};
 VZKernelInitApplyVerifiedSlice(&q,&access,&r.receipt);
 static _Atomic unsigned observations;
 unsigned ordinal=atomic_load_explicit(&observations,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&observations,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal<8){int saved=errno;dprintf(2,"[Independent27Control0_20] sample=%u status=%u reads=%u attempted=%u completed=%u canonicalEngine=1 actualOwner=1 versionEveryAccess=1 globalMutex=0 nativeCalls=0\n",ordinal+1,r.receipt.status,r.receipt.attemptedReads,r.receipt.attemptedWrites,r.receipt.completedWrites);errno=saved;}
 return r;
}
