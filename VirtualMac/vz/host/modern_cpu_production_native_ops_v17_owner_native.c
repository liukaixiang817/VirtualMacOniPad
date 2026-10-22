/* Keep generic Production14 reads/writes, lifecycle and native8 untouched.
 * Only a ready C1 service 2..6 is a finite, callback-free owner transaction. */
#include "modern_cpu_production_native_ops_v17_pac_batch.inc"
#include "modern_cpu_production_pac_service_v16.h"

VM27PACServiceResultV16 VM27ProductionPACServiceV16(uintptr_t context,
 uint32_t nativeISA,uint32_t operation) {
 VM27PACServiceResultV16 r={0};
 if(!context || operation<2 || operation>6 || (nativeISA!=1 && nativeISA!=2))return r;
 const uint64_t bank=UINT64_C(1)<<((operation==4 || operation==5)?60:61);
 const uint64_t forbidden=nativeISA==1?UINT64_C(0xdf00000000000000):UINT64_C(0xcf00000000000000);
 if(bank&forbidden)return r;
 uint64_t thread=ProductionThreadV1(NULL);if(!thread)return r;
 LockProductionV1();ProductionCPUV1 *cpu=CurrentCPUProductionV1(thread);
 bool admitted=ProductionV1.installed && ProductionV1.vmLive &&
  FastCPUProductionV10(cpu,thread) && cpu->nativeContext==context;
 const uint32_t reads[]={0x4000,0x4110,0x4100,0x748,0x10,0x18,0x7b0};
 for(unsigned i=0;i<sizeof(reads)/sizeof(*reads) && admitted;++i)
  admitted=ContextRangeProductionV10(cpu,(void *)(context+reads[i]),8,false);
 admitted=admitted && ContextRangeProductionV10(cpu,(void *)(context+0x4030),1,false);
 uint64_t version=0,active=0,ready=0,dirty=0,value=0,mode=0,control=0;
 if(admitted) {
  NativeLoadProductionV10((void *)(context+0x4000),8,&version);
  NativeLoadProductionV10((void *)(context+0x4030),1,&r.policy);
  NativeLoadProductionV10((void *)(context+0x4110),8,&active);
  NativeLoadProductionV10((void *)(context+0x4100),8,&ready);
  admitted=version==VZ_KERNEL_NATIVE_CONTEXT_VERSION && (r.policy&0x10) && (active&bank);
  if(admitted && !(ready&bank)){r.syncNeeded=1;UnlockProductionV1();return r;}
 }
 if(!admitted){UnlockProductionV1();return r;}
 NativeLoadProductionV10((void *)(context+0x748),8,&dirty);
 NativeLoadProductionV10((void *)(context+(operation==5?0x18:0x10)),8,&value);
 if(operation==5) {
  NativeLoadProductionV10((void *)(context+0x10),8,&mode);
  NativeLoadProductionV10((void *)(context+0x7b0),8,&control);
 }
 uint32_t offsets[8]={0x748};uint64_t values[8]={dirty|bank};unsigned count=1;
 if(operation==2 || operation==3) {
  const uint32_t key2[]={0x7d0,0x7c8,0x7e8,0x7f0},key3[]={0x7e0,0x7d8,0x7f8,0x800};
  const uint32_t *keys=operation==2?key2:key3;const unsigned add[]={0,1,3,2};
  for(unsigned i=0;i<4;++i){offsets[count]=keys[i];values[count++]=value+add[i];}
 } else {
  offsets[count]=operation==6?0x7c0:0x810;values[count++]=value;
  offsets[count]=operation==6?0x7b8:0x808;values[count++]=value+1;
  if(operation==5 && mode<=1){offsets[count]=0x7b0;values[count++]=mode?control|2:control&~UINT64_C(2);}
 }
 offsets[count]=8;values[count++]=0; // Original successful C1 response in X0.
 for(unsigned i=0;i<count && admitted;++i)
  admitted=WritableProductionV1(offsets[i],8) &&
   ContextRangeProductionV10(cpu,(void *)(context+offsets[i]),8,true);
 if(!admitted){UnlockProductionV1();return r;}
 r.handled=1;r.ok=1;
 for(unsigned i=0;i<count && r.ok;++i) {
  uint64_t readback=0;++r.attempted;
  NativeStoreProductionV10((void *)(context+offsets[i]),8,&values[i]);
  NativeLoadProductionV10((void *)(context+offsets[i]),8,&readback);
  r.ok=readback==values[i];if(r.ok)++r.completed;
  CountProductionV10(&cpu->fastWrites);
 }
 NativeLoadProductionV10((void *)(context+0x4000),8,&version);
 r.ok=r.ok && version==VZ_KERNEL_NATIVE_CONTEXT_VERSION;
 if(!r.ok)cpu->writeFailed=true;
 UnlockProductionV1();
 static _Atomic unsigned observations;
 unsigned ordinal=atomic_load_explicit(&observations,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&observations,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal<8){int saved=errno;dprintf(2,"[Independent27PACService16] sample=%u operation=%u attempted=%u completed=%u success=%u exactNativeOwner=1 readyBank=1 actualOriginalKeyValues=1 perFieldReadback=1 nativeCalls=0\n",ordinal+1,operation,r.attempted,r.completed,r.ok);errno=saved;}
 return r;
}
