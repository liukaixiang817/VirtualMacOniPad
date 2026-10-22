/* The live native6 mapping pins its heap CPU token to this exact pthread
 * until native7. VM destruction/uninstall reject that live CPU. Admission
 * checks the current mapping epoch, process and actual native version.
 * This finite C1 transaction touches only the owner's native context and
 * local operands; it needs no shared registry/list lock. Foreign and
 * unadmitted calls retain the unchanged Production17/16 path.
 * Every original operand, bank policy, readback and failure result remains.
 */
#define VM27ProductionPACServiceV16 VM27ProductionPACServiceSlowV18
#include "modern_cpu_production_native_ops_v17_owner_native.c"
#undef VM27ProductionPACServiceV16
static void NativeLoadOwnerPACV18(const void *p,size_t n,void *out) {
 uintptr_t at=(uintptr_t)p;
 if(n==8 && !(at&7)){uint64_t v=*(const volatile uint64_t *)p;memcpy(out,&v,8);}
 else if(n==1){*(unsigned char *)out=*(const volatile unsigned char *)p;}
 else NativeLoadProductionV10(p,n,out);
}
static void NativeStoreOwnerPACV18(void *p,size_t n,const void *value) {
 if(n==8 && !((uintptr_t)p&7)){uint64_t v;memcpy(&v,value,8);*(volatile uint64_t *)p=v;}
 else NativeStoreProductionV10(p,n,value);
}
VM27PACServiceResultV16 VM27ProductionPACServiceV16(uintptr_t context,
 uint32_t nativeISA,uint32_t operation) {
 VM27PACServiceResultV16 r={0};
 if(!context || operation<2 || operation>6 || (nativeISA!=1 && nativeISA!=2))return r;
 const uint64_t bank=UINT64_C(1)<<((operation==4 || operation==5)?60:61);
 const uint64_t forbidden=nativeISA==1?UINT64_C(0xdf00000000000000):UINT64_C(0xcf00000000000000);
 if(bank&forbidden)return r;
 VM27OwnedNativeAdmissionV7 admission={0};
 if(!VM27CPUOwnedNativeAdmissionV7(&admission))
  return VM27ProductionPACServiceSlowV18(context,nativeISA,operation);
 ProductionCPUV1 *cpu=(ProductionCPUV1 *)admission.token;
 bool admitted=cpu && admission.context==context &&
  admission.version==VZ_KERNEL_NATIVE_CONTEXT_VERSION &&
  cpu->nativeContext==context && cpu->live && cpu->usable &&
  !cpu->destroying && !cpu->writeFailed && pthread_equal(cpu->pthread,pthread_self());
 const uint32_t reads[]={0x4000,0x4110,0x4100,0x748,0x10,0x18,0x7b0};
 for(unsigned i=0;i<sizeof(reads)/sizeof(*reads) && admitted;++i)
  admitted=ContextRangeProductionV10(cpu,(void *)(context+reads[i]),8,false);
 admitted=admitted && ContextRangeProductionV10(cpu,(void *)(context+0x4030),1,false);
 uint64_t version=0,active=0,ready=0,dirty=0,value=0,mode=0,control=0;
 if(admitted) {
  NativeLoadOwnerPACV18((void *)(context+0x4000),8,&version);
  NativeLoadOwnerPACV18((void *)(context+0x4030),1,&r.policy);
  NativeLoadOwnerPACV18((void *)(context+0x4110),8,&active);
  NativeLoadOwnerPACV18((void *)(context+0x4100),8,&ready);
  admitted=version==VZ_KERNEL_NATIVE_CONTEXT_VERSION && (r.policy&0x10) && (active&bank);
  if(admitted && !(ready&bank)){r.syncNeeded=1;return r;}
 }
 if(!admitted){return r;}
 NativeLoadOwnerPACV18((void *)(context+0x748),8,&dirty);
 NativeLoadOwnerPACV18((void *)(context+(operation==5?0x18:0x10)),8,&value);
 if(operation==5) {
  NativeLoadOwnerPACV18((void *)(context+0x10),8,&mode);
  NativeLoadOwnerPACV18((void *)(context+0x7b0),8,&control);
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
 if(!admitted){return r;}
 r.handled=1;r.ok=1;
 for(unsigned i=0;i<count && r.ok;++i) {
  uint64_t readback=0;++r.attempted;
  NativeStoreOwnerPACV18((void *)(context+offsets[i]),8,&values[i]);
  NativeLoadOwnerPACV18((void *)(context+offsets[i]),8,&readback);
  r.ok=readback==values[i];if(r.ok)++r.completed;
  CountProductionV10(&cpu->fastWrites);
 }
 NativeLoadOwnerPACV18((void *)(context+0x4000),8,&version);
 r.ok=r.ok && version==VZ_KERNEL_NATIVE_CONTEXT_VERSION && cpu->live && cpu->usable && !cpu->destroying && !cpu->writeFailed;
 if(!r.ok)cpu->writeFailed=true;
 
 static _Atomic unsigned observations;
 unsigned ordinal=atomic_load_explicit(&observations,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&observations,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal<8){int saved=errno;dprintf(2,"[Independent27PACService18] sample=%u operation=%u attempted=%u completed=%u success=%u exactNativeOwner=1 epochAdmitted=1 globalMutex=0 readyBank=1 actualOriginalKeyValues=1 perFieldReadback=1 nativeCalls=0\n",ordinal+1,operation,r.attempted,r.completed,r.ok);errno=saved;}
 return r;
}
