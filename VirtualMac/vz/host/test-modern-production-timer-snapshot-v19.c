/* Host-only real transaction tests. Native HV creation/entry is not simulated
 * as success: any accidental native call aborts this test. */
#include "modern_cpu_production_native_ops_v19_timer_snapshot.c"
#include <stdio.h>
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}}while(0)
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *p){(void)op;(void)p;abort();}
static void Put(uintptr_t p,unsigned off,uint64_t v){memcpy((void *)(p+off),&v,8);}
static void *Foreign(void *p){VM27PACServiceResultV16 r=VM27ProductionPACServiceV16((uintptr_t)p,2,2);CHECK(!r.handled&&!r.attempted);return NULL;}
int main(void){
 void *memory=NULL;CHECK(!posix_memalign(&memory,0x4000,0x8000));uintptr_t ctx=(uintptr_t)memory;
 ProductionCPUV1 cpu={.pthread=pthread_self(),.nativeContext=ctx,.live=true,.usable=true,.contextReadablePages=3,.contextWritablePages=3};CHECK(!pthread_threadid_np(NULL,&cpu.thread));
 ProductionV1.installed=ProductionV1.vmLive=true;ProductionV1.cpus=&cpu;
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t stackBytes=pthread_get_stacksize_np(pthread_self());
 CHECK(VM27CPUOwnedMappingPublishV1(0,(uintptr_t)&cpu,cpu.thread,ctx,3,3,top-stackBytes,stackBytes,true));


 // Snapshot exactly the real grouped fields and leave all source bytes intact.
 memset(memory,0,0x8000);Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 const unsigned off[3][3]={{0x6a0,0x748,0x4100},{0x438,0x3f0,0},{0x430,0x3e8,0x6d8}};
 for(unsigned kind=0;kind<3;++kind){
  unsigned count=kind==1?2:3;for(unsigned i=0;i<count;++i)Put(ctx,off[kind][i],0x918234+kind*8+i);
  unsigned char before[0x8000];memcpy(before,memory,sizeof(before));
  LockProductionV1();VM27NativeTimerSnapshotV19 snap=VM27ProductionTimerSnapshotV19(ctx,kind);UnlockProductionV1();
  CHECK(snap.valid&&snap.first==0x918234+kind*8&&snap.second==0x918235+kind*8&&snap.third==(count==3?0x918236+kind*8:0));
  CHECK(!memcmp(before,memory,sizeof(before)));
 }
 CHECK(!VM27ProductionTimerSnapshotV19(ctx,3).valid);CHECK(!VM27ProductionTimerSnapshotV19(ctx+8,0).valid);
 cpu.contextReadablePages=1;CHECK(!VM27ProductionTimerSnapshotV19(ctx,0).valid);CHECK(VM27ProductionTimerSnapshotV19(ctx,1).valid);cpu.contextReadablePages=3;
 cpu.usable=false;CHECK(!VM27ProductionTimerSnapshotV19(ctx,0).valid);cpu.usable=true;
 Put(ctx,0x4000,0);CHECK(!VM27ProductionTimerSnapshotV19(ctx,0).valid);Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 for(unsigned op=2;op<=6;++op)for(unsigned mode=0;mode<3;++mode)for(unsigned trial=0;trial<100;++trial){
  memset(memory,0x91,0x8000);Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);*((uint8_t *)(ctx+0x4030))=0x10;
  Put(ctx,0x4100,UINT64_C(3)<<60);Put(ctx,0x4110,UINT64_C(3)<<60);Put(ctx,0x748,0x42);
  uint64_t value=trial==99?UINT64_MAX:UINT64_C(0xc1923517021323)+trial;
  Put(ctx,0x10,op==5?mode:value);Put(ctx,0x18,value);Put(ctx,0x7b0,0x11);
  unsigned char expected[0x8000];memcpy(expected,memory,sizeof(expected));uintptr_t e=(uintptr_t)expected;
  uint64_t bank=UINT64_C(1)<<((op==4||op==5)?60:61);Put(e,0x748,0x42|bank);
  if(op==2||op==3){unsigned offsets2[]={0x7d0,0x7c8,0x7e8,0x7f0},offsets3[]={0x7e0,0x7d8,0x7f8,0x800};unsigned *offsets=op==2?offsets2:offsets3;unsigned add[]={0,1,3,2};for(unsigned i=0;i<4;++i)Put(e,offsets[i],value+add[i]);}
  else {Put(e,op==6?0x7c0:0x810,value);Put(e,op==6?0x7b8:0x808,value+1);if(op==5&&mode<=1)Put(e,0x7b0,mode?0x13:0x11);}
  Put(e,8,0);VM27PACServiceResultV16 r=VM27ProductionPACServiceV16(ctx,2,op);
  CHECK(r.handled&&r.ok&&r.attempted==r.completed&&r.attempted>=4);CHECK(!memcmp(expected,memory,sizeof(expected)));
 }
 memset(memory,0,0x8000);Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);*((uint8_t *)(ctx+0x4030))=0x10;Put(ctx,0x4110,UINT64_C(3)<<60);Put(ctx,0x4100,UINT64_C(3)<<60);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,Foreign,memory));CHECK(!pthread_join(foreign,NULL));
 for(unsigned kind=0;kind<6;++kind){
  unsigned char before[0x8000];memcpy(before,memory,sizeof(before));
  if(kind==0)Put(ctx,0x4100,0);if(kind==1)Put(ctx,0x4110,0);if(kind==2)*((uint8_t *)(ctx+0x4030))=0;
  if(kind==3)cpu.writeFailed=true;if(kind==4)cpu.contextWritablePages=0;if(kind==5)Put(ctx,0x4000,0);
  unsigned char rejected[0x8000];memcpy(rejected,memory,sizeof(rejected));VM27PACServiceResultV16 r=VM27ProductionPACServiceV16(ctx,2,2);CHECK(!r.handled&&!r.attempted);CHECK(r.syncNeeded==(kind==0));CHECK(!memcmp(rejected,memory,sizeof(rejected)));
  memcpy(memory,before,sizeof(before));cpu.writeFailed=false;cpu.contextWritablePages=3;
 }
 CHECK(!VM27ProductionPACServiceV16(ctx,1,4).handled);CHECK(!VM27ProductionPACServiceV16(ctx,2,0).handled);

 // The same actual owner transaction must complete while the former shared
 // mutex is already held. This is a boundary regression test, not HV proof.
 memset(memory,0,0x8000);Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);*((uint8_t *)(ctx+0x4030))=0x10;
 Put(ctx,0x4100,UINT64_C(3)<<60);Put(ctx,0x4110,UINT64_C(3)<<60);Put(ctx,0x10,17);
 LockProductionV1();VM27PACServiceResultV16 independent=VM27ProductionPACServiceV16(ctx,2,2);UnlockProductionV1();
 CHECK(independent.handled&&independent.ok&&independent.completed==6);
 VM27CPUOwnedMappingWithdrawV1(0,(uintptr_t)&cpu,NULL);
 VM27OwnedNativeAdmissionV7 withdrawn={0};CHECK(!VM27CPUOwnedNativeAdmissionV7(&withdrawn));CHECK(!VM27ProductionTimerSnapshotV19(ctx,0).valid);
 ProductionV1.cpus=NULL;ProductionV1.installed=ProductionV1.vmLive=false;free(memory);
 printf("actual ready-bank C1 2..6 transaction: all bytes, overflow, mode, foreign-owner, fallback, epoch withdrawal and mutex independence checks=%u PASS; native execution not claimed\n",checks);return 0;
}
