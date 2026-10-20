// Reuse the frozen fixture's real SDK types, CF config and native-op mocks.
// The original finite regression is separately executed against Factory10.
#define main VM27Factory8UnchangedFixtureMain
#pragma clang diagnostic push
// C's implicit return 0 applies to main only. The renamed frozen function is
// never called here; its original main is tested in a separate executable.
#pragma clang diagnostic ignored "-Wreturn-type"
#include "test-modern-cpu-hv-public-factory-v8.m"
#pragma clang diagnostic pop
#undef main
#include "modern_cpu_native_public_factory_v10.h"
#include <unistd.h>

#ifndef VM27_VTIMER_RELEASE_TEST
#define VM27_VTIMER_RELEASE_TEST 0
#endif
#if VM27_VTIMER_RELEASE_TEST
static bool HoldRelease;
static unsigned ReleaseAttempts,ReleaseSuccesses;
extern VZKernelStatus OwnRealCPUReleaseBorrow(VZKernelCPUBorrowV5 *);
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *b) {
 ++ReleaseAttempts;if(HoldRelease)return VZ_KERNEL_BUSY;
 VZKernelStatus s=OwnRealCPUReleaseBorrow(b);if(!s)++ReleaseSuccesses;return s;
}
#endif
typedef struct {
 Mock base;
 bool active,reenter,failDirtyRead,alterDirtyAfterFirst;
 unsigned failWriteOrdinal,versionAfterWrite,ownerAfterWrite,writeOrdinal,events;
 uint32_t nativeISA;
 struct {char kind;uint32_t offset;size_t bytes;uint64_t value;} trace[16];
} VtimerMock;
static uint64_t VtimerThread(void *p) {
 VtimerMock *m=p;uint64_t thread=Thread(&m->base);
 if(m->active && m->reenter)CHECK(hv_vcpu_set_vtimer_offset(m->base.id,UINT64_MAX)==BUSY);
 return m->active && m->ownerAfterWrite && m->writeOrdinal>=m->ownerAfterWrite?thread+1:thread;
}
static int32_t VtimerTrap(void *p,uint64_t op,void *arg) {
 VtimerMock *m=p;
 if(op==1){CHECK(arg && ((VZKernelNativeVMConfig *)arg)->nativeHVISA==m->nativeISA);++m->base.ops[1];return 0;}
 return Trap(&m->base,op,arg);
}
static void Trace(VtimerMock *m,char kind,uintptr_t offset,size_t n,uint64_t value) {
 CHECK(m->events<16 && offset<0x8000 && n<=0x8000-offset);
 m->trace[m->events].kind=kind;m->trace[m->events].offset=(uint32_t)offset;
 m->trace[m->events].bytes=n;m->trace[m->events].value=value;++m->events;
}
static bool VtimerRead(void *p,const void *a,size_t n,void *out) {
 VtimerMock *m=p;uintptr_t off=(uintptr_t)a-(uintptr_t)m->base.memory;
 if(m->active && off!=0x4000) {
  Trace(m,'R',off,n,0);
  if(m->failDirtyRead && off==0x748){++m->base.reads;return false;}
 }
 return Read(&m->base,a,n,out);
}
static bool VtimerWrite(void *p,void *a,size_t n,const void *value) {
 VtimerMock *m=p;uintptr_t off=(uintptr_t)a-(uintptr_t)m->base.memory;
 uint64_t v=0;if(n==8)memcpy(&v,value,8);
 if(m->active){Trace(m,'W',off,n,v);++m->writeOrdinal;}
 bool result=Write(&m->base,a,n,value);
 if(m->active && m->writeOrdinal==1 && m->alterDirtyAfterFirst) {
  uint64_t dirty=UINT64_C(0x8000100000000020);memcpy(m->base.memory+0x748,&dirty,8);
 }
 if(m->active && m->versionAfterWrite && m->writeOrdinal>=m->versionAfterWrite) {
  uint64_t bad=VZ_KERNEL_NATIVE_CONTEXT_VERSION^UINT64_C(0x100000000);memcpy(m->base.memory+0x4000,&bad,8);
 }
 return result && !(m->active && m->failWriteOrdinal==m->writeOrdinal);
}
static uint64_t Word(VtimerMock *m,uint32_t off) {
 uint64_t word=0;memcpy(&word,m->base.memory+off,8);return word;
}
static void Put(VtimerMock *m,uint32_t off,uint64_t word){memcpy(m->base.memory+off,&word,8);}
static void Clean(VtimerMock *m,bool poisoned) {
 m->active=false;m->base.reentry=false;m->base.writeFail=false;m->ownerAfterWrite=0;
 Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
 if(poisoned)CHECK(!VM27CPUFactoryOwnerCleanupV2(m->base.vm,NULL));
 else CHECK(!hv_vcpu_destroy(m->base.id));
 unsigned writes=m->base.writes;CHECK(hv_vcpu_set_vtimer_offset(m->base.id,0)==BAD && m->base.writes==writes);
 CHECK(!VM27CPUFactoryVMDestroyV2(m->base.vm,NULL));CHECK(!VM27CPUFactoryVMFreeV2(m->base.vm));
 CHECK(m->base.ops[8]==0 && m->base.ops[9]==0 && m->base.ops[6]==1 && m->base.ops[7]==1);
 CHECK(!munmap(m->base.memory,0x8000));
}
static void *VtimerForeign(void *p) {
 VtimerMock *m=p;CHECK(hv_vcpu_set_vtimer_offset(m->base.id,9)==BAD);
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());return NULL;
}

#include "modern_cpu_native_public_factory_v11.h"
typedef struct {VtimerMock base;uint32_t failReadAt;}DebugMock;
static uint64_t DebugThread(void *p) {
 DebugMock *m=p;uint64_t thread=VtimerThread(&m->base);
 if(m->base.active && m->base.reenter) {
  CHECK(hv_vcpu_set_trap_debug_exceptions(m->base.base.id,true)==BUSY);
  CHECK(hv_vcpu_set_trap_debug_reg_accesses(m->base.base.id,false)==BUSY);
 }
 return thread;
}
static bool DebugRead(void *p,const void *a,size_t n,void *out) {
 DebugMock *m=p;uintptr_t off=(uintptr_t)a-(uintptr_t)m->base.base.memory;
 if(m->base.active && m->failReadAt==off) {
  Trace(&m->base,'R',off,n,0);++m->base.base.reads;return false;
 }
 return VtimerRead(&m->base,a,n,out);
}
static void CreateDebug(DebugMock *m,uint32_t isa) {
 memset(m,0,sizeof(*m));After9=false;RunPostOwnerFail=false;RunPostVersionFail=false;
 VtimerMock *b=&m->base;b->nativeISA=isa;
 b->base.memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(b->base.memory!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,VtimerTrap,DebugThread,DebugRead};
 VZKernelVMOptions options={36,0,isa,false,false};VZKernelInitWriter writer={m,VtimerWrite};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&b->base.vm,NULL));
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&b->base.id,&exit,NULL));CHECK(b->base.id && exit);
 Put(b,0x670,UINT64_C(0xabcdef0123456789));Put(b,0x678,UINT64_C(0x1020304050607080));
 Put(b,0x748,UINT64_C(0x8000000000000020));b->active=true;
}
static void *DebugForeign(void *p) {
 DebugMock *m=p;CHECK(hv_vcpu_set_trap_debug_exceptions(m->base.base.id,true)==BAD);
 CHECK(hv_vcpu_set_trap_debug_reg_accesses(m->base.base.id,false)==BAD);
 return VtimerForeign(&m->base);
}
static void DebugSuccess(uint32_t isa) {
 DebugMock m;CreateDebug(&m,isa);VtimerMock *b=&m.base;
 hv_return_t (*typed[2])(hv_vcpu_t,bool)={hv_vcpu_set_trap_debug_exceptions,hv_vcpu_set_trap_debug_reg_accesses};
 unsigned reads=b->base.reads,writes=b->base.writes;
 CHECK(typed[0](UINT64_MAX,true)==BAD && typed[1](UINT64_MAX,false)==BAD);
 pthread_t t;CHECK(!pthread_create(&t,NULL,DebugForeign,&m));CHECK(!pthread_join(t,NULL));
 CHECK(b->base.reads==reads && b->base.writes==writes);
 const uint64_t seed=UINT64_C(0xdeadbeef89abcf00);
 for(unsigned kind=0;kind<2;++kind)for(unsigned enabled=0;enabled<2;++enabled) {
  Put(b,0x688,seed);Put(b,0x678,UINT64_C(0x1020304050607080));
  Put(b,0x670,UINT64_C(0xabcdef0123456789));Put(b,0x748,UINT64_C(0x8000000000000020));
  b->events=0;b->writeOrdinal=0;b->reenter=true;b->base.reentry=true;
  CHECK(!typed[kind](b->base.id,(bool)enabled));b->reenter=false;b->base.reentry=false;
  uint64_t mask=UINT64_C(1)<<(8+kind),expected=(seed&~mask)|(enabled?mask:0);
  CHECK(Word(b,0x688)==expected && (Word(b,0x688)>>32)==(seed>>32));
  CHECK(Word(b,0x678)==(UINT64_C(0x1020304050607080)|(UINT64_C(1)<<56)));
  CHECK(Word(b,0x670)==(UINT64_C(0xabcdef0123456789)|(UINT64_C(1)<<18)));
  CHECK(Word(b,0x748)==UINT64_C(0x8000000000000024));CHECK(b->events==8 && b->writeOrdinal==4);
  const uint32_t offsets[]={0x688,0x688,0x678,0x678,0x670,0x670,0x748,0x748};
  for(unsigned i=0;i<8;++i)CHECK(b->trace[i].kind==(i%2?'W':'R') && b->trace[i].offset==offsets[i] && b->trace[i].bytes==8);
  CHECK(b->base.ops[8]==0 && b->base.ops[9]==0);
 }
 VM27CPUFactoryBorrowV2 *borrow=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(b->base.id,&borrow));
 VZKernelInitReceipt r={0};VM27CPUFactoryDiagnosticV2 diag={0};b->events=0;b->writeOrdinal=0;
 CHECK(!VM27CPUFactoryBorrowSetDebugTrapV11(borrow,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,false,&r,&diag));
 CHECK(r.attemptedReads==4 && r.attemptedWrites==4 && r.completedWrites==4 && !r.mutationPoisoned);
 CHECK(!r.runAllowed && !r.architecturalResetComplete && r.cpuCleanupRequired && !diag.nativeInvoked);
 reads=b->base.reads;writes=b->base.writes;
 CHECK(VM27CPUFactoryBorrowSetDebugTrapV11(borrow,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,true,(VZKernelInitReceipt *)(void *)(b->base.memory+8),NULL)==BAD);
 CHECK(VM27CPUFactoryBorrowSetDebugTrapV11(borrow,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,true,&r,(VM27CPUFactoryDiagnosticV2 *)(void *)(b->base.memory+8))==BAD);
 CHECK(VM27CPUFactoryBorrowSetDebugTrapV11(borrow,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,true,(VZKernelInitReceipt *)(void *)borrow,NULL)==BAD);
 CHECK(b->base.reads==reads && b->base.writes==writes);
 VM27CPUFactoryViewV2 view={0};CHECK(!VM27CPUFactoryBorrowViewV2(borrow,&view));
 VZKernelCPUBorrowV5 *kernelBorrow=NULL;VZKernelCPU *cpu=NULL;
 CHECK(!VZKernelCPUBorrowIdentityV5(b->base.id,&kernelBorrow));CHECK(!VZKernelCPUBorrowHandleV5(kernelBorrow,&cpu));
 uint64_t owner=0;CHECK(!pthread_threadid_np(NULL,&owner));
 VZKernelDebugRequestV13 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,isa,0,view.vmEpoch,view.identity,owner,view.cpuGeneration,0,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,false,{0}};
 VZKernelInitWriter writer={&m,VtimerWrite};VZKernelLifecycleResult lifecycle={0};
 ++q.expectedVMEpoch;writes=b->base.writes;reads=b->base.reads;
 CHECK(VZKernelCPUSetDebugTrapV13(cpu,&q,&writer,&r,&lifecycle)==VZ_KERNEL_BAD_ARGUMENT);--q.expectedVMEpoch;
 CHECK(b->base.reads==reads && b->base.writes==writes);
 q.kind=(VZKernelDebugKindV13)3;CHECK(VZKernelCPUSetDebugTrapV13(cpu,&q,&writer,&r,&lifecycle)==VZ_KERNEL_UNSUPPORTED);q.kind=VZ_KERNEL_DEBUG_EXCEPTIONS_V13;
 CHECK(VZKernelCPUSetDebugTrapV13(cpu,&q,&writer,(VZKernelInitReceipt *)(void *)&q,&lifecycle)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VZKernelCPUSetDebugTrapV13(cpu,&q,&writer,(VZKernelInitReceipt *)(void *)(b->base.memory+0x688),&lifecycle)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(!VZKernelCPUReleaseBorrowV5(kernelBorrow));CHECK(!VM27CPUFactoryBorrowReleaseV2(borrow));
 // Validate the real split mapping: read-only metadata with writable controls.
 CHECK(!mprotect(b->base.memory+0x4000,0x4000,PROT_READ));b->events=0;b->writeOrdinal=0;
 CHECK(!typed[0](b->base.id,true) && !typed[1](b->base.id,false));
 CHECK(!mprotect(b->base.memory+0x4000,0x4000,PROT_READ|PROT_WRITE));
 CHECK(!mprotect(b->base.memory,0x8000,PROT_READ));writes=b->base.writes;
 CHECK(typed[0](b->base.id,false)==ERROR && b->base.writes==writes);
 CHECK(!mprotect(b->base.memory,0x8000,PROT_READ|PROT_WRITE));Clean(b,false);
}
static void DebugFailures(void) {
 for(unsigned kind=0;kind<10;++kind) {
  DebugMock m;CreateDebug(&m,1);VtimerMock *b=&m.base;
  if(kind==0)m.failReadAt=0x688;
  else if(kind<=4)b->failWriteOrdinal=kind;
  else if(kind<=7)m.failReadAt=(uint32_t[]){0x678,0x670,0x748}[kind-5];
  else if(kind==8)b->versionAfterWrite=4;else b->ownerAfterWrite=4;
  VM27CPUFactoryBorrowV2 *borrow=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(b->base.id,&borrow));VZKernelInitReceipt r={0};
  hv_return_t status=VM27CPUFactoryBorrowSetDebugTrapV11(borrow,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,true,&r,NULL);
  CHECK(status==(kind==9?BAD:ERROR));CHECK(r.mutationPoisoned==(kind!=0) && r.cpuCleanupRequired && !r.runAllowed);
  if(kind==0) {
   CHECK(!r.attemptedWrites && r.attemptedReads==1 && r.failedNativeOffset==0x688);
   m.failReadAt=0;b->events=0;b->writeOrdinal=0;CHECK(!hv_vcpu_set_trap_debug_exceptions(b->base.id,true));
  } else {
   CHECK(r.attemptedWrites==(kind<=4?kind:kind<=7?kind-4:4));
   CHECK(Word(b,0x688)&UINT64_C(0x100));
   if(kind<=4)CHECK(r.failedWriteOrdinal==kind && r.completedWrites==kind-1);
   unsigned writes=b->base.writes;CHECK(hv_vcpu_set_trap_debug_exceptions(b->base.id,false)==BAD && b->base.writes==writes);
   b->active=false;Put(b,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
   CHECK(VM27CPUFactoryOwnerCleanupV2(b->base.vm,NULL)==BUSY && b->base.ops[7]==0);
  }
  CHECK(!VM27CPUFactoryBorrowReleaseV2(borrow));Clean(b,kind!=0);
 }
}
#if VM27_VTIMER_RELEASE_TEST
static void DebugRelease(void) {
 for(unsigned kind=0;kind<3;++kind) {
  DebugMock m;CreateDebug(&m,1);VtimerMock *b=&m.base;
  if(kind==1)b->failWriteOrdinal=1;else if(kind==2)m.failReadAt=0x748;
  HoldRelease=true;CHECK(hv_vcpu_set_trap_debug_exceptions(b->base.id,true)==(kind?ERROR:BUSY));
  unsigned writes=b->base.writes;CHECK(hv_vcpu_set_trap_debug_reg_accesses(b->base.id,true)==BUSY && b->base.writes==writes);
  CHECK(hv_vcpu_destroy(b->base.id)==BUSY && b->base.ops[7]==0);
  CHECK(VM27CPUFactoryOwnerCleanupV2(b->base.vm,NULL)==BUSY && b->base.ops[7]==0);
  CHECK(VM27CPUFactoryPublicDrainBorrowV6()==BUSY);
  pthread_t t;CHECK(!pthread_create(&t,NULL,DebugForeign,&m));CHECK(!pthread_join(t,NULL));
  HoldRelease=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());Clean(b,true);
 }
 CHECK(ReleaseAttempts>ReleaseSuccesses);
}
#endif
int main(void) {
 alarm(20);DebugSuccess(1);DebugSuccess(2);DebugFailures();
#if VM27_VTIMER_RELEASE_TEST
 DebugRelease();
#endif
 uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);
 CHECK(created==destroyed && created==(VM27_VTIMER_RELEASE_TEST?15:12));
 printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"releaseFaultInjected\":%s,\"exactNativeFieldWrites\":4,\"falsePreservesHigh32\":true,\"native8\":0,\"native9\":0,\"full27Backend\":false}\n",Checks,
  (unsigned long long)created,(unsigned long long)destroyed,VM27_VTIMER_RELEASE_TEST?"true":"false");
 return 0;
}
