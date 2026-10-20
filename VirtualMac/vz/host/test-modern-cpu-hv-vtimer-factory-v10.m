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
static void Create(VtimerMock *m,uint32_t isa) {
 memset(m,0,sizeof(*m));After9=false;RunPostOwnerFail=false;RunPostVersionFail=false;
 m->nativeISA=isa;m->base.memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m->base.memory!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,VtimerTrap,VtimerThread,VtimerRead};
 VZKernelVMOptions options={36,0,isa,false,false};VZKernelInitWriter writer={m,VtimerWrite};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m->base.vm,NULL));
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m->base.id,&exit,NULL));CHECK(m->base.id && exit);
 Put(m,0x670,UINT64_C(0xabcdef0123456789));Put(m,0x678,UINT64_C(0x1020304050607080));
 Put(m,0x748,UINT64_C(0x8000000000000020));m->active=true;
}
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
static void SuccessCases(uint32_t isa) {
 VtimerMock m;Create(&m,isa);hv_return_t (*typed)(hv_vcpu_t,uint64_t)=hv_vcpu_set_vtimer_offset;
 unsigned reads=m.base.reads,writes=m.base.writes;
 CHECK(typed(UINT64_MAX,55)==BAD && m.base.reads==reads && m.base.writes==writes);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,VtimerForeign,&m));CHECK(!pthread_join(foreign,NULL));
 CHECK(m.base.reads==reads && m.base.writes==writes);
 const uint64_t values[]={0,UINT64_MAX,UINT64_C(0x123456789abcdef0)};
 for(unsigned i=0;i<3;++i) {
  m.events=0;m.writeOrdinal=0;m.alterDirtyAfterFirst=i==2;m.reenter=true;m.base.reentry=true;
  CHECK(!typed(m.base.id,values[i]));m.reenter=false;m.base.reentry=false;
  CHECK(m.events==3 && m.writeOrdinal==2);
  CHECK(m.trace[0].kind=='W' && m.trace[0].offset==0x6a0 && m.trace[0].bytes==8 && m.trace[0].value==values[i]);
  CHECK(m.trace[1].kind=='R' && m.trace[1].offset==0x748 && m.trace[1].bytes==8);
  CHECK(m.trace[2].kind=='W' && m.trace[2].offset==0x748 && m.trace[2].bytes==8);
  CHECK(Word(&m,0x6a0)==values[i] && Word(&m,0x748)==(i==2?UINT64_C(0x8000100000000024):UINT64_C(0x8000000000000024)));
  CHECK(Word(&m,0x670)==UINT64_C(0xabcdef0123456789) && Word(&m,0x678)==UINT64_C(0x1020304050607080));
  CHECK(m.base.ops[8]==0 && m.base.ops[9]==0);
 }
 VM27CPUFactoryBorrowV2 *borrow=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(m.base.id,&borrow));
 VZKernelInitReceipt receipt={0};VM27CPUFactoryDiagnosticV2 diagnostic={0};m.events=0;m.writeOrdinal=0;
 CHECK(!VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,55,&receipt,&diagnostic));
 CHECK(receipt.status==VZ_KERNEL_OK && receipt.attemptedWrites==2 && receipt.completedWrites==2 && receipt.attemptedReads==1);
 CHECK(receipt.failedWriteOrdinal==UINT32_MAX && receipt.failedNativeOffset==UINT32_MAX && !receipt.mutationPoisoned &&
  receipt.cpuCleanupRequired && receipt.creationPolicySliceComplete && !receipt.architecturalResetComplete && !receipt.runAllowed);
 CHECK(diagnostic.vmEpoch && diagnostic.cpuGeneration && !diagnostic.nativeInvoked);
 reads=m.base.reads;writes=m.base.writes;
 CHECK(VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,99,(VZKernelInitReceipt *)(void *)(m.base.memory+8),NULL)==BAD);
 CHECK(VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,99,&receipt,(VM27CPUFactoryDiagnosticV2 *)(void *)(m.base.memory+8))==BAD);
 CHECK(VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,99,(VZKernelInitReceipt *)(void *)borrow,NULL)==BAD);
 CHECK(VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,99,&receipt,(VM27CPUFactoryDiagnosticV2 *)(void *)&receipt)==BAD);
 CHECK(m.base.reads==reads && m.base.writes==writes);
 VM27CPUFactoryViewV2 view={0};CHECK(!VM27CPUFactoryBorrowViewV2(borrow,&view));
 VZKernelCPUBorrowV5 *kernelBorrow=NULL;VZKernelCPU *cpu=NULL;
 CHECK(!VZKernelCPUBorrowIdentityV5(m.base.id,&kernelBorrow));CHECK(!VZKernelCPUBorrowHandleV5(kernelBorrow,&cpu));
 uint64_t owner=0;CHECK(!pthread_threadid_np(NULL,&owner));
 VZKernelVtimerRequestV12 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,isa,0,view.vmEpoch,view.identity,owner,view.cpuGeneration,0,UINT64_C(0xfeed)};
 VZKernelInitWriter writer={&m,VtimerWrite};VZKernelLifecycleResult lifecycle={0};
 for(unsigned i=0;i<5;++i) {
  VZKernelVtimerRequestV12 bad=q;
  switch(i){case 0:++bad.expectedVMEpoch;break;case 1:++bad.expectedPublicIdentity;break;
   case 2:++bad.expectedOwnerThread;break;case 3:++bad.expectedCPUGeneration;break;default:++bad.expectedReturnedSlotWord;break;}
  writes=m.base.writes;reads=m.base.reads;
  CHECK(VZKernelCPUSetVtimerOffsetV12(cpu,&bad,&writer,&receipt,&lifecycle)==VZ_KERNEL_BAD_ARGUMENT);
  CHECK(m.base.writes==writes && m.base.reads==reads && !receipt.mutationPoisoned);
 }
 q.nativeHVISA=3;CHECK(VZKernelCPUSetVtimerOffsetV12(cpu,&q,&writer,&receipt,&lifecycle)==VZ_KERNEL_UNSUPPORTED);q.nativeHVISA=isa;
 writes=m.base.writes;reads=m.base.reads;
 CHECK(VZKernelCPUSetVtimerOffsetV12(cpu,&q,&writer,(VZKernelInitReceipt *)(void *)&q,&lifecycle)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VZKernelCPUSetVtimerOffsetV12(cpu,&q,&writer,(VZKernelInitReceipt *)(void *)(m.base.memory+0x6a0),&lifecycle)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(m.base.writes==writes && m.base.reads==reads);
 CHECK(!VZKernelCPUReleaseBorrowV5(kernelBorrow));CHECK(!VM27CPUFactoryBorrowReleaseV2(borrow));
 // A version or mapping refusal before the first write is recoverable, and
 // must not be presented as proof of a rolled-back failed write.
 m.events=0;m.writeOrdinal=0;Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION^1);writes=m.base.writes;
 CHECK(typed(m.base.id,66)==ERROR && m.base.writes==writes);Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 CHECK(!mprotect(m.base.memory,0x8000,PROT_READ));CHECK(typed(m.base.id,66)==ERROR && m.base.writes==writes);
 CHECK(!mprotect(m.base.memory,0x8000,PROT_READ|PROT_WRITE));CHECK(!typed(m.base.id,66));
 // Read-only version/exit metadata must not prohibit the two writable timer
 // fields. These are actual split Mach mappings, not a permission mock.
 CHECK(!mprotect(m.base.memory+0x4000,0x4000,PROT_READ));m.events=0;m.writeOrdinal=0;
 CHECK(!typed(m.base.id,UINT64_C(0x9876543212345678)) && Word(&m,0x6a0)==UINT64_C(0x9876543212345678));
 CHECK(m.events==3 && m.writeOrdinal==2);
 CHECK(!mprotect(m.base.memory+0x4000,0x4000,PROT_READ|PROT_WRITE));
 Clean(&m,false);
}
static void FailureCases(void) {
 for(unsigned kind=0;kind<7;++kind) {
  VtimerMock m;Create(&m,1);VM27CPUFactoryBorrowV2 *borrow=NULL;
  CHECK(!VM27CPUFactoryBorrowAcquireV2(m.base.id,&borrow));VZKernelInitReceipt r={0};
  switch(kind){case 0:m.failWriteOrdinal=1;break;case 1:m.failDirtyRead=true;break;
   case 2:m.failWriteOrdinal=2;break;case 3:m.versionAfterWrite=1;break;
   case 4:m.versionAfterWrite=2;break;case 5:m.ownerAfterWrite=1;break;default:m.ownerAfterWrite=2;break;}
  hv_return_t status=VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,UINT64_C(0x12345678abcdef01),&r,NULL);
  CHECK(status==(kind>=5?BAD:ERROR));CHECK(r.mutationPoisoned && r.cpuCleanupRequired && !r.runAllowed);
  CHECK(r.attemptedWrites==(kind==2 || kind==4 || kind==6?2:1));
  CHECK(r.completedWrites==(kind==0?0:kind==2?1:kind==4 || kind==6?2:1));
  CHECK(Word(&m,0x6a0)==UINT64_C(0x12345678abcdef01));
  if(kind==0 || kind==2)CHECK(r.failedWriteOrdinal==(kind==0?1:2) && r.failedNativeOffset==(kind==0?0x6a0:0x748));
  unsigned writes=m.base.writes;CHECK(hv_vcpu_set_vtimer_offset(m.base.id,999)==BAD && m.base.writes==writes);
  m.active=false;Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
  CHECK(VM27CPUFactoryOwnerCleanupV2(m.base.vm,NULL)==BUSY && m.base.ops[7]==0);
  CHECK(!VM27CPUFactoryBorrowReleaseV2(borrow));Clean(&m,true);
 }
}
#if VM27_VTIMER_RELEASE_TEST
static void ReleaseCases(void) {
 VtimerMock m;Create(&m,1);HoldRelease=true;
 CHECK(hv_vcpu_set_vtimer_offset(m.base.id,0x99)==BUSY && Word(&m,0x6a0)==0x99);
 unsigned writes=m.base.writes;
 CHECK(hv_vcpu_set_vtimer_offset(m.base.id,0xaa)==BUSY && m.base.writes==writes);
 CHECK(hv_vcpu_destroy(m.base.id)==BUSY && m.base.ops[7]==0);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.base.vm,NULL)==BUSY && m.base.ops[7]==0);
 CHECK(VM27CPUFactoryPublicDrainBorrowV6()==BUSY);
 // Another pthread has empty public TLS and cannot drain the owner's borrow.
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,VtimerForeign,&m));CHECK(!pthread_join(thread,NULL));
 HoldRelease=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
 // OwnerCleanup has already withdrawn this ID; retained state is cleaned by
 // the actual owner after drain rather than publishing a new success.
 Clean(&m,true);CHECK(ReleaseAttempts>ReleaseSuccesses);
}
#endif
int main(void) {
 alarm(20);SuccessCases(1);SuccessCases(2);FailureCases();
#if VM27_VTIMER_RELEASE_TEST
 ReleaseCases();
#endif
 uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);
 CHECK(created==destroyed && created==(VM27_VTIMER_RELEASE_TEST?10:9));
 printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"releaseFaultInjected\":%s,\"exactNativeFieldWrites\":2,\"native8\":0,\"native9\":0,\"full27Backend\":false}\n",Checks,
  (unsigned long long)created,(unsigned long long)destroyed,VM27_VTIMER_RELEASE_TEST?"true":"false");
 return 0;
}
