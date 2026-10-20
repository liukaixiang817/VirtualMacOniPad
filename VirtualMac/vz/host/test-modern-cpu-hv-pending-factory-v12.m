#define main VM27InheritedFactory8FixtureMain
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type"
#include "test-modern-cpu-hv-public-factory-v8.m"
#pragma clang diagnostic pop
#undef main
#include "modern_cpu_native_public_factory_v12.h"
#ifndef VM27_PENDING_RELEASE_TEST
#define VM27_PENDING_RELEASE_TEST 0
#endif
#if VM27_PENDING_RELEASE_TEST
static bool HoldRelease;static unsigned ReleaseAttempts,ReleaseSuccesses;
extern VZKernelStatus OwnRealCPUReleaseBorrow(VZKernelCPUBorrowV5 *);
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *b) {
 ++ReleaseAttempts;if(HoldRelease)return VZ_KERNEL_BUSY;
 VZKernelStatus s=OwnRealCPUReleaseBorrow(b);if(!s)++ReleaseSuccesses;return s;
}
#endif
typedef struct {
 Mock base;hv_vcpu_exit_t *exit;uint32_t isa;
 bool active,reenter,modifyPostControl;
 unsigned events,writeOrdinal,readOrdinal,failWrite,failRead,ownerAfterWrite,versionAfterWrite;
 uint64_t expectedEntry,postControl;
 struct {char kind;uint32_t offset;uint64_t value;} trace[32];
} PendingMock;
static uint64_t PWord(PendingMock *m,uint32_t off){uint64_t v;memcpy(&v,m->base.memory+off,8);return v;}
static void PPut(PendingMock *m,uint32_t off,uint64_t v){memcpy(m->base.memory+off,&v,8);}
static void PTrace(PendingMock *m,char kind,uint32_t off,uint64_t value) {
 CHECK(m->events<32);m->trace[m->events].kind=kind;m->trace[m->events].offset=off;
 m->trace[m->events].value=value;++m->events;
}
static void PReenter(PendingMock *m) {
 if(!m->active || !m->reenter)return;
 bool pending=true;CHECK(hv_vcpu_get_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_IRQ,&pending)==BUSY && pending);
 CHECK(hv_vcpu_set_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_FIQ,false)==BUSY);
 CHECK(hv_vcpu_set_vtimer_offset(m->base.id,9)==BUSY);
 CHECK(hv_vcpu_set_trap_debug_exceptions(m->base.id,true)==BUSY);
 CHECK(VM27CPUFactoryVMDestroyV2(m->base.vm,NULL)==BUSY);
}
static uint64_t PThread(void *p) {
 PendingMock *m=p;PReenter(m);uint64_t owner=Thread(&m->base);
 return m->active && m->ownerAfterWrite && m->writeOrdinal>=m->ownerAfterWrite?owner+1:owner;
}
static int32_t PTrap(void *p,uint64_t op,void *arg) {
 PendingMock *m=p;PReenter(m);
 if(op==1){CHECK(arg && ((VZKernelNativeVMConfig *)arg)->nativeHVISA==m->isa);++m->base.ops[1];return 0;}
 if(op==9 && m->active) {
  PTrace(m,'N',9,0);CHECK(PWord(m,0x670)==m->expectedEntry);
  if(m->modifyPostControl) {
   // Genuine kernel consumes dirty and may change current controls. This
   // supplied post state differs in upper32 bits from the pre-entry state.
   PPut(m,0x670,m->postControl);PPut(m,0x678,UINT64_C(0x2468ace013579bdf));PPut(m,0x748,0);
  }
 }
 return Trap(&m->base,op,arg);
}
static bool PRead(void *p,const void *a,size_t n,void *out) {
 PendingMock *m=p;uintptr_t off=(uintptr_t)a-(uintptr_t)m->base.memory;PReenter(m);
 if(m->active && (off==0x670 || off==0x678 || off==0x748)) {
  CHECK(n==8);PTrace(m,'R',(uint32_t)off,0);++m->readOrdinal;
  if(m->failRead==m->readOrdinal){++m->base.reads;return false;}
 }
 return Read(&m->base,a,n,out);
}
static bool PWrite(void *p,void *a,size_t n,const void *value) {
 PendingMock *m=p;uintptr_t off=(uintptr_t)a-(uintptr_t)m->base.memory;PReenter(m);
 if(m->active){uint64_t v=0;CHECK(n==8);memcpy(&v,value,8);PTrace(m,'W',(uint32_t)off,v);++m->writeOrdinal;}
 bool result=Write(&m->base,a,n,value);
 if(m->active && m->versionAfterWrite && m->writeOrdinal>=m->versionAfterWrite)
  PPut(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION^UINT64_C(0x100000000));
 return result && !(m->active && m->failWrite==m->writeOrdinal);
}
static void PCreate(PendingMock *m,uint32_t isa) {
 memset(m,0,sizeof(*m));After9=false;RunPostOwnerFail=RunPostVersionFail=RunReadFail=false;
 RunReason=1;RunSyndrome=0x96000004;RunReturn=0;m->isa=isa;
 m->base.memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m->base.memory!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,PTrap,PThread,PRead};
 VZKernelVMOptions options={36,0,isa,false,false};VZKernelInitWriter writer={m,PWrite};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m->base.vm,NULL));
 CHECK(!hv_vcpu_create(&m->base.id,&m->exit,NULL));CHECK(m->base.id && m->exit);
}
static void PPrepare(PendingMock *m,bool irq,bool fiq) {
 m->active=false;After9=false;CHECK(!hv_vcpu_set_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_IRQ,irq));
 CHECK(!hv_vcpu_set_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_FIQ,fiq));
 const uint64_t initial=UINT64_C(0xabcdef0180000030);
 PPut(m,0x670,initial);PPut(m,0x678,UINT64_C(0x1020304050607080));PPut(m,0x748,UINT64_C(0x8000000000000020));
 uint64_t mask=(irq?UINT64_C(0x80):0)|(fiq?UINT64_C(0x40):0);
 m->expectedEntry=initial|mask|(mask?(UINT64_C(1)<<18):0);
 m->postControl=UINT64_C(0x76543210f00001f0);m->modifyPostControl=true;
 m->events=m->writeOrdinal=m->readOrdinal=0;m->active=true;
}
static void PClean(PendingMock *m,bool poisoned) {
 m->active=false;m->base.reentry=false;m->reenter=false;m->ownerAfterWrite=0;
 RunPostOwnerFail=RunPostVersionFail=RunReadFail=false;PPut(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
 if(poisoned)CHECK(!VM27CPUFactoryOwnerCleanupV2(m->base.vm,NULL));else CHECK(!hv_vcpu_destroy(m->base.id));
 bool out=true;CHECK(hv_vcpu_get_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_IRQ,&out)==BAD && out);
 CHECK(!VM27CPUFactoryVMDestroyV2(m->base.vm,NULL));CHECK(!VM27CPUFactoryVMFreeV2(m->base.vm));
 CHECK(m->base.ops[8]==0 && m->base.ops[6]==1 && m->base.ops[7]==1);
 CHECK(!munmap(m->base.memory,0x8000));
}
static void *PForeign(void *p) {
 PendingMock *m=p;bool out=true;
 CHECK(hv_vcpu_get_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_IRQ,&out)==BAD && out);
 CHECK(hv_vcpu_set_pending_interrupt(m->base.id,HV_INTERRUPT_TYPE_IRQ,true)==BAD);
 CHECK(hv_vcpu_run(m->base.id)==BAD);return NULL;
}
static void PSuccess(uint32_t isa) {
 PendingMock m;PCreate(&m,isa);
 _Static_assert(sizeof(hv_interrupt_type_t)==4 && sizeof(bool)==1,"actual SDK pending caller ABI");
 hv_return_t (*get)(hv_vcpu_t,hv_interrupt_type_t,bool *)=hv_vcpu_get_pending_interrupt;
 hv_return_t (*set)(hv_vcpu_t,hv_interrupt_type_t,bool)=hv_vcpu_set_pending_interrupt;
 for(unsigned irq=0;irq<2;++irq)for(unsigned fiq=0;fiq<2;++fiq) {
  PPrepare(&m,irq,fiq);bool out=false;CHECK(!get(m.base.id,HV_INTERRUPT_TYPE_IRQ,&out) && out==(bool)irq);
  CHECK(!get(m.base.id,HV_INTERRUPT_TYPE_FIQ,&out) && out==(bool)fiq);
  unsigned reads=m.base.reads,writes=m.base.writes,calls=m.base.ops[9];out=true;
  CHECK(get(m.base.id,(hv_interrupt_type_t)2,&out)==BAD && out);
  CHECK(set(m.base.id,(hv_interrupt_type_t)2,true)==BAD);
  CHECK(get(UINT64_MAX,HV_INTERRUPT_TYPE_IRQ,&out)==BAD && out);
  CHECK(get(m.base.id,HV_INTERRUPT_TYPE_IRQ,NULL)==BAD);
  CHECK(get(m.base.id,HV_INTERRUPT_TYPE_IRQ,(bool *)m.exit)==BAD);
  CHECK(get(m.base.id,HV_INTERRUPT_TYPE_IRQ,(bool *)(void *)(m.base.memory+0x670))==BAD);
  CHECK(get(m.base.id,HV_INTERRUPT_TYPE_IRQ,(bool *)(void *)1)==BAD);
  VM27CPUFactoryBorrowV2 *owned=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(m.base.id,&owned));
  VM27CPUFactoryRunDiagnosticV3 untouched,saved;memset(&untouched,0xa5,sizeof(untouched));saved=untouched;
  CHECK(VM27CPUFactoryRunOwnedStepV3(NULL,&untouched)==BAD && !memcmp(&untouched,&saved,sizeof(saved)));
  CHECK(VM27CPUFactoryRunOwnedStepV3(owned,(VM27CPUFactoryRunDiagnosticV3 *)(void *)m.base.memory)==BAD);
  CHECK(VM27CPUFactoryRunOwnedStepV3(owned,(VM27CPUFactoryRunDiagnosticV3 *)(void *)owned)==BAD);
  CHECK(VM27CPUFactoryRunOwnedStepV3(owned,(VM27CPUFactoryRunDiagnosticV3 *)(void *)1)==BAD);
  CHECK(m.base.ops[9]==calls && m.base.writes==writes);
  CHECK(!VM27CPUFactoryBorrowReleaseV2(owned));
  pthread_t t;CHECK(!pthread_create(&t,NULL,PForeign,&m));CHECK(!pthread_join(t,NULL));
  CHECK(m.base.writes==writes && m.base.ops[9]==calls && m.base.reads>=reads);
  m.reenter=m.base.reentry=true;CHECK(!hv_vcpu_run(m.base.id));m.reenter=m.base.reentry=false;
  CHECK(m.base.ops[9]==calls+1 && ExitValid(&m.base,m.exit));
  CHECK(!get(m.base.id,HV_INTERRUPT_TYPE_IRQ,&out) && !out);
  CHECK(!get(m.base.id,HV_INTERRUPT_TYPE_FIQ,&out) && !out);
  if(irq || fiq) {
   CHECK(m.writeOrdinal==8 && m.readOrdinal==8 && m.events==17);
   const uint32_t offsets[]={0x670,0x670,0x678,0x678,0x670,0x670,0x748,0x748,9,
    0x670,0x670,0x678,0x678,0x670,0x670,0x748,0x748};
   for(unsigned i=0;i<17;++i)CHECK(m.trace[i].offset==offsets[i] &&
    m.trace[i].kind==(i==8?'N':(i<8?(i%2?'W':'R'):((i-9)%2?'W':'R'))));
   CHECK(PWord(&m,0x670)==((m.postControl&~UINT64_C(0xc0))|(UINT64_C(1)<<18)));
   CHECK(PWord(&m,0x678)==(UINT64_C(0x2468ace013579bdf)|(UINT64_C(1)<<56)) && PWord(&m,0x748)==4);
  } else CHECK(m.writeOrdinal==0 && m.readOrdinal==0 && m.events==1 && PWord(&m,0x670)==m.postControl);
 }
 // Genuine one-byte bool output changes no neighbor bytes.
 struct {unsigned char before;bool pending;unsigned char after;} canary={0xa5,true,0x5a};
 CHECK(!get(m.base.id,HV_INTERRUPT_TYPE_IRQ,&canary.pending) && !canary.pending && canary.before==0xa5 && canary.after==0x5a);
 PClean(&m,false);
}
static void PStatuses(void) {
 for(unsigned scenario=0;scenario<4;++scenario) {
  PendingMock m;PCreate(&m,1);PPrepare(&m,true,true);
  unsigned char saved[32];memcpy(saved,m.exit,32);
  if(scenario==0)RunReturn=-123;else if(scenario==1)RunReason=11;else if(scenario==2)RunReason=99;else RunReadFail=true;
  hv_return_t expected=scenario==1?BUSY:scenario==2?(int32_t)UINT32_C(0xfae9400f):ERROR;
  CHECK(hv_vcpu_run(m.base.id)==expected && m.base.ops[9]==1 && m.writeOrdinal==8);
  CHECK(!memcmp(saved,m.exit,32) && !ExitValid(&m.base,m.exit));RunReadFail=false;
  bool out=true;CHECK(!hv_vcpu_get_pending_interrupt(m.base.id,HV_INTERRUPT_TYPE_IRQ,&out) && !out);
  CHECK(PWord(&m,0x670)==((m.postControl&~UINT64_C(0xc0))|(UINT64_C(1)<<18)));PClean(&m,false);
 }
}
static void PFailures(void) {
 for(unsigned ordinal=1;ordinal<=8;++ordinal) {
  PendingMock m;PCreate(&m,1);PPrepare(&m,true,true);m.failWrite=ordinal;
  unsigned char saved[32];memcpy(saved,m.exit,32);
  CHECK(hv_vcpu_run(m.base.id)==ERROR && m.writeOrdinal==ordinal && m.base.ops[9]==(ordinal>4));
  CHECK(!memcmp(saved,m.exit,32));bool out=true;
  CHECK(hv_vcpu_get_pending_interrupt(m.base.id,HV_INTERRUPT_TYPE_IRQ,&out)==BAD && out);
  VZKernelCPUBorrowV5 *b=NULL;CHECK(VZKernelCPUBorrowIdentityV5(m.base.id,&b)!=VZ_KERNEL_OK && !b);
  PClean(&m,true);
 }
 for(unsigned ordinal=1;ordinal<=8;++ordinal) {
  PendingMock m;PCreate(&m,1);PPrepare(&m,true,false);m.failRead=ordinal;
  CHECK(hv_vcpu_run(m.base.id)==ERROR && m.base.ops[9]==(ordinal>4));
  if(ordinal==1) {
   CHECK(m.writeOrdinal==0);bool out=false;CHECK(!hv_vcpu_get_pending_interrupt(m.base.id,HV_INTERRUPT_TYPE_IRQ,&out) && out);
   m.failRead=0;PPrepare(&m,true,false);CHECK(!hv_vcpu_run(m.base.id));PClean(&m,false);
  } else PClean(&m,true);
 }
 for(unsigned mode=0;mode<2;++mode)for(unsigned ordinal=1;ordinal<=8;++ordinal) {
  PendingMock m;PCreate(&m,1);PPrepare(&m,true,true);
  if(mode)m.ownerAfterWrite=ordinal;else m.versionAfterWrite=ordinal;
  CHECK(hv_vcpu_run(m.base.id)==(mode?BAD:ERROR) && m.writeOrdinal==ordinal && m.base.ops[9]==(ordinal>4));
  PClean(&m,true);
 }
}
static void PTypedLease(void) {
 PendingMock m;PCreate(&m,2);PPrepare(&m,true,true);
 VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 view={0};CHECK(!VM27CPUFactoryBorrowAcquireV2(m.base.id,&b));
 CHECK(!VM27CPUFactoryBorrowViewV2(b,&view));VZKernelCPUBorrowV5 *kb=NULL;VZKernelCPU *cpu=NULL;
 CHECK(!VZKernelCPUBorrowIdentityV5(m.base.id,&kb));CHECK(!VZKernelCPUBorrowHandleV5(kb,&cpu));
 uint64_t owner=0;CHECK(!pthread_threadid_np(NULL,&owner));
 VZKernelRunPendingRequestV14 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,view.vmEpoch,view.identity,owner,view.cpuGeneration,0};
 VZKernelInitWriter writer={&m,PWrite};VZKernelRunPendingReceiptV14 receipt={0};
 uint64_t *identities[]={&q.expectedVMEpoch,&q.expectedPublicIdentity,&q.expectedOwnerThread,&q.expectedCPUGeneration,&q.expectedReturnedSlotWord};
 for(unsigned i=0;i<5;++i) {
  ++*identities[i];CHECK(VZKernelCPURunOwnedPendingStepV14(cpu,&q,&writer,&receipt)==VZ_KERNEL_BAD_ARGUMENT);--*identities[i];
 }
 CHECK(VZKernelCPURunOwnedPendingStepV14(cpu,&q,&writer,(VZKernelRunPendingReceiptV14 *)(void *)m.base.memory)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(m.base.ops[9]==0 && m.writeOrdinal==0);
 RunReturn=-123;CHECK(VZKernelCPURunOwnedPendingStepV14(cpu,&q,&writer,&receipt)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(receipt.step.lifecycle.nativeInvoked && receipt.step.lifecycle.nativeReturn==-123);
 CHECK(receipt.runStatusBeforeCleanup==VZ_KERNEL_NATIVE_ERROR && receipt.cleanupStatus==VZ_KERNEL_OK);
 CHECK(receipt.entryControl.attemptedReads==4 && receipt.entryControl.completedWrites==4 &&
  receipt.returnControl.attemptedReads==4 && receipt.returnControl.completedWrites==4);
 CHECK(receipt.entryPendingMask==0xc0 && receipt.entryControlComplete && receipt.pendingCleared && receipt.returnControlComplete);
 CHECK(!receipt.mutationPoisoned && !receipt.identityWithdrawn && !receipt.step.fullPublicRunEquivalent);
 CHECK(!VZKernelCPUReleaseBorrowV5(kb));CHECK(!VM27CPUFactoryBorrowReleaseV2(b));PClean(&m,false);
}
#if VM27_PENDING_RELEASE_TEST
static void PReleaseFailure(void) {
 for(unsigned mode=0;mode<3;++mode) {
  PendingMock m;PCreate(&m,1);PPrepare(&m,true,true);bool out=true;HoldRelease=true;
  if(mode==0) {
   // Getter stages true, but failed real release leaves caller bytes intact.
   out=false;CHECK(hv_vcpu_get_pending_interrupt(m.base.id,HV_INTERRUPT_TYPE_IRQ,&out)==BUSY && !out);
  } else {
   if(mode==1)RunReturn=-123;else m.failWrite=1;
   CHECK(hv_vcpu_run(m.base.id)==ERROR && m.base.ops[9]==(mode==1));
  }
  CHECK(VM27CPUFactoryPublicDrainBorrowV6()==BUSY && VM27CPUFactoryVMDestroyV2(m.base.vm,NULL)==BUSY);
  CHECK(VM27CPUFactoryOwnerCleanupV2(m.base.vm,NULL)==BUSY);
  CHECK(hv_vcpu_set_pending_interrupt(m.base.id,HV_INTERRUPT_TYPE_IRQ,false)==BUSY);
  // OwnerCleanup deliberately withdrew the ID before reporting BUSY. Its
  // same real owner must resume that cleanup after the retained borrow drains.
  HoldRelease=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());PClean(&m,true);
 }
}
#endif
int main(void) {
 PSuccess(1);PSuccess(2);PStatuses();PFailures();PTypedLease();
#if VM27_PENDING_RELEASE_TEST
 PReleaseFailure();
#endif
 uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);CHECK(created==destroyed);
 printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"releaseFaultInjected\":%s,\"actualNativeCalls\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",
  Checks,(unsigned long long)created,(unsigned long long)destroyed,VM27_PENDING_RELEASE_TEST?"true":"false");
}
