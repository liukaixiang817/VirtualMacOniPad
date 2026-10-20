#include "vm27_hv_public_vm_bootstrap_v6.h"
#include "modern_cpu_kernel_physical_timer_v19.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <pthread.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do{++Checks;if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
#define BUSY ((hv_return_t)UINT32_C(0xfae94002))
#define BAD ((hv_return_t)UINT32_C(0xfae94003))
VZKernelStatus VM27TimerModelPostV19(VZKernelPhysicalTimerOwnerV19 *,
 const VZKernelRunPendingRequestV14 *,const VZKernelInitWriter *,bool,bool,
 VZKernelPhysicalTimerActionV19,uint32_t,uint64_t,uint64_t *,VZKernelPhysicalTimerReceiptV19 *);
void VM27TimerModelRevokePostV19(VZKernelPhysicalTimerOwnerV19 *);
static unsigned Checks;
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *o){*o=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *o){*o=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){*o=(VM27CPUTLBICapabilityValueV1){0};}
typedef struct {
 unsigned char *native,*ram;unsigned calls[11],writes,routes,deadlines,quiets,reentries;
 uint64_t now,hWCTL,hWCVAL,deadline;bool ppiEnabled,ppiLevel,otherIRQ,armed;
 uint64_t hostBias;unsigned counterCalls,failCounterAt,changeBiasAt;bool badEpoch,badFrequency,unstableBias;
 bool counterFail,routeFail,deadlineFail,quietFail,writeFail,reenter,native8Fail,cpuFail;
 bool revokePostOnCounter,revokePostOnWrite;
 hv_vcpu_t id;VM27CPUFactoryVMV2 *vm;VZKernelPhysicalTimerOwnerV19 *timer;
 VZKernelRunPendingRequestV14 identity;
} Model;
static uint64_t Word(Model *m,unsigned off){uint64_t v;memcpy(&v,m->native+off,8);return v;}
static void Put(Model *m,unsigned off,uint64_t v){memcpy(m->native+off,&v,8);}
static uint64_t Thread(void *p){(void)p;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t;}
static int32_t Trap(void *p,uint64_t op,void *packet) {
 Model *m=p;CHECK(op>=1 && op<=9);++m->calls[op];
 if(op==1){CHECK(packet && ((VZKernelNativeVMConfig *)packet)->nativeHVISA==2);return 0;}
 if(op==2 || op==4){CHECK(op==2?!packet:packet!=NULL);return 0;}
 if(op==3){CHECK(packet);return 0;}
 if(op==6){CHECK(packet);((uint64_t *)packet)[1]=(uintptr_t)m->native;Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);return 0;}
 if(op==7){CHECK(!packet);return m->cpuFail?-7:0;}
 if(op==8){CHECK(!packet);if(m->native8Fail)return -8;Put(m,0x4100,Word(m,0x4100)|1);Put(m,0x438,m->hWCTL);Put(m,0x3f0,m->hWCVAL);return 0;}
 CHECK(op==9 && !packet);CHECK((Word(m,0x670)&UINT64_C(0xc0))==UINT64_C(0x80));
 uint32_t reason=1,esr=0xf2000000;memcpy(m->native+0x4008,&reason,4);memcpy(m->native+0x400c,&esr,4);
 return 0;
}
static bool Read(void *p,const void *src,size_t n,void *out) {
 Model *m=p;uintptr_t off=(uintptr_t)src-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 return VM27CPUSelfReadV1(NULL,src,n,out);
}
static void Reenter(Model *m) {
 if(!m->reenter)return;++m->reentries;
 bool pending=true;CHECK(hv_vcpu_get_pending_interrupt(m->id,HV_INTERRUPT_TYPE_IRQ,&pending)==BUSY && pending);
 CHECK(hv_vcpu_set_vtimer_offset(m->id,0)==BUSY);CHECK(hv_vm_destroy()==BUSY);
 CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY);
 VZKernelPhysicalTimerReceiptV19 r={0};VZKernelLifecycleResult l={0};
 CHECK(VZKernelPhysicalTimerOwnerAccessV19(m->timer,VZ_KERNEL_PHYSICAL_TIMER_POLL_V19,0,0,NULL,&r,&l)==VZ_KERNEL_BUSY);
}
static bool Write(void *p,void *dst,size_t n,const void *v) {
 Model *m=p;uintptr_t off=(uintptr_t)dst-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 ++m->writes;Reenter(m);bool real=VM27CPUSelfWriteV1(NULL,dst,n,v);
 if(m->revokePostOnWrite)VM27TimerModelRevokePostV19(m->timer);return real && !m->writeFail;
}
static bool Counter(void *p,VZKernelCounterDomainSampleV19 *out) {
 Model *m=p;Reenter(m);++m->counterCalls;
 if(m->revokePostOnCounter)VM27TimerModelRevokePostV19(m->timer);
 if(m->counterFail || m->counterCalls==m->failCounterAt)return false;
 if(m->counterCalls==m->changeBiasAt)m->hostBias=100;
 *out=(VZKernelCounterDomainSampleV19){m->now,m->now+m->hostBias+(m->badEpoch?1:0),m->now,
  m->badFrequency?24000001:24000000,m->hostBias,m->hostBias+(m->unstableBias?1:0),125,3,3,3,1,1};
 return true;
}
static VZKernelStatus Validate(void *p,const VZKernelRunPendingRequestV14 *q) {
 Model *m=p;CHECK(!memcmp(q,&m->identity,sizeof(*q)));CHECK(q->expectedOwnerThread==Thread(m));return VZ_KERNEL_OK;
}
static VZKernelStatus Route(void *p,const VZKernelRunPendingRequestV14 *q,bool level,bool *out) {
 Model *m=p;CHECK(Validate(m,q)==VZ_KERNEL_OK);++m->routes;Reenter(m);m->ppiLevel=level;
 if(m->routeFail)return VZ_KERNEL_NATIVE_ERROR;*out=m->otherIRQ || (m->ppiEnabled && level);return VZ_KERNEL_OK;
}
static VZKernelStatus Deadline(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t when) {
 Model *m=p;CHECK(Validate(m,q)==VZ_KERNEL_OK);++m->deadlines;Reenter(m);m->armed=arm;m->deadline=when;
 return m->deadlineFail?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
}
static VZKernelStatus Quiet(void *p,const VZKernelRunPendingRequestV14 *q) {
 Model *m=p;CHECK(Validate(m,q)==VZ_KERNEL_OK);++m->quiets;
 if(m->quietFail)return VZ_KERNEL_NATIVE_ERROR;m->armed=false;m->ppiLevel=false;return VZ_KERNEL_OK;
}
static VZKernelStatus Access(Model *m,unsigned action,uint32_t id,uint64_t value,uint64_t *out,
 VZKernelPhysicalTimerReceiptV19 *r) {
 VZKernelLifecycleResult l={0};return VZKernelPhysicalTimerOwnerAccessV19(m->timer,action,id,value,out,r,&l);
}
static void *Foreign(void *p) {
 Model *m=p;VZKernelPhysicalTimerReceiptV19 r={0};uint64_t output=99;
 CHECK(Access(m,VZ_KERNEL_PHYSICAL_TIMER_READ_V19,0xdf11,0,&output,&r)==VZ_KERNEL_WRONG_THREAD && output==99);
 CHECK(VZKernelPhysicalTimerOwnerDestroyV19(m->timer)==VZ_KERNEL_WRONG_THREAD);return NULL;
}
static void NewCPU(Model *m,const VZKernelInitWriter *writer) {
 memset(m->native,0,0x8000);hv_vcpu_exit_t *exit=NULL;
 CHECK(!hv_vcpu_create(&m->id,&exit,NULL));VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->id,&b));CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));
 m->identity=(VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,
  v.vmEpoch,m->id,Thread(m),v.cpuGeneration,0};CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 VZKernelPhysicalTimerBindingV19 binding={m,m,Counter,Validate,Route,Deadline,Quiet};
 CHECK(!VZKernelPhysicalTimerOwnerCreateV19(&m->identity,&binding,writer,&m->timer));
 Put(m,0x4100,1);m->ppiEnabled=true;m->otherIRQ=false;m->routeFail=false;m->now=100;
}
int main(void) {
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());Model m={0};
 m.native=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m.ram=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.native!=MAP_FAILED && m.ram!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));hv_vm_config_t cfg=hv_vm_config_create();CHECK(cfg);
 CHECK(!_hv_vm_config_set_isa(cfg,2) && !hv_vm_create(cfg));CHECK(!VM27HVVMGetOwnedVMV1(&m.vm));
 CHECK(!hv_vm_map(m.ram,0x40000000,0x4000,7));hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m.id,&exit,NULL));
 VM27CPUFactoryBorrowV2 *viewBorrow=NULL;VM27CPUFactoryViewV2 view={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&viewBorrow));CHECK(!VM27CPUFactoryBorrowViewV2(viewBorrow,&view));
 m.identity=(VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,
  view.vmEpoch,m.id,Thread(&m),view.cpuGeneration,0};
 CHECK(!VM27CPUFactoryBorrowReleaseV2(viewBorrow));
 VZKernelPhysicalTimerBindingV19 binding={&m,&m,Counter,Validate,Route,Deadline,Quiet};
 CHECK(!VZKernelPhysicalTimerOwnerCreateV19(&m.identity,&binding,&writer,&m.timer) && m.timer);
 VZKernelPhysicalTimerOwnerV19 *duplicate=NULL;
 CHECK(VZKernelPhysicalTimerOwnerCreateV19(&m.identity,&binding,&writer,&duplicate)==VZ_KERNEL_BUSY && !duplicate);
 CHECK(hv_vm_destroy()==BUSY && !m.calls[2]);
 VZKernelPhysicalTimerReceiptV19 r={0};uint64_t out=99;m.hWCTL=0xffff000000000005;m.hWCVAL=50;m.now=50;
 Put(&m,0x4100,0);Put(&m,0x748,UINT64_C(0x8000000000000020));unsigned writes=m.writes;
 CHECK(Access(&m,1,0xdf11,0,&out,&r)==VZ_KERNEL_OK && out==5);
 CHECK(r.nativeOp8Required && r.nativeOp8Invoked && r.counterSampled && m.calls[8]==1 && m.writes==writes);
 CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==50 && m.calls[8]==1);
 m.counterFail=true;out=99;CHECK(Access(&m,1,0xdf11,0,&out,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && out==99 && !r.mutationPoisoned);m.counterFail=false;
 // Actual SDK offset setter writes native6a0/dirty4. Timer writes real CVAL
 // and dirty1, preserving the unrelated groups; getters return logical CVAL.
 m.ppiEnabled=true;m.now=1199;CHECK(!hv_vcpu_set_vtimer_offset(m.id,1000));writes=m.writes;
 CHECK(Access(&m,2,0xdf12,200,NULL,&r)==VZ_KERNEL_OK && r.domainValidated && r.offsetRebased);
 CHECK(r.previousPhysicalOffset==0 && r.vtimerOffset==1000 && r.logicalCVAL==200);
 CHECK(Word(&m,0x3f0)==1200 && m.writes==writes+2 && m.armed && m.deadline==1200 && !m.ppiLevel);
 CHECK((Word(&m,0x748)&5)==5 && Word(&m,0x6a0)==1000);
 CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==200 && r.nativeCVAL==1200);
 m.now=1200;CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && r.physicalTimerAsserted && r.aggregateIRQ);
 m.now=2099;CHECK(!hv_vcpu_set_vtimer_offset(m.id,2000));writes=m.writes;
 CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==200 && r.offsetRebased && r.deadlineComplete);
 CHECK(Word(&m,0x3f0)==2200 && m.writes==writes+2 && m.armed && m.deadline==2200 && !m.ppiLevel);
 m.now=2200;CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && r.aggregateIRQ);
 CHECK(!hv_vcpu_set_vtimer_offset(m.id,0));CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && Word(&m,0x3f0)==200);
 // Positive and negative real additive bias retain the same guest domain.
 m.hostBias=100;m.now=1199;CHECK(!hv_vcpu_set_vtimer_offset(m.id,1100));
 CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==200 && r.physicalOffset==1000 && r.hostCounterBias==100);
 CHECK(Word(&m,0x3f0)==1200 && m.armed && m.deadline==1200);
 m.hostBias=200;CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==200 && r.offsetRebased && r.physicalOffset==900);
 CHECK(Word(&m,0x3f0)==1100 && !m.armed && r.aggregateIRQ);
 m.hostBias=UINT64_MAX-99;CHECK(!hv_vcpu_set_vtimer_offset(m.id,900));
 CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==200 && r.hostCounterBias==UINT64_MAX-99 && r.physicalOffset==1000);
 CHECK(Word(&m,0x3f0)==1200 && m.armed && m.deadline==1200);
 m.hostBias=0;CHECK(!hv_vcpu_set_vtimer_offset(m.id,0));CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && Word(&m,0x3f0)==200);
 unsigned routes=m.routes;writes=m.writes;out=99;m.badEpoch=true;
 CHECK(Access(&m,2,0xdf12,300,NULL,&r)==VZ_KERNEL_UNSUPPORTED && r.domainResult==VZ_COUNTER_DOMAIN_EPOCH_V19 && m.writes==writes);
 m.badEpoch=false;m.badFrequency=true;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_UNSUPPORTED && r.domainResult==VZ_COUNTER_DOMAIN_FREQUENCY_V19 && m.routes==routes);
 m.badFrequency=false;m.unstableBias=true;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_UNSUPPORTED && r.domainResult==VZ_COUNTER_DOMAIN_UNSTABLE_V19 && !r.mutationPoisoned);m.unstableBias=false;
 CHECK(!hv_vcpu_set_vtimer_offset(m.id,2300));writes=m.writes;CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_UNSUPPORTED && m.writes==writes);
 CHECK(!hv_vcpu_set_vtimer_offset(m.id,1));writes=m.writes;CHECK(Access(&m,2,0xdf12,UINT64_MAX,NULL,&r)==VZ_KERNEL_UNSUPPORTED && m.writes==writes);
 CHECK(!hv_vcpu_set_vtimer_offset(m.id,0));writes=m.writes;
 CHECK(Access(&m,2,0xdf12,UINT64_MAX,NULL,&r)==VZ_KERNEL_UNSUPPORTED && m.writes==writes && r.domainResult==VZ_COUNTER_DOMAIN_TRANSLATION_RANGE_V19);
 CHECK(Access(&m,1,0xdf10,0,&out,&r)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(Access(&m,1,0xdf11,0,(uint64_t *)(void *)(m.native+0x438),&r)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(Access(&m,1,0xdf11,0,(uint64_t *)(void *)m.timer,&r)==VZ_KERNEL_BAD_ARGUMENT);
 m.now=40;m.ppiEnabled=true;m.reenter=true;writes=m.writes;
 CHECK(Access(&m,2,0xdf12,100,NULL,&r)==VZ_KERNEL_OK);CHECK(m.writes==writes+2 && Word(&m,0x3f0)==100);
 CHECK(Word(&m,0x748)==UINT64_C(0x8000000000000025) && m.armed && m.deadline==100 && !m.ppiLevel);
 CHECK(Access(&m,2,0xdf11,UINT64_C(0xffff000000000005),NULL,&r)==VZ_KERNEL_OK && Word(&m,0x438)==1);
 m.reenter=false;CHECK(m.reentries>0);
 bool pending=true;CHECK(!hv_vcpu_get_pending_interrupt(m.id,HV_INTERRUPT_TYPE_IRQ,&pending) && !pending);
 CHECK(!hv_vcpu_set_pending_interrupt(m.id,HV_INTERRUPT_TYPE_FIQ,true));m.now=100;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && r.physicalTimerAsserted && r.aggregateIRQ && !m.armed);
 CHECK(!hv_vcpu_get_pending_interrupt(m.id,HV_INTERRUPT_TYPE_FIQ,&pending) && pending);
 CHECK(!hv_vcpu_set_pending_interrupt(m.id,HV_INTERRUPT_TYPE_FIQ,false));
 CHECK(!hv_vcpu_run(m.id) && m.calls[9]==1 && exit->exception.syndrome==0xf2000000);
 CHECK(!hv_vcpu_get_pending_interrupt(m.id,HV_INTERRUPT_TYPE_IRQ,&pending) && !pending);
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && r.aggregateIRQ);
 // A pending dirty bank is authoritative even when native8 ready is clear.
 // Real native8 does not consult dirty748 and would overwrite these fields.
 unsigned before8=m.calls[8];Put(&m,0x4100,0);Put(&m,0x748,1);m.hWCVAL=999;m.hWCTL=3;
 CHECK(Access(&m,2,0xdf12,201,NULL,&r)==VZ_KERNEL_OK && Word(&m,0x3f0)==201 && Word(&m,0x438)==1 && m.calls[8]==before8);
 Put(&m,0x4100,1);m.now=1200;CHECK(!hv_vcpu_set_vtimer_offset(m.id,1000));out=99;
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,true,true,1,0xdf01,0,&out,&r)==VZ_KERNEL_NOT_LIVE && out==99);
 m.revokePostOnCounter=true;out=99;
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,true,1,0xdf01,0,&out,&r)==VZ_KERNEL_NOT_LIVE && out==99 && !r.mutationPoisoned);
 m.revokePostOnCounter=false;
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,true,1,0xdf01,0,&out,&r)==VZ_KERNEL_OK && out==200 && !r.attemptedWrites);
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,true,1,0xdf00,0,&out,&r)==VZ_KERNEL_OK && out==24000000);
 m.hostBias=100;CHECK(!hv_vcpu_set_vtimer_offset(m.id,1100));
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,true,1,0xdf01,0,&out,&r)==VZ_KERNEL_OK && out==200 && r.hostCounterBias==100);
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,false,2,0xdf12,300,NULL,&r)==VZ_KERNEL_OK && Word(&m,0x3f0)==1300 && r.deadlineArmed);
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,false,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==300);
 m.reenter=true;
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,false,2,0xdf11,1,NULL,&r)==VZ_KERNEL_OK && !r.mutationPoisoned);
 m.reenter=false;m.hostBias=0;CHECK(!hv_vcpu_set_vtimer_offset(m.id,0));
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && Word(&m,0x3f0)==300);
 m.ppiEnabled=false;CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_OK && r.physicalTimerAsserted && !r.aggregateIRQ);
 m.otherIRQ=true;CHECK(Access(&m,2,0xdf11,0,NULL,&r)==VZ_KERNEL_OK && !r.physicalTimerAsserted && r.aggregateIRQ);
 CHECK(!hv_vcpu_get_pending_interrupt(m.id,HV_INTERRUPT_TYPE_IRQ,&pending) && pending);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,Foreign,&m) && !pthread_join(foreign,NULL));
 // Native8 error refuses before writes and preserves the actual timer owner.
 Put(&m,0x4100,0);Put(&m,0x748,0);m.native8Fail=true;writes=m.writes;
 CHECK(Access(&m,2,0xdf12,200,NULL,&r)==VZ_KERNEL_NATIVE_ERROR && !r.mutationPoisoned && m.writes==writes);m.native8Fail=false;
 Put(&m,0x4100,1);m.routeFail=true;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_NATIVE_ERROR && r.mutationPoisoned && r.identityWithdrawn && r.irqRouteAttempted && !r.irqRouteComplete);
 CHECK(hv_vcpu_get_pending_interrupt(m.id,HV_INTERRUPT_TYPE_IRQ,&pending)==BAD);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && !m.calls[7]);CHECK(hv_vm_destroy()==BUSY);
 m.quietFail=true;CHECK(VZKernelPhysicalTimerOwnerDestroyV19(m.timer)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && !m.calls[7]);m.quietFail=false;
 CHECK(VZKernelPhysicalTimerOwnerDestroyV19(m.timer)==VZ_KERNEL_OK);m.timer=NULL;CHECK(!m.armed && !m.ppiLevel);
 m.cpuFail=true;CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)!=0 && m.calls[7]==1 && hv_vm_destroy()==BUSY);
 m.cpuFail=false;CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL) && m.calls[7]==2);
 // A callback may modify bytes and still report failure. Poison immediately,
 // and keep the native CPU and its mapped RAM until the timer is quiesced.
 NewCPU(&m,&writer);m.writeFail=true;writes=m.writes;
 CHECK(Access(&m,2,0xdf12,200,NULL,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(r.mutationPoisoned && r.identityWithdrawn && r.attemptedWrites==1 && !r.completedWrites);
 CHECK(Word(&m,0x3f0)==200 && m.writes==writes+1 && hv_vm_unmap(0x40000000,0x4000)==BUSY);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);m.writeFail=false;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV19(m.timer));m.timer=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // Deadline failure after a real PPI update does not publish pending success.
 NewCPU(&m,&writer);Put(&m,0x438,1);Put(&m,0x3f0,200);m.deadlineFail=true;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(r.irqRouteComplete && r.deadlineAttempted && !r.deadlineComplete && r.deadlineArmed);
 CHECK(r.mutationPoisoned && r.identityWithdrawn && m.armed && m.deadline==200);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && hv_vm_destroy()==BUSY);m.deadlineFail=false;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV19(m.timer));m.timer=NULL;CHECK(!m.armed);
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // Counter failure following real native writes is also a partial mutation.
 NewCPU(&m,&writer);m.failCounterAt=m.counterCalls+2;
 CHECK(Access(&m,2,0xdf12,300,NULL,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(r.completedWrites==2 && r.counterSampled && r.mutationPoisoned && r.identityWithdrawn);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);m.failCounterAt=0;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV19(m.timer));m.timer=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // A verified new bias after writes is still a partial clock-domain change.
 NewCPU(&m,&writer);m.changeBiasAt=m.counterCalls+2;
 CHECK(Access(&m,2,0xdf12,300,NULL,&r)==VZ_KERNEL_UNSUPPORTED && r.completedWrites==2 && r.mutationPoisoned);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);m.changeBiasAt=0;m.hostBias=0;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV19(m.timer));m.timer=NULL;CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // Failed genuine rebase write may have changed actual bytes; retain owner.
 NewCPU(&m,&writer);m.now=2000;CHECK(!hv_vcpu_set_vtimer_offset(m.id,1000));m.writeFail=true;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && r.attemptedWrites==1 && !r.completedWrites);
 CHECK(Word(&m,0x3f0)==1000 && r.mutationPoisoned && r.identityWithdrawn);
 CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY && VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);
 m.quietFail=true;CHECK(VZKernelPhysicalTimerOwnerDestroyV19(m.timer)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);m.quietFail=false;m.writeFail=false;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV19(m.timer));m.timer=NULL;CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // Token loss after bytes are written is a genuine partial mutation: the
 // shared core withdraws publication and keeps the borrowed native CPU/RAM.
 NewCPU(&m,&writer);CHECK(!hv_vcpu_set_pending_interrupt(m.id,HV_INTERRUPT_TYPE_IRQ,true));
 CHECK(!hv_vcpu_run(m.id));m.revokePostOnWrite=true;writes=m.writes;
 CHECK(VM27TimerModelPostV19(m.timer,&m.identity,&writer,false,false,2,0xdf12,300,NULL,&r)==VZ_KERNEL_NOT_LIVE);
 CHECK(r.mutationPoisoned && r.identityWithdrawn && r.attemptedWrites==1 && !r.completedWrites && Word(&m,0x3f0)==300);
 CHECK(m.writes==writes+1 && VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && hv_vm_destroy()==BUSY);
 m.revokePostOnWrite=false;CHECK(!VZKernelPhysicalTimerOwnerDestroyV19(m.timer));m.timer=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 CHECK(!hv_vm_unmap(0x40000000,0x4000) && !hv_vm_destroy());CFRelease((CFTypeRef)cfg);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m.native,0x8000) && !munmap(m.ram,0x8000));
 printf("{\"checks\":%u,\"native8ModelCalls\":%u,\"native9ModelCalls\":%u,\"reentryChecks\":%u,\"routerFailureRetainsCPUVMRAM\":true,\"actualNativeCalls\":0,\"deviceOperations\":0,\"fullGICImplemented\":false}\n",Checks,m.calls[8],m.calls[9],m.reentries);return 0;
}
