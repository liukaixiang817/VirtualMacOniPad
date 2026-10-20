#include "vm27_hv_public_vm_bootstrap_v6.h"
#include "modern_cpu_kernel_physical_timer_v16.h"
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
static unsigned Checks;
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *o){*o=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *o){*o=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){*o=(VM27CPUTLBICapabilityValueV1){0};}
typedef struct {
 unsigned char *native,*ram;unsigned calls[11],writes,routes,deadlines,quiets,reentries;
 uint64_t now,hWCTL,hWCVAL,deadline;bool ppiEnabled,ppiLevel,otherIRQ,armed;
 bool counterFail,routeFail,deadlineFail,quietFail,writeFail,reenter,native8Fail,cpuFail;
 hv_vcpu_t id;VM27CPUFactoryVMV2 *vm;VZKernelPhysicalTimerOwnerV16 *timer;
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
 VZKernelPhysicalTimerReceiptV16 r={0};VZKernelLifecycleResult l={0};
 CHECK(VZKernelPhysicalTimerOwnerAccessV16(m->timer,VZ_KERNEL_PHYSICAL_TIMER_POLL_V16,0,0,NULL,&r,&l)==VZ_KERNEL_BUSY);
}
static bool Write(void *p,void *dst,size_t n,const void *v) {
 Model *m=p;uintptr_t off=(uintptr_t)dst-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 ++m->writes;Reenter(m);bool real=VM27CPUSelfWriteV1(NULL,dst,n,v);return real && !m->writeFail;
}
static bool Counter(void *p,uint64_t *out){Model *m=p;Reenter(m);if(m->counterFail)return false;*out=m->now;return true;}
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
 VZKernelPhysicalTimerReceiptV16 *r) {
 VZKernelLifecycleResult l={0};return VZKernelPhysicalTimerOwnerAccessV16(m->timer,action,id,value,out,r,&l);
}
static void *Foreign(void *p) {
 Model *m=p;VZKernelPhysicalTimerReceiptV16 r={0};uint64_t output=99;
 CHECK(Access(m,VZ_KERNEL_PHYSICAL_TIMER_READ_V16,0xdf11,0,&output,&r)==VZ_KERNEL_WRONG_THREAD && output==99);
 CHECK(VZKernelPhysicalTimerOwnerDestroyV16(m->timer)==VZ_KERNEL_WRONG_THREAD);return NULL;
}
static void NewCPU(Model *m,const VZKernelInitWriter *writer) {
 memset(m->native,0,0x8000);hv_vcpu_exit_t *exit=NULL;
 CHECK(!hv_vcpu_create(&m->id,&exit,NULL));VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->id,&b));CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));
 m->identity=(VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,
  v.vmEpoch,m->id,Thread(m),v.cpuGeneration,0};CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 VZKernelPhysicalTimerBindingV16 binding={m,m,Counter,Validate,Route,Deadline,Quiet};
 CHECK(!VZKernelPhysicalTimerOwnerCreateV16(&m->identity,&binding,writer,&m->timer));
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
 VZKernelPhysicalTimerBindingV16 binding={&m,&m,Counter,Validate,Route,Deadline,Quiet};
 CHECK(!VZKernelPhysicalTimerOwnerCreateV16(&m.identity,&binding,&writer,&m.timer) && m.timer);
 CHECK(hv_vm_destroy()==BUSY && !m.calls[2]);
 VZKernelPhysicalTimerReceiptV16 r={0};uint64_t out=99;m.hWCTL=0xffff000000000005;m.hWCVAL=50;m.now=50;
 Put(&m,0x4100,0);Put(&m,0x748,UINT64_C(0x8000000000000020));unsigned writes=m.writes;
 CHECK(Access(&m,1,0xdf11,0,&out,&r)==VZ_KERNEL_OK && out==5);
 CHECK(r.nativeOp8Required && r.nativeOp8Invoked && r.counterSampled && m.calls[8]==1 && m.writes==writes);
 CHECK(Access(&m,1,0xdf12,0,&out,&r)==VZ_KERNEL_OK && out==50 && m.calls[8]==1);
 m.counterFail=true;out=99;CHECK(Access(&m,1,0xdf11,0,&out,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && out==99 && !r.mutationPoisoned);m.counterFail=false;
 Put(&m,0x6a0,1);unsigned routes=m.routes;CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_UNSUPPORTED && m.routes==routes);Put(&m,0x6a0,0);
 CHECK(Access(&m,1,0xdf10,0,&out,&r)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(Access(&m,1,0xdf11,0,(uint64_t *)(void *)(m.native+0x438),&r)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(Access(&m,1,0xdf11,0,(uint64_t *)(void *)m.timer,&r)==VZ_KERNEL_BAD_ARGUMENT);
 m.now=40;m.ppiEnabled=true;m.reenter=true;writes=m.writes;
 CHECK(Access(&m,2,0xdf12,100,NULL,&r)==VZ_KERNEL_OK);CHECK(m.writes==writes+2 && Word(&m,0x3f0)==100);
 CHECK(Word(&m,0x748)==UINT64_C(0x8000000000000021) && m.armed && m.deadline==100 && !m.ppiLevel);
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
 m.quietFail=true;CHECK(VZKernelPhysicalTimerOwnerDestroyV16(m.timer)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && !m.calls[7]);m.quietFail=false;
 CHECK(VZKernelPhysicalTimerOwnerDestroyV16(m.timer)==VZ_KERNEL_OK);m.timer=NULL;CHECK(!m.armed && !m.ppiLevel);
 m.cpuFail=true;CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)!=0 && m.calls[7]==1 && hv_vm_destroy()==BUSY);
 m.cpuFail=false;CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL) && m.calls[7]==2);
 // A callback may modify bytes and still report failure. Poison immediately,
 // and keep the native CPU and its mapped RAM until the timer is quiesced.
 NewCPU(&m,&writer);m.writeFail=true;writes=m.writes;
 CHECK(Access(&m,2,0xdf12,200,NULL,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(r.mutationPoisoned && r.identityWithdrawn && r.attemptedWrites==1 && !r.completedWrites);
 CHECK(Word(&m,0x3f0)==200 && m.writes==writes+1 && hv_vm_unmap(0x40000000,0x4000)==BUSY);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);m.writeFail=false;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV16(m.timer));m.timer=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // Deadline failure after a real PPI update does not publish pending success.
 NewCPU(&m,&writer);Put(&m,0x438,1);Put(&m,0x3f0,200);m.deadlineFail=true;
 CHECK(Access(&m,3,0,0,NULL,&r)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(r.irqRouteComplete && r.deadlineAttempted && !r.deadlineComplete && r.deadlineArmed);
 CHECK(r.mutationPoisoned && r.identityWithdrawn && m.armed && m.deadline==200);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && hv_vm_destroy()==BUSY);m.deadlineFail=false;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV16(m.timer));m.timer=NULL;CHECK(!m.armed);
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 // Counter failure following real native writes is also a partial mutation.
 NewCPU(&m,&writer);m.counterFail=true;
 CHECK(Access(&m,2,0xdf12,300,NULL,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(r.completedWrites==2 && !r.counterSampled && r.mutationPoisoned && r.identityWithdrawn);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY);m.counterFail=false;
 CHECK(!VZKernelPhysicalTimerOwnerDestroyV16(m.timer));m.timer=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 CHECK(!hv_vm_unmap(0x40000000,0x4000) && !hv_vm_destroy());CFRelease((CFTypeRef)cfg);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m.native,0x8000) && !munmap(m.ram,0x8000));
 printf("{\"checks\":%u,\"native8ModelCalls\":%u,\"native9ModelCalls\":%u,\"reentryChecks\":%u,\"routerFailureRetainsCPUVMRAM\":true,\"actualNativeCalls\":0,\"deviceOperations\":0,\"fullGICImplemented\":false}\n",Checks,m.calls[8],m.calls[9],m.reentries);return 0;
}
