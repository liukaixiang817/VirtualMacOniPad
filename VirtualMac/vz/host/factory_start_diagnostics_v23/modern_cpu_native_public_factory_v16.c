// New Factory16 exact-source derivative; frozen Factory15 remains unchanged.
#include "modern_cpu_native_public_factory_v16.h"
#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static bool FactoryConfigRangeV15(const void *,size_t);
static VZKernelStatus FactorySystemBridgeV15(VZKernelCPU *,const VZKernelSysRequest *,
 const VZKernelInitWriter *,uint64_t *,VZKernelSysReceipt *,VZKernelLifecycleResult *);
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryCreateV2) FactoryInheritedCreateV15;
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryDestroyV2) FactoryInheritedDestroyV15;
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryOwnerCleanupV2) FactoryInheritedCleanupV15;
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryVMDestroyV2) FactoryInheritedVMDestroyV15;
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_run) FactoryInheritedPublicRunV15;
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_create) FactoryInheritedPublicCreateV15;
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_destroy) FactoryInheritedPublicDestroyV15;
#define VM27CPUConfigOutputRangeDisjointV3 FactoryConfigRangeV15
#define VM27CPUFactoryCreateV2 FactoryInheritedCreateV15
#define VM27CPUFactoryDestroyV2 FactoryInheritedDestroyV15
#define VM27CPUFactoryOwnerCleanupV2 FactoryInheritedCleanupV15
#define VM27CPUFactoryVMDestroyV2 FactoryInheritedVMDestroyV15
#define hv_vcpu_run FactoryInheritedPublicRunV15
#define hv_vcpu_create FactoryInheritedPublicCreateV15
#define hv_vcpu_destroy FactoryInheritedPublicDestroyV15
#define VZKernelCPUAccessSystemRegister FactorySystemBridgeV15
#define VZKernelCPURunOwnedPendingStepV14 VZKernelCPURunGICPendingV18
#include "modern_cpu_native_public_factory_v14.c"
#undef VZKernelCPURunOwnedPendingStepV14
#undef VZKernelCPUAccessSystemRegister
#undef hv_vcpu_run
#undef hv_vcpu_create
#undef hv_vcpu_destroy
#undef VM27CPUFactoryVMDestroyV2
#undef VM27CPUFactoryOwnerCleanupV2
#undef VM27CPUFactoryDestroyV2
#undef VM27CPUFactoryCreateV2
#undef VM27CPUConfigOutputRangeDisjointV3

typedef struct FactoryGICRetainV15 {
 struct FactoryGICRetainV15 *next;
 VM27CPUFactoryBorrowV2 *borrow;
 VZKernelCPUWakeOwnerV17 *wake;
 VZKernelRunPendingRequestV14 identity;
 unsigned callbacks;
 bool closing;
} FactoryGICRetainV15;
typedef struct FactoryGICCPUV15 {
 struct FactoryGICCPUV15 *next;
 Entry *entry;
 VZKernelCPUGICOwnerV18 *lower;
 VZKernelRunPendingRequestV14 identity;
 bool attached;
} FactoryGICCPUV15;
typedef struct {
 VM27CPUFactoryVMV2 *vm;
 uint64_t epoch;
 VM27GICV3V1 *engine;
 VM27CPUFactoryGICSchedulerV15 scheduler;
 FactoryGICRetainV15 *retains;
 FactoryGICCPUV15 *cpus;
 bool closing;
} FactoryGICVMV15;
static pthread_mutex_t GICRegistryV15=PTHREAD_MUTEX_INITIALIZER;
static FactoryGICVMV15 *GICRegisteredV15;
static void GICLockV15(void){if(pthread_mutex_lock(&GICRegistryV15))abort();}
static void GICUnlockV15(void){if(pthread_mutex_unlock(&GICRegistryV15))abort();}
bool VM27CPUFactoryGICOutputRangeDisjointV15(const void *p,size_t n) {
 if(!p || n>UINTPTR_MAX-(uintptr_t)p)return false;
 GICLockV15();FactoryGICVMV15 *g=GICRegisteredV15;bool valid=true;
 if(g) {
  valid=Disjoint(p,n,g,sizeof(*g));
  if(g->engine)valid=valid && VM27GICOutputRangeDisjointV1(g->engine,p,n);
  for(FactoryGICCPUV15 *c=g->cpus;c && valid;c=c->next)valid=Disjoint(p,n,c,sizeof(*c));
  for(FactoryGICRetainV15 *r=g->retains;r && valid;r=r->next) {
   valid=Disjoint(p,n,r,sizeof(*r));
   if(r->wake)valid=valid && VZKernelCPUWakeRangeDisjointV18(r->wake,p,n);
  }
 }
 GICUnlockV15();return valid && VZKernelCPUControllerOutputRangeDisjointV18(p,n);
}
static bool FactoryConfigRangeV15(const void *p,size_t n) {
 return VM27CPUConfigOutputRangeDisjointV3(p,n) && VM27CPUFactoryGICOutputRangeDisjointV15(p,n);
}
static bool GICFactoryOutputV15(const void *p,size_t n,bool write) {
 Lock();bool ok=Output(p,n) && VZKernelCPUOutputRangeDisjointV12(p,n) &&
  VM27CPUSelfMappedRangeV1(p,n,write,NULL);Unlock();return ok;
}
static FactoryGICVMV15 *GICVMV15(VM27CPUFactoryVMV2 *vm) {
 GICLockV15();FactoryGICVMV15 *g=GICRegisteredV15;
 if(g && (g->vm!=vm || g->epoch!=vm->epoch || g->closing))g=NULL;
 GICUnlockV15();return g;
}
static FactoryGICCPUV15 *GICCPUV15(Entry *entry) {
 GICLockV15();FactoryGICCPUV15 *found=NULL;
 if(GICRegisteredV15)for(FactoryGICCPUV15 *c=GICRegisteredV15->cpus;c;c=c->next)
  if(c->entry==entry){found=c;break;}
 GICUnlockV15();return found;
}
static VZKernelStatus GICRetainCPUCallbackV15(void *opaque,const VZKernelRunPendingRequestV14 *q,void **out) {
 FactoryGICVMV15 *g=opaque;
 Lock();Entry *entry=NULL;
 if(Registered==g->vm && g->epoch==g->vm->epoch && q->expectedVMEpoch==g->epoch)
  for(Entry *e=Registered->entries;e;e=e->next)
   if(e==Owned && e->published && !e->draining && e->live && e->complete &&
    !memcmp(q,&(VZKernelRunPendingRequestV14){1,e->vm->profile,e->vm->nativeISA,0,e->vm->epoch,
      e->identity,e->nativeOwnerThread,e->generation,e->returnedSlotWord},sizeof(*q))){entry=e;break;}
 Unlock();if(!entry)return VZ_KERNEL_NOT_LIVE;
 FactoryGICRetainV15 *r=calloc(1,sizeof(*r));if(!r)return VZ_KERNEL_OUT_OF_MEMORY;
 r->identity=*q;VM27CPUFactoryBorrowV2 *borrow=NULL;
 VM27CPUFactoryMachStatusV2 result=VM27CPUFactoryBorrowAcquireV2(entry->identity,&borrow);
 if(result){free(r);return result==Mach(VZ_KERNEL_BUSY)?VZ_KERNEL_BUSY:VZ_KERNEL_NATIVE_ERROR;}
 r->borrow=borrow;GICLockV15();r->next=g->retains;g->retains=r;GICUnlockV15();*out=r;
 VZKernelCPUWakeOwnerV17 *wake=NULL;VZKernelStatus s=VZKernelCPUWakeOwnerCreateV17(q,&wake);
 GICLockV15();r->wake=wake;if(s!=VZ_KERNEL_OK)r->closing=true;GICUnlockV15();return s;
}
static VZKernelStatus GICReleaseCPUCallbackV15(void *opaque,void *token) {
 FactoryGICVMV15 *g=opaque;GICLockV15();FactoryGICRetainV15 *r=NULL;
 for(FactoryGICRetainV15 *p=g->retains;p;p=p->next)if(p==token){r=p;break;}
 if(!r){GICUnlockV15();return VZ_KERNEL_BAD_ARGUMENT;}
 r->closing=true;bool busy=r->callbacks!=0;GICUnlockV15();if(busy)return VZ_KERNEL_BUSY;
 if(r->wake) {
  VZKernelStatus s=VZKernelCPUWakeOwnerDestroyV17(r->wake);if(s!=VZ_KERNEL_OK)return s;
  GICLockV15();r->wake=NULL;GICUnlockV15();
 }
 VM27CPUFactoryMachStatusV2 s=VM27CPUFactoryBorrowReleaseV2(r->borrow);
 if(s)return s==Mach(VZ_KERNEL_BUSY)?VZ_KERNEL_BUSY:VZ_KERNEL_NATIVE_ERROR;
 GICLockV15();FactoryGICRetainV15 **link=&g->retains;
 while(*link && *link!=r)link=&(*link)->next;
 if(!*link)abort();*link=r->next;GICUnlockV15();memset(r,0,sizeof(*r));free(r);return VZ_KERNEL_OK;
}
VZKernelStatus VM27CPUFactoryGICSignalWakeV15(VM27CPUFactoryVMV2 *vm,
 const VZKernelRunPendingRequestV14 *input) {
 if(!input || !VM27CPUSelfMappedRangeV1(input,sizeof(*input),false,NULL))return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelRunPendingRequestV14 q=*input;GICLockV15();FactoryGICVMV15 *g=GICRegisteredV15;
 FactoryGICRetainV15 *r=NULL;
 if(g && g->vm==vm && !g->closing)for(FactoryGICRetainV15 *p=g->retains;p;p=p->next)
  if(!p->closing && p->wake && !memcmp(&q,&p->identity,sizeof(q))){r=p;break;}
 if(r && r->callbacks!=UINT_MAX)++r->callbacks;else r=NULL;
 GICUnlockV15();if(!r)return VZ_KERNEL_NOT_LIVE;
 Lock();bool actual=Registered==vm && ContainsBorrow(r->borrow) && r->borrow->entry->live &&
  r->borrow->entry->published && !r->borrow->entry->draining &&
  r->borrow->epoch==q.expectedVMEpoch && r->borrow->generation==q.expectedCPUGeneration;
 Unlock();VZKernelCPUWakeReceiptV17 receipt={0};
 VZKernelStatus s=actual?VZKernelCPUWakeOwnerSignalV17(r->wake,&q,&receipt):VZ_KERNEL_NOT_LIVE;
 GICLockV15();--r->callbacks;GICUnlockV15();return s;
}
static VZKernelStatus GICWakeCallbackV15(void *opaque,const VZKernelRunPendingRequestV14 *q) {
 FactoryGICVMV15 *g=opaque;return VM27CPUFactoryGICSignalWakeV15(g->vm,q);
}
static VZKernelStatus GICScheduleCallbackV15(void *opaque,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t when) {
 FactoryGICVMV15 *g=opaque;
 return g->scheduler.scheduleDeadline(g->scheduler.context,q,arm,when);
}
static VZKernelStatus GICDrainCallbackV15(void *opaque,const VZKernelRunPendingRequestV14 *q) {
 FactoryGICVMV15 *g=opaque;return g->scheduler.drainDeadline(g->scheduler.context,q);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICDescribeV15(VM27CPUFactoryVMV2 *vm,
 VM27CPUFactoryVMGICDescriptionV15 *out) {
 VZKernelStatus s=BeginVM(vm);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!GICFactoryOutputV15(out,sizeof(*out),true)){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!pthread_equal(pthread_self(),vm->owner))s=VZ_KERNEL_WRONG_THREAD;
 VM27CPUFactoryVMGICDescriptionV15 d={1,vm->nativeISA,vm->profile,0,vm->epoch,vm->live,false};
 Lock();for(Entry *e=vm->entries;e;e=e->next)if(e->live)++d.liveCPUCount;Unlock();
 GICLockV15();d.gicInstalled=GICRegisteredV15 && GICRegisteredV15->vm==vm;GICUnlockV15();
 if(s==VZ_KERNEL_OK)*out=d;End(&vm->operation);return Mach(s);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICInstallV15(VM27CPUFactoryVMV2 *vm,
 const VM27GICConfigV1 *input,const VM27CPUFactoryGICSchedulerV15 *scheduler) {
 VZKernelStatus s=BeginVM(vm);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!GICFactoryOutputV15(input,sizeof(*input),false) || !GICFactoryOutputV15(scheduler,sizeof(*scheduler),false) ||
  !Disjoint(input,sizeof(*input),scheduler,sizeof(*scheduler)))s=VZ_KERNEL_BAD_ARGUMENT;
 VM27GICConfigV1 config={0};VM27CPUFactoryGICSchedulerV15 staged={0};
 if(s==VZ_KERNEL_OK){config=*input;staged=*scheduler;}
 if(s==VZ_KERNEL_OK)s=RAMReadyV5(vm,NULL);
 GICLockV15();bool installed=GICRegisteredV15!=NULL;GICUnlockV15();
 if(s==VZ_KERNEL_OK && installed)s=VZ_KERNEL_BUSY;
 if(s==VZ_KERNEL_OK && (config.vmEpoch!=vm->epoch || !staged.context ||
  !staged.scheduleDeadline || !staged.drainDeadline))s=VZ_KERNEL_BAD_ARGUMENT;
 FactoryGICVMV15 *g=NULL;
 if(s==VZ_KERNEL_OK){g=calloc(1,sizeof(*g));if(!g)s=VZ_KERNEL_OUT_OF_MEMORY;}
 if(s==VZ_KERNEL_OK) {
  g->vm=vm;g->epoch=vm->epoch;g->scheduler=staged;
  VM27GICBindingsV1 bindings={g,GICRetainCPUCallbackV15,GICReleaseCPUCallbackV15,GICWakeCallbackV15,
   GICScheduleCallbackV15,GICDrainCallbackV15};
  s=VM27GICCreateV1(&config,&bindings,&g->engine);
  if(s==VZ_KERNEL_OK){GICLockV15();GICRegisteredV15=g;GICUnlockV15();}else free(g);
 }
 End(&vm->operation);return Mach(s);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICTeardownV15(VM27CPUFactoryVMV2 *vm) {
 VZKernelStatus s=BeginVM(vm);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!pthread_equal(pthread_self(),vm->owner))s=VZ_KERNEL_WRONG_THREAD;
 Lock();bool CPUs=vm->entries!=NULL;Unlock();if(s==VZ_KERNEL_OK && CPUs)s=VZ_KERNEL_BUSY;
 GICLockV15();FactoryGICVMV15 *g=GICRegisteredV15;
 if(g && g->vm!=vm){g=NULL;if(s==VZ_KERNEL_OK)s=VZ_KERNEL_NOT_LIVE;}
 if(s==VZ_KERNEL_OK && g){g->closing=true;if(g->cpus || g->retains)s=VZ_KERNEL_BUSY;}
 GICUnlockV15();
 if(s==VZ_KERNEL_OK && g) {
  s=VM27GICDestroyV1(g->engine);
  if(s==VZ_KERNEL_OK){GICLockV15();GICRegisteredV15=NULL;GICUnlockV15();memset(g,0,sizeof(*g));free(g);}
 }
 End(&vm->operation);return Mach(s);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICAccessV15(VM27CPUFactoryVMV2 *vm,
 VM27CPUFactoryVMGICActionV15 action,uint64_t selector,uint64_t value,uint64_t *out) {
 VZKernelStatus s=BeginVM(vm);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(out && !GICFactoryOutputV15(out,sizeof(*out),true))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK && !vm->live)s=VZ_KERNEL_NOT_LIVE;
 FactoryGICVMV15 *g=s==VZ_KERNEL_OK?GICVMV15(vm):NULL;if(s==VZ_KERNEL_OK && !g)s=VZ_KERNEL_NOT_LIVE;
 uint64_t result=0;
 if(s==VZ_KERNEL_OK) {
  if(action==1 || action==2)s=(selector>UINT16_MAX || (action==1 && (!out || value)))?VZ_KERNEL_BAD_ARGUMENT:
   VM27GICDistributorRegV1(g->engine,(uint16_t)selector,action==2,value,&result);
  else if(action==3)s=selector>UINT32_MAX || value>1?VZ_KERNEL_BAD_ARGUMENT:
   VM27GICSetSPIV1(g->engine,(uint32_t)selector,value!=0);
  else if(action==4)s=value>UINT32_MAX?VZ_KERNEL_BAD_ARGUMENT:
   VM27GICSendMSIV1(g->engine,selector,(uint32_t)value);
  else if(action==5 && !selector && !value)s=VM27GICResetV1(g->engine);
  else s=VZ_KERNEL_BAD_ARGUMENT;
 }
 if(s==VZ_KERNEL_OK && action==1) {
  if(!GICFactoryOutputV15(out,sizeof(*out),true))s=VZ_KERNEL_BAD_ARGUMENT;else *out=result;
 }
 End(&vm->operation);return Mach(s);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowGICAccessV15(VM27CPUFactoryBorrowV2 *borrow,
 VM27CPUFactoryCPUGICActionV15 action,uint32_t selector,uint64_t value,uint64_t *out) {
 if((action==1 || action==3 || action==5 || action==6) && !out)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus s=BeginBorrow(borrow);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!pthread_equal(pthread_self(),borrow->borrower)){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 Lock();bool valid=ContainsBorrow(borrow) && (!out || (Output(out,sizeof(*out)) &&
  VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) && VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL)));
 Entry *e=valid?borrow->entry:NULL;
 bool owned=e && e==Owned && pthread_equal(e->owner,pthread_self());
 bool begun=owned && Begin(&e->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!owned){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 FactoryGICCPUV15 *c=GICCPUV15(e);VZKernelCPU *cpu=NULL;uint64_t result=0;
 s=e->draining || !c || !c->lower?VZ_KERNEL_NOT_LIVE:VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(s==VZ_KERNEL_OK && cpu!=e->cpu)s=VZ_KERNEL_NOT_LIVE;
 VZKernelPhysicalTimerReceiptV16 receipt={0};
 if(s==VZ_KERNEL_OK)s=VZKernelCPUGICOwnerAccessV18(c->lower,action,selector,value,
  (action==1 || action==3 || action==5 || action==6)?&result:NULL,&receipt);
 if(c && c->lower) {
  bool poisoned=false;VZKernelStatus queried=VZKernelCPUGICOwnerPoisonedV18(c->lower,&poisoned);
  if(queried==VZ_KERNEL_OK && poisoned){Lock();e->published=false;e->draining=true;e->exitRecordValid=false;Unlock();}
  else if(queried!=VZ_KERNEL_OK && s==VZ_KERNEL_OK)s=queried;
 }
 if(s==VZ_KERNEL_OK && (action==1 || action==3 || action==5 || action==6)) {
  if(!out || !GICFactoryOutputV15(out,sizeof(*out),true)) {
   s=VZ_KERNEL_BAD_ARGUMENT;
   if(action==1 && (selector==0xc640 || selector==0xc660)) {
    (void)VZKernelCPUGICOwnerPoisonV18(c->lower);Lock();e->published=false;e->draining=true;Unlock();
   }
  }else *out=result;
 }
 End(&e->operation);End(&borrow->operation);return Mach(s);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryPoisonGICCPUV15(VM27CPUFactoryIDV2 id,
 uint64_t epoch,uint64_t generation) {
 Lock();Entry *e=NULL;
 if(Registered && Registered->live && Registered->epoch==epoch)
  for(Entry *p=Registered->entries;p;p=p->next)
   if(p->identity==id && p->generation==generation && p->live && p->complete && p->configComplete){e=p;break;}
 bool owned=e && e==Owned && pthread_equal(e->owner,pthread_self());
 bool begun=owned && Begin(&e->operation);Unlock();
 if(!e)return Mach(VZ_KERNEL_NOT_LIVE);
 if(!owned)return Mach(VZ_KERNEL_WRONG_THREAD);
 if(!begun)return Mach(VZ_KERNEL_BUSY);
 FactoryGICCPUV15 *c=GICCPUV15(e);VZKernelStatus s=VZ_KERNEL_NOT_LIVE;
 if(c && c->attached && c->lower &&
  c->identity.expectedVMEpoch==epoch && c->identity.expectedCPUGeneration==generation &&
  c->identity.expectedPublicIdentity==id) {
  s=VZKernelCPUGICOwnerPoisonV18(c->lower);
  if(s==VZ_KERNEL_OK){Lock();e->published=false;e->draining=true;e->exitRecordValid=false;Unlock();}
 }
 End(&e->operation);return Mach(s);
}
static VZKernelStatus FactorySystemBridgeV15(VZKernelCPU *cpu,const VZKernelSysRequest *q,
 const VZKernelInitWriter *writer,uint64_t *out,VZKernelSysReceipt *receipt,VZKernelLifecycleResult *lifecycle) {
 Lock();Entry *e=NULL;if(Registered)for(Entry *p=Registered->entries;p;p=p->next)if(p->cpu==cpu){e=p;break;}
 bool actual=e && e==Owned && e->configComplete && e->published && !e->draining &&
  atomic_load_explicit(&e->operation,memory_order_relaxed) && e->borrowCount;Unlock();
 if(!actual)return VZ_KERNEL_NOT_LIVE;
 FactoryGICCPUV15 *c=GICCPUV15(e);VZKernelStatus s;
 if(c && c->lower && (q->identifier==0xdf11 || q->identifier==0xdf12)) {
  if(q->action!=VZ_KERNEL_SYS_READ && q->action!=VZ_KERNEL_SYS_WRITE)return VZ_KERNEL_BAD_ARGUMENT;
  VZKernelPhysicalTimerReceiptV16 timer={0};
  s=VZKernelCPUGICOwnerAccessV18(c->lower,q->action==VZ_KERNEL_SYS_READ?6:7,q->identifier,q->value,out,&timer);
  *receipt=(VZKernelSysReceipt){.status=s,.attemptedNativeReads=timer.attemptedReads,
   .attemptedNativeWrites=timer.attemptedWrites,.completedNativeWrites=timer.completedWrites,
   .nativeOp8Required=timer.nativeOp8Required,.nativeOp8Invoked=timer.nativeOp8Invoked,
   .mutationPoisoned=timer.mutationPoisoned,.cpuCleanupRequired=true};
  lifecycle->status=s;lifecycle->cpuLive=true;lifecycle->ownerThread=e->nativeOwnerThread;
  lifecycle->generation=e->generation;lifecycle->returnedSlotWord=e->returnedSlotWord;
  return s;
 }
 s=VZKernelCPUAccessSystemRegister(cpu,q,writer,out,receipt,lifecycle);
 if(s==VZ_KERNEL_OK && c && c->lower && q->action==VZ_KERNEL_SYS_WRITE && q->identifier==0xc005) {
  s=VZKernelCPUGICOwnerSetAffinityV18(c->lower,q->value);
  if(s!=VZ_KERNEL_OK){(void)VZKernelCPUGICOwnerPoisonV18(c->lower);receipt->mutationPoisoned=true;
   receipt->status=s;lifecycle->status=s;}
 }
 return s;
}
static void GICWithdrawFactoryV15(Entry *e) {
 Lock();e->published=false;e->draining=true;e->exitRecordValid=false;Unlock();
 (void)VZKernelCPUUnpublishIdentityV5(e->cpu);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryCreateV2(VM27CPUFactoryVMV2 *vm,
 VM27CPUFactoryIDV2 *outID,VM27CPUFactoryExitV2 **outExit,
 VM27CPUFactoryForeignConfigV2 config,VM27CPUFactoryDiagnosticV2 *diagnostic) {
 if(!GICFactoryOutputV15(outID,sizeof(*outID),true) || !GICFactoryOutputV15(outExit,sizeof(*outExit),true) ||
  (diagnostic && !GICFactoryOutputV15(diagnostic,sizeof(*diagnostic),true)) ||
  !Disjoint(outID,sizeof(*outID),outExit,sizeof(*outExit)) ||
  (diagnostic && (!Disjoint(outID,sizeof(*outID),diagnostic,sizeof(*diagnostic)) ||
   !Disjoint(outExit,sizeof(*outExit),diagnostic,sizeof(*diagnostic)))))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryIDV2 id=0;VM27CPUFactoryExitV2 *exit=NULL;VM27CPUFactoryDiagnosticV2 staged={0};
 VM27CPUFactoryMachStatusV2 status=FactoryInheritedCreateV15(vm,&id,&exit,config,&staged);
 Entry *e=Owned;FactoryGICVMV15 *g=NULL;VZKernelStatus own=VZ_KERNEL_OK;
 if(!status) {
  own=BeginVM(vm);bool vmEntered=own==VZ_KERNEL_OK;if(vmEntered)g=GICVMV15(vm);
  if(own==VZ_KERNEL_OK && g) {
   FactoryGICCPUV15 *c=calloc(1,sizeof(*c));if(!c)own=VZ_KERNEL_OUT_OF_MEMORY;
   if(c) {
    c->entry=e;c->identity=FactoryPendingRequestV12(e);
    GICLockV15();c->next=g->cpus;g->cpus=c;GICUnlockV15();
    VM27CPUFactoryBorrowV2 *borrow=NULL;uint64_t mpidr=0;VZKernelSysReceipt receipt={0};
    status=VM27CPUFactoryBorrowAcquireV2(id,&borrow);
    if(!status)status=VM27CPUFactoryBorrowAccessSystemV4(borrow,VZ_KERNEL_SYS_READ,0xc005,0,&mpidr,&receipt,NULL);
    if(borrow){VM27CPUFactoryMachStatusV2 released=VM27CPUFactoryBorrowReleaseV2(borrow);
     if(released){PublicDeferredBorrowV6=borrow;status=released;}}
    if(status)own=VZ_KERNEL_NATIVE_ERROR;
    if(own==VZ_KERNEL_OK) {
     own=VM27GICAttachCPUV1(g->engine,&c->identity,mpidr);
     // Failed attachment can still hold the concrete retain callback token.
     GICLockV15();c->attached=own==VZ_KERNEL_OK;
     if(!c->attached)for(FactoryGICRetainV15 *r=g->retains;r;r=r->next)
      if(!memcmp(&r->identity,&c->identity,sizeof(c->identity))){c->attached=true;break;}
     GICUnlockV15();
    }
    if(own==VZ_KERNEL_OK) {
     VZKernelCPUGICOwnerV18 *lower=NULL;
     own=VZKernelCPUGICOwnerCreateV18(&c->identity,g->engine,&vm->writer,&lower);
     GICLockV15();c->lower=lower;GICUnlockV15();
    }
   }
  }
  if(own!=VZ_KERNEL_OK){GICWithdrawFactoryV15(e);status=Mach(own);staged.ownStatus=own;staged.cleanupPending=true;}
  if(vmEntered)End(&vm->operation);
 }
 if(!status) {
  if(!GICFactoryOutputV15(outID,sizeof(*outID),true) || !GICFactoryOutputV15(outExit,sizeof(*outExit),true)) {
   GICWithdrawFactoryV15(e);status=Mach(VZ_KERNEL_BAD_ARGUMENT);
  }else{*outID=id;*outExit=exit;}
 }
 if(diagnostic && GICFactoryOutputV15(diagnostic,sizeof(*diagnostic),true))*diagnostic=staged;
 return status;
}
static VZKernelStatus GICDetachOwnerV15(Entry *entry) {
 FactoryGICCPUV15 *c=GICCPUV15(entry);if(!c)return VZ_KERNEL_OK;
 if(!pthread_equal(entry->owner,pthread_self()) || Owned!=entry)return VZ_KERNEL_WRONG_THREAD;
 if(c->lower) {
  VZKernelStatus s=VZKernelCPUGICOwnerDestroyV18(c->lower);if(s!=VZ_KERNEL_OK)return s;
  GICLockV15();c->lower=NULL;GICUnlockV15();
 }
 FactoryGICVMV15 *g=GICVMV15(entry->vm);if(!g)return VZ_KERNEL_NOT_LIVE;
 if(c->attached) {
  VZKernelStatus s=VM27GICDetachCPUV1(g->engine,&c->identity);if(s!=VZ_KERNEL_OK)return s;
  c->attached=false;
 }
 GICLockV15();FactoryGICCPUV15 **link=&g->cpus;
 while(*link && *link!=c)link=&(*link)->next;
 if(!*link)abort();*link=c->next;GICUnlockV15();memset(c,0,sizeof(*c));free(c);return VZ_KERNEL_OK;
}
static VM27CPUFactoryMachStatusV2 GICDestroyCPUOwnerV15(VM27CPUFactoryIDV2 id,
 VM27CPUFactoryVMV2 *vm,VM27CPUFactoryDiagnosticV2 *diagnostic,bool cleanup) {
 Lock();Entry *entry=cleanup?Owned:NULL;
 if(!cleanup && Registered)for(Entry *e=Registered->entries;e;e=e->next)
  if(e->identity==id && e->published){entry=e;break;}
 bool valid=entry && Contains(entry) && (!cleanup || entry->vm==vm) && DiagnosticOutput(diagnostic);
 bool begun=valid && Begin(&entry->operation);Unlock();
 if(!valid)return Mach(VZ_KERNEL_BAD_ARGUMENT);if(!begun)return Mach(VZ_KERNEL_BUSY);
 VZKernelStatus s=GICDetachOwnerV15(entry);
 if(s!=VZ_KERNEL_OK){Diagnose(diagnostic,s,NULL,entry->vm,entry,true);End(&entry->operation);return Mach(s);}
 End(&entry->operation);
 return cleanup?FactoryInheritedCleanupV15(vm,diagnostic):FactoryInheritedDestroyV15(id,diagnostic);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryDestroyV2(VM27CPUFactoryIDV2 id,VM27CPUFactoryDiagnosticV2 *d) {
 return GICDestroyCPUOwnerV15(id,NULL,d,false);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryOwnerCleanupV2(VM27CPUFactoryVMV2 *vm,VM27CPUFactoryDiagnosticV2 *d) {
 return GICDestroyCPUOwnerV15(0,vm,d,true);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMDestroyV2(VM27CPUFactoryVMV2 *vm,VM27CPUFactoryDiagnosticV2 *d) {
 VM27CPUFactoryMachStatusV2 s=VM27CPUFactoryVMGICTeardownV15(vm);
 return s?s:FactoryInheritedVMDestroyV15(vm,d);
}
hv_return_t hv_vcpu_create(hv_vcpu_t *out,hv_vcpu_exit_t **exit,hv_vcpu_config_t config) {
 if(!PublicBeginV6()){dprintf(2,"[Independent27HV] failed stage=vcpu-create-admission status=0x%08x\n",(unsigned)Mach(VZ_KERNEL_BUSY));return Mach(VZ_KERNEL_BUSY);}
 Lock();VM27CPUFactoryVMV2 *vm=Registered;Unlock();
 VM27CPUFactoryDiagnosticV2 diagnostic={0};
 hv_return_t s=vm?VM27CPUFactoryCreateV2(vm,(VM27CPUFactoryIDV2 *)out,(VM27CPUFactoryExitV2 **)exit,
  (const void *)config,&diagnostic):Mach(VZ_KERNEL_NOT_LIVE);
 if(s)dprintf(2,"[Independent27HV] failed stage=vcpu-create status=0x%08x ownStatus=%u nativeInvoked=%u nativeReturn=%d nativeCreated=%u configured=%u creationStatus=%u failedOffset=0x%x cleanupPending=%u\n",(unsigned)s,(unsigned)diagnostic.ownStatus,diagnostic.nativeInvoked,diagnostic.nativeReturn,diagnostic.nativeCPUCreationComplete,diagnostic.creationConfigComplete,(unsigned)diagnostic.creationReceipt.status,diagnostic.creationReceipt.failedNativeOffset,diagnostic.cleanupPending);
 PublicEndV6();return s;
}
hv_return_t hv_vcpu_destroy(hv_vcpu_t id) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 hv_return_t s=VM27CPUFactoryDestroyV2(id,NULL);PublicEndV6();return s;
}
__attribute__((visibility("hidden"))) hv_return_t FactoryInheritedPublicRunV16(hv_vcpu_t id) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 VM27CPUFactoryBorrowV2 *borrow=NULL;VM27CPUFactoryRunDiagnosticV3 diagnostic={0};
 hv_return_t status=VM27CPUFactoryBorrowAcquireV2(id,&borrow);bool canceled=false;
 Entry *entry=NULL;FactoryGICCPUV15 *c=NULL;uint64_t epoch=0,generation=0,owner=0;
 if(!status) {
  entry=borrow->entry;c=GICCPUV15(entry);epoch=entry->vm->epoch;generation=entry->generation;owner=entry->nativeOwnerThread;
  if(c && c->lower)status=Mach(VZKernelCPUGICOwnerTakeExitV18(c->lower,&canceled));
  if(!status && !canceled) {
   status=RunOwnedStepV8(borrow,&diagnostic,false);
   if(status==Mach(VZ_KERNEL_BUSY) && c && c->lower) {
    VZKernelStatus took=VZKernelCPUGICOwnerTakeExitV18(c->lower,&canceled);
    if(took!=VZ_KERNEL_OK)status=Mach(took);else if(canceled)status=0;
   }
  }
  hv_return_t before=status;status=PublicReleaseV6(borrow,status);
  if(canceled && !before && status && c && c->lower) {
   bool wake=false;(void)VZKernelCPUGICOwnerRequestExitV18(c->lower,&wake);
  }
 }
 if(!status) {
  Lock();Entry *live=NULL;
  if(Registered)for(Entry *e=Registered->entries;e;e=e->next)if(e==entry && e->identity==id){live=e;break;}
  const VZKernelRunStepReceiptV7 *step=&diagnostic.step;
  bool valid=live && live==Owned && live->published && live->live && live->complete && live->configComplete &&
   !live->draining && live->vm->live && live->vm->epoch==epoch && live->generation==generation &&
   live->nativeOwnerThread==owner && pthread_equal(pthread_self(),live->owner);
  if(valid && !canceled)valid=step->status==VZ_KERNEL_OK && step->lifecycle.nativeInvoked &&
   !step->lifecycle.nativeReturn && step->postReturnIdentityValidated && step->runToken &&
   step->vmEpoch==epoch && step->cpuGeneration==generation && step->ownerThread==owner &&
   step->reductionValid && step->publicExceptionProduced &&
   step->reduction.kind==VZ_CPU_EXIT_DECODED_EXCEPTION_V1 && step->reduction.hasPublicException==1;
  bool begun=valid && Begin(&live->operation);
  if(!valid)status=Mach(VZ_KERNEL_NOT_LIVE);else if(!begun)status=Mach(VZ_KERNEL_BUSY);
  else {
   VM27CPUFactoryExitV2 exit={0};if(!canceled)memcpy(&exit,&step->reduction.exception,sizeof(exit));
   memcpy(live->exitStorage,&exit,sizeof(exit));live->exitRecordValid=true;End(&live->operation);
  }
  Unlock();
 }
 PublicEndV6();return status;
}
hv_return_t hv_vcpus_exit(hv_vcpu_t *ids,uint32_t count) {
 if(!ids || !count || count>VM27_GIC_CPUS_V1 || !GICFactoryOutputV15(ids,(size_t)count*sizeof(*ids),false))
  return Mach(VZ_KERNEL_BAD_ARGUMENT);
 hv_vcpu_t staged[VM27_GIC_CPUS_V1];memcpy(staged,ids,(size_t)count*sizeof(*ids));
 // First validate the whole vector against concrete attachments. Their real
 // retained factory/kernel borrows pin them across the asynchronous request.
 FactoryGICCPUV15 *cpus[VM27_GIC_CPUS_V1]={0};FactoryGICRetainV15 *pins[VM27_GIC_CPUS_V1]={0};
 VZKernelCPUGICOwnerV18 *owners[VM27_GIC_CPUS_V1]={0};
 GICLockV15();FactoryGICVMV15 *g=GICRegisteredV15;bool valid=g && !g->closing;
 for(uint32_t i=0;i<count && valid;++i) {
  for(uint32_t j=0;j<i;++j)if(staged[i]==staged[j])valid=false;
  for(FactoryGICCPUV15 *c=g->cpus;c;c=c->next)if(c->identity.expectedPublicIdentity==staged[i] && c->lower && c->attached){cpus[i]=c;break;}
  for(FactoryGICRetainV15 *r=g->retains;r;r=r->next)if(!r->closing && r->wake && r->identity.expectedPublicIdentity==staged[i]){pins[i]=r;break;}
  if(!cpus[i] || !pins[i] || pins[i]->callbacks==UINT_MAX)valid=false;
 }
 if(valid)for(uint32_t i=0;i<count;++i){++pins[i]->callbacks;owners[i]=cpus[i]->lower;}
 GICUnlockV15();if(!valid)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 Lock();for(uint32_t i=0;i<count && valid;++i)valid=Registered==g->vm && ContainsBorrow(pins[i]->borrow) &&
  pins[i]->borrow->entry->published && !pins[i]->borrow->entry->draining && pins[i]->borrow->entry->live;
 Unlock();
 VZKernelStatus own=VZ_KERNEL_OK;
 if(!valid)own=VZ_KERNEL_NOT_LIVE;
 for(uint32_t i=0;i<count && valid;++i) {
  bool wake=false;VZKernelStatus s=VZKernelCPUGICOwnerRequestExitV18(owners[i],&wake);
  if(s==VZ_KERNEL_OK && wake) {VZKernelCPUWakeReceiptV17 receipt={0};
   s=VZKernelCPUWakeOwnerSignalV17(pins[i]->wake,&pins[i]->identity,&receipt);}
  if(s!=VZ_KERNEL_OK && own==VZ_KERNEL_OK)own=s;
 }
 GICLockV15();for(uint32_t i=0;i<count;++i)--pins[i]->callbacks;GICUnlockV15();return Mach(own);
}

static void FactoryMaskPoisonV16(Entry *e,const VZKernelRunPendingRequestV14 *q) {
 // The factory operation and actual borrow already hold this exact CPU.
 (void)VZKernelCPUProducerPoisonV20(e->cpu,q);
 Lock();e->published=false;e->draining=true;e->exitRecordValid=false;Unlock();
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessVtimerMaskV16(
 VM27CPUFactoryBorrowV2 *borrow,bool write,bool mask,bool *out,VZKernelVtimerMaskReceiptV20 *outReceipt) {
 if(!outReceipt || (!write && !out))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus s=BeginBorrow(borrow);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!pthread_equal(pthread_self(),borrow->borrower)){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 Lock();bool valid=ContainsBorrow(borrow) && Output(outReceipt,sizeof(*outReceipt)) &&
  VZKernelCPUOutputRangeDisjointV12(outReceipt,sizeof(*outReceipt)) &&
  VM27CPUSelfMappedRangeV1(outReceipt,sizeof(*outReceipt),true,NULL) &&
  (!out || (Output(out,sizeof(*out)) && VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) &&
   Disjoint(out,sizeof(*out),outReceipt,sizeof(*outReceipt)) && VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL)));
 Entry *e=valid?borrow->entry:NULL;bool owned=e && e==Owned && pthread_equal(e->owner,pthread_self());
 bool begun=owned && Begin(&e->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!owned){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelLifecycleResult lifecycle={0};VZKernelVtimerMaskReceiptV20 r={0};bool result=false;
 s=!e->published || e->draining || !e->configComplete?VZ_KERNEL_NOT_LIVE:
  VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(s==VZ_KERNEL_OK && cpu!=e->cpu)s=VZ_KERNEL_NOT_LIVE;
 VZKernelRunPendingRequestV14 q=FactoryPendingRequestV12(e);
 if(s==VZ_KERNEL_OK) {
  s=VZKernelCPUAccessVtimerMaskV20(cpu,&q,&e->vm->writer,write,mask,write?NULL:&result,&r,&lifecycle);
  if(r.attemptedWrites)e->exitRecordValid=false;
  if(r.mutationPoisoned){Lock();e->published=false;e->draining=true;Unlock();}
 }
 bool outputValid=GICFactoryOutputV15(outReceipt,sizeof(*outReceipt),true) &&
  (!out || (GICFactoryOutputV15(out,sizeof(*out),true) && Disjoint(out,sizeof(*out),outReceipt,sizeof(*outReceipt))));
 if(!outputValid) {
  s=VZ_KERNEL_BAD_ARGUMENT;
  if(r.attemptedWrites)FactoryMaskPoisonV16(e,&q);
 }else {
  r.status=s;*outReceipt=r;if(s==VZ_KERNEL_OK && !write)*out=result;
 }
 End(&e->operation);End(&borrow->operation);return Mach(s);
}
hv_return_t hv_vcpu_get_vtimer_mask(hv_vcpu_t id,bool *out) {
 if(!GICFactoryOutputV15(out,sizeof(*out),true))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 VM27CPUFactoryBorrowV2 *borrow=NULL;VZKernelVtimerMaskReceiptV20 r={0};bool mask=false;
 hv_return_t s=VM27CPUFactoryBorrowAcquireV2(id,&borrow);
 if(!s)s=VM27CPUFactoryBorrowAccessVtimerMaskV16(borrow,false,false,&mask,&r);
 if(borrow)s=PublicReleaseV6(borrow,s);
 if(!s){if(!GICFactoryOutputV15(out,sizeof(*out),true))s=Mach(VZ_KERNEL_BAD_ARGUMENT);else *out=mask;}
 PublicEndV6();return s;
}
hv_return_t hv_vcpu_set_vtimer_mask(hv_vcpu_t id,bool mask) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 VM27CPUFactoryBorrowV2 *borrow=NULL;VZKernelVtimerMaskReceiptV20 r={0};
 hv_return_t s=VM27CPUFactoryBorrowAcquireV2(id,&borrow);
 if(!s)s=VM27CPUFactoryBorrowAccessVtimerMaskV16(borrow,true,mask,NULL,&r);
 if(borrow)s=PublicReleaseV6(borrow,s);
 PublicEndV6();return s;
}
static bool FactoryPublicProducerValidV16(const VZKernelRunPublicReceiptV20 *r,
 uint64_t epoch,uint64_t generation,uint64_t owner) {
 const VZKernelRunStepReceiptV7 *s=&r->pending.step;
 if(!r->publicExitProduced || r->pending.mutationPoisoned || r->pending.identityWithdrawn ||
  s->status!=VZ_KERNEL_OK || !s->lifecycle.nativeInvoked || s->lifecycle.nativeReturn ||
  !s->postReturnIdentityValidated || !s->runToken || s->vmEpoch!=epoch ||
  s->cpuGeneration!=generation || s->ownerThread!=owner)return false;
 uint32_t raw=s->nativeValues.rawReason;
 if(r->publicExit.reason==1) {
  if(r->ordinaryHVCProduced) {
   uint64_t x0=r->nativeHVCX0;bool privateFamily=!(s->nativeValues.syndrome32&0xffff) && !(x0>>32) &&
    ((x0>=UINT64_C(0xc6000000) && x0<=UINT64_C(0xc600001f)) || x0==UINT64_C(0xc3000006));
   return (raw==1 || raw==6 || raw==8) && s->nativeValues.knownFields==VZ_CPU_EXIT_ALL_KNOWN_V1 &&
    (s->nativeValues.syndrome32>>26)==0x16 && r->nativeHVCX0Read && r->nativeHVCCPSRRead &&
    (r->nativeHVCCPSR&0xc)==4 && !privateFamily && !r->publicExit.reserved &&
    r->publicExit.syndrome==s->nativeValues.syndrome32 &&
    r->publicExit.virtualAddress==s->nativeValues.virtualAddress &&
    r->publicExit.physicalAddress==s->nativeValues.physicalAddress && !s->publicExceptionProduced && !s->reductionValid;
  }
  return s->reductionValid && s->publicExceptionProduced &&
   s->reduction.kind==VZ_CPU_EXIT_DECODED_EXCEPTION_V1 && s->reduction.hasPublicException==1 &&
   !memcmp(&r->publicExit,&s->reduction.exception,sizeof(r->publicExit));
 }
 if(r->publicExit.reason==0)return raw==0;
 if(r->publicExit.reason==2)return (raw==3 || raw==4) && r->initialVtimerMaskKnown &&
  !r->initialVtimerMask && r->nativeCNTVControlRead && r->nativeCNTVControlFresh &&
  r->entryActiveBanksRead && (r->entryActiveBanks&1) && r->returnReadyBanksRead && r->nativeCNTVControl==5 &&
  r->autoMaskWritesAttempted==1 && r->autoMaskWritesCompleted==1 && r->autoMaskCommitted;
 if(r->publicExit.reason==3)return raw==5 || raw==9 || raw==10 ||
  ((raw==3 || raw==4) && r->initialVtimerMaskKnown && r->nativeCNTVControlRead && r->nativeCNTVControlFresh &&
   (r->initialVtimerMask || r->nativeCNTVControl!=5));
 return false;
}
static hv_return_t FactoryRunProducerV16(VM27CPUFactoryBorrowV2 *borrow,
 VZKernelRunPublicReceiptV20 *out) {
 VZKernelStatus s=BeginBorrow(borrow);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!pthread_equal(pthread_self(),borrow->borrower)){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 Lock();bool valid=ContainsBorrow(borrow) && Output(out,sizeof(*out)) &&
  VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) && VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL);
 Entry *e=valid?borrow->entry:NULL;bool owned=e && e==Owned && pthread_equal(e->owner,pthread_self());
 bool begun=owned && Begin(&e->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!owned){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelRunPublicReceiptV20 r={0};
 s=!e->published || e->draining || !e->configComplete?VZ_KERNEL_NOT_LIVE:
  VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(s==VZ_KERNEL_OK && cpu!=e->cpu)s=VZ_KERNEL_NOT_LIVE;
 VZKernelRunPendingRequestV14 q=FactoryPendingRequestV12(e);
 if(s==VZ_KERNEL_OK) {
  e->exitRecordValid=false;s=VZKernelCPURunGICPublicV20(cpu,&q,&e->vm->writer,&r);
  if(r.pending.mutationPoisoned || r.pending.identityWithdrawn){Lock();e->published=false;e->draining=true;Unlock();}
  if(s==VZ_KERNEL_OK && !FactoryPublicProducerValidV16(&r,e->vm->epoch,e->generation,e->nativeOwnerThread)) {
   s=VZ_KERNEL_NOT_LIVE;if(r.autoMaskWritesAttempted || r.runStateMutationAttempted)FactoryMaskPoisonV16(e,&q);
  }
 }
 if(!GICFactoryOutputV15(out,sizeof(*out),true)) {
  s=VZ_KERNEL_BAD_ARGUMENT;if(r.autoMaskWritesAttempted || r.runStateMutationAttempted)FactoryMaskPoisonV16(e,&q);
 }else *out=r;
 End(&e->operation);End(&borrow->operation);return Mach(s);
}
hv_return_t hv_vcpu_run(hv_vcpu_t id) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 VM27CPUFactoryBorrowV2 *borrow=NULL;VZKernelRunPublicReceiptV20 r={0};
 hv_return_t status=VM27CPUFactoryBorrowAcquireV2(id,&borrow);bool canceled=false;
 Entry *entry=NULL;FactoryGICCPUV15 *c=NULL;uint64_t epoch=0,generation=0,owner=0;
 if(!status) {
  entry=borrow->entry;c=GICCPUV15(entry);epoch=entry->vm->epoch;generation=entry->generation;owner=entry->nativeOwnerThread;
  if(c && c->lower)status=Mach(VZKernelCPUGICOwnerTakeExitV18(c->lower,&canceled));
  if(!status && !canceled) {
   status=FactoryRunProducerV16(borrow,&r);
   if((status==Mach(VZ_KERNEL_BUSY) || (!status && r.publicExitProduced && !r.publicExit.reason)) && c && c->lower) {
    bool ownCanceled=false;VZKernelStatus took=VZKernelCPUGICOwnerTakeExitV18(c->lower,&ownCanceled);
    if(took!=VZ_KERNEL_OK)status=Mach(took);else if(ownCanceled){canceled=true;status=0;}
   }
  }
  hv_return_t before=status;status=PublicReleaseV6(borrow,status);
  if(canceled && !before && status && c && c->lower){bool wake=false;(void)VZKernelCPUGICOwnerRequestExitV18(c->lower,&wake);}
  if(status && !before && (r.autoMaskWritesAttempted || r.runStateMutationAttempted))(void)VM27CPUFactoryPoisonGICCPUV15(id,epoch,generation);
 }
 if(!status) {
  Lock();Entry *live=NULL;
  if(Registered)for(Entry *e=Registered->entries;e;e=e->next)if(e==entry && e->identity==id){live=e;break;}
  bool valid=live && live==Owned && live->published && live->live && live->complete && live->configComplete &&
   !live->draining && live->vm->live && live->vm->epoch==epoch && live->generation==generation &&
   live->nativeOwnerThread==owner && pthread_equal(pthread_self(),live->owner);
  if(valid && !canceled)valid=FactoryPublicProducerValidV16(&r,epoch,generation,owner);
  bool begun=valid && Begin(&live->operation);
  if(!valid)status=Mach(VZ_KERNEL_NOT_LIVE);else if(!begun)status=Mach(VZ_KERNEL_BUSY);
  else {
   VM27CPUFactoryExitV2 exit={0};if(!canceled)memcpy(&exit,&r.publicExit,sizeof(exit));
   memcpy(live->exitStorage,&exit,sizeof(exit));live->exitRecordValid=true;End(&live->operation);
  }
  Unlock();
  if(status && (r.autoMaskWritesAttempted || r.runStateMutationAttempted))(void)VM27CPUFactoryPoisonGICCPUV15(id,epoch,generation);
 }
 PublicEndV6();return status;
}
