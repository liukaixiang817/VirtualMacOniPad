// Include after a new lifecycle TU's frozen Life14/15 definitions.
// Exact current native fields: kernel80a99a0/99b0 save CNTP CVAL/CTL to3f0/438;
// kernel80abc90/abca0 restore them when dirty748 bit0 is set. No modern field
// offset is copied to the old context, and neither version nor ready is written.
struct VZKernelPhysicalTimerOwnerV19 {
 VZKernelCPUBorrowV5 *borrow;
 VZKernelCPU *cpu;
 VZKernelRunPendingRequestV14 identity;
 VZKernelPhysicalTimerBindingV19 binding;
 VZKernelInitWriter writer;
 _Atomic bool operation;
 pthread_t ownerPthread;
 bool quiesced;
 uint64_t translationOffset;
 struct VZKernelPhysicalTimerOwnerV19 *next;
 bool registered;
};
static pthread_mutex_t PhysicalOwnersMutexV19=PTHREAD_MUTEX_INITIALIZER;
static VZKernelPhysicalTimerOwnerV19 *PhysicalOwnersV19;
static bool PhysicalRegisterV19(VZKernelPhysicalTimerOwnerV19 *o) {
 Lock(&PhysicalOwnersMutexV19);bool unique=true;
 for(VZKernelPhysicalTimerOwnerV19 *p=PhysicalOwnersV19;p;p=p->next)if(p->cpu==o->cpu){unique=false;break;}
 if(unique){o->next=PhysicalOwnersV19;PhysicalOwnersV19=o;o->registered=true;}
 Unlock(&PhysicalOwnersMutexV19);return unique;
}
static void PhysicalUnregisterV19(VZKernelPhysicalTimerOwnerV19 *o) {
 Lock(&PhysicalOwnersMutexV19);VZKernelPhysicalTimerOwnerV19 **p=&PhysicalOwnersV19;
 while(*p && *p!=o)p=&(*p)->next;
 if(o->registered){if(*p!=o)abort();*p=o->next;o->registered=false;}
 Unlock(&PhysicalOwnersMutexV19);
}
#include <mach/mach_time.h>
#include "modern_cpu_native_self_memory_v1.h"
VZKernelCounterDomainResultV19 VZKernelValidateCounterDomainV19(const VZKernelCounterDomainSampleV19 *s) {
 if(!s || s->commpageVersionBefore!=3 || s->commpageVersionAfter!=3 ||
  s->userTimebaseBefore<1 || s->userTimebaseBefore>3 ||
  s->userTimebaseAfter!=s->userTimebaseBefore)return VZ_COUNTER_DOMAIN_COMMPAGE_V19;
 if(s->physicalAfter<s->physicalBefore || s->commpageBaseBefore!=s->commpageBaseAfter)
  return VZ_COUNTER_DOMAIN_UNSTABLE_V19;
 if(!s->counterFrequency || s->counterFrequency>UINT32_MAX || !s->timebaseNumer || !s->timebaseDenom ||
  (__uint128_t)s->counterFrequency*s->timebaseNumer!=(__uint128_t)UINT64_C(1000000000)*s->timebaseDenom)
  return VZ_COUNTER_DOMAIN_FREQUENCY_V19;
 if(s->machAbsolute-s->commpageBaseBefore<s->physicalBefore ||
  s->machAbsolute-s->commpageBaseBefore>s->physicalAfter)return VZ_COUNTER_DOMAIN_EPOCH_V19;
 // Bias is a uint64 modular additive offset, including a negative value in
 // two's complement. Exact kernel80abb7c subtracts that same global from
 // native6a0 before MSR CNTVOFF; actual commpage88 is copied from it.
 return VZ_COUNTER_DOMAIN_VALID_V19;
}
bool VZKernelReadCounterDomainSampleV19(void *context,VZKernelCounterDomainSampleV19 *out) {
 (void)context;if(!out)return false;
#if defined(__aarch64__)
 VZKernelCounterDomainSampleV19 s={0};mach_timebase_info_data_t t={0};
 const uintptr_t base=UINT64_C(0x0000000fffffc000);
 if(mach_timebase_info(&t)!=KERN_SUCCESS)return false;
 if(!VM27CPUSelfReadV1(NULL,(const void *)(base+0x1e),2,&s.commpageVersionBefore) ||
  !VM27CPUSelfReadV1(NULL,(const void *)(base+0x90),1,&s.userTimebaseBefore) ||
  !VM27CPUSelfReadV1(NULL,(const void *)(base+0x88),8,&s.commpageBaseBefore))return false;
 __asm__ volatile("isb\n\tmrs %0, cntfrq_el0":"=r"(s.counterFrequency)::"memory");
 __asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(s.physicalBefore)::"memory");
 s.machAbsolute=mach_absolute_time();
 __asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(s.physicalAfter)::"memory");
 if(!VM27CPUSelfReadV1(NULL,(const void *)(base+0x88),8,&s.commpageBaseAfter) ||
  !VM27CPUSelfReadV1(NULL,(const void *)(base+0x90),1,&s.userTimebaseAfter) ||
  !VM27CPUSelfReadV1(NULL,(const void *)(base+0x1e),2,&s.commpageVersionAfter))return false;
 s.timebaseNumer=t.numer;s.timebaseDenom=t.denom;*out=s;return true;
#else
 return false;
#endif
}
static bool PhysicalOwnerRangesV19(VZKernelPhysicalTimerOwnerV19 *o,
 const void *const *p,const size_t *n,unsigned count) {
 if(!PendingRangesV14(o->cpu,p,n,count))return false;
 for(unsigned i=0;i<count;++i)
  if(!PendingOutputDisjointV3(p[i],n[i],o,sizeof(*o)))return false;
 return true;
}
// When a Run guard is already held, every field and callback also checks its
// actual V7 post capability. An ordinary owner guard cannot stand in for it.
static bool PhysicalBoundaryV19(InitializationAccess *a,PendingRunAccessV14 *post) {
 if(post) {
  if(!post->post || post->init.cpu!=a->cpu || !post->init.writer ||
   post->init.writer->context!=a->writer->context ||
   post->init.writer->writeMemory!=a->writer->writeMemory) {
   a->boundaryStatus=VZ_KERNEL_BAD_ARGUMENT;return false;
  }
  if(!PendingBoundaryV14(post)){a->boundaryStatus=post->init.boundaryStatus;return false;}
 }
 return InitializationOwned(a);
}
static bool PhysicalReadV19(InitializationAccess *a,VZKernelPhysicalTimerReceiptV19 *r,
 PendingRunAccessV14 *post,uint32_t offset,uint64_t *out) {
 ++r->attemptedReads;
 bool exact=offset==0x3f0 || offset==0x438 || offset==0x6a0 || offset==0x748 || offset==0x4100;
 bool ok=exact && PhysicalBoundaryV19(a,post) &&
  a->cpu->nativeContext<=UINTPTR_MAX-offset-8 &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),8,false,NULL) &&
  a->cpu->vm->ops.readMemory(a->cpu->vm->ops.context,
   (const void *)(a->cpu->nativeContext+offset),8,out) && PhysicalBoundaryV19(a,post);
 if(!ok){r->failedNativeOffset=offset;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
static bool PhysicalWriteV19(InitializationAccess *a,VZKernelPhysicalTimerReceiptV19 *r,
 PendingRunAccessV14 *post,uint32_t offset,uint64_t value) {
 ++r->attemptedWrites;
 bool exact=offset==0x3f0 || offset==0x438 || offset==0x748;
 bool ok=exact && a->writer && a->writer->writeMemory && PhysicalBoundaryV19(a,post) &&
  a->cpu->nativeContext<=UINTPTR_MAX-offset-8 &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),8,true,NULL) &&
  a->writer->writeMemory(a->writer->context,
   (void *)(a->cpu->nativeContext+offset),8,&value) && PhysicalBoundaryV19(a,post);
 if(ok)++r->completedWrites;
 else{r->failedNativeOffset=offset;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
VZKernelStatus VZKernelPhysicalTimerOwnerCreateV19(const VZKernelRunPendingRequestV14 *input,
 const VZKernelPhysicalTimerBindingV19 *binding,const VZKernelInitWriter *writer,
 VZKernelPhysicalTimerOwnerV19 **out) {
 if(!input || !binding || !writer || !out)return VZ_KERNEL_BAD_ARGUMENT;
 const void *p[]={input,binding,writer,out};const size_t n[]={sizeof(*input),sizeof(*binding),sizeof(*writer),sizeof(*out)};
 for(unsigned i=0;i<4;++i) {
  if(!VZKernelCPUOutputRangeDisjointV12(p[i],n[i]))return VZ_KERNEL_BAD_ARGUMENT;
  for(unsigned j=0;j<i;++j)if(!PendingOutputDisjointV3(p[i],n[i],p[j],n[j]))return VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelRunPendingRequestV14 q=*input;VZKernelPhysicalTimerBindingV19 b=*binding;
 VZKernelInitWriter w=*writer;
 if(!b.readCounterDomain || !b.gicOwner || !b.validateGICOwner || !b.routePhysicalTimer ||
  !b.updatePhysicalDeadline || !b.quiescePhysicalTimer || !w.writeMemory)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelPhysicalTimerOwnerV19 *o=calloc(1,sizeof(*o));if(!o)return VZ_KERNEL_OUT_OF_MEMORY;
 o->identity=q;o->binding=b;o->writer=w;o->ownerPthread=pthread_self();atomic_init(&o->operation,false);
 VZKernelStatus status=VZKernelCPUBorrowIdentityV5(q.expectedPublicIdentity,&o->borrow);
 if(status==VZ_KERNEL_OK)status=VZKernelCPUBorrowHandleV5(o->borrow,&o->cpu);
 bool entered=false;
 if(status==VZ_KERNEL_OK){status=BeginCPUOperation(o->cpu);entered=status!=VZ_KERNEL_BUSY;}
 if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(o->cpu,&q);
 if(status==VZ_KERNEL_OK && (b.nativeContext!=o->cpu->vm->ops.context || w.context!=b.nativeContext))
  status=VZ_KERNEL_BAD_ARGUMENT;
 VZKernelLifecycleResult lifecycle={0};
 if(status==VZ_KERNEL_OK)status=Version(o->cpu,&lifecycle);
 if(status==VZ_KERNEL_OK)status=b.validateGICOwner(b.gicOwner,&q);
 InitializationAccess a={o->cpu,&w,&lifecycle,VZ_KERNEL_OK};
 if(status==VZ_KERNEL_OK && !InitializationOwned(&a))status=a.boundaryStatus;
 VZKernelPhysicalTimerReceiptV19 initial={0};
 if(status==VZ_KERNEL_OK && o->cpu->runToken)status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK && (!PhysicalReadV19(&a,&initial,NULL,0x3f0,&initial.nativeCVAL) ||
  !PhysicalReadV19(&a,&initial,NULL,0x438,&initial.nativeControl)))status=initial.status;
 if(status==VZ_KERNEL_OK && (initial.nativeCVAL || initial.nativeControl))status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK && !PhysicalRegisterV19(o))status=VZ_KERNEL_BUSY;
 if(entered)EndOperation(&o->cpu->operationInProgress);
 if(status==VZ_KERNEL_OK){*out=o;return status;}
 if(o->borrow && VZKernelCPUReleaseBorrowV5(o->borrow)!=VZ_KERNEL_OK) {
  // The caller must retain this concrete cleanup allocation on release failure.
  o->quiesced=true;*out=o;return VZ_KERNEL_NATIVE_ERROR;
 }
 free(o);return status;
}
#include "modern_gic_physical_batch_v9.h"
typedef struct {InitializationAccess *access;PendingRunAccessV14 *post;} PhysicalBatchBoundaryV20;
static VZKernelStatus PhysicalBatchCheckV20(void *opaque) {
 PhysicalBatchBoundaryV20 *b=opaque;
 return PhysicalBoundaryV19(b->access,b->post)?VZ_KERNEL_OK:b->access->boundaryStatus;
}
static VZKernelStatus PhysicalAccessCoreV19(VZKernelPhysicalTimerOwnerV19 *o,
 VZKernelPhysicalTimerActionV19 action,uint32_t identifier,uint64_t value,uint64_t *outValue,
 VZKernelPhysicalTimerReceiptV19 *outReceipt,VZKernelLifecycleResult *outLifecycle,
 PendingRunAccessV14 *post) {
 VZKernelPhysicalTimerReceiptV19 r={0};VZKernelLifecycleResult lifecycle={0};VZKernelCPU *cpu=o->cpu;VZKernelStatus status;r.failedNativeOffset=UINT32_MAX;
 status=PendingRequestOwnedV14(cpu,&o->identity);
 if(status==VZ_KERNEL_OK && ((action!=VZ_KERNEL_PHYSICAL_TIMER_READ_V19 &&
  action!=VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19 && action!=VZ_KERNEL_PHYSICAL_TIMER_POLL_V19) ||
  (action==VZ_KERNEL_PHYSICAL_TIMER_POLL_V19?(identifier || value):
   (identifier!=VZ_KERNEL_PHYSICAL_TIMER_CTL_V19 && identifier!=VZ_KERNEL_PHYSICAL_TIMER_CVAL_V19)) ||
  (action==VZ_KERNEL_PHYSICAL_TIMER_READ_V19 && (!outValue || value))))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 InitializationAccess a={cpu,&o->writer,&lifecycle,VZ_KERNEL_OK};uint64_t offset=0,ready=0,dirty=0;
 if(status==VZ_KERNEL_OK && !PhysicalReadV19(&a,&r,post,0x6a0,&offset))status=r.status;
 if(status==VZ_KERNEL_OK)status=o->binding.validateGICOwner(o->binding.gicOwner,&o->identity);
 if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
 if(status==VZ_KERNEL_OK) {
  if(!PhysicalReadV19(&a,&r,post,0x748,&dirty))status=r.status;
  if(status==VZ_KERNEL_OK && !PhysicalReadV19(&a,&r,post,0x4100,&ready))status=r.status;
  if(status==VZ_KERNEL_OK && !((ready|dirty)&UINT64_C(1))) {
   r.nativeOp8Required=true;status=PrepareSystemNative8V8(&a,&r.nativeOp8Invoked);
  }
 }
 if(status==VZ_KERNEL_OK && (!PhysicalReadV19(&a,&r,post,0x438,&r.nativeControl) ||
  !PhysicalReadV19(&a,&r,post,0x3f0,&r.nativeCVAL)))status=r.status;
 if(status==VZ_KERNEL_OK) {
  r.physicalStateRead=true;
  if(!PhysicalBoundaryV19(&a,post) || !o->binding.readCounterDomain(o->binding.nativeContext,&r.counterDomain) ||
   !PhysicalBoundaryV19(&a,post))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else {
   r.counterSampled=true;r.domainResult=VZKernelValidateCounterDomainV19(&r.counterDomain);
   r.domainValidated=r.domainResult==VZ_COUNTER_DOMAIN_VALID_V19;
   if(!r.domainValidated)status=VZ_KERNEL_UNSUPPORTED;
   r.nativeCounter=r.counterDomain.physicalAfter;
  }
 }
 r.vtimerOffset=offset;r.hostCounterBias=r.counterDomain.commpageBaseBefore;
 uint64_t physicalOffset=offset-r.hostCounterBias;
 r.physicalOffset=physicalOffset;r.previousPhysicalOffset=o->translationOffset;
 if(status==VZ_KERNEL_OK && (r.nativeCVAL<o->translationOffset || physicalOffset>r.counterDomain.physicalBefore))
  status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK)r.logicalCVAL=r.nativeCVAL-o->translationOffset;
 uint64_t logicalTarget=r.logicalCVAL;
 if(action==VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19 && identifier==VZ_KERNEL_PHYSICAL_TIMER_CVAL_V19)
  logicalTarget=value;
 if(status==VZ_KERNEL_OK && logicalTarget>UINT64_MAX-physicalOffset)status=VZ_KERNEL_UNSUPPORTED;
 // The dispatch scheduler admits only a finite representable relative delay.
 uint64_t targetPhysicalCVAL=logicalTarget+physicalOffset;
 uint64_t targetControl=action==VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19 &&
  identifier==VZ_KERNEL_PHYSICAL_TIMER_CTL_V19?value:r.nativeControl;
 if(status==VZ_KERNEL_OK && (targetControl&UINT64_C(3))==UINT64_C(1) &&
  targetPhysicalCVAL>r.nativeCounter) {
  __uint128_t ns=((__uint128_t)(targetPhysicalCVAL-r.nativeCounter)*UINT64_C(1000000000)+
   r.counterDomain.counterFrequency-1)/r.counterDomain.counterFrequency;
  if(ns>INT64_MAX)status=VZ_KERNEL_UNSUPPORTED;
 }
 if(status==VZ_KERNEL_UNSUPPORTED && r.domainValidated)r.domainResult=VZ_COUNTER_DOMAIN_TRANSLATION_RANGE_V19;
 bool rebase=status==VZ_KERNEL_OK && physicalOffset!=o->translationOffset;
 bool writeCVAL=status==VZ_KERNEL_OK && (rebase ||
  (action==VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19 && identifier==VZ_KERNEL_PHYSICAL_TIMER_CVAL_V19));
 if(writeCVAL && !PhysicalWriteV19(&a,&r,post,0x3f0,targetPhysicalCVAL))status=r.status;
 if(status==VZ_KERNEL_OK && action==VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19 &&
  identifier==VZ_KERNEL_PHYSICAL_TIMER_CTL_V19 && !PhysicalWriteV19(&a,&r,post,0x438,value&UINT64_C(3)))status=r.status;
 if(status==VZ_KERNEL_OK && r.attemptedWrites) {
  if(!PhysicalReadV19(&a,&r,post,0x748,&dirty) || !PhysicalWriteV19(&a,&r,post,0x748,dirty|UINT64_C(1)))status=r.status;
  if(status==VZ_KERNEL_OK) {
   o->translationOffset=physicalOffset;r.offsetRebased=rebase;
   if(!PhysicalReadV19(&a,&r,post,0x438,&r.nativeControl) || !PhysicalReadV19(&a,&r,post,0x3f0,&r.nativeCVAL))status=r.status;
  }
  if(status==VZ_KERNEL_OK) {
   VZKernelCounterDomainSampleV19 after={0},before=r.counterDomain;
   if(!PhysicalBoundaryV19(&a,post) || !o->binding.readCounterDomain(o->binding.nativeContext,&after) ||
    !PhysicalBoundaryV19(&a,post))status=VZ_KERNEL_CONTEXT_UNREADABLE;
   else {
    r.counterDomain=after;r.domainResult=VZKernelValidateCounterDomainV19(&after);
    r.domainValidated=r.domainResult==VZ_COUNTER_DOMAIN_VALID_V19;
    if(!r.domainValidated)status=VZ_KERNEL_UNSUPPORTED;
    if(status==VZ_KERNEL_OK && (after.physicalBefore<before.physicalAfter ||
     after.commpageBaseBefore!=before.commpageBaseBefore ||
     after.counterFrequency!=before.counterFrequency || after.timebaseNumer!=before.timebaseNumer ||
     after.timebaseDenom!=before.timebaseDenom || after.userTimebaseBefore!=before.userTimebaseBefore))
      status=VZ_KERNEL_UNSUPPORTED;
    r.nativeCounter=after.physicalAfter;
   }
  }
 }
 if(status==VZ_KERNEL_OK)r.logicalCVAL=r.nativeCVAL-physicalOffset;
 uint64_t result=identifier==VZ_KERNEL_PHYSICAL_TIMER_CTL_V19?
  ((r.nativeControl&UINT64_C(3))|(r.nativeCounter>=r.nativeCVAL?UINT64_C(4):0)):r.logicalCVAL;
 if(status==VZ_KERNEL_OK && (action!=VZ_KERNEL_PHYSICAL_TIMER_READ_V19 || rebase)) {
  r.physicalTimerAsserted=(r.nativeControl&UINT64_C(3))==UINT64_C(1) && r.nativeCounter>=r.nativeCVAL;
  bool aggregate=false;r.irqRouteAttempted=true;
  bool concreteGIC=o->binding.validateGICOwner==VM27GICValidateTimerOwnerV1 &&
      o->binding.routePhysicalTimer==VM27GICRoutePhysicalTimerV1 &&
      o->binding.updatePhysicalDeadline==VM27GICUpdatePhysicalDeadlineV1 &&
      o->binding.quiescePhysicalTimer==VM27GICQuiescePhysicalTimerV1;
  if(concreteGIC) {
   r.deadlineArmed=(r.nativeControl&UINT64_C(3))==UINT64_C(1) && r.nativeCounter<r.nativeCVAL;
   PhysicalBatchBoundaryV20 boundary={&a,post};VM27GICPhysicalBatchResultV9 batch={0};
   status=VM27GICRouteAndDeadlineV9(o->binding.gicOwner,&o->identity,
       r.physicalTimerAsserted,r.deadlineArmed,r.nativeCVAL,PhysicalBatchCheckV20,&boundary,&batch);
   aggregate=batch.irq;r.irqRouteComplete=batch.routeComplete;
   if(batch.routeComplete)r.aggregateIRQ=aggregate;
   r.deadlineAttempted=batch.deadlineAttempted;
   if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
   if(status==VZ_KERNEL_OK){r.deadlineComplete=true;cpu->pendingInterrupts.irqPending=(uint32_t)aggregate;}
  } else {
   status=o->binding.routePhysicalTimer(o->binding.gicOwner,&o->identity,r.physicalTimerAsserted,&aggregate);
   if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
   if(status==VZ_KERNEL_OK){r.irqRouteComplete=true;r.aggregateIRQ=aggregate;}
   if(status==VZ_KERNEL_OK) {
    r.deadlineArmed=(r.nativeControl&UINT64_C(3))==UINT64_C(1) && r.nativeCounter<r.nativeCVAL;
    r.deadlineAttempted=true;
    status=o->binding.updatePhysicalDeadline(o->binding.gicOwner,&o->identity,r.deadlineArmed,r.nativeCVAL);
    if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
    if(status==VZ_KERNEL_OK){r.deadlineComplete=true;cpu->pendingInterrupts.irqPending=(uint32_t)aggregate;}
   }
  }
 }
 if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
 if(a.boundaryStatus!=VZ_KERNEL_OK)status=a.boundaryStatus;
 if(status!=VZ_KERNEL_OK && (r.attemptedWrites || r.irqRouteAttempted || r.deadlineAttempted)) {
  cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
  cpu->registryEntry->published=false;cpu->registryEntry->draining=true;
  Unlock(&cpu->vm->mutex);r.identityWithdrawn=true;
 }
 CPUResult(cpu,&lifecycle);Finish(&lifecycle,status);r.status=status;r.mutationPoisoned=cpu->mutationPoisoned;
 if(status==VZ_KERNEL_OK && action==VZ_KERNEL_PHYSICAL_TIMER_READ_V19)*outValue=result;
 *outReceipt=r;*outLifecycle=lifecycle;return status;
}
VZKernelStatus VZKernelPhysicalTimerOwnerAccessV19(VZKernelPhysicalTimerOwnerV19 *o,
 VZKernelPhysicalTimerActionV19 action,uint32_t identifier,uint64_t value,uint64_t *outValue,
 VZKernelPhysicalTimerReceiptV19 *outReceipt,VZKernelLifecycleResult *outLifecycle) {
 if(!o || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(o->ownerPthread,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 if(!BeginOperation(&o->operation))return VZ_KERNEL_BUSY;
 if(o->quiesced){EndOperation(&o->operation);return VZ_KERNEL_NOT_LIVE;}
 VZKernelCPU *cpu=NULL;VZKernelStatus status=VZKernelCPUBorrowHandleV5(o->borrow,&cpu);
 bool entered=false;
 if(status==VZ_KERNEL_OK){status=BeginCPUOperation(cpu);entered=status!=VZ_KERNEL_BUSY;}
 if(status!=VZ_KERNEL_OK){if(entered)EndOperation(&cpu->operationInProgress);EndOperation(&o->operation);return status;}
 const void *p[]={outReceipt,outLifecycle,outValue};const size_t n[]={sizeof(*outReceipt),sizeof(*outLifecycle),sizeof(*outValue)};
 if(!PhysicalOwnerRangesV19(o,p,n,outValue?3:2)) {
  EndOperation(&cpu->operationInProgress);EndOperation(&o->operation);return VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelStatus result=PhysicalAccessCoreV19(o,action,identifier,value,outValue,outReceipt,outLifecycle,NULL);
 EndOperation(&cpu->operationInProgress);EndOperation(&o->operation);return result;
}
// Private same-TU entry: Life20 must pass the actual native9 return token.
// It shares the exact same owner translation field and conversion core.
static __attribute__((unused)) VZKernelStatus PhysicalTimerPostAccessV19(
 VZKernelPhysicalTimerOwnerV19 *o,PendingRunAccessV14 *post,
 VZKernelPhysicalTimerActionV19 action,uint32_t identifier,uint64_t value,
 uint64_t *outValue,VZKernelPhysicalTimerReceiptV19 *outReceipt) {
 if(!o || !post || !post->post || !outReceipt)return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(o->ownerPthread,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 if(!BeginOperation(&o->operation))return VZ_KERNEL_BUSY;
 VZKernelStatus status=VZ_KERNEL_OK;
 if(o->quiesced)status=VZ_KERNEL_NOT_LIVE;
 else if(post->init.cpu!=o->cpu)status=VZ_KERNEL_BAD_ARGUMENT;
 const void *p[]={outReceipt,outValue};const size_t n[]={sizeof(*outReceipt),sizeof(*outValue)};
 if(status==VZ_KERNEL_OK && !PhysicalOwnerRangesV19(o,p,n,outValue?2:1))status=VZ_KERNEL_BAD_ARGUMENT;
 InitializationAccess a={o->cpu,&o->writer,post->init.lifecycle,VZ_KERNEL_OK};
 if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
 if(status==VZ_KERNEL_OK) {
  VZKernelLifecycleResult lifecycle={0};
  status=PhysicalAccessCoreV19(o,action,identifier,value,outValue,outReceipt,&lifecycle,post);
  *post->init.lifecycle=lifecycle;
 }
 EndOperation(&o->operation);return status;
}
// df01 reads the same logical counter as physical CVAL/CTL emulation. It never
// returns a raw host CNTPCT under a nonzero guest offset. No timer field is
// changed by either counter/frequency getter.
static __attribute__((unused)) VZKernelStatus PhysicalTimerPostCounterV19(
 VZKernelPhysicalTimerOwnerV19 *o,PendingRunAccessV14 *post,uint16_t selector,
 uint64_t *outValue,VZKernelPhysicalTimerReceiptV19 *outReceipt) {
 if(!o || !post || !post->post || !outValue || !outReceipt ||
  (selector!=UINT16_C(0xdf00) && selector!=UINT16_C(0xdf01)))return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(o->ownerPthread,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 if(!BeginOperation(&o->operation))return VZ_KERNEL_BUSY;
 VZKernelStatus status=o->quiesced?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK && post->init.cpu!=o->cpu)status=VZ_KERNEL_BAD_ARGUMENT;
 const void *p[]={outReceipt,outValue};const size_t n[]={sizeof(*outReceipt),sizeof(*outValue)};
 if(status==VZ_KERNEL_OK && !PhysicalOwnerRangesV19(o,p,n,2))status=VZ_KERNEL_BAD_ARGUMENT;
 VZKernelPhysicalTimerReceiptV19 r={0};r.failedNativeOffset=UINT32_MAX;
 InitializationAccess a={o->cpu,&o->writer,post->init.lifecycle,VZ_KERNEL_OK};uint64_t offset=0;
 if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(status==VZ_KERNEL_OK && !PhysicalBoundaryV19(&a,post))status=a.boundaryStatus;
 if(status==VZ_KERNEL_OK)status=o->binding.validateGICOwner(o->binding.gicOwner,&o->identity);
 if(status==VZ_KERNEL_OK && !PhysicalReadV19(&a,&r,post,0x6a0,&offset))status=r.status;
 if(status==VZ_KERNEL_OK && (!PhysicalBoundaryV19(&a,post) ||
  !o->binding.readCounterDomain(o->binding.nativeContext,&r.counterDomain) ||
  !PhysicalBoundaryV19(&a,post)))status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK) {
  r.counterSampled=true;r.domainResult=VZKernelValidateCounterDomainV19(&r.counterDomain);
  r.domainValidated=r.domainResult==VZ_COUNTER_DOMAIN_VALID_V19;
  if(!r.domainValidated)status=VZ_KERNEL_UNSUPPORTED;
 }
 r.vtimerOffset=offset;r.hostCounterBias=r.counterDomain.commpageBaseBefore;
 r.physicalOffset=offset-r.hostCounterBias;r.previousPhysicalOffset=o->translationOffset;
 if(status==VZ_KERNEL_OK && r.physicalOffset>r.counterDomain.physicalBefore) {
  r.domainResult=VZ_COUNTER_DOMAIN_TRANSLATION_RANGE_V19;status=VZ_KERNEL_UNSUPPORTED;
 }
 if(a.boundaryStatus!=VZ_KERNEL_OK)status=a.boundaryStatus;
 r.status=status;r.nativeCounter=r.counterDomain.physicalAfter;
 r.mutationPoisoned=o->cpu->mutationPoisoned;
 if(status==VZ_KERNEL_OK)*outValue=selector==UINT16_C(0xdf00)?r.counterDomain.counterFrequency:
  r.counterDomain.machAbsolute-offset;
 // Output validation failure cannot be allowed to publish even a receipt.
 if(PhysicalOwnerRangesV19(o,p,n,2))*outReceipt=r;
 EndOperation(&o->operation);return status;
}
VZKernelStatus VZKernelPhysicalTimerOwnerDestroyV19(VZKernelPhysicalTimerOwnerV19 *o) {
 if(!o)return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(o->ownerPthread,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 if(!BeginOperation(&o->operation))return VZ_KERNEL_BUSY;
 if(!o->quiesced) {
  VZKernelStatus quiet=o->binding.quiescePhysicalTimer(o->binding.gicOwner,&o->identity);
  if(quiet!=VZ_KERNEL_OK){EndOperation(&o->operation);return quiet;}
  o->quiesced=true;
 }
 VZKernelStatus status=VZKernelCPUReleaseBorrowV5(o->borrow);
 if(status!=VZ_KERNEL_OK){EndOperation(&o->operation);return status;}
 PhysicalUnregisterV19(o);memset(o,0,sizeof(*o));free(o);return VZ_KERNEL_OK;
}
