// Life20 retains the exact private V18 ownership ABI used by frozen Factory15.
// Its actual timer owner uses Timer19; the legacy receipt exposes only actual
// shared fields and counts, while Timer19 owns the complete domain evidence.
static VZKernelPhysicalTimerReceiptV16 GICTimerLegacyReceiptV20(const VZKernelPhysicalTimerReceiptV19 *r) {
 return (VZKernelPhysicalTimerReceiptV16){.status=r->status,.attemptedReads=r->attemptedReads,.attemptedWrites=r->attemptedWrites,.completedWrites=r->completedWrites,.failedNativeOffset=r->failedNativeOffset,.nativeControl=r->nativeControl,.nativeCVAL=r->nativeCVAL,.nativeCounter=r->nativeCounter,.nativeOp8Required=r->nativeOp8Required,.nativeOp8Invoked=r->nativeOp8Invoked,.physicalStateRead=r->physicalStateRead,.counterSampled=r->counterSampled,.physicalTimerAsserted=r->physicalTimerAsserted,.aggregateIRQ=r->aggregateIRQ,.irqRouteAttempted=r->irqRouteAttempted,.irqRouteComplete=r->irqRouteComplete,.deadlineAttempted=r->deadlineAttempted,.deadlineComplete=r->deadlineComplete,.deadlineArmed=r->deadlineArmed,.mutationPoisoned=r->mutationPoisoned,.identityWithdrawn=r->identityWithdrawn};
}
// Actual CPU sidecars; no modern context layout is copied to the old kernel.
struct VZKernelCPUGICOwnerV18 {
 struct VZKernelCPUGICOwnerV18 *next;
 VZKernelCPUBorrowV5 *borrow;
 VZKernelCPU *cpu;
 VZKernelRunPendingRequestV14 identity;
 VM27GICV3V1 *engine;
 VZKernelPhysicalTimerOwnerV19 *timer;
 VZKernelInitWriter writer;
 pthread_t owner;
 _Atomic bool operation;
 _Atomic bool exitRequested,running;
 _Atomic bool draining;
 VM27WFxWaitV30 wfx;
};
static VZKernelStatus GICOwnerBeginV18(VZKernelCPUGICOwnerV18 *,VZKernelCPUGICOwnerV18 **);
static pthread_mutex_t GICOwnersMutexV18=PTHREAD_MUTEX_INITIALIZER;
static VZKernelCPUGICOwnerV18 *GICOwnersV18;
static VZKernelStatus GICWakeNotifyV30(const VZKernelRunPendingRequestV14 *q,VZKernelStatus status) {
 VZKernelStatus result=VZ_KERNEL_OK;
 Lock(&GICOwnersMutexV18);
 for(VZKernelCPUGICOwnerV18 *o=GICOwnersV18;o;o=o->next)
  if(!o->draining && !memcmp(q,&o->identity,sizeof(*q))) {
   result=VM27WFxSignalV30(&o->wfx,status);break;
  }
 Unlock(&GICOwnersMutexV18);return result;
}

static VZKernelCPUGICOwnerV18 *GICFindOwnerV18(VZKernelCPU *cpu) {
 VZKernelCPUGICOwnerV18 *found=NULL;Lock(&GICOwnersMutexV18);
 for(VZKernelCPUGICOwnerV18 *o=GICOwnersV18;o;o=o->next)if(o->cpu==cpu){found=o;break;}
 Unlock(&GICOwnersMutexV18);return found;
}
bool VZKernelCPUControllerOutputRangeDisjointV18(const void *p,size_t n) {
 if(!p || n>UINTPTR_MAX-(uintptr_t)p)return false;
 Lock(&GICOwnersMutexV18);bool valid=true;
 for(VZKernelCPUGICOwnerV18 *o=GICOwnersV18;o && valid;o=o->next) {
  valid=PendingOutputDisjointV3(p,n,o,sizeof(*o));
  if(o->engine)valid=valid && VM27GICOutputRangeDisjointV1(o->engine,p,n);
  if(o->timer)valid=valid && PendingOutputDisjointV3(p,n,o->timer,sizeof(*o->timer));
 }
 Unlock(&GICOwnersMutexV18);return valid;
}
bool VZKernelCPUWakeRangeDisjointV18(VZKernelCPUWakeOwnerV17 *o,const void *p,size_t n) {
 return o && PendingOutputDisjointV3(p,n,o,sizeof(*o));
}
static bool GICOwnerRangesV18(VZKernelCPUGICOwnerV18 *o,const void *const *p,
 const size_t *n,unsigned count) {
 if(!PendingRangesV14(o->cpu,p,n,count))return false;
 for(unsigned i=0;i<count;++i)if(!VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]) ||
  !VM27CPUSelfMappedRangeV1(p[i],n[i],true,NULL))return false;
 return true;
}
VZKernelStatus VZKernelCPUGICOwnerCreateV18(const VZKernelRunPendingRequestV14 *input,
 VM27GICV3V1 *engine,const VZKernelInitWriter *writer,VZKernelCPUGICOwnerV18 **out) {
 if(!input || !engine || !writer || !out)return VZ_KERNEL_BAD_ARGUMENT;
 const void *p[]={input,writer,out};const size_t n[]={sizeof(*input),sizeof(*writer),sizeof(*out)};
 for(unsigned i=0;i<3;++i) {
  if(!VZKernelCPUOutputRangeDisjointV12(p[i],n[i]) ||
   !VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]))return VZ_KERNEL_BAD_ARGUMENT;
  for(unsigned j=0;j<i;++j)if(!PendingOutputDisjointV3(p[i],n[i],p[j],n[j]))return VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelCPUGICOwnerV18 *o=calloc(1,sizeof(*o));if(!o)return VZ_KERNEL_OUT_OF_MEMORY;
 o->identity=*input;o->writer=*writer;o->engine=engine;o->owner=pthread_self();atomic_init(&o->operation,false);
 atomic_init(&o->exitRequested,false);atomic_init(&o->running,false);
 atomic_init(&o->draining,false);
 VZKernelStatus waitInit=VM27WFxInitV30(&o->wfx);
 if(waitInit!=VZ_KERNEL_OK){free(o);return waitInit;}
 VZKernelStatus status=VZKernelCPUBorrowIdentityV5(input->expectedPublicIdentity,&o->borrow);
 if(status==VZ_KERNEL_OK)status=VZKernelCPUBorrowHandleV5(o->borrow,&o->cpu);
 bool entered=false;
 if(status==VZ_KERNEL_OK){status=BeginCPUOperation(o->cpu);entered=status!=VZ_KERNEL_BUSY;}
 VZKernelLifecycleResult lifecycle={0};
 if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(status==VZ_KERNEL_OK && (!o->writer.writeMemory || o->writer.context!=o->cpu->vm->ops.context))
  status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK)status=Version(o->cpu,&lifecycle);
 if(status==VZ_KERNEL_OK && GICFindOwnerV18(o->cpu))status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK)status=VM27GICValidateTimerOwnerV1(engine,&o->identity);
 if(entered)EndOperation(&o->cpu->operationInProgress);
 // The Timer19 owner obtains its own concrete borrow. The sidecar remains
 // registered until both real releases succeed, including failed setup.
 Lock(&GICOwnersMutexV18);o->next=GICOwnersV18;GICOwnersV18=o;Unlock(&GICOwnersMutexV18);
 if(status==VZ_KERNEL_OK) {
  VZKernelPhysicalTimerBindingV19 b={o->cpu->vm->ops.context,engine,VZKernelReadCounterDomainSampleV19,
   VM27GICValidateTimerOwnerV1,VM27GICRoutePhysicalTimerV1,
   VM27GICUpdatePhysicalDeadlineV1,VM27GICQuiescePhysicalTimerV1};
  VZKernelPhysicalTimerOwnerV19 *timer=NULL;
  status=VZKernelPhysicalTimerOwnerCreateV19(&o->identity,&b,&o->writer,&timer);
  Lock(&GICOwnersMutexV18);o->timer=timer;Unlock(&GICOwnersMutexV18);
 }
 if(status==VZ_KERNEL_OK){*out=o;return status;}
 o->draining=true;
 VZKernelStatus cleanup=VZKernelCPUGICOwnerDestroyV18(o);
 if(cleanup!=VZ_KERNEL_OK)*out=o;
 return cleanup==VZ_KERNEL_OK?status:cleanup;
}
VZKernelStatus VZKernelCPUGICOwnerRequestExitV18(VZKernelCPUGICOwnerV18 *needle,bool *wake) {
 if(!wake || !VZKernelCPUControllerOutputRangeDisjointV18(wake,sizeof(*wake)) ||
  !VZKernelCPUOutputRangeDisjointV12(wake,sizeof(*wake)))return VZ_KERNEL_BAD_ARGUMENT;
 Lock(&GICOwnersMutexV18);VZKernelCPUGICOwnerV18 *o=NULL;
 for(VZKernelCPUGICOwnerV18 *p=GICOwnersV18;p;p=p->next)if(p==needle){o=p;break;}
 VZKernelStatus s=!o || o->draining?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
 if(s==VZ_KERNEL_OK){atomic_store_explicit(&o->exitRequested,true,memory_order_release);
  *wake=atomic_load_explicit(&o->running,memory_order_acquire);
  s=VM27WFxSignalV30(&o->wfx,VZ_KERNEL_OK);}
 Unlock(&GICOwnersMutexV18);return s;
}
VZKernelStatus VZKernelCPUGICOwnerTakeExitV18(VZKernelCPUGICOwnerV18 *needle,bool *out) {
 if(!out)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus s=GICOwnerBeginV18(needle,&o);if(s!=VZ_KERNEL_OK)return s;
 if(!pthread_equal(o->owner,pthread_self()))s=VZ_KERNEL_WRONG_THREAD;
 else if(o->draining)s=VZ_KERNEL_NOT_LIVE;
 const void *p[]={out};const size_t n[]={sizeof(*out)};
 if(s==VZ_KERNEL_OK && !GICOwnerRangesV18(o,p,n,1))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK) {
  s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
  VZKernelLifecycleResult lifecycle={0};
  if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
  if(s==VZ_KERNEL_OK)s=Version(o->cpu,&lifecycle);
  if(s==VZ_KERNEL_OK && !GICOwnerRangesV18(o,p,n,1))s=VZ_KERNEL_BAD_ARGUMENT;
  if(s==VZ_KERNEL_OK)*out=atomic_exchange_explicit(&o->exitRequested,false,memory_order_acq_rel);
  if(entered)EndOperation(&o->cpu->operationInProgress);
 }
 EndOperation(&o->operation);return s;
}
static VZKernelStatus GICOwnerBeginV18(VZKernelCPUGICOwnerV18 *needle,VZKernelCPUGICOwnerV18 **out) {
 Lock(&GICOwnersMutexV18);VZKernelCPUGICOwnerV18 *o=NULL;
 for(VZKernelCPUGICOwnerV18 *p=GICOwnersV18;p;p=p->next)if(p==needle){o=p;break;}
 VZKernelStatus s=!o?VZ_KERNEL_BAD_ARGUMENT:BeginOperation(&o->operation)?VZ_KERNEL_OK:VZ_KERNEL_BUSY;
 if(s==VZ_KERNEL_OK)*out=o;Unlock(&GICOwnersMutexV18);return s;
}
VZKernelStatus VZKernelCPUGICOwnerDestroyV18(VZKernelCPUGICOwnerV18 *needle) {
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus s=GICOwnerBeginV18(needle,&o);if(s!=VZ_KERNEL_OK)return s;
 if(!pthread_equal(o->owner,pthread_self())){EndOperation(&o->operation);return VZ_KERNEL_WRONG_THREAD;}
 o->draining=true;
 if(o->timer) {
  s=VZKernelPhysicalTimerOwnerDestroyV19(o->timer);
  if(s!=VZ_KERNEL_OK){EndOperation(&o->operation);return s;}
  Lock(&GICOwnersMutexV18);o->timer=NULL;Unlock(&GICOwnersMutexV18);
 }
 if(o->borrow) {
  s=VZKernelCPUReleaseBorrowV5(o->borrow);
  if(s!=VZ_KERNEL_OK){EndOperation(&o->operation);return s;}
  o->borrow=NULL;
 }
 Lock(&GICOwnersMutexV18);VZKernelCPUGICOwnerV18 **link=&GICOwnersV18;
 while(*link && *link!=o)link=&(*link)->next;
 if(!*link)abort();*link=o->next;Unlock(&GICOwnersMutexV18);
 if(VM27WFxDestroyV30(&o->wfx)!=VZ_KERNEL_OK)abort();
 memset(o,0,sizeof(*o));free(o);return VZ_KERNEL_OK;
}
VZKernelStatus VZKernelCPUGICOwnerSetAffinityV18(VZKernelCPUGICOwnerV18 *needle,uint64_t mpidr) {
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus s=GICOwnerBeginV18(needle,&o);if(s!=VZ_KERNEL_OK)return s;
 if(!pthread_equal(o->owner,pthread_self()))s=VZ_KERNEL_WRONG_THREAD;
 else if(o->draining)s=VZ_KERNEL_NOT_LIVE;
 else {
  s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
  VZKernelLifecycleResult lifecycle={0};uint64_t actual=0;
  if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
  if(s==VZ_KERNEL_OK)s=Version(o->cpu,&lifecycle);
  InitializationAccess a={o->cpu,&o->writer,&lifecycle,VZ_KERNEL_OK};
  if(s==VZ_KERNEL_OK && !SystemReadMappedV8(&a,0x690,8,&actual))s=VZ_KERNEL_CONTEXT_UNREADABLE;
  if(s==VZ_KERNEL_OK && actual!=mpidr)s=VZ_KERNEL_BAD_ARGUMENT;
  if(s==VZ_KERNEL_OK)s=VM27GICSetAffinityV1(o->engine,&o->identity,actual);
  if(s==VZ_KERNEL_OK && !InitializationOwned(&a))s=a.boundaryStatus;
  if(entered)EndOperation(&o->cpu->operationInProgress);
 }
 EndOperation(&o->operation);return s;
}
VZKernelStatus VZKernelCPUGICOwnerAccessV18(VZKernelCPUGICOwnerV18 *needle,
 uint32_t action,uint32_t selector,uint64_t value,uint64_t *out,VZKernelPhysicalTimerReceiptV16 *outTimer) {
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus s=GICOwnerBeginV18(needle,&o);if(s!=VZ_KERNEL_OK)return s;
 if(!pthread_equal(o->owner,pthread_self()))s=VZ_KERNEL_WRONG_THREAD;
 else if(o->draining)s=VZ_KERNEL_NOT_LIVE;
 else {
  const void *p[]={out,outTimer};const size_t n[]={sizeof(*out),sizeof(*outTimer)};
  for(unsigned i=0;i<2 && s==VZ_KERNEL_OK;++i)if(p[i]) {
   if(!GICOwnerRangesV18(o,&p[i],&n[i],1) || !VM27CPUSelfMappedRangeV1(p[i],n[i],true,NULL))s=VZ_KERNEL_BAD_ARGUMENT;
  }
  if(out && outTimer && !PendingOutputDisjointV3(out,sizeof(*out),outTimer,sizeof(*outTimer)))s=VZ_KERNEL_BAD_ARGUMENT;
  if((action==1 || action==3 || action==5 || action==6) && !out)s=VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelLifecycleResult lifecycle={0};uint64_t result=0;VZKernelPhysicalTimerReceiptV19 timer={0};bool timerProduced=false;
 bool engineCommitted=false;
 if(s==VZ_KERNEL_OK && (action==6 || action==7)) {
  s=VZKernelPhysicalTimerOwnerAccessV19(o->timer,action==6?VZ_KERNEL_PHYSICAL_TIMER_READ_V19:
   VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19,selector,value,action==6?&result:NULL,&timer,&lifecycle);
  timerProduced=true;engineCommitted=timer.attemptedWrites || timer.irqRouteAttempted || timer.deadlineAttempted;
 } else if(s==VZ_KERNEL_OK) {
  s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
  if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
  if(s==VZ_KERNEL_OK)s=Version(o->cpu,&lifecycle);
  bool engineAttempted=false;
  if(s==VZ_KERNEL_OK) {
   engineAttempted=true;
   if(action==1 || action==2)s=selector>UINT16_MAX?VZ_KERNEL_BAD_ARGUMENT:
    VM27GICICCRegV1(o->engine,&o->identity,(uint16_t)selector,action==2,value,&result);
   else if(action==3 || action==4)s=VM27GICRedistributorRegV1(o->engine,&o->identity,selector,action==4,value,&result);
   else if(action==5 && !selector && !value)s=VM27GICRedistributorBaseV1(o->engine,&o->identity,&result);
   else s=VZ_KERNEL_BAD_ARGUMENT;
   engineCommitted=s==VZ_KERNEL_OK && (action==2 || action==4 ||
    (action==1 && (selector==0xc640 || selector==0xc660)));
  }
  if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
  if((engineCommitted && s!=VZ_KERNEL_OK) ||
   (engineAttempted && (action==2 || action==4) && s!=VZ_KERNEL_OK &&
    s!=VZ_KERNEL_UNSUPPORTED && s!=VZ_KERNEL_BAD_ARGUMENT)) {
   o->cpu->mutationPoisoned=true;Lock(&o->cpu->vm->mutex);
   o->cpu->registryEntry->published=false;o->cpu->registryEntry->draining=true;Unlock(&o->cpu->vm->mutex);
  }
  if(entered)EndOperation(&o->cpu->operationInProgress);
 }
 const void *outputs[]={out,outTimer};const size_t sizes[]={sizeof(*out),sizeof(*outTimer)};
 bool valid=true;for(unsigned i=0;i<2 && valid;++i)if(outputs[i])
  valid=GICOwnerRangesV18(o,&outputs[i],&sizes[i],1) && VM27CPUSelfMappedRangeV1(outputs[i],sizes[i],true,NULL);
 if(!valid) {
  s=VZ_KERNEL_BAD_ARGUMENT;
  if(engineCommitted) {
   o->cpu->mutationPoisoned=true;Lock(&o->cpu->vm->mutex);
   o->cpu->registryEntry->published=false;o->cpu->registryEntry->draining=true;Unlock(&o->cpu->vm->mutex);
  }
 }
 if(valid && outTimer && timerProduced)*outTimer=GICTimerLegacyReceiptV20(&timer);
 if(valid && s==VZ_KERNEL_OK && (action==1 || action==3 || action==5 || action==6)) {
  if(!out)s=VZ_KERNEL_BAD_ARGUMENT;else *out=result;
 }
 EndOperation(&o->operation);return s;
}
VZKernelStatus VZKernelCPUGICOwnerPoisonV18(VZKernelCPUGICOwnerV18 *needle) {
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus s=GICOwnerBeginV18(needle,&o);if(s!=VZ_KERNEL_OK)return s;
 if(!pthread_equal(o->owner,pthread_self()))s=VZ_KERNEL_WRONG_THREAD;
 else {
  s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
  if(s==VZ_KERNEL_OK)s=CPUOwnedV5(o->cpu);
  if(s==VZ_KERNEL_OK){o->cpu->mutationPoisoned=true;Lock(&o->cpu->vm->mutex);
   o->cpu->registryEntry->published=false;o->cpu->registryEntry->draining=true;Unlock(&o->cpu->vm->mutex);}
  if(entered)EndOperation(&o->cpu->operationInProgress);
 }
 EndOperation(&o->operation);return s;
}
VZKernelStatus VZKernelCPUGICOwnerPoisonedV18(VZKernelCPUGICOwnerV18 *needle,bool *out) {
 if(!out)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus s=GICOwnerBeginV18(needle,&o);if(s!=VZ_KERNEL_OK)return s;
 if(!pthread_equal(o->owner,pthread_self()))s=VZ_KERNEL_WRONG_THREAD;
 const void *p[]={out};const size_t n[]={sizeof(*out)};
 if(s==VZ_KERNEL_OK && !GICOwnerRangesV18(o,p,n,1))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK) {
  s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
  if(s==VZ_KERNEL_OK)s=CPUOwnedV5(o->cpu);
  if(s==VZ_KERNEL_OK && !GICOwnerRangesV18(o,p,n,1))s=VZ_KERNEL_BAD_ARGUMENT;
  if(s==VZ_KERNEL_OK)*out=o->cpu->mutationPoisoned;
  if(entered)EndOperation(&o->cpu->operationInProgress);
 }
 EndOperation(&o->operation);return s;
}
