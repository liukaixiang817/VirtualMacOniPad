// Include after a new lifecycle TU's frozen Life14/15 definitions.
// Exact current native fields: kernel80a99a0/99b0 save CNTP CVAL/CTL to3f0/438;
// kernel80abc90/abca0 restore them when dirty748 bit0 is set. No modern field
// offset is copied to the old context, and neither version nor ready is written.
struct VZKernelPhysicalTimerOwnerV16 {
 VZKernelCPUBorrowV5 *borrow;
 VZKernelCPU *cpu;
 VZKernelRunPendingRequestV14 identity;
 VZKernelPhysicalTimerBindingV16 binding;
 VZKernelInitWriter writer;
 _Atomic bool operation;
 pthread_t ownerPthread;
 bool quiesced;
};
bool VZKernelReadPhysicalCounterV16(void *context,uint64_t *out) {
 (void)context;if(!out)return false;
#if defined(__aarch64__)
 uint64_t value;__asm__ volatile("isb\n\tmrs %0, cntpct_el0":"=r"(value)::"memory");
 *out=value;return true;
#else
 return false;
#endif
}
static bool PhysicalOwnerRangesV16(VZKernelPhysicalTimerOwnerV16 *o,
 const void *const *p,const size_t *n,unsigned count) {
 if(!PendingRangesV14(o->cpu,p,n,count))return false;
 for(unsigned i=0;i<count;++i)
  if(!PendingOutputDisjointV3(p[i],n[i],o,sizeof(*o)))return false;
 return true;
}
static bool PhysicalReadV16(InitializationAccess *a,VZKernelPhysicalTimerReceiptV16 *r,
 uint32_t offset,uint64_t *out) {
 ++r->attemptedReads;
 bool exact=offset==0x3f0 || offset==0x438 || offset==0x6a0 || offset==0x748 || offset==0x4100;
 bool ok=exact && InitializationOwned(a) &&
  a->cpu->nativeContext<=UINTPTR_MAX-offset-8 &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),8,false,NULL) &&
  a->cpu->vm->ops.readMemory(a->cpu->vm->ops.context,
   (const void *)(a->cpu->nativeContext+offset),8,out) && InitializationOwned(a);
 if(!ok){r->failedNativeOffset=offset;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
static bool PhysicalWriteV16(InitializationAccess *a,VZKernelPhysicalTimerReceiptV16 *r,
 uint32_t offset,uint64_t value) {
 ++r->attemptedWrites;
 bool exact=offset==0x3f0 || offset==0x438 || offset==0x748;
 bool ok=exact && a->writer && a->writer->writeMemory && InitializationOwned(a) &&
  a->cpu->nativeContext<=UINTPTR_MAX-offset-8 &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),8,true,NULL) &&
  a->writer->writeMemory(a->writer->context,
   (void *)(a->cpu->nativeContext+offset),8,&value) && InitializationOwned(a);
 if(ok)++r->completedWrites;
 else{r->failedNativeOffset=offset;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
VZKernelStatus VZKernelPhysicalTimerOwnerCreateV16(const VZKernelRunPendingRequestV14 *input,
 const VZKernelPhysicalTimerBindingV16 *binding,const VZKernelInitWriter *writer,
 VZKernelPhysicalTimerOwnerV16 **out) {
 if(!input || !binding || !writer || !out)return VZ_KERNEL_BAD_ARGUMENT;
 const void *p[]={input,binding,writer,out};const size_t n[]={sizeof(*input),sizeof(*binding),sizeof(*writer),sizeof(*out)};
 for(unsigned i=0;i<4;++i) {
  if(!VZKernelCPUOutputRangeDisjointV12(p[i],n[i]))return VZ_KERNEL_BAD_ARGUMENT;
  for(unsigned j=0;j<i;++j)if(!PendingOutputDisjointV3(p[i],n[i],p[j],n[j]))return VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelRunPendingRequestV14 q=*input;VZKernelPhysicalTimerBindingV16 b=*binding;
 VZKernelInitWriter w=*writer;
 if(!b.readPhysicalCounter || !b.gicOwner || !b.validateGICOwner || !b.routePhysicalTimer ||
  !b.updatePhysicalDeadline || !b.quiescePhysicalTimer || !w.writeMemory)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelPhysicalTimerOwnerV16 *o=calloc(1,sizeof(*o));if(!o)return VZ_KERNEL_OUT_OF_MEMORY;
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
 if(entered)EndOperation(&o->cpu->operationInProgress);
 if(status==VZ_KERNEL_OK){*out=o;return status;}
 if(o->borrow && VZKernelCPUReleaseBorrowV5(o->borrow)!=VZ_KERNEL_OK) {
  // The caller must retain this concrete cleanup allocation on release failure.
  *out=o;return VZ_KERNEL_NATIVE_ERROR;
 }
 free(o);return status;
}
VZKernelStatus VZKernelPhysicalTimerOwnerAccessV16(VZKernelPhysicalTimerOwnerV16 *o,
 VZKernelPhysicalTimerActionV16 action,uint32_t identifier,uint64_t value,uint64_t *outValue,
 VZKernelPhysicalTimerReceiptV16 *outReceipt,VZKernelLifecycleResult *outLifecycle) {
 if(!o || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(o->ownerPthread,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 if(!BeginOperation(&o->operation))return VZ_KERNEL_BUSY;
 if(o->quiesced){EndOperation(&o->operation);return VZ_KERNEL_NOT_LIVE;}
 VZKernelCPU *cpu=NULL;VZKernelStatus status=VZKernelCPUBorrowHandleV5(o->borrow,&cpu);
 bool entered=false;
 if(status==VZ_KERNEL_OK){status=BeginCPUOperation(cpu);entered=status!=VZ_KERNEL_BUSY;}
 if(status!=VZ_KERNEL_OK){if(entered)EndOperation(&cpu->operationInProgress);EndOperation(&o->operation);return status;}
 const void *p[]={outReceipt,outLifecycle,outValue};const size_t n[]={sizeof(*outReceipt),sizeof(*outLifecycle),sizeof(*outValue)};
 if(!PhysicalOwnerRangesV16(o,p,n,outValue?3:2)) {
  EndOperation(&cpu->operationInProgress);EndOperation(&o->operation);return VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelPhysicalTimerReceiptV16 r={0};VZKernelLifecycleResult lifecycle={0};r.failedNativeOffset=UINT32_MAX;
 status=PendingRequestOwnedV14(cpu,&o->identity);
 if(status==VZ_KERNEL_OK && ((action!=VZ_KERNEL_PHYSICAL_TIMER_READ_V16 &&
  action!=VZ_KERNEL_PHYSICAL_TIMER_WRITE_V16 && action!=VZ_KERNEL_PHYSICAL_TIMER_POLL_V16) ||
  (action==VZ_KERNEL_PHYSICAL_TIMER_POLL_V16?(identifier || value):
   (identifier!=VZ_KERNEL_PHYSICAL_TIMER_CTL_V16 && identifier!=VZ_KERNEL_PHYSICAL_TIMER_CVAL_V16)) ||
  (action==VZ_KERNEL_PHYSICAL_TIMER_READ_V16 && (!outValue || value))))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 InitializationAccess a={cpu,&o->writer,&lifecycle,VZ_KERNEL_OK};uint64_t offset=0,ready=0,dirty=0;
 if(status==VZ_KERNEL_OK && !PhysicalReadV16(&a,&r,0x6a0,&offset))status=r.status;
 // The device's mach-clock/CNTPCT relation and nonzero migration offset are
 // not yet proved. Admit only the bounded zero-offset native-counter profile.
 if(status==VZ_KERNEL_OK && offset)status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK)status=o->binding.validateGICOwner(o->binding.gicOwner,&o->identity);
 if(status==VZ_KERNEL_OK && !InitializationOwned(&a))status=a.boundaryStatus;
 if(status==VZ_KERNEL_OK) {
  if(action!=VZ_KERNEL_PHYSICAL_TIMER_WRITE_V16 && !PhysicalReadV16(&a,&r,0x748,&dirty))status=r.status;
  if(status==VZ_KERNEL_OK && !PhysicalReadV16(&a,&r,0x4100,&ready))status=r.status;
  if(status==VZ_KERNEL_OK && !((ready|dirty)&UINT64_C(1))) {
   r.nativeOp8Required=true;status=PrepareSystemNative8V8(&a,&r.nativeOp8Invoked);
  }
 }
 if(status==VZ_KERNEL_OK && action==VZ_KERNEL_PHYSICAL_TIMER_WRITE_V16) {
  uint32_t field=identifier==VZ_KERNEL_PHYSICAL_TIMER_CTL_V16?0x438:0x3f0;
  uint64_t actual=identifier==VZ_KERNEL_PHYSICAL_TIMER_CTL_V16?value&UINT64_C(3):value;
  if(!PhysicalWriteV16(&a,&r,field,actual))status=r.status;
  if(status==VZ_KERNEL_OK && !PhysicalReadV16(&a,&r,0x748,&dirty))status=r.status;
  if(status==VZ_KERNEL_OK && !PhysicalWriteV16(&a,&r,0x748,dirty|UINT64_C(1)))status=r.status;
 }
 if(status==VZ_KERNEL_OK && (!PhysicalReadV16(&a,&r,0x438,&r.nativeControl) ||
  !PhysicalReadV16(&a,&r,0x3f0,&r.nativeCVAL)))status=r.status;
 if(status==VZ_KERNEL_OK) {
  r.physicalStateRead=true;
  if(!InitializationOwned(&a) || !o->binding.readPhysicalCounter(o->binding.nativeContext,&r.nativeCounter) ||
   !InitializationOwned(&a))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else r.counterSampled=true;
 }
 uint64_t result=identifier==VZ_KERNEL_PHYSICAL_TIMER_CTL_V16?
  ((r.nativeControl&UINT64_C(3))|(r.nativeCounter>=r.nativeCVAL?UINT64_C(4):0)):r.nativeCVAL;
 if(status==VZ_KERNEL_OK && action!=VZ_KERNEL_PHYSICAL_TIMER_READ_V16) {
  r.physicalTimerAsserted=(r.nativeControl&UINT64_C(3))==UINT64_C(1) && r.nativeCounter>=r.nativeCVAL;
  bool aggregate=false;r.irqRouteAttempted=true;
  status=o->binding.routePhysicalTimer(o->binding.gicOwner,&o->identity,r.physicalTimerAsserted,&aggregate);
  if(status==VZ_KERNEL_OK && !InitializationOwned(&a))status=a.boundaryStatus;
  if(status==VZ_KERNEL_OK){r.irqRouteComplete=true;r.aggregateIRQ=aggregate;}
  if(status==VZ_KERNEL_OK) {
   r.deadlineArmed=(r.nativeControl&UINT64_C(3))==UINT64_C(1) && r.nativeCounter<r.nativeCVAL;
   r.deadlineAttempted=true;
   status=o->binding.updatePhysicalDeadline(o->binding.gicOwner,&o->identity,r.deadlineArmed,r.nativeCVAL);
   if(status==VZ_KERNEL_OK && !InitializationOwned(&a))status=a.boundaryStatus;
   if(status==VZ_KERNEL_OK){r.deadlineComplete=true;cpu->pendingInterrupts.irqPending=(uint32_t)aggregate;}
  }
 }
 if(status==VZ_KERNEL_OK && !InitializationOwned(&a))status=a.boundaryStatus;
 if(a.boundaryStatus!=VZ_KERNEL_OK)status=a.boundaryStatus;
 if(status!=VZ_KERNEL_OK && (r.attemptedWrites || r.irqRouteAttempted || r.deadlineAttempted)) {
  cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
  cpu->registryEntry->published=false;cpu->registryEntry->draining=true;
  Unlock(&cpu->vm->mutex);r.identityWithdrawn=true;
 }
 CPUResult(cpu,&lifecycle);Finish(&lifecycle,status);r.status=status;r.mutationPoisoned=cpu->mutationPoisoned;
 if(status==VZ_KERNEL_OK && action==VZ_KERNEL_PHYSICAL_TIMER_READ_V16)*outValue=result;
 *outReceipt=r;*outLifecycle=lifecycle;EndOperation(&cpu->operationInProgress);EndOperation(&o->operation);return status;
}
VZKernelStatus VZKernelPhysicalTimerOwnerDestroyV16(VZKernelPhysicalTimerOwnerV16 *o) {
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
 memset(o,0,sizeof(*o));free(o);return VZ_KERNEL_OK;
}
