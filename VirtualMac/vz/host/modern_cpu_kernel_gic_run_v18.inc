// Only real RunPostAccessV7 capabilities may reach these native reads/writes.
static bool GICPostFieldV18(PendingRunAccessV14 *a,uint32_t off,bool write,uint64_t *v) {
 bool scalar=(off==0x108 || (off>=8 && off<=0xf8 && !(off&7)));
 bool timer=off==0x3f0 || off==0x438 || off==0x748 || off==0x4100 || off==0x6a0;
 if(!a->post || (!scalar && !timer) || (write && (off==0x4100 || off==0x6a0)) ||
  !PendingBoundaryV14(a) || a->init.cpu->nativeContext>UINTPTR_MAX-off-8 ||
  !VM27CPUSelfMappedRangeV1((const void *)(a->init.cpu->nativeContext+off),8,write,NULL))return false;
 bool ok=write?a->init.writer->writeMemory(a->init.writer->context,
  (void *)(a->init.cpu->nativeContext+off),8,v):a->init.cpu->vm->ops.readMemory(
  a->init.cpu->vm->ops.context,(const void *)(a->init.cpu->nativeContext+off),8,v);
 return ok && PendingBoundaryV14(a);
}
static void GICPoisonV18(VZKernelCPU *cpu) {
 cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
 cpu->registryEntry->published=false;cpu->registryEntry->draining=true;Unlock(&cpu->vm->mutex);
}
static VZKernelStatus GICTimerTrapV18(VZKernelCPUGICOwnerV18 *o,PendingRunAccessV14 *a,
 uint16_t selector,bool write,uint64_t source,uint64_t *result,bool *mutated) {
 uint64_t offset=0,ready=0,dirty=0,control=0,cval=0,now=0;
 if(!GICPostFieldV18(a,0x6a0,false,&offset))return VZ_KERNEL_CONTEXT_UNREADABLE;
 if(offset)return VZ_KERNEL_UNSUPPORTED;
 if(!GICPostFieldV18(a,0x748,false,&dirty) || !GICPostFieldV18(a,0x4100,false,&ready))
  return VZ_KERNEL_CONTEXT_UNREADABLE;
 if(!((ready|(write?0:dirty))&1)) {
  bool invoked=false;if(!PendingBoundaryV14(a))return a->init.boundaryStatus;
  VZKernelStatus s=PrepareSystemNative8V8(&a->init,&invoked);(void)invoked;
  if(s!=VZ_KERNEL_OK)return s;if(!PendingBoundaryV14(a))return a->init.boundaryStatus;
 }
 if(write) {
  uint64_t actual=selector==0xdf11?source&UINT64_C(3):source;*mutated=true;
  if(!GICPostFieldV18(a,selector==0xdf11?0x438:0x3f0,true,&actual) ||
   !GICPostFieldV18(a,0x748,false,&dirty))return VZ_KERNEL_CONTEXT_UNREADABLE;
  dirty|=1;if(!GICPostFieldV18(a,0x748,true,&dirty))return VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 if(!GICPostFieldV18(a,0x438,false,&control) || !GICPostFieldV18(a,0x3f0,false,&cval) ||
  !PendingBoundaryV14(a) || !o->timer->binding.readPhysicalCounter(o->timer->binding.nativeContext,&now) ||
  !PendingBoundaryV14(a))return VZ_KERNEL_CONTEXT_UNREADABLE;
 *result=selector==0xdf11?((control&3)|(now>=cval?4:0)):cval;
 if(write) {
  bool irq=false;VZKernelStatus s=VM27GICRoutePhysicalTimerV1(o->engine,&o->identity,(control&3)==1 && now>=cval,&irq);
  if(s!=VZ_KERNEL_OK)return s;if(!PendingBoundaryV14(a))return a->init.boundaryStatus;
  s=VM27GICUpdatePhysicalDeadlineV1(o->engine,&o->identity,(control&3)==1 && now<cval,cval);
  if(s!=VZ_KERNEL_OK)return s;if(!PendingBoundaryV14(a))return a->init.boundaryStatus;
  a->init.cpu->pendingInterrupts.irqPending=(uint32_t)irq;
 }
 return VZ_KERNEL_OK;
}
static VZKernelStatus GICHandlePostV18(VZKernelCPUGICOwnerV18 *o,PendingRunAccessV14 *a,
 VZKernelRunStepReceiptV7 *step,bool *resume) {
 if(!o)return VZ_KERNEL_UNSUPPORTED;
 const uint32_t esr=step->nativeValues.syndrome32,ec=esr>>26;
 if(ec!=0x18 && ec!=0x24)return VZ_KERNEL_UNSUPPORTED;
 uint32_t rt=ec==0x18?(esr>>5)&31:(esr>>16)&31;
 uint64_t pc=0,source=0;
 if(!GICPostFieldV18(a,0x108,false,&pc) || (rt!=31 && !GICPostFieldV18(a,8+8*rt,false,&source)))
  return VZ_KERNEL_CONTEXT_UNREADABLE;
 if(pc>UINT64_MAX-4)return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICTrapResultV1 trap={0};VZKernelStatus s;bool mutated=false;
 uint16_t selector=(uint16_t)((((esr>>20)&3)<<14)|(((esr>>14)&7)<<11)|
  (((esr>>10)&15)<<7)|(((esr>>1)&15)<<3)|((esr>>17)&7));
 if(ec==0x18 && (esr&(1u<<25)) && (selector==0xdf11 || selector==0xdf12)) {
  trap=(VM27GICTrapResultV1){.write=(esr&1)==0,.is64Bit=true,.registerIndex=rt,.bytes=8};
  s=GICTimerTrapV18(o,a,selector,trap.write,rt==31?0:source,&trap.readValue,&mutated);
  trap.handled=s==VZ_KERNEL_OK;trap.controllerStateCommitted=mutated;
 } else if(ec==0x18)s=VM27GICHandleSystemV1(o->engine,&o->identity,esr,source,&trap);
 else s=VM27GICHandleAbortV1(o->engine,&o->identity,esr,step->nativeValues.physicalAddress,source,&trap);
 mutated=mutated || trap.controllerStateCommitted;
 if(s==VZ_KERNEL_OK && !PendingBoundaryV14(a))s=a->init.boundaryStatus;
 if(s==VZ_KERNEL_OK && trap.handled) {
  if(!trap.write && trap.registerIndex!=31) {
   mutated=true;if(!GICPostFieldV18(a,8+8*trap.registerIndex,true,&trap.readValue))s=VZ_KERNEL_CONTEXT_UNREADABLE;
  }
  if(s==VZ_KERNEL_OK){pc+=4;mutated=true;if(!GICPostFieldV18(a,0x108,true,&pc))s=VZ_KERNEL_CONTEXT_UNREADABLE;}
  if(s==VZ_KERNEL_OK)*resume=true;
 }
 if(s!=VZ_KERNEL_OK && mutated)GICPoisonV18(a->init.cpu);
 return s;
}

// Preserves frozen Pending14 entry/return CONTROL0 order, including native9 error cleanup.
static VZKernelStatus GICRunActualStepV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *input,const VZKernelInitWriter *writer,
 VZKernelRunPendingReceiptV14 *out,VZKernelCPUGICOwnerV18 *gic,bool *resume) {
 if(!cpu || !input || !writer || !out)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=BeginCPUOperation(cpu);
 if(status!=VZ_KERNEL_OK){if(status!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return status;}
 const void *p[]={input,writer,out};const size_t n[]={sizeof(*input),sizeof(*writer),sizeof(*out)};
 if(!PendingRangesV14(cpu,p,n,3)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelRunPendingRequestV14 q=*input;VZKernelInitWriter ownWriter=*writer;
 VZKernelRunPendingReceiptV14 r={0};VZKernelRunStepReceiptV7 *step=&r.step;
 r.entryControl.failedNativeOffset=r.returnControl.failedNativeOffset=UINT32_MAX;
 r.entryControl.failedWriteOrdinal=r.returnControl.failedWriteOrdinal=UINT32_MAX;
 status=PendingRequestOwnedV14(cpu,&q);
 if(status==VZ_KERNEL_OK && (!ownWriter.writeMemory || ownWriter.context!=cpu->vm->ops.context))
  status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && (cpu->creationConfig.fineGrainedTraps || cpu->creationConfig.trapTLBISW))
  status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK && cpu->runToken==UINT64_MAX)status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&step->lifecycle);
 PendingRunAccessV14 access={{cpu,&ownWriter,&step->lifecycle,VZ_KERNEL_OK},NULL};
 VZCPUControl0EntryValuePlanV1 entry={0};uint64_t control0=0;
 if(status==VZ_KERNEL_OK) {
  // Zero pending skips both control slices, exactly like the original Run.
  uint64_t mask=(cpu->pendingInterrupts.irqPending?UINT64_C(0x80):0)|
   (cpu->pendingInterrupts.fiqPending?UINT64_C(0x40):0);
  if(mask) {
   const uint32_t fields[]={0x670,0x678,0x748};
   for(unsigned i=0;i<3 && status==VZ_KERNEL_OK;++i)
    if(!VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+fields[i]),8,true,NULL))
     status=VZ_KERNEL_CONTEXT_UNREADABLE;
   if(status==VZ_KERNEL_OK) {
    ++r.entryControl.attemptedReads;
    if(!PendingReadMappedV14(&access,0x670,8,&control0)) {
     r.entryControl.failedNativeOffset=0x670;status=VZ_KERNEL_CONTEXT_UNREADABLE;
    }
   }
  }
  if(status==VZ_KERNEL_OK)status=PendingValueStatusV3(VZCPUPlanControl0EntryValueV1(
   &cpu->pendingInterrupts,step->lifecycle.nativeContextVersion,control0,&entry));
  r.entryPendingMask=entry.latchedPendingMask;
  if(status==VZ_KERNEL_OK && entry.needsControl0Slice) {
   status=PendingControl0V14(&access,entry.requestedControl0Value,&r.entryControl);
   r.entryControlComplete=status==VZ_KERNEL_OK;
  }
 }
 if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&access))status=access.init.boundaryStatus;
 if(status==VZ_KERNEL_OK) {
  step->vmEpoch=cpu->vm->generation;step->cpuGeneration=cpu->generation;
  step->ownerThread=cpu->owner;step->runToken=++cpu->runToken;
  step->lifecycle.nativeInvoked=true;
  step->lifecycle.nativeReturn=cpu->vm->ops.nativeTrap(cpu->vm->ops.context,9,NULL);
  memcpy(&step->nativeValues.nativeReturnBits,&step->lifecycle.nativeReturn,4);
  step->nativeValues.schemaVersion=VZ_CPU_EXIT_REDUCER_SCHEMA_V1;
  cpu->runPostReturnActive=true;
  RunPostAccessV7 post={cpu,step->vmEpoch,step->cpuGeneration,step->ownerThread,
   step->runToken,&step->lifecycle,VZ_KERNEL_OK};access.post=&post;
  if(!RunPostOwnedV7(&post))status=post.status;
  else if(step->lifecycle.nativeReturn)status=VZ_KERNEL_NATIVE_ERROR;
  r.runStatusBeforeCleanup=status;
  if(entry.needsControl0Slice) {
   // Nonzero native status is NOT permission to skip this protocol. Only a
   // failed real ownership/version boundary forbids touching the live state.
   VZKernelStatus cleanup=VZ_KERNEL_OK;
   if(!PendingBoundaryV14(&access))cleanup=access.init.boundaryStatus;
   if(cleanup==VZ_KERNEL_OK) {
    cpu->pendingInterrupts.irqPending=0;cpu->pendingInterrupts.fiqPending=0;r.pendingCleared=true;
    ++r.returnControl.attemptedReads;
    if(!PendingReadMappedV14(&access,0x670,8,&control0)) {
     r.returnControl.failedNativeOffset=0x670;cleanup=VZ_KERNEL_CONTEXT_UNREADABLE;
    }
    VZCPUControl0ReturnValuePlanV1 returned={0};
    if(cleanup==VZ_KERNEL_OK)cleanup=PendingValueStatusV3(VZCPUPlanControl0ReturnValueV1(
     &entry,&cpu->pendingInterrupts,step->lifecycle.nativeContextVersion,control0,
     step->nativeValues.nativeReturnBits,&returned));
    if(cleanup==VZ_KERNEL_OK)cleanup=PendingControl0V14(&access,
     returned.requestedControl0Value,&r.returnControl);
    r.returnControlComplete=cleanup==VZ_KERNEL_OK;
   }
   if(access.init.boundaryStatus!=VZ_KERNEL_OK)cleanup=access.init.boundaryStatus;
   r.cleanupStatus=cleanup;r.returnControl.status=cleanup;
   if(cleanup!=VZ_KERNEL_OK)status=cleanup;
  }
  if(status==VZ_KERNEL_OK) {
   step->nativeValues.nativeContextVersion=step->lifecycle.nativeContextVersion;
   if(!RunPostReadV7(&post,0x4008,4,&step->nativeValues.rawReason))status=post.status;
   else {
    step->nativeValues.knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
    uint32_t reason=step->nativeValues.rawReason;
    if(reason==1 || reason==6 || reason==8) {
     if(!RunPostReadV7(&post,0x400c,4,&step->nativeValues.syndrome32) ||
      !RunPostReadV7(&post,0x4018,8,&step->nativeValues.virtualAddress) ||
      !RunPostReadV7(&post,0x4020,8,&step->nativeValues.physicalAddress))status=post.status;
     else step->nativeValues.knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
    }
    if(status==VZ_KERNEL_OK && !RunPostOwnedV7(&post))status=post.status;
    if(status==VZ_KERNEL_OK) {
     step->postReturnIdentityValidated=true;
     if(gic && (reason==1 || reason==6 || reason==8)) {
      VZKernelStatus handled=GICHandlePostV18(gic,&access,step,resume);
      if(handled!=VZ_KERNEL_UNSUPPORTED || cpu->mutationPoisoned)status=handled;
     }
     if(status==VZ_KERNEL_OK && !*resume) {
      VZCPUExitReducerStatusV1 reduced=VZCPUReduceNativeExitV1(&step->nativeValues,&step->reduction);
      if(reduced!=VZ_CPU_EXIT_REDUCER_OK_V1)status=VZ_KERNEL_UNSUPPORTED;
      else {step->reductionValid=true;step->publicExceptionProduced=step->reduction.hasPublicException==1;
       if(!step->publicExceptionProduced)status=VZ_KERNEL_BUSY;}
     }
     if(gic && status==VZ_KERNEL_BUSY && (reason==2 || reason==11)) {*resume=true;status=VZ_KERNEL_OK;}
    }
   }
  }
  cpu->runPostReturnActive=false;
 }
 // Successful cleanup followed by a BUSY/unsupported guest exit does not
 // poison the CPU. Partial native mutation or failed cleanup always does.
 if((r.entryControl.attemptedWrites && (!r.entryControlComplete ||
     (!step->lifecycle.nativeInvoked && status!=VZ_KERNEL_OK))) ||
  (step->lifecycle.nativeInvoked && entry.needsControl0Slice && !r.returnControlComplete)) {
  cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
  cpu->registryEntry->published=false;cpu->registryEntry->draining=true;
  Unlock(&cpu->vm->mutex);r.identityWithdrawn=true;
 }
 if(access.init.boundaryStatus!=VZ_KERNEL_OK)status=access.init.boundaryStatus;
 r.mutationPoisoned=cpu->mutationPoisoned;
 r.entryControl.mutationPoisoned=r.returnControl.mutationPoisoned=r.mutationPoisoned;
 CPUResult(cpu,&step->lifecycle);step->lifecycle.status=status;step->status=status;
 *out=r;EndOperation(&cpu->operationInProgress);return status;
}

static VZKernelStatus GICPollBeforeRunV18(VZKernelCPUGICOwnerV18 *o) {
 VZKernelPhysicalTimerReceiptV16 timer={0};VZKernelLifecycleResult lifecycle={0};
 VZKernelStatus s=VZKernelPhysicalTimerOwnerAccessV16(o->timer,VZ_KERNEL_PHYSICAL_TIMER_POLL_V16,
  0,0,NULL,&timer,&lifecycle);if(s!=VZ_KERNEL_OK)return s;
 s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(s==VZ_KERNEL_OK)s=Version(o->cpu,&lifecycle);
 VM27GICLinesV1 lines={0};
 if(s==VZ_KERNEL_OK)s=VM27GICGetLinesV1(o->engine,&o->identity,&lines);
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(s==VZ_KERNEL_OK){o->cpu->pendingInterrupts.irqPending=(uint32_t)lines.irq;
  o->cpu->pendingInterrupts.fiqPending=(uint32_t)lines.fiq;}
 if(entered)EndOperation(&o->cpu->operationInProgress);return s;
}
VZKernelStatus VZKernelCPURunGICPendingBoundedV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,uint64_t limit,
 VZKernelRunPendingReceiptV14 *out) {
 if(!cpu || !q || !writer || !out)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelCPUGICOwnerV18 *needle=GICFindOwnerV18(cpu);
 if(!needle)return VZKernelCPURunOwnedPendingStepV14(cpu,q,writer,out);
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus status=GICOwnerBeginV18(needle,&o);
 if(status!=VZ_KERNEL_OK)return status;
 const void *p[]={q,writer,out};const size_t n[]={sizeof(*q),sizeof(*writer),sizeof(*out)};
 bool valid=PendingRangesV14(cpu,p,n,3);
 for(unsigned i=0;i<3 && valid;++i)valid=VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]);
 if(!valid){EndOperation(&o->operation);return VZ_KERNEL_BAD_ARGUMENT;}
 if(!pthread_equal(o->owner,pthread_self()))status=VZ_KERNEL_WRONG_THREAD;
 else if(o->draining || memcmp(q,&o->identity,sizeof(*q)) || writer->context!=o->writer.context ||
  writer->writeMemory!=o->writer.writeMemory)status=VZ_KERNEL_NOT_LIVE;
 VZKernelRunPendingRequestV14 ownQ=*q;VZKernelInitWriter ownWriter=*writer;
 VZKernelRunPendingReceiptV14 receipt={0};bool begun=false;
 if(status==VZ_KERNEL_OK) {
  status=BeginCPUOperation(cpu);bool entered=status!=VZ_KERNEL_BUSY;
  if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(cpu,&ownQ);
  if(status==VZ_KERNEL_OK)status=Version(cpu,&receipt.step.lifecycle);
  if(entered)EndOperation(&cpu->operationInProgress);
 }
 if(status==VZ_KERNEL_OK){status=VM27GICBeginRunV1(o->engine,&o->identity);begun=status==VZ_KERNEL_OK;}
 if(status==VZ_KERNEL_OK)atomic_store_explicit(&o->running,true,memory_order_release);
 for(uint64_t count=0;status==VZ_KERNEL_OK;++count) {
  if(atomic_load_explicit(&o->exitRequested,memory_order_acquire)){status=VZ_KERNEL_BUSY;break;}
  if(limit && count==limit){status=VZ_KERNEL_BUSY;break;}
  status=GICPollBeforeRunV18(o);if(status!=VZ_KERNEL_OK)break;
  // Recheck immediately before the actual entry producer. A concurrent exit
  // while running=true also issues native10, so the native cancellation record
  // closes the interval from this check through the actual native9 entry.
  if(atomic_load_explicit(&o->exitRequested,memory_order_acquire)){status=VZ_KERNEL_BUSY;break;}
  bool resume=false;memset(&receipt,0,sizeof(receipt));
  status=GICRunActualStepV18(cpu,&ownQ,&ownWriter,&receipt,o,&resume);
  if(status!=VZ_KERNEL_OK || !resume)break;
  if(count==UINT64_MAX-1){status=VZ_KERNEL_BUSY;break;}
 }
 atomic_store_explicit(&o->running,false,memory_order_release);
 if(begun) {
  VZKernelStatus ended=VM27GICEndRunV1(o->engine,&o->identity);
  if(ended!=VZ_KERNEL_OK){GICPoisonV18(cpu);status=ended;}
 }
 receipt.mutationPoisoned=cpu->mutationPoisoned;
 receipt.identityWithdrawn=receipt.identityWithdrawn || cpu->mutationPoisoned;
 receipt.step.status=receipt.step.lifecycle.status=status;
 valid=PendingRangesV14(cpu,p,n,3);
 for(unsigned i=0;i<3 && valid;++i)valid=VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]);
 if(!valid || !VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL))status=VZ_KERNEL_BAD_ARGUMENT;
 else *out=receipt;
 EndOperation(&o->operation);return status;
}
VZKernelStatus VZKernelCPURunGICPendingV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,VZKernelRunPendingReceiptV14 *out) {
 return VZKernelCPURunGICPendingBoundedV18(cpu,q,writer,0,out);
}
