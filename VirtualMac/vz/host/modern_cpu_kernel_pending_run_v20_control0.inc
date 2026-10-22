#include "modern_cpu_production_control0_v20.h"
#include "modern_cpu_production_pac_batch_v14.h"
static VZKernelStatus PendingRequestOwnedV14(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q) {
 VZKernelCPURegistryEntryV5 *e=cpu->registryEntry;
 if(CPUOwnedV5(cpu)!=VZ_KERNEL_OK)return VZ_KERNEL_NOT_LIVE;
 Lock(&cpu->vm->mutex);
 bool live=e->creationComplete && e->identityIssued && e->published && !e->draining;
 Unlock(&cpu->vm->mutex);
 if(!live || !cpu->creationPolicySliceComplete || !cpu->creationConfigComplete || cpu->mutationPoisoned)
  return VZ_KERNEL_NOT_LIVE;
 if(q->expectedVMEpoch!=cpu->vm->generation || q->expectedPublicIdentity!=e->publicIdentity ||
  q->expectedOwnerThread!=cpu->owner || q->expectedCPUGeneration!=cpu->generation ||
  q->expectedReturnedSlotWord!=cpu->returnedSlot || q->reserved)return VZ_KERNEL_BAD_ARGUMENT;
 if(q->schemaVersion!=1 || q->validatedKernelProfile!=cpu->vm->ops.validatedKernelProfile ||
  q->validatedKernelProfile!=VZ_KERNEL_PROFILE_IPADOS_16_1_1 || q->nativeHVISA!=cpu->vm->nativeHVISA ||
  !VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA))return VZ_KERNEL_UNSUPPORTED;
 return VZ_KERNEL_OK;
}
static bool PendingRangesV14(VZKernelCPU *cpu,const void *const *p,const size_t *n,unsigned count) {
 Lock(&RegistryMutex);Lock(&cpu->vm->mutex);bool valid=RegisteredVM==cpu->vm;
 for(unsigned i=0;i<count && valid;++i) {
  valid=VtimerOutputDisjointLockedV12(cpu->vm,p[i],n[i]);
  for(unsigned j=0;j<i && valid;++j)valid=PendingOutputDisjointV3(p[i],n[i],p[j],n[j]);
 }
 Unlock(&cpu->vm->mutex);Unlock(&RegistryMutex);return valid;
}
VZKernelStatus VZKernelCPUAccessPendingInterruptV14(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *input,VZKernelPendingActionV14 action,
 uint32_t type,bool value,bool *out) {
 if(!cpu || !input || (action==VZ_KERNEL_PENDING_READ_V14 && !out))return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=BeginCPUOperation(cpu);
 if(status!=VZ_KERNEL_OK){if(status!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return status;}
 const void *p[]={input,out};const size_t n[]={sizeof(*input),sizeof(*out)};
 if(!PendingRangesV14(cpu,p,n,out?2:1)) {
  EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;
 }
 VZKernelRunPendingRequestV14 q=*input;VZKernelLifecycleResult lifecycle={0};
 if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(cpu,&q);
 if(status==VZ_KERNEL_OK && ((uint32_t)type>1 ||
  (action!=VZ_KERNEL_PENDING_READ_V14 && action!=VZ_KERNEL_PENDING_WRITE_V14)))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 if(status==VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context)!=cpu->owner)
  status=VZ_KERNEL_WRONG_THREAD;
 if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(cpu,&q);
 if(status==VZ_KERNEL_OK) {
  VZCPUPendingInterruptValuesV1 staged;
  status=PendingValueStatusV3(VZCPUSetPendingInterruptValueV1(&cpu->pendingInterrupts,
   (uint32_t)type,action==VZ_KERNEL_PENDING_WRITE_V14?(uint32_t)value:
   ((uint32_t)type?cpu->pendingInterrupts.fiqPending:cpu->pendingInterrupts.irqPending),&staged));
  if(status==VZ_KERNEL_OK && action==VZ_KERNEL_PENDING_WRITE_V14)cpu->pendingInterrupts=staged;
  else if(status==VZ_KERNEL_OK)*out=((uint32_t)type?staged.fiqPending:staged.irqPending)!=0;
 }
 EndOperation(&cpu->operationInProgress);return status;
}
typedef struct {InitializationAccess init;RunPostAccessV7 *post;} PendingRunAccessV14;
static bool PendingBoundaryV14(PendingRunAccessV14 *a) {
 if(a->post && !RunPostOwnedV7(a->post)){a->init.boundaryStatus=a->post->status;return false;}
 return InitializationOwned(&a->init);
}
static bool PendingReadMappedV14(void *opaque,uint32_t offset,size_t bytes,void *out) {
 PendingRunAccessV14 *a=opaque;
 return PendingBoundaryV14(a) && SystemReadMappedV8(&a->init,offset,bytes,out) && PendingBoundaryV14(a);
}
static bool PendingWriteMappedV14(void *opaque,uint32_t offset,size_t bytes,const void *value) {
 PendingRunAccessV14 *a=opaque;
 return PendingBoundaryV14(a) && SystemWriteMappedV8(&a->init,offset,bytes,value) && PendingBoundaryV14(a);
}
static VZKernelStatus PendingControl0V14(PendingRunAccessV14 *a,uint64_t value,VZKernelInitReceipt *r) {
 VZKernelCPU *cpu=a->init.cpu;
 VZKernelInitRequest q={1,cpu->vm->ops.validatedKernelProfile,cpu->owner,cpu->generation,
  cpu->returnedSlot,cpu->vm->nativeHVISA,VZ_KERNEL_INIT_CONTROL,0,value,0};
 VZKernelInitAccess access={a,PendingReadMappedV14,PendingWriteMappedV14};
 VZKernelStatus status;
 bool fast=false;
 if(StableOwnerMetadataV67(cpu) &&
    VM27ProductionPACBatchEligibleV14(&cpu->vm->ops,a->init.writer) && PendingBoundaryV14(a)) {
  VM27Control0ResultV20 result=VM27ProductionControl0V20(cpu->nativeContext,q.nativeHVISA,value);
  if(result.handled) {
   fast=true;status=result.receipt.status;
   r->attemptedReads+=result.receipt.attemptedReads;
   r->attemptedWrites+=result.receipt.attemptedWrites;
   r->completedWrites+=result.receipt.completedWrites;
   if(status!=VZ_KERNEL_OK) {
    r->failedNativeOffset=result.receipt.failedNativeOffset;
    if(result.receipt.failedWriteOrdinal!=UINT32_MAX)
     r->failedWriteOrdinal=r->attemptedWrites;
   } else {r->architecturalResetComplete=false;r->runAllowed=false;}
  }
 }
 if(!fast)status=VZKernelInitApplyVerifiedSlice(&q,&access,r);
 if(status==VZ_KERNEL_OK && !PendingBoundaryV14(a))status=a->init.boundaryStatus;
 if(a->init.boundaryStatus!=VZ_KERNEL_OK)status=a->init.boundaryStatus;
 r->status=status;r->creationPolicySliceComplete=cpu->creationPolicySliceComplete;
 r->cpuCleanupRequired=cpu->live;return status;
}
VZKernelStatus VZKernelCPURunOwnedPendingStepV14(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *input,const VZKernelInitWriter *writer,
 VZKernelRunPendingReceiptV14 *out) {
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
     VZCPUExitReducerStatusV1 reduced=VZCPUReduceNativeExitV1(&step->nativeValues,&step->reduction);
     if(reduced!=VZ_CPU_EXIT_REDUCER_OK_V1)status=VZ_KERNEL_UNSUPPORTED;
     else {step->reductionValid=true;step->publicExceptionProduced=step->reduction.hasPublicException==1;
      if(!step->publicExceptionProduced)status=VZ_KERNEL_BUSY;}
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
