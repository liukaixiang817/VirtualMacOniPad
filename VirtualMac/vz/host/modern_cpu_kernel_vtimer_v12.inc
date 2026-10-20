// Original old hv_vcpu_set_vtimer_offset 0x7a1c..0x7a4c performs exactly:
// store requested64 at +0x6a0; read dirty64 at +0x748; store dirty64 | 4.
// CONTROL4 additionally changes +0x678/+0x670 and is not this operation.
static bool VtimerOutputDisjointLockedV12(VZKernelVM *vm,const void *p,size_t n) {
 if(!p || n>UINTPTR_MAX-(uintptr_t)p || !OutputAllPrivateDisjointLockedV5(vm,p,n))return false;
 for(VZKernelCPURegistryEntryV5 *e=vm->cpuRegistry;e;e=e->next) {
  uintptr_t native=e->cpu->nativeContext;
  if(native && !PendingOutputDisjointV3(p,n,(const void *)native,0x4108))return false;
 }
 return true;
}
bool VZKernelCPUOutputRangeDisjointV12(const void *p,size_t n) {
 if(!p || n>UINTPTR_MAX-(uintptr_t)p)return false;
 Lock(&RegistryMutex);VZKernelVM *vm=RegisteredVM;bool valid=true;
 if(vm){Lock(&vm->mutex);valid=VtimerOutputDisjointLockedV12(vm,p,n);Unlock(&vm->mutex);}
 Unlock(&RegistryMutex);return valid;
}
static bool VtimerWriteV12(InitializationAccess *a,VZKernelInitReceipt *r,
 uint32_t offset,uint64_t value) {
 ++r->attemptedWrites;
 if(SystemWriteMappedV8(a,offset,8,&value)){++r->completedWrites;return true;}
 r->failedNativeOffset=offset;r->failedWriteOrdinal=r->attemptedWrites;return false;
}
VZKernelStatus VZKernelCPUSetVtimerOffsetV12(VZKernelCPU *cpu,
 const VZKernelVtimerRequestV12 *input,const VZKernelInitWriter *writer,
 VZKernelInitReceipt *outReceipt,VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !input || !writer || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=BeginCPUOperation(cpu);
 if(status==VZ_KERNEL_BUSY)return status;
 if(status!=VZ_KERNEL_OK){EndOperation(&cpu->operationInProgress);return status;}
 const void *ranges[]={input,writer,outReceipt,outLifecycle};
 const size_t sizes[]={sizeof(*input),sizeof(*writer),sizeof(*outReceipt),sizeof(*outLifecycle)};
 Lock(&RegistryMutex);Lock(&cpu->vm->mutex);bool disjoint=true;
 for(unsigned i=0;i<4 && disjoint;++i) {
  disjoint=VtimerOutputDisjointLockedV12(cpu->vm,ranges[i],sizes[i]);
  for(unsigned j=0;j<i && disjoint;++j)
   disjoint=PendingOutputDisjointV3(ranges[i],sizes[i],ranges[j],sizes[j]);
 }
 VZKernelCPURegistryEntryV5 *entry=cpu->registryEntry;
 bool published=RegisteredVM==cpu->vm && CPURegisteredLockedV5(cpu) &&
  entry->creationComplete && entry->identityIssued && entry->published && !entry->draining;
 Unlock(&cpu->vm->mutex);Unlock(&RegistryMutex);
 if(!disjoint){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelVtimerRequestV12 q=*input;VZKernelInitWriter stagedWriter=*writer;
 VZKernelLifecycleResult lifecycle={0};VZKernelInitReceipt receipt={0};
 receipt.failedNativeOffset=UINT32_MAX;receipt.failedWriteOrdinal=UINT32_MAX;
 if(!published || CPUOwnedV5(cpu)!=VZ_KERNEL_OK)status=VZ_KERNEL_NOT_LIVE;
 else if(q.expectedVMEpoch!=cpu->vm->generation || q.expectedPublicIdentity!=entry->publicIdentity ||
  q.expectedOwnerThread!=cpu->owner || q.expectedCPUGeneration!=cpu->generation ||
  q.expectedReturnedSlotWord!=cpu->returnedSlot || !stagedWriter.writeMemory ||
  stagedWriter.context!=cpu->vm->ops.context || q.reserved)status=VZ_KERNEL_BAD_ARGUMENT;
 else if(q.schemaVersion!=1 || q.validatedKernelProfile!=cpu->vm->ops.validatedKernelProfile ||
  q.validatedKernelProfile!=VZ_KERNEL_PROFILE_IPADOS_16_1_1 || q.nativeHVISA!=cpu->vm->nativeHVISA ||
  !VZKernelNativeISAHasValidatedContextV2(q.nativeHVISA))status=VZ_KERNEL_UNSUPPORTED;
 else if(cpu->mutationPoisoned || !cpu->creationPolicySliceComplete || !cpu->creationConfigComplete)
  status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK &&
  (!VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL) ||
   !VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+0x6a0),8,true,NULL) ||
   !VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+0x748),8,true,NULL)))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 if(status==VZ_KERNEL_OK) {
  InitializationAccess access={cpu,&stagedWriter,&lifecycle,VZ_KERNEL_OK};uint64_t dirty=0;
  if(!VtimerWriteV12(&access,&receipt,0x6a0,q.vtimerOffset))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  if(status==VZ_KERNEL_OK) {
   ++receipt.attemptedReads;
   if(!SystemReadMappedV8(&access,0x748,8,&dirty)) {
    receipt.failedNativeOffset=0x748;status=VZ_KERNEL_CONTEXT_UNREADABLE;
   }
  }
  if(status==VZ_KERNEL_OK && !VtimerWriteV12(&access,&receipt,0x748,dirty|UINT64_C(4)))
   status=VZ_KERNEL_CONTEXT_UNREADABLE;
  // Successful callbacks can still change the real owner/version. Check the
  // returned state, including after the final write, before reporting success.
  if(status==VZ_KERNEL_OK && !InitializationOwned(&access))status=access.boundaryStatus;
  if(access.boundaryStatus!=VZ_KERNEL_OK)status=access.boundaryStatus;
  // A writer returning false may already have changed the native context.
  if(status!=VZ_KERNEL_OK && receipt.attemptedWrites)cpu->mutationPoisoned=true;
 }
 CPUResult(cpu,&lifecycle);receipt.status=status;
 receipt.creationPolicySliceComplete=cpu->creationPolicySliceComplete;
 receipt.mutationPoisoned=cpu->mutationPoisoned;receipt.cpuCleanupRequired=cpu->live;
 receipt.architecturalResetComplete=false;receipt.runAllowed=false;
 Finish(&lifecycle,status);*outReceipt=receipt;*outLifecycle=lifecycle;
 EndOperation(&cpu->operationInProgress);return status;
}
