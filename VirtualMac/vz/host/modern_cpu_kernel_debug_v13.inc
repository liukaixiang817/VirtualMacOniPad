// Modern internal setters 0x9d08/0x9de0 preserve all64 unrelated bits for both
// bool values. The old public wrappers truncate32 on false; copying that old
// transform would not implement the modern contract. Only the native field
// and sync sequence come from old CONTROL2 resolver56c4/setter57d8.
VZKernelStatus VZKernelCPUSetDebugTrapV13(VZKernelCPU *cpu,
 const VZKernelDebugRequestV13 *input,const VZKernelInitWriter *writer,
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
 bool published=RegisteredVM==cpu->vm && CPURegisteredLockedV5(cpu) && entry->creationComplete &&
  entry->identityIssued && entry->published && !entry->draining;
 Unlock(&cpu->vm->mutex);Unlock(&RegistryMutex);
 if(!disjoint){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelDebugRequestV13 q=*input;VZKernelInitWriter stagedWriter=*writer;
 VZKernelLifecycleResult lifecycle={0};VZKernelInitReceipt receipt={0};
 receipt.failedNativeOffset=UINT32_MAX;receipt.failedWriteOrdinal=UINT32_MAX;
 if(!published || CPUOwnedV5(cpu)!=VZ_KERNEL_OK)status=VZ_KERNEL_NOT_LIVE;
 else if(q.expectedVMEpoch!=cpu->vm->generation || q.expectedPublicIdentity!=entry->publicIdentity ||
  q.expectedOwnerThread!=cpu->owner || q.expectedCPUGeneration!=cpu->generation ||
  q.expectedReturnedSlotWord!=cpu->returnedSlot || !stagedWriter.writeMemory ||
  stagedWriter.context!=cpu->vm->ops.context || q.reserved || q.reservedBytes[0] ||
  q.reservedBytes[1] || q.reservedBytes[2])status=VZ_KERNEL_BAD_ARGUMENT;
 else if(q.schemaVersion!=1 || q.validatedKernelProfile!=cpu->vm->ops.validatedKernelProfile ||
  q.validatedKernelProfile!=VZ_KERNEL_PROFILE_IPADOS_16_1_1 || q.nativeHVISA!=cpu->vm->nativeHVISA ||
  !VZKernelNativeISAHasValidatedContextV2(q.nativeHVISA) ||
  (q.kind!=VZ_KERNEL_DEBUG_EXCEPTIONS_V13 && q.kind!=VZ_KERNEL_DEBUG_REGISTER_ACCESSES_V13))
  status=VZ_KERNEL_UNSUPPORTED;
 else if(cpu->mutationPoisoned || !cpu->creationPolicySliceComplete || !cpu->creationConfigComplete)
  status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK &&
  !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 static const uint32_t writable[]={0x688,0x678,0x670,0x748};
 for(unsigned i=0;i<4 && status==VZ_KERNEL_OK;++i)
  if(!VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+writable[i]),8,true,NULL))
   status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 if(status==VZ_KERNEL_OK) {
  InitializationAccess opaque={cpu,&stagedWriter,&lifecycle,VZ_KERNEL_OK};uint64_t current=0;
  ++receipt.attemptedReads;
  if(!SystemReadMappedV8(&opaque,0x688,8,&current)) {
   receipt.failedNativeOffset=0x688;status=VZ_KERNEL_CONTEXT_UNREADABLE;
  }
  if(status==VZ_KERNEL_OK) {
   uint64_t mask=UINT64_C(1)<<(q.kind==VZ_KERNEL_DEBUG_EXCEPTIONS_V13?8:9);
   uint64_t value=(current&~mask)|(q.value?mask:0);
   VZKernelInitRequest control={1,q.validatedKernelProfile,q.expectedOwnerThread,
    q.expectedCPUGeneration,q.expectedReturnedSlotWord,q.nativeHVISA,VZ_KERNEL_INIT_CONTROL,2,value,0};
   VZKernelInitAccess access={&opaque,SystemReadMappedV8,SystemWriteMappedV8};
   // Original CONTROL2 writes688 first, then reads each current sync word
   // immediately before writing678|bit56,670|bit18,748|bit2. No native8/9.
   status=VZKernelInitApplyVerifiedSlice(&control,&access,&receipt);
  }
  if(status==VZ_KERNEL_OK && !InitializationOwned(&opaque))status=opaque.boundaryStatus;
  if(opaque.boundaryStatus!=VZ_KERNEL_OK)status=opaque.boundaryStatus;
  if(status!=VZ_KERNEL_OK && receipt.attemptedWrites)cpu->mutationPoisoned=true;
 }
 CPUResult(cpu,&lifecycle);receipt.status=status;
 receipt.creationPolicySliceComplete=cpu->creationPolicySliceComplete;
 receipt.mutationPoisoned=cpu->mutationPoisoned;receipt.cpuCleanupRequired=cpu->live;
 receipt.architecturalResetComplete=false;receipt.runAllowed=false;
 Finish(&lifecycle,status);*outReceipt=receipt;*outLifecycle=lifecycle;
 EndOperation(&cpu->operationInProgress);return status;
}
