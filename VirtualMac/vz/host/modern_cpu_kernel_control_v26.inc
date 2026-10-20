VZKernelStatus VZKernelCPUAccessControlV22(VZKernelCPU *cpu,
 const VZKernelControlRequestV22 *input,const VZKernelInitWriter *writer,
 uint64_t *outValue,VZKernelInitReceipt *outReceipt,VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !input || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=BeginCPUOperation(cpu);
 if(status!=VZ_KERNEL_OK){if(status!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return status;}
 const void *p[5]={input,outReceipt,outLifecycle};
 size_t n[5]={sizeof(*input),sizeof(*outReceipt),sizeof(*outLifecycle)};unsigned count=3;
 if(writer){p[count]=writer;n[count++]=sizeof(*writer);}
 if(outValue){p[count]=outValue;n[count++]=sizeof(*outValue);}
 if(!PendingRangesV14(cpu,p,n,count)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 const VZKernelControlRequestV22 q=*input;
 VZKernelInitWriter ownWriter=writer?*writer:(VZKernelInitWriter){0};
 VZKernelInitReceipt receipt={0};VZKernelLifecycleResult lifecycle={0};
 receipt.failedNativeOffset=UINT32_MAX;receipt.failedWriteOrdinal=UINT32_MAX;
 status=PendingRequestOwnedV14(cpu,&q.identity);
 if(status==VZ_KERNEL_OK && q.action!=VZ_KERNEL_CONTROL_READ_V22 && q.action!=VZ_KERNEL_CONTROL_WRITE_V22)
  status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && ((q.action==VZ_KERNEL_CONTROL_READ_V22 && (!outValue || q.value)) ||
  (q.action==VZ_KERNEL_CONTROL_WRITE_V22 && (outValue || !ownWriter.writeMemory || ownWriter.context!=cpu->vm->ops.context))))
  status=VZ_KERNEL_BAD_ARGUMENT;
 uint32_t offset=q.identifier==0?0x670:q.identifier==2?0x688:q.identifier==7?0x6e0:q.identifier==8?0x6e8:q.identifier==9?0x6f0:0;
 if(status==VZ_KERNEL_OK && (q.identifier>17 || !(UINT32_C(0x3fbef)&(UINT32_C(1)<<q.identifier))))
  status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && !offset)status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 InitializationAccess access={cpu,&ownWriter,&lifecycle,VZ_KERNEL_OK};uint64_t actual=0;
 if(status==VZ_KERNEL_OK) {
  if(q.action==VZ_KERNEL_CONTROL_READ_V22) {
   ++receipt.attemptedReads;
   if(!SystemReadMappedV8(&access,offset,8,&actual)) {
    receipt.failedNativeOffset=offset;status=VZ_KERNEL_CONTEXT_UNREADABLE;
   }
  } else {
   const VZKernelInitRequest request={1,q.identity.validatedKernelProfile,
    q.identity.expectedOwnerThread,q.identity.expectedCPUGeneration,
    q.identity.expectedReturnedSlotWord,q.identity.nativeHVISA,
    VZ_KERNEL_INIT_CONTROL,q.identifier,q.value,0};
   const VZKernelInitAccess callbacks={&access,SystemReadMappedV8,SystemWriteMappedV8};
   /* Exact old13 setter57d8: requested field first, then fresh678|56,
    * fresh670|18, fresh748|2. Preserve unrelated bits and current alias order. */
   status=VZKernelInitApplyVerifiedSlice(&request,&callbacks,&receipt);
  }
 }
 if(status==VZ_KERNEL_OK && !InitializationOwned(&access))status=access.boundaryStatus;
 if(access.boundaryStatus!=VZ_KERNEL_OK)status=access.boundaryStatus;
 if(status!=VZ_KERNEL_OK && receipt.attemptedWrites)cpu->mutationPoisoned=true;
 CPUResult(cpu,&lifecycle);receipt.status=status;receipt.mutationPoisoned=cpu->mutationPoisoned;
 receipt.cpuCleanupRequired=cpu->live;receipt.creationPolicySliceComplete=cpu->creationPolicySliceComplete;
 receipt.architecturalResetComplete=false;receipt.runAllowed=false;
 Finish(&lifecycle,status);
 if(status==VZ_KERNEL_OK && q.action==VZ_KERNEL_CONTROL_READ_V22)*outValue=actual;
 *outReceipt=receipt;*outLifecycle=lifecycle;
 EndOperation(&cpu->operationInProgress);return status;
}
