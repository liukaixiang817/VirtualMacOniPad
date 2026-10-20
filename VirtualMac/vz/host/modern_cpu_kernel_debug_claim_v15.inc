// Intended for a NEW Life15 translation unit after frozen Life14 definitions.
// Real 20B101 kernel native8 MRS DBGCLAIMCLR -> STRB context668; native9
// clears all ff then MSR DBGCLAIMSET from context668. Dirty bank2 at748
// reaches4110/4108; public context4100 is native saved-state ready mask.
// Do not add668 to a broad field whitelist or alias old vtimerOffset6a0.
static bool ClaimReadV15(InitializationAccess *a,VZKernelDebugClaimReceiptV15 *r,
 uint32_t offset,size_t bytes,void *out) {
 ++r->attemptedReads;
 bool exact=(offset==0x668 && bytes==1) ||
  ((offset==0x748 || offset==0x4100) && bytes==8);
 bool ok=exact && InitializationOwned(a) &&
  a->cpu->nativeContext<=UINTPTR_MAX-offset-bytes &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),bytes,false,NULL) &&
  a->cpu->vm->ops.readMemory(a->cpu->vm->ops.context,
   (const void *)(a->cpu->nativeContext+offset),bytes,out) && InitializationOwned(a);
 if(!ok){r->failedNativeOffset=offset;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
static bool ClaimWriteV15(InitializationAccess *a,VZKernelDebugClaimReceiptV15 *r,
 uint32_t offset,size_t bytes,const void *value) {
 ++r->attemptedWrites;
 bool exact=(offset==0x668 && bytes==1) || (offset==0x748 && bytes==8);
 bool ok=exact && a->writer && a->writer->writeMemory && InitializationOwned(a) &&
  a->cpu->nativeContext<=UINTPTR_MAX-offset-bytes &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),bytes,true,NULL) &&
  a->writer->writeMemory(a->writer->context,(void *)(a->cpu->nativeContext+offset),bytes,value) &&
  InitializationOwned(a);
 if(ok)++r->completedWrites;
 else{r->failedNativeOffset=offset;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
VZKernelStatus VZKernelCPUAccessPhysicalDebugClaimV15(VZKernelCPU *cpu,
 const VZKernelDebugClaimRequestV15 *input,const VZKernelInitWriter *writer,
 uint64_t *outValue,VZKernelDebugClaimReceiptV15 *outReceipt,VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !input || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=BeginCPUOperation(cpu);
 if(status!=VZ_KERNEL_OK){if(status!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return status;}
 const void *p[5]={input,outReceipt,outLifecycle};
 size_t n[5]={sizeof(*input),sizeof(*outReceipt),sizeof(*outLifecycle)};unsigned count=3;
 if(writer){p[count]=writer;n[count++]=sizeof(*writer);}
 if(outValue){p[count]=outValue;n[count++]=sizeof(*outValue);}
 if(!PendingRangesV14(cpu,p,n,count)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelDebugClaimRequestV15 q=*input;VZKernelInitWriter ownWriter=writer?*writer:(VZKernelInitWriter){0};
 VZKernelDebugClaimReceiptV15 r={0};VZKernelLifecycleResult lifecycle={0};
 r.failedNativeOffset=UINT32_MAX;
 status=PendingRequestOwnedV14(cpu,&q.identity);
 if(status==VZ_KERNEL_OK && (q.reserved ||
  (q.action!=VZ_KERNEL_DEBUG_CLAIM_READ_V15 && q.action!=VZ_KERNEL_DEBUG_CLAIM_WRITE_V15)))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && ((q.action==VZ_KERNEL_DEBUG_CLAIM_READ_V15 && (!outValue || q.value)) ||
  (q.action==VZ_KERNEL_DEBUG_CLAIM_WRITE_V15 && (!ownWriter.writeMemory || ownWriter.context!=cpu->vm->ops.context))))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && q.value>UINT64_C(0xff))status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 InitializationAccess access={cpu,&ownWriter,&lifecycle,VZ_KERNEL_OK};uint64_t ready=0,dirty=0;uint8_t actual=0;
 if(status==VZ_KERNEL_OK) {
  if(q.action==VZ_KERNEL_DEBUG_CLAIM_READ_V15 && !ClaimReadV15(&access,&r,0x748,8,&dirty))status=r.status;
  if(status==VZ_KERNEL_OK && !ClaimReadV15(&access,&r,0x4100,8,&ready))status=r.status;
  uint64_t available=ready|(q.action==VZ_KERNEL_DEBUG_CLAIM_READ_V15?dirty:0);
  if(status==VZ_KERNEL_OK && !(available&UINT64_C(2))) {
   r.nativeOp8Required=true;
   status=PrepareSystemNative8V8(&access,&r.nativeOp8Invoked);
  }
 }
 if(status==VZ_KERNEL_OK) {
  if(q.action==VZ_KERNEL_DEBUG_CLAIM_READ_V15) {
   if(!ClaimReadV15(&access,&r,0x668,1,&actual))status=r.status;
   else r.actualClaimStateRead=true;
  } else {
   actual=(uint8_t)q.value;
   if(!ClaimWriteV15(&access,&r,0x668,1,&actual))status=r.status;
   else {
    r.actualClaimStateWritten=true;
    if(!ClaimReadV15(&access,&r,0x748,8,&dirty))status=r.status;
    else{dirty|=UINT64_C(2);if(!ClaimWriteV15(&access,&r,0x748,8,&dirty))status=r.status;}
   }
  }
 }
 if(status==VZ_KERNEL_OK && !InitializationOwned(&access))status=access.boundaryStatus;
 if(access.boundaryStatus!=VZ_KERNEL_OK)status=access.boundaryStatus;
 if(status!=VZ_KERNEL_OK && r.attemptedWrites)cpu->mutationPoisoned=true;
 CPUResult(cpu,&lifecycle);r.status=status;r.mutationPoisoned=cpu->mutationPoisoned;r.cpuCleanupRequired=cpu->live;
 Finish(&lifecycle,status);
 if(status==VZ_KERNEL_OK && q.action==VZ_KERNEL_DEBUG_CLAIM_READ_V15)*outValue=actual;
 *outReceipt=r;*outLifecycle=lifecycle;EndOperation(&cpu->operationInProgress);return status;
}
