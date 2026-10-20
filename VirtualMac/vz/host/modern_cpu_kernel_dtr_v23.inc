static VZKernelStatus DTRBoundaryV23(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *identity,VZKernelLifecycleResult *r) {
 VZKernelStatus s=PendingRequestOwnedV14(cpu,identity);
 if(s==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  s=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(s==VZ_KERNEL_OK)s=Version(cpu,r);
 if(s==VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context)!=cpu->owner)s=VZ_KERNEL_WRONG_THREAD;
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(cpu,identity);
 return s;
}
VZKernelStatus VZKernelCPUAccessDTRV23(VZKernelCPU *cpu,const VZKernelDTRRequestV23 *input,
 uint64_t *out,VZKernelDTRReceiptV23 *outReceipt,VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !input || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus s=BeginCPUOperation(cpu);
 if(s!=VZ_KERNEL_OK){if(s!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return s;}
 const void *p[]={input,outReceipt,outLifecycle,out};
 const size_t n[]={sizeof(*input),sizeof(*outReceipt),sizeof(*outLifecycle),sizeof(*out)};
 if(!PendingRangesV14(cpu,p,n,out?4:3)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 const VZKernelDTRRequestV23 q=*input;VZKernelDTRReceiptV23 receipt={0};VZKernelLifecycleResult lifecycle={0};
 receipt.action=q.action;receipt.ownResetZeroPolicy=true;uint64_t value=0;
 bool read=q.action==VZ_KERNEL_DTR_READ_PAIR_V23 || q.action==VZ_KERNEL_DTR_READ_RX_V23;
 if(q.reserved || q.action<VZ_KERNEL_DTR_READ_PAIR_V23 || q.action>VZ_KERNEL_DTR_WRITE_TX_V23 ||
  (read && (!out || q.value)) || (!read && out))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK)s=DTRBoundaryV23(cpu,&q.identity,&lifecycle);
 if(s==VZ_KERNEL_OK) {
  if(read) {
   receipt.rxValue=cpu->dtrRXV23;value=cpu->dtrRXV23;
   if(q.action==VZ_KERNEL_DTR_READ_PAIR_V23) {
    /* Genuine 2964e0 reads W20/RX, then a second owned/version boundary
     * precedes 296510 full TX read and ORR TX<<32. */
    s=DTRBoundaryV23(cpu,&q.identity,&lifecycle);
    if(s==VZ_KERNEL_OK){receipt.txValue=cpu->dtrTXV23;value=(uint32_t)value|(cpu->dtrTXV23<<32);}
   }
  } else {
   uint64_t first=q.action==VZ_KERNEL_DTR_WRITE_PAIR_V23?(uint32_t)q.value:q.value;
   cpu->dtrTXV23=first;receipt.firstTXValue=first;receipt.finalTXValue=first;receipt.actualSoftwareWrites=1;
   if(q.action==VZ_KERNEL_DTR_WRITE_PAIR_V23) {
    /* Preserve the actual 296580 and 2965c0 stores: both target TX.
     * This is deliberately two stores, with the original second boundary. */
    s=DTRBoundaryV23(cpu,&q.identity,&lifecycle);
    if(s==VZ_KERNEL_OK){cpu->dtrTXV23=q.value>>32;receipt.finalTXValue=cpu->dtrTXV23;receipt.actualSoftwareWrites=2;}
   }
  }
 }
 if(s==VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context)!=cpu->owner)s=VZ_KERNEL_WRONG_THREAD;
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(cpu,&q.identity);
 if(s!=VZ_KERNEL_OK && receipt.actualSoftwareWrites)cpu->mutationPoisoned=true;
 receipt.status=s;receipt.mutationPoisoned=cpu->mutationPoisoned;
 CPUResult(cpu,&lifecycle);Finish(&lifecycle,s);
 if(s==VZ_KERNEL_OK && read)*out=value;
 *outReceipt=receipt;*outLifecycle=lifecycle;EndOperation(&cpu->operationInProgress);return s;
}
