VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowSetDebugTrapV11(
 VM27CPUFactoryBorrowV2 *borrow,VZKernelDebugKindV13 kind,bool value,
 VZKernelInitReceipt *outReceipt,VM27CPUFactoryDiagnosticV2 *diagnostic) {
 if(!outReceipt)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus status=BeginBorrow(borrow);if(status!=VZ_KERNEL_OK)return Mach(status);
 if(!pthread_equal(pthread_self(),borrow->borrower)) {
  End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);
 }
 Lock();bool valid=ContainsBorrow(borrow) && Output(outReceipt,sizeof(*outReceipt)) &&
  VZKernelCPUOutputRangeDisjointV12(outReceipt,sizeof(*outReceipt)) && DiagnosticOutput(diagnostic) &&
  (!diagnostic || (Disjoint(outReceipt,sizeof(*outReceipt),diagnostic,sizeof(*diagnostic)) &&
   VZKernelCPUOutputRangeDisjointV12(diagnostic,sizeof(*diagnostic))));
 Entry *entry=valid?borrow->entry:NULL;bool begun=entry && Begin(&entry->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelLifecycleResult lifecycle={0};VZKernelInitReceipt receipt={0};
 receipt.failedNativeOffset=UINT32_MAX;receipt.failedWriteOrdinal=UINT32_MAX;
 status=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:
  VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(status==VZ_KERNEL_OK && cpu!=entry->cpu)status=VZ_KERNEL_NOT_LIVE;
 if(status==VZ_KERNEL_OK) {
  entry->exitRecordValid=false;
  VZKernelDebugRequestV13 request={1,entry->vm->profile,entry->vm->nativeISA,0,
   entry->vm->epoch,entry->identity,entry->nativeOwnerThread,entry->generation,
   entry->returnedSlotWord,kind,value,{0}};
  status=VZKernelCPUSetDebugTrapV13(cpu,&request,&entry->vm->writer,&receipt,&lifecycle);
  if(status!=VZ_KERNEL_OK && receipt.mutationPoisoned && receipt.attemptedWrites) {
   Lock();entry->published=false;entry->draining=true;Unlock();
   (void)VZKernelCPUUnpublishIdentityV5(cpu);
  }
 }
 receipt.status=status;*outReceipt=receipt;
 Diagnose(diagnostic,status,&lifecycle,entry->vm,entry,false);
 End(&entry->operation);End(&borrow->operation);return Mach(status);
}
static hv_return_t PublicDebugV11(hv_vcpu_t identifier,VZKernelDebugKindV13 kind,bool value) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 VM27CPUFactoryBorrowV2 *borrow=NULL;hv_return_t status=VM27CPUFactoryBorrowAcquireV2(identifier,&borrow);
 if(!status) {
  VZKernelInitReceipt receipt={0};
  status=VM27CPUFactoryBorrowSetDebugTrapV11(borrow,kind,value,&receipt,NULL);
  status=PublicReleaseV6(borrow,status);
 }
 PublicEndV6();return status;
}
hv_return_t hv_vcpu_set_trap_debug_exceptions(hv_vcpu_t identifier,bool value) {
 return PublicDebugV11(identifier,VZ_KERNEL_DEBUG_EXCEPTIONS_V13,value);
}
hv_return_t hv_vcpu_set_trap_debug_reg_accesses(hv_vcpu_t identifier,bool value) {
 return PublicDebugV11(identifier,VZ_KERNEL_DEBUG_REGISTER_ACCESSES_V13,value);
}
