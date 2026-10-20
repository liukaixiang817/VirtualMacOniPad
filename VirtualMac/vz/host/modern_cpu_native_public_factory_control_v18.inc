static bool ControlRangeV18(const void *p,size_t n) {
 return p && n && n<=UINTPTR_MAX-(uintptr_t)p &&
  VM27CPUFactoryOutputRangeDisjointV3(p,n) && VZKernelCPUOutputRangeDisjointV12(p,n) &&
  VM27CPUConfigOutputRangeDisjointV3(p,n) && VM27CPUFactoryGICOutputRangeDisjointV15(p,n) &&
  VM27CPUSelfMappedRangeV1(p,n,true,NULL);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessControlV18(
 VM27CPUFactoryBorrowV2 *borrow,VZKernelControlActionV22 action,uint32_t identifier,
 uint64_t value,uint64_t *outValue,VZKernelInitReceipt *outReceipt,
 VM27CPUFactoryDiagnosticV2 *diagnostic) {
 if((action==VZ_KERNEL_CONTROL_READ_V22 && (!outValue || value)) ||
  (action==VZ_KERNEL_CONTROL_WRITE_V22 && outValue) ||
  (action!=VZ_KERNEL_CONTROL_READ_V22 && action!=VZ_KERNEL_CONTROL_WRITE_V22))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 if(!ControlRangeV18(outReceipt,sizeof(*outReceipt)) ||
  (outValue && !ControlRangeV18(outValue,sizeof(*outValue))) ||
  (diagnostic && !ControlRangeV18(diagnostic,sizeof(*diagnostic))))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus status=BeginBorrow(borrow);if(status!=VZ_KERNEL_OK)return Mach(status);
 if(!pthread_equal(pthread_self(),borrow->borrower)){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 Lock();bool valid=ContainsBorrow(borrow) && Output(outReceipt,sizeof(*outReceipt)) && DiagnosticOutput(diagnostic) &&
  (!outValue || (Output(outValue,sizeof(*outValue)) && Disjoint(outValue,sizeof(*outValue),outReceipt,sizeof(*outReceipt)))) &&
  (!diagnostic || (Disjoint(outReceipt,sizeof(*outReceipt),diagnostic,sizeof(*diagnostic)) &&
   (!outValue || Disjoint(outValue,sizeof(*outValue),diagnostic,sizeof(*diagnostic)))));
 Entry *entry=valid?borrow->entry:NULL;bool begun=entry && Begin(&entry->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelLifecycleResult lifecycle={0};VZKernelInitReceipt receipt={0};
 receipt.failedNativeOffset=UINT32_MAX;receipt.failedWriteOrdinal=UINT32_MAX;uint64_t actual=0;
 status=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(status==VZ_KERNEL_OK && cpu!=entry->cpu)status=VZ_KERNEL_NOT_LIVE;
 if(status==VZ_KERNEL_OK) {
  if(action==VZ_KERNEL_CONTROL_WRITE_V22)entry->exitRecordValid=false;
  const VZKernelControlRequestV22 request={{1,entry->vm->profile,entry->vm->nativeISA,0,
   entry->vm->epoch,entry->identity,entry->nativeOwnerThread,entry->generation,entry->returnedSlotWord},action,identifier,value};
  status=VZKernelCPUAccessControlV22(cpu,&request,&entry->vm->writer,
   action==VZ_KERNEL_CONTROL_READ_V22?&actual:NULL,&receipt,&lifecycle);
  if(status!=VZ_KERNEL_OK && receipt.mutationPoisoned && receipt.attemptedWrites) {
   Lock();entry->published=false;entry->draining=true;Unlock();
   (void)VZKernelCPUUnpublishIdentityV5(cpu);
  }
 }
 if(status==VZ_KERNEL_OK && action==VZ_KERNEL_CONTROL_READ_V22 && outValue)*outValue=actual;
 receipt.status=status;*outReceipt=receipt;
 Diagnose(diagnostic,status,&lifecycle,entry->vm,entry,false);
 End(&entry->operation);End(&borrow->operation);return Mach(status);
}
static hv_return_t PublicControlV18(hv_vcpu_t identifier,VZKernelControlActionV22 action,
 uint32_t field,uint64_t value,uint64_t *outValue) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 hv_return_t status=action==VZ_KERNEL_CONTROL_READ_V22 && !ControlRangeV18(outValue,sizeof(*outValue))?
  Mach(VZ_KERNEL_BAD_ARGUMENT):0;
 VM27CPUFactoryBorrowV2 *borrow=NULL;uint64_t actual=0;
 if(!status)status=VM27CPUFactoryBorrowAcquireV2(identifier,&borrow);
 if(!status) {
  VZKernelInitReceipt receipt={0};
  status=VM27CPUFactoryBorrowAccessControlV18(borrow,action,field,value,
   action==VZ_KERNEL_CONTROL_READ_V22?&actual:NULL,&receipt,NULL);
  status=PublicReleaseV6(borrow,status);
 }
 if(!status && action==VZ_KERNEL_CONTROL_READ_V22) {
  if(!ControlRangeV18(outValue,sizeof(*outValue)))status=Mach(VZ_KERNEL_BAD_ARGUMENT);
  else if(!VM27CPUSelfWriteV1(NULL,outValue,sizeof(actual),&actual))status=Mach(VZ_KERNEL_CONTEXT_UNREADABLE);
 }
 PublicEndV6();return status;
}
hv_return_t _hv_vcpu_get_control_field(hv_vcpu_t cpu,uint32_t field,uint64_t *out) {
 return PublicControlV18(cpu,VZ_KERNEL_CONTROL_READ_V22,field,0,out);
}
hv_return_t _hv_vcpu_set_control_field(hv_vcpu_t cpu,uint32_t field,uint64_t value) {
 return PublicControlV18(cpu,VZ_KERNEL_CONTROL_WRITE_V22,field,value,NULL);
}
