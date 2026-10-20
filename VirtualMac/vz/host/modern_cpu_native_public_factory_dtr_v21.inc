VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessDTRV21(VM27CPUFactoryBorrowV2 *borrow,
 VZKernelDTRActionV23 action,uint64_t value,uint64_t *out,VZKernelDTRReceiptV23 *outReceipt,
 VM27CPUFactoryDiagnosticV2 *diagnostic) {
 bool read=action==VZ_KERNEL_DTR_READ_PAIR_V23 || action==VZ_KERNEL_DTR_READ_RX_V23;
 if(action<VZ_KERNEL_DTR_READ_PAIR_V23 || action>VZ_KERNEL_DTR_WRITE_TX_V23 ||
  (read && (!out || value)) || (!read && out))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 if(!ControlRangeV18(outReceipt,sizeof(*outReceipt)) || (out && !ControlRangeV18(out,sizeof(*out))) ||
  (diagnostic && !ControlRangeV18(diagnostic,sizeof(*diagnostic))))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus s=BeginBorrow(borrow);if(s!=VZ_KERNEL_OK)return Mach(s);
 if(!pthread_equal(pthread_self(),borrow->borrower)){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 Lock();bool valid=ContainsBorrow(borrow) && Output(outReceipt,sizeof(*outReceipt)) && DiagnosticOutput(diagnostic) &&
  (!out || (Output(out,sizeof(*out)) && Disjoint(out,sizeof(*out),outReceipt,sizeof(*outReceipt)))) &&
  (!diagnostic || (Disjoint(outReceipt,sizeof(*outReceipt),diagnostic,sizeof(*diagnostic)) &&
   (!out || Disjoint(out,sizeof(*out),diagnostic,sizeof(*diagnostic)))));
 Entry *entry=valid?borrow->entry:NULL;bool begun=entry && Begin(&entry->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelLifecycleResult lifecycle={0};VZKernelDTRReceiptV23 receipt={0};uint64_t actual=0;
 s=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(s==VZ_KERNEL_OK && cpu!=entry->cpu)s=VZ_KERNEL_NOT_LIVE;
 if(s==VZ_KERNEL_OK) {
  if(!read)entry->exitRecordValid=false;
  const VZKernelDTRRequestV23 q={{1,entry->vm->profile,entry->vm->nativeISA,0,
   entry->vm->epoch,entry->identity,entry->nativeOwnerThread,entry->generation,entry->returnedSlotWord},action,0,value};
  s=VZKernelCPUAccessDTRV23(cpu,&q,read?&actual:NULL,&receipt,&lifecycle);
  if(s!=VZ_KERNEL_OK && receipt.mutationPoisoned && receipt.actualSoftwareWrites) {
   Lock();entry->published=false;entry->draining=true;Unlock();(void)VZKernelCPUUnpublishIdentityV5(cpu);
  }
 }
 if(s==VZ_KERNEL_OK && read)*out=actual;
 receipt.status=s;*outReceipt=receipt;Diagnose(diagnostic,s,&lifecycle,entry->vm,entry,false);
 End(&entry->operation);End(&borrow->operation);return Mach(s);
}
hv_return_t VM27CPUFactoryAccessDTRV21(hv_vcpu_t cpu,VZKernelDTRActionV23 action,uint64_t value,uint64_t *out) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 bool read=action==VZ_KERNEL_DTR_READ_PAIR_V23 || action==VZ_KERNEL_DTR_READ_RX_V23;
 hv_return_t status=read && !ControlRangeV18(out,sizeof(*out))?Mach(VZ_KERNEL_BAD_ARGUMENT):0;
 VM27CPUFactoryBorrowV2 *borrow=NULL;uint64_t actual=0;
 if(!status)status=VM27CPUFactoryBorrowAcquireV2(cpu,&borrow);
 if(!status) {
  VZKernelDTRReceiptV23 receipt={0};
  status=VM27CPUFactoryBorrowAccessDTRV21(borrow,action,value,read?&actual:out,&receipt,NULL);
  status=PublicReleaseV6(borrow,status);
 }
 if(!status && read) {
  if(!ControlRangeV18(out,sizeof(*out)))status=Mach(VZ_KERNEL_BAD_ARGUMENT);
  else if(!VM27CPUSelfWriteV1(NULL,out,sizeof(actual),&actual))status=Mach(VZ_KERNEL_CONTEXT_UNREADABLE);
 }
 PublicEndV6();return status;
}
