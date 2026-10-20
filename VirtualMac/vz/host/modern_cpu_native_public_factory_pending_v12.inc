static VZKernelRunPendingRequestV14 FactoryPendingRequestV12(Entry *e) {
 return (VZKernelRunPendingRequestV14){1,e->vm->profile,e->vm->nativeISA,0,
  e->vm->epoch,e->identity,e->nativeOwnerThread,e->generation,e->returnedSlotWord};
}
static bool FactoryRunOutputV12(VM27CPUFactoryRunDiagnosticV3 *out) {
 if(!out)return true;
 Lock();bool valid=Output(out,sizeof(*out)) &&
  VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) &&
  VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL);Unlock();return valid;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRunOwnedStepV3(
 VM27CPUFactoryBorrowV2 *borrow,VM27CPUFactoryRunDiagnosticV3 *out) {
 // Keep the inherited real admission/lease/release path, but stage this own
 // diagnostic so a caller cannot turn its final copy into a native-context
 // write. Public hv_vcpu_run already uses an internal stack diagnostic.
 if(!FactoryRunOutputV12(out))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryRunDiagnosticV3 staged={0};
 VM27CPUFactoryMachStatusV2 status=FactoryInheritedRunDiagnosticV12(borrow,out?&staged:NULL);
 if(out && staged.factory.vmEpoch) {
  if(!FactoryRunOutputV12(out))return Mach(VZ_KERNEL_BAD_ARGUMENT);
  *out=staged;
 }
 return status;
}
static VZKernelStatus FactoryPendingRunBridgeV12(VZKernelCPU *cpu,VZKernelRunStepReceiptV7 *out) {
 // Called only by the inherited Run producer while its real retained borrow
 // and Entry operation remain held; never creates an unretained run lease.
 Lock();Entry *entry=NULL;
 if(Registered)for(Entry *e=Registered->entries;e;e=e->next)if(e->cpu==cpu){entry=e;break;}
 bool valid=entry && entry==Owned && entry->live && entry->published && !entry->draining &&
  entry->configComplete && atomic_load_explicit(&entry->operation,memory_order_relaxed) && entry->borrowCount;
 VZKernelRunPendingRequestV14 q={0};VZKernelInitWriter writer={0};
 if(valid){q=FactoryPendingRequestV12(entry);writer=entry->vm->writer;}Unlock();
 if(!valid)return VZ_KERNEL_NOT_LIVE;
 VZKernelRunPendingReceiptV14 receipt={0};
 VZKernelStatus status=VZKernelCPURunOwnedPendingStepV14(cpu,&q,&writer,&receipt);
 if(receipt.mutationPoisoned) {Lock();entry->published=false;entry->draining=true;Unlock();}
 *out=receipt.step;return status;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowPendingInterruptV12(
 VM27CPUFactoryBorrowV2 *borrow,VZKernelPendingActionV14 action,hv_interrupt_type_t type,
 bool value,bool *out,VM27CPUFactoryDiagnosticV2 *diagnostic) {
 if(action==VZ_KERNEL_PENDING_READ_V14 && !out)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus status=BeginBorrow(borrow);if(status!=VZ_KERNEL_OK)return Mach(status);
 if(!pthread_equal(pthread_self(),borrow->borrower)){End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);}
 Lock();bool valid=ContainsBorrow(borrow) && DiagnosticOutput(diagnostic) &&
  (!out || (Output(out,sizeof(*out)) && VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) &&
   VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL))) &&
  (!diagnostic || VZKernelCPUOutputRangeDisjointV12(diagnostic,sizeof(*diagnostic))) &&
  (!out || !diagnostic || Disjoint(out,sizeof(*out),diagnostic,sizeof(*diagnostic)));
 Entry *entry=valid?borrow->entry:NULL;bool begun=entry && Begin(&entry->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelLifecycleResult lifecycle={0};
 status=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:
  VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(status==VZ_KERNEL_OK && cpu!=entry->cpu)status=VZ_KERNEL_NOT_LIVE;
 if(status==VZ_KERNEL_OK) {
  VZKernelRunPendingRequestV14 q=FactoryPendingRequestV12(entry);
  status=VZKernelCPUAccessPendingInterruptV14(cpu,&q,action,type,value,out);
  if(status==VZ_KERNEL_OK && action==VZ_KERNEL_PENDING_WRITE_V14)entry->exitRecordValid=false;
 }
 Diagnose(diagnostic,status,&lifecycle,entry->vm,entry,false);
 End(&entry->operation);End(&borrow->operation);return Mach(status);
}
static hv_return_t PublicPendingV12(hv_vcpu_t id,hv_interrupt_type_t type,bool value,bool *out,
 VZKernelPendingActionV14 action) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 Lock();bool valid=!out || (Output(out,sizeof(*out)) &&
  VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) && VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL));Unlock();
 if((action==VZ_KERNEL_PENDING_READ_V14 && !out) || !valid){PublicEndV6();return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 VM27CPUFactoryBorrowV2 *borrow=NULL;bool staged=false;
 hv_return_t status=VM27CPUFactoryBorrowAcquireV2(id,&borrow);
 if(!status) {
  status=VM27CPUFactoryBorrowPendingInterruptV12(borrow,action,type,value,
   action==VZ_KERNEL_PENDING_READ_V14?&staged:NULL,NULL);
  status=PublicReleaseV6(borrow,status);
 }
 if(!status && action==VZ_KERNEL_PENDING_READ_V14) {
  Lock();valid=Output(out,sizeof(*out)) && VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) &&
   VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL);Unlock();
  if(valid)*out=staged;else status=Mach(VZ_KERNEL_BAD_ARGUMENT);
 }
 PublicEndV6();return status;
}
hv_return_t hv_vcpu_get_pending_interrupt(hv_vcpu_t id,hv_interrupt_type_t type,bool *out) {
 return PublicPendingV12(id,type,false,out,VZ_KERNEL_PENDING_READ_V14);
}
hv_return_t hv_vcpu_set_pending_interrupt(hv_vcpu_t id,hv_interrupt_type_t type,bool value) {
 return PublicPendingV12(id,type,value,NULL,VZ_KERNEL_PENDING_WRITE_V14);
}
