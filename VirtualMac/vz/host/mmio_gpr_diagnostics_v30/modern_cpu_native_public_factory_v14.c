#include "modern_cpu_native_public_factory_v14.h"
#include "modern_cpu_native_public_factory_v13.c"

static bool FactoryACTLROutputsV14(uint64_t *value,VZKernelACTLRReceiptV16 *receipt,
 VM27CPUFactoryDiagnosticV2 *diagnostic) {
 const void *p[3]={receipt,value,diagnostic};
 const size_t n[3]={sizeof(*receipt),sizeof(*value),sizeof(*diagnostic)};
 bool valid=receipt!=NULL;
 for(unsigned i=0;i<3 && valid;++i)if(p[i]) {
  valid=Output(p[i],n[i]) && VZKernelCPUOutputRangeDisjointV12(p[i],n[i]) &&
   VM27CPUSelfMappedRangeV1(p[i],n[i],true,NULL);
  for(unsigned j=0;j<i && valid;++j)if(p[j])valid=Disjoint(p[i],n[i],p[j],n[j]);
 }
 return valid;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessPhysicalACTLRV14(
 VM27CPUFactoryBorrowV2 *borrow,VZKernelACTLRActionV16 action,uint64_t value,
 uint64_t *readOutput,VZKernelACTLRReceiptV16 *outReceipt,
 VM27CPUFactoryDiagnosticV2 *outDiagnostic) {
 if(!outReceipt || (action==VZ_KERNEL_ACTLR_READ_V16 && !readOutput))return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VZKernelStatus status=BeginBorrow(borrow);if(status!=VZ_KERNEL_OK)return Mach(status);
 if(!pthread_equal(pthread_self(),borrow->borrower)) {
  End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);
 }
 Lock();bool valid=ContainsBorrow(borrow) && FactoryACTLROutputsV14(readOutput,outReceipt,outDiagnostic);
 Entry *entry=valid?borrow->entry:NULL;bool begun=entry && Begin(&entry->operation);Unlock();
 if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
 VZKernelCPU *cpu=NULL;VZKernelACTLRReceiptV16 receipt={0};
 VZKernelLifecycleResult lifecycle={0};VM27CPUFactoryDiagnosticV2 diagnostic={0};uint64_t output=0;
 status=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:
  VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
 if(status==VZ_KERNEL_OK && cpu!=entry->cpu)status=VZ_KERNEL_NOT_LIVE;
 if(status==VZ_KERNEL_OK) {
  VZKernelACTLRRequestV16 request={FactoryPendingRequestV12(entry),action,0,value};
  status=VZKernelCPUAccessPhysicalACTLRV16(cpu,&request,&entry->vm->writer,
   action==VZ_KERNEL_ACTLR_READ_V16?&output:NULL,&receipt,&lifecycle);
  if(action==VZ_KERNEL_ACTLR_WRITE_V16 && receipt.attemptedWrites)entry->exitRecordValid=false;
  if(status!=VZ_KERNEL_OK && receipt.mutationPoisoned && receipt.attemptedWrites) {
   Lock();entry->published=false;entry->draining=true;Unlock();
   (void)VZKernelCPUUnpublishIdentityV5(entry->cpu);
  }
 }
 receipt.status=status;Diagnose(&diagnostic,status,&lifecycle,entry->vm,entry,false);
 // Revalidate final caller ranges after all native/reader/writer callbacks.
 // The operation and retained borrow still protect both ownership registries.
 Lock();valid=ContainsBorrow(borrow) && FactoryACTLROutputsV14(readOutput,outReceipt,outDiagnostic);Unlock();
 if(valid) {
  if(status==VZ_KERNEL_OK && action==VZ_KERNEL_ACTLR_READ_V16)*readOutput=output;
  *outReceipt=receipt;if(outDiagnostic)*outDiagnostic=diagnostic;
 } else status=VZ_KERNEL_BAD_ARGUMENT;
 End(&entry->operation);End(&borrow->operation);return Mach(status);
}
