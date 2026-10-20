// Include only after the actual lifecycle definitions. Original13 getter79ac
// and setter79dc..79ec access true6d8; the setter preserves every bit except0.
// Actual20B101 native9 ac46c..474 consumes bit0 into private4090. Neither the
// original setter nor this typed owner port changes dirty/ready or runs native.
static bool VtimerMaskNativeV20(InitializationAccess *access,bool write,uint64_t *value) {
 const uint32_t offset=0x6d8;VZKernelCPU *cpu=access->cpu;
 if(!InitializationOwned(access) || cpu->nativeContext>UINTPTR_MAX-offset-8 ||
  !VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+offset),8,write,NULL))return false;
 bool ok=write?access->writer->writeMemory(access->writer->context,
  (void *)(cpu->nativeContext+offset),8,value):cpu->vm->ops.readMemory(cpu->vm->ops.context,
  (const void *)(cpu->nativeContext+offset),8,value);
 return ok && InitializationOwned(access);
}
static bool VtimerMaskRangesV20(VZKernelCPU *cpu,const void *const *p,
 const size_t *n,unsigned count,unsigned inputs) {
 if(!PendingRangesV14(cpu,p,n,count))return false;
 for(unsigned i=0;i<count;++i) {
  if(!VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]) ||
   !VM27CPUSelfMappedRangeV1(p[i],n[i],i>=inputs,NULL))return false;
 }
 return true;
}
VZKernelStatus VZKernelCPUAccessVtimerMaskV20(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *input,const VZKernelInitWriter *writer,
 bool write,bool mask,bool *out,VZKernelVtimerMaskReceiptV20 *outReceipt,
 VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !input || !writer || !outReceipt || !outLifecycle || (!write && !out))
  return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus s=BeginCPUOperation(cpu);
 if(s!=VZ_KERNEL_OK){if(s!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return s;}
 const void *p[]={input,writer,outReceipt,outLifecycle,out};
 const size_t n[]={sizeof(*input),sizeof(*writer),sizeof(*outReceipt),sizeof(*outLifecycle),sizeof(*out)};
 unsigned count=out?5:4;
 if(!VtimerMaskRangesV20(cpu,p,n,count,2)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelRunPendingRequestV14 q=*input;VZKernelInitWriter w=*writer;
 VZKernelVtimerMaskReceiptV20 r={0};VZKernelLifecycleResult lifecycle={0};
 s=PendingRequestOwnedV14(cpu,&q);
 if(s==VZ_KERNEL_OK && (!w.writeMemory || w.context!=cpu->vm->ops.context || (!write && mask)))
  s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
  s=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(s==VZ_KERNEL_OK)s=Version(cpu,&lifecycle);
 InitializationAccess access={cpu,&w,&lifecycle,VZ_KERNEL_OK};
 if(s==VZ_KERNEL_OK) {
  ++r.attemptedReads;
  if(!VtimerMaskNativeV20(&access,false,&r.initialNativeValue))s=VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 if(s==VZ_KERNEL_OK) {
  r.initialMask=(r.initialNativeValue&1)!=0;r.requestedMask=write?mask:r.initialMask;
  r.requestedNativeValue=(r.initialNativeValue&~UINT64_C(1))|(uint64_t)r.requestedMask;
  if(write) {
   ++r.attemptedWrites;
   if(VtimerMaskNativeV20(&access,true,&r.requestedNativeValue))++r.completedWrites;
   else s=VZ_KERNEL_CONTEXT_UNREADABLE;
  }
 }
 if(s==VZ_KERNEL_OK && !InitializationOwned(&access))s=access.boundaryStatus;
 if(access.boundaryStatus!=VZ_KERNEL_OK)s=access.boundaryStatus;
 bool valid=VtimerMaskRangesV20(cpu,p,n,count,2);
 if(!valid)s=VZ_KERNEL_BAD_ARGUMENT;
 if(s!=VZ_KERNEL_OK && r.attemptedWrites) {
  cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
  cpu->registryEntry->published=false;cpu->registryEntry->draining=true;Unlock(&cpu->vm->mutex);
  r.identityWithdrawn=true;
 }
 CPUResult(cpu,&lifecycle);Finish(&lifecycle,s);r.status=s;r.mutationPoisoned=cpu->mutationPoisoned;
 if(valid) {
  if(s==VZ_KERNEL_OK && !write)*out=r.initialMask;
  *outReceipt=r;*outLifecycle=lifecycle;
 }
 EndOperation(&cpu->operationInProgress);return s;
}
