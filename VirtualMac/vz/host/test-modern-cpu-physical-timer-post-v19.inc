// A test-only model of the interval after the real fixture native9 returned.
// This does not claim a device post token; production cannot construct it here.
VZKernelStatus VM27TimerModelPostV19(VZKernelPhysicalTimerOwnerV19 *o,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,bool invalid,
 bool counter,VZKernelPhysicalTimerActionV19 action,uint32_t selector,uint64_t value,
 uint64_t *out,VZKernelPhysicalTimerReceiptV19 *receipt) {
 if(!o || !q || !writer)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelCPU *cpu=o->cpu;VZKernelLifecycleResult lifecycle={0};
 VZKernelStatus s=BeginCPUOperation(cpu);bool entered=s!=VZ_KERNEL_BUSY;
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(cpu,q);
 if(s==VZ_KERNEL_OK && !cpu->runToken)s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK) {
  cpu->runPostReturnActive=true;
  RunPostAccessV7 cap={cpu,cpu->vm->generation,cpu->generation,cpu->owner,
   cpu->runToken+(invalid?1:0),&lifecycle,VZ_KERNEL_OK};
  PendingRunAccessV14 access={{cpu,writer,&lifecycle,VZ_KERNEL_OK},&cap};
  s=counter?PhysicalTimerPostCounterV19(o,&access,(uint16_t)selector,out,receipt):
   PhysicalTimerPostAccessV19(o,&access,action,selector,value,out,receipt);
  cpu->runPostReturnActive=false;
 }
 if(entered)EndOperation(&cpu->operationInProgress);return s;
}
void VM27TimerModelRevokePostV19(VZKernelPhysicalTimerOwnerV19 *o) {
 if(o && atomic_load_explicit(&o->cpu->operationInProgress,memory_order_relaxed))
  o->cpu->runPostReturnActive=false;
}
