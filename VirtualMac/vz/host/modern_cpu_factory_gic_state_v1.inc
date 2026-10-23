/* Appended to the actual frozen Factory translation unit, preserving its
 * operation admission, owner mapping, serialized queue and all existing code. */
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICStateTransferV1(VM27GICV3V1 *,void *,size_t,bool);
__attribute__((visibility("hidden"))) VM27CPUFactoryMachStatusV2 VM27CPUFactoryGICStateV1(
 VM27CPUFactoryVMV2 *vm,void *data,size_t bytes,bool restore) {
 if(VM27GICVMQueueEnteredV12)return Mach(VZ_KERNEL_BUSY);
 bool queued=false;VZKernelStatus s=VM27GICVMBeginSerializedV12(vm,&queued);
 if(s!=VZ_KERNEL_OK)return Mach(s);
 if(s==VZ_KERNEL_OK && !GICFactoryOutputV15(data,bytes,!restore))s=VZ_KERNEL_BAD_ARGUMENT;
 FactoryGICVMV15 *g=s==VZ_KERNEL_OK && vm->live?GICVMV15(vm):NULL;
 if(s==VZ_KERNEL_OK && !g)s=VZ_KERNEL_NOT_LIVE;
 if(s==VZ_KERNEL_OK)s=VM27GICStateTransferV1(g->engine,data,bytes,restore);
 End(&vm->operation);if(queued)VM27GICVMQueueLeaveV12();return Mach(s);
}
