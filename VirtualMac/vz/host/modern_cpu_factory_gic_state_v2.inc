/* The restore buffer is read-only input. A write exclusion check may reject
 * valid saved-state mappings; engine parsing validates every serialized field
 * before changing controller state. Capture still requires the full output
 * boundary. VM lifetime and the serialized queue are unchanged. */
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICStateTransferV1(VM27GICV3V1 *,void *,size_t,bool);
__attribute__((visibility("hidden"))) VM27CPUFactoryMachStatusV2 VM27CPUFactoryGICStateV1(
 VM27CPUFactoryVMV2 *vm,void *data,size_t bytes,bool restore) {
 if(VM27GICVMQueueEnteredV12)return Mach(VZ_KERNEL_BUSY);
 bool queued=false;VZKernelStatus s=VM27GICVMBeginSerializedV12(vm,&queued);
 if(s!=VZ_KERNEL_OK)return Mach(s);
 bool rangeOK=restore?VM27CPUSelfMappedRangeV1(data,bytes,false,NULL):GICFactoryOutputV15(data,bytes,true);
 if(!rangeOK)s=VZ_KERNEL_BAD_ARGUMENT;
 FactoryGICVMV15 *g=s==VZ_KERNEL_OK && vm->live?GICVMV15(vm):NULL;
 if(s==VZ_KERNEL_OK && !g)s=VZ_KERNEL_NOT_LIVE;
 VZKernelStatus admitted=s;
 if(s==VZ_KERNEL_OK)s=VM27GICStateTransferV1(g->engine,data,bytes,restore);
 if(restore)dprintf(2,"[VM27GICFactoryStateV2] readable=%u controller=%u admitted=%u transfer=%u\n",rangeOK,g!=NULL,(unsigned)admitted,(unsigned)s);
 End(&vm->operation);if(queued)VM27GICVMQueueLeaveV12();return Mach(s);
}
