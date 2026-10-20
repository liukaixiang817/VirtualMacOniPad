// Compiled only inside the new Factory9 owner; not a parallel registry.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMAdoptHostV9(VM27CPUFactoryVMV2 *needle,
 void *host,uint64_t bytes,VM27CPUFactoryRAMV5 **outRAM,VZKernelRAMResultV9 *out) {
 if(!needle || !bytes || bytes>SIZE_MAX)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *unused=NULL;
 VZKernelStatus status=RAMBeginV5(needle,NULL,&vm,&unused);if(status)return Mach(status);
 Lock();bool valid=Output(outRAM,sizeof(*outRAM)) && Output(out,sizeof(*out)) && Output(host,(size_t)bytes) &&
  Disjoint(out,sizeof(*out),outRAM,sizeof(*outRAM)) && Disjoint(host,(size_t)bytes,outRAM,sizeof(*outRAM)) &&
  Disjoint(host,(size_t)bytes,out,sizeof(*out));Unlock();
 if(!valid){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 status=RAMReadyV5(vm,NULL);VM27CPUFactoryRAMV5 *ram=NULL;VZKernelRAMResultV9 staged={0};
 if(status==VZ_KERNEL_OK){ram=calloc(1,sizeof(*ram));if(!ram)status=VZ_KERNEL_OUT_OF_MEMORY;}
 if(status==VZ_KERNEL_OK)status=VZKernelRAMAdoptHostRangeV11(vm->kernel,host,bytes,&ram->kernel,&staged);
 if(status==VZ_KERNEL_OK) {
  ram->vm=vm;ram->epoch=vm->epoch;ram->bytes=bytes;ram->host=host;
  Lock();ram->next=vm->ramRegistry;vm->ramRegistry=ram;Unlock();*outRAM=ram;
 } else {free(ram);ram=NULL;}
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
