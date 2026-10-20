/* Additive RAM admission plus actual GPR/SIMD/AMX failure records.
 * All inherited owner registries and every destructive RAM guard remain. */
#include "modern_cpu_native_public_factory_v22.h"
#include "modern_vmm_amx_availability_v1.h"
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_get_reg) VM27InheritedGetRegisterFailureV2;
#define hv_vcpu_get_reg VM27InheritedGetRegisterFailureV2
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_set_reg) VM27InheritedSetRegisterFailureV2;
#define hv_vcpu_set_reg VM27InheritedSetRegisterFailureV2
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_get_simd_fp_reg) VM27InheritedGetSIMDRegisterFailureV2;
#define hv_vcpu_get_simd_fp_reg VM27InheritedGetSIMDRegisterFailureV2
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_set_simd_fp_reg) VM27InheritedSetSIMDRegisterFailureV2;
#define hv_vcpu_set_simd_fp_reg VM27InheritedSetSIMDRegisterFailureV2
__attribute__((visibility("hidden"))) __typeof__(VM27VMMGetAMXAvailabilityV1) VM27InheritedGetAMXAvailabilityFailureV2;
#define VM27VMMGetAMXAvailabilityV1 VM27InheritedGetAMXAvailabilityFailureV2
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryRAMCreateV5) VM27InheritedRAMCreateV6;
#define VM27CPUFactoryRAMCreateV5 VM27InheritedRAMCreateV6
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryRAMAdoptHostV9) VM27InheritedRAMAdoptV6;
#define VM27CPUFactoryRAMAdoptHostV9 VM27InheritedRAMAdoptV6
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryRAMMapV5) VM27InheritedRAMMapV6;
#define VM27CPUFactoryRAMMapV5 VM27InheritedRAMMapV6
#include "modern_cpu_native_public_factory_startup_failure_v5.c"
#undef hv_vcpu_get_reg
#undef hv_vcpu_set_reg
#undef hv_vcpu_get_simd_fp_reg
#undef hv_vcpu_set_simd_fp_reg
#undef VM27VMMGetAMXAvailabilityV1
#undef VM27CPUFactoryRAMCreateV5
#undef VM27CPUFactoryRAMAdoptHostV9
#undef VM27CPUFactoryRAMMapV5
#include "modern_cpu_register_failure_diagnostic_v2.inc"

static VZKernelStatus RAMReadyAdditiveV6(VM27CPUFactoryVMV2 *vm,VM27CPUFactoryRAMV5 *ram) {
 Lock();bool live=vm->live;
 bool identity=Registered==vm && (!ram || (ram->vm==vm && ram->epoch==vm->epoch));Unlock();
 return !identity || !live?VZ_KERNEL_NOT_LIVE:
  !pthread_equal(pthread_self(),vm->owner)?VZ_KERNEL_WRONG_THREAD:VZ_KERNEL_OK;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMCreateV5(VM27CPUFactoryVMV2 *needle,
 uint64_t bytes,VM27CPUFactoryRAMV5 **outRAM,void **outHost,VZKernelRAMResultV9 *out) {
 if(!needle)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *unused=NULL;
 VZKernelStatus status=RAMBeginV5(needle,NULL,&vm,&unused);if(status)return Mach(status);
 Lock();bool valid=Output(outRAM,sizeof(*outRAM)) && Output(outHost,sizeof(*outHost)) && Output(out,sizeof(*out)) &&
  Disjoint(outRAM,sizeof(*outRAM),outHost,sizeof(*outHost)) && Disjoint(out,sizeof(*out),outRAM,sizeof(*outRAM)) &&
  Disjoint(out,sizeof(*out),outHost,sizeof(*outHost));Unlock();
 if(!valid){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 status=RAMReadyAdditiveV6(vm,NULL);VM27CPUFactoryRAMV5 *ram=NULL;VZKernelRAMResultV9 staged={0};
 if(status==VZ_KERNEL_OK) {
  ram=calloc(1,sizeof(*ram));if(!ram)status=VZ_KERNEL_OUT_OF_MEMORY;
 }
 if(status==VZ_KERNEL_OK)status=VZKernelRAMCreateV9(vm->kernel,bytes,&ram->kernel,&ram->host,&staged);
 if(status==VZ_KERNEL_OK) {
  ram->vm=vm;ram->epoch=vm->epoch;ram->bytes=bytes;
  Lock();ram->next=vm->ramRegistry;vm->ramRegistry=ram;Unlock();
  *outRAM=ram;*outHost=ram->host;
 }else{free(ram);ram=NULL;}
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
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
 status=RAMReadyAdditiveV6(vm,NULL);VM27CPUFactoryRAMV5 *ram=NULL;VZKernelRAMResultV9 staged={0};
 if(status==VZ_KERNEL_OK){ram=calloc(1,sizeof(*ram));if(!ram)status=VZ_KERNEL_OUT_OF_MEMORY;}
 if(status==VZ_KERNEL_OK)status=VZKernelRAMAdoptHostRangeV11(vm->kernel,host,bytes,&ram->kernel,&staged);
 if(status==VZ_KERNEL_OK) {
  ram->vm=vm;ram->epoch=vm->epoch;ram->bytes=bytes;ram->host=host;
  Lock();ram->next=vm->ramRegistry;vm->ramRegistry=ram;Unlock();*outRAM=ram;
 } else {free(ram);ram=NULL;}
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMMapV5(VM27CPUFactoryRAMV5 *needle,
 uint64_t guestAddress,uint64_t flags,VZKernelRAMResultV9 *out) {
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *ram=NULL;
 VZKernelStatus status=RAMAdmitV5(needle,out,&vm,&ram);if(status)return Mach(status);
 status=RAMReadyAdditiveV6(vm,ram);VZKernelRAMResultV9 staged=RAMSeedV5(vm,ram);
 // The actual kernel owner admits only a fresh nonmapped, nonuncertain RAM
 // handle and an exact GPA range disjoint from every mapped/uncertain range.
 if(status==VZ_KERNEL_OK)status=VZKernelRAMMapV9(ram->kernel,guestAddress,flags,&staged);
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
