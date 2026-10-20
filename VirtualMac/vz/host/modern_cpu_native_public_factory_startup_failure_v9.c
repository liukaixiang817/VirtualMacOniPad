/* Additive RAM admission plus actual GPR/SIMD/AMX failure records.
 * All inherited owner registries and every destructive RAM guard remain. */
#include "modern_cpu_native_public_factory_v22.h"
#include "modern_cpu_ram_host_input_v52.h"
#include "modern_cpu_ram_task_scope_v53.h"
#include "modern_cpu_ram_range_v54.h"
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

// Factory Registry -> Bootstrap Mutex is the same direction as Output().
// Only RAM data backing is omitted here; the kernel input guard below rejects
// aliases of provider-owned mmap allocations and every native CPU context.
static bool FactoryRAMHostInputLockedV7(const void *host,size_t bytes) {
 if(!host || !bytes || bytes>UINTPTR_MAX-(uintptr_t)host ||
  !Disjoint(host,bytes,&Registry,sizeof(Registry)) ||
  !Disjoint(host,bytes,&Registered,sizeof(Registered)) ||
  !Disjoint(host,bytes,&Admission,sizeof(Admission)) ||
  !VM27HVVMRAMHostInputRangeDisjointV26(host,bytes))return false;
 if(!Registered)return true;
 if(!Disjoint(host,bytes,Registered,sizeof(*Registered)))return false;
 for(VM27CPUFactoryRAMV5 *ram=Registered->ramRegistry;ram;ram=ram->next)
  if(!Disjoint(host,bytes,ram,sizeof(*ram)))return false;
 for(Entry *entry=Registered->entries;entry;entry=entry->next) {
  if(!Disjoint(host,bytes,entry,sizeof(*entry)) ||
   !Disjoint(host,bytes,entry->exitStorage,sizeof(*entry->exitStorage)))return false;
  for(VM27CPUFactoryBorrowV2 *borrow=entry->borrows;borrow;borrow=borrow->next)
   if(!Disjoint(host,bytes,borrow,sizeof(*borrow)))return false;
 }
 return true;
}
bool VM27CPUFactoryRAMHostInputRangeDisjointV7(const void *host,size_t bytes) {
 Lock();bool valid=FactoryRAMHostInputLockedV7(host,bytes);Unlock();
 // OS config/GIC sidecar guards and kernel Registry->VM validation run after
 // dropping the Factory lock. No injected/native callback runs under a lock.
 return valid && FactoryConfigRangeV15(host,bytes) &&
  VZKernelRAMHostInputRangeDisjointV52(host,bytes);
}
static VZKernelStatus RAMReadyAdditiveV8(VM27CPUFactoryVMV2 *needle,VM27CPUFactoryRAMV5 *ram) {
 Lock();VM27CPUFactoryVMV2 *vm=Registered==needle?Registered:NULL;
 bool identity=vm && vm->live && vm->epoch && vm->profile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  (!ram || (ram->vm==vm && ram->epoch==vm->epoch));
 VZKernelVM *kernel=identity?vm->kernel:NULL;uint64_t epoch=identity?vm->epoch:0;Unlock();
 // The kernel compares this exact opaque VM and allocation epoch before any
 // dereference. The following real RAM API takes its own operation exclusion.
 return !identity?VZ_KERNEL_NOT_LIVE:VZKernelRAMTaskScopeV53(kernel,epoch);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMTaskScopeV8(VM27CPUFactoryVMV2 *needle) {
 return Mach(RAMReadyAdditiveV8(needle,NULL));
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
 status=RAMReadyAdditiveV8(vm,NULL);VM27CPUFactoryRAMV5 *ram=NULL;VZKernelRAMResultV9 staged={0};
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
 Lock();bool valid=Output(outRAM,sizeof(*outRAM)) && Output(out,sizeof(*out)) &&
  Disjoint(out,sizeof(*out),outRAM,sizeof(*outRAM)) && Disjoint(host,(size_t)bytes,outRAM,sizeof(*outRAM)) &&
  Disjoint(host,(size_t)bytes,out,sizeof(*out));Unlock();
 if(valid)valid=VM27CPUFactoryRAMHostInputRangeDisjointV7(host,(size_t)bytes);
 if(!valid){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 status=RAMReadyAdditiveV8(vm,NULL);VM27CPUFactoryRAMV5 *ram=NULL;VZKernelRAMResultV9 staged={0};
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
 status=RAMReadyAdditiveV8(vm,ram);VZKernelRAMResultV9 staged=RAMSeedV5(vm,ram);
 // The actual kernel owner admits only a fresh nonmapped, nonuncertain RAM
 // handle and an exact GPA range disjoint from every mapped/uncertain range.
 if(status==VZ_KERNEL_OK)status=VZKernelRAMMapV9(ram->kernel,guestAddress,flags,&staged);
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMRangeChangeV9(VM27CPUFactoryVMV2 *needle,
 VZKernelMemoryOperation operation,uint64_t ipa,uint64_t bytes,uint64_t flags,VZKernelRAMResultV9 *out) {
 if(!needle)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *unused=NULL;
 VZKernelStatus status=RAMBeginV5(needle,NULL,&vm,&unused);if(status)return Mach(status);
 Lock();bool valid=Output(out,sizeof(*out));Unlock();
 if(!valid){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 VZKernelRAMResultV9 receipt=RAMSeedV5(vm,NULL);status=RAMReadyAdditiveV8(vm,NULL);
 if(status==VZ_KERNEL_OK)status=VZKernelRAMRangeChangeV54(vm->kernel,vm->epoch,operation,ipa,bytes,flags,&receipt);
 receipt.status=status;memcpy(out,&receipt,sizeof(receipt));End(&vm->operation);return Mach(status);
}
