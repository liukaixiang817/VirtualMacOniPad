#include "vm27_hv_public_vm_bootstrap_v14.h"
#include <stdio.h>
// The original GIC/scheduler teardown runs first. Its existing leaf enters
// Admission and invokes this exact same-owner RAM drain before native VM2.
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryVMDestroyV2) VM27DrainMappedVMBeforeDestroyV23;
#define VM27CPUFactoryVMDestroyV2 VM27DrainMappedVMBeforeDestroyV23
#include "vm27_hv_public_vm_bootstrap_v20.m"
#undef VM27CPUFactoryVMDestroyV2
VM27CPUFactoryMachStatusV2 VM27DrainMappedVMBeforeDestroyV23(
 VM27CPUFactoryVMV2 *vm,VM27CPUFactoryDiagnosticV2 *diagnostic) {
 Lock();bool owner=atomic_load(&Admission) && vm && Backend.vm==vm && !Backend.vmDestroyed &&
  pthread_equal(Backend.owner,pthread_self());Unlock();
 if(!owner){dprintf(2,"[Independent27HV] failed stage=vm-destroy-owner status=0x%08x\n",(unsigned)Error(3));return Error(3);}
 for(;;) {
  Lock();MapEntry *entry=Maps;Unlock();if(!entry)break;
  VZKernelRAMResultV9 receipt={0};hv_return_t status=0;
  if(!entry->cleanupOnly) {
   status=VM27CPUFactoryRAMUnmapV5(entry->ram,&receipt);
   if(status){dprintf(2,"[Independent27HV] failed stage=vm-destroy-unmap status=0x%08x nativeInvoked=%u nativeReturn=%d ipa=0x%llx bytes=%zu\n",(unsigned)status,receipt.nativeInvoked,receipt.nativeReturn,(unsigned long long)entry->guestAddress,(size_t)entry->bytes);return status;}
   Lock();entry->cleanupOnly=true;Unlock();
  }
  status=VM27CPUFactoryRAMFreeV5(entry->ram);
  if(status){dprintf(2,"[Independent27HV] failed stage=vm-destroy-ram-free status=0x%08x\n",(unsigned)status);return status;}
  // A caller-owned adopted range is never unmapped or freed by RAMFree.
  RemoveMap(entry);
 }
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryVMDestroyV2(vm,diagnostic);
 if(status)dprintf(2,"[Independent27HV] failed stage=vm-destroy-native status=0x%08x\n",(unsigned)status);
 return status;
}
