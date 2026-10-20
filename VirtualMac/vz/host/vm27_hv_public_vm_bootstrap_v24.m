#include "vm27_hv_public_vm_bootstrap_v14.h"
#include <stdio.h>
#include <errno.h>
__attribute__((visibility("hidden"))) __typeof__(_hv_vm_config_set_isa) VM27HVVMInheritedISASetterV24;
#define _hv_vm_config_set_isa VM27HVVMInheritedISASetterV24
#include "vm27_hv_public_vm_bootstrap_v23.m"
#undef _hv_vm_config_set_isa

static _Atomic unsigned VM27ISASetterObservationsV24;
hv_return_t _hv_vm_config_set_isa(hv_vm_config_t config,uint32_t requestedModernISA) {
 // Same Mac hardware ISA -> internal ISA0 -> wire ISA0: the genuine modern
 // caller selects HV3 and the genuine old caller selects native2. Modern4
 // folds several different wire values and has no unambiguous translation.
 const uint32_t nativeISA=requestedModernISA==3?2:requestedModernISA;
 hv_return_t result=VM27HVVMInheritedISASetterV24(config,nativeISA);
 unsigned ordinal=atomic_load_explicit(&VM27ISASetterObservationsV24,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&VM27ISASetterObservationsV24,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal<8) {
  const int savedErrno=errno;
  dprintf(2,"[Independent27HV] vm-isa-set ordinal=%u requestedModernISA=%u nativeISA=%u result=0x%08x\n",ordinal+1,requestedModernISA,nativeISA,(unsigned)result);
  errno=savedErrno;
 }
 return result;
}
