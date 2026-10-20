/* Preserve Factory10; observe the actual VM GIC result without retries or mutation changes. */
#include "modern_cpu_native_public_factory_v22.h"
__attribute__((visibility("hidden"))) __typeof__(VM27CPUFactoryVMGICAccessV15) VM27InheritedVMGICAccessV11;
#define VM27CPUFactoryVMGICAccessV15 VM27InheritedVMGICAccessV11
#include "modern_cpu_native_public_factory_startup_failure_v10.c"
#undef VM27CPUFactoryVMGICAccessV15
#include <errno.h>
#include <stdio.h>
static _Atomic unsigned VM27GICVMFailureLogsV11;
static VM27CPUFactoryMachStatusV2 VM27GICVMResultV11(const char *stage,
 VM27CPUFactoryVMGICActionV15 action,uint64_t selector,uint64_t value,VZKernelStatus status) {
 VM27CPUFactoryMachStatusV2 result=Mach(status);
 if(status!=VZ_KERNEL_OK) {
  int savedErrno=errno;
  unsigned n=atomic_load_explicit(&VM27GICVMFailureLogsV11,memory_order_relaxed);
  while(n<8 && !atomic_compare_exchange_weak_explicit(&VM27GICVMFailureLogsV11,
   &n,n+1,memory_order_relaxed,memory_order_relaxed)){}
  if(n<8)dprintf(2,"[Independent27HV] gic-vm-failure ordinal=%u stage=%s action=%u selector=0x%llx value=0x%llx ownStatus=%u publicStatus=0x%08x actualOriginalOperationPreserved=1\n",
   n+1,stage,(unsigned)action,(unsigned long long)selector,(unsigned long long)value,
   (unsigned)status,(unsigned)result);
  errno=savedErrno;
 }
 return result;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMGICAccessV15(VM27CPUFactoryVMV2 *vm,
 VM27CPUFactoryVMGICActionV15 action,uint64_t selector,uint64_t value,uint64_t *out) {
 VZKernelStatus s=BeginVM(vm);if(s!=VZ_KERNEL_OK)return VM27GICVMResultV11("vm-admission",action,selector,value,s);
 const char *stage="output-and-vm-live";
 if(out && !GICFactoryOutputV15(out,sizeof(*out),true))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK && !vm->live)s=VZ_KERNEL_NOT_LIVE;
 FactoryGICVMV15 *g=s==VZ_KERNEL_OK?GICVMV15(vm):NULL;if(s==VZ_KERNEL_OK && !g)s=VZ_KERNEL_NOT_LIVE;
 uint64_t result=0;
 if(s==VZ_KERNEL_OK) {
  stage="engine-action-or-wake";
  if(action==1 || action==2)s=(selector>UINT16_MAX || (action==1 && (!out || value)))?VZ_KERNEL_BAD_ARGUMENT:
   VM27GICDistributorRegV1(g->engine,(uint16_t)selector,action==2,value,&result);
  else if(action==3)s=selector>UINT32_MAX || value>1?VZ_KERNEL_BAD_ARGUMENT:
   VM27GICSetSPIV1(g->engine,(uint32_t)selector,value!=0);
  else if(action==4)s=value>UINT32_MAX?VZ_KERNEL_BAD_ARGUMENT:
   VM27GICSendMSIV1(g->engine,selector,(uint32_t)value);
  else if(action==5 && !selector && !value)s=VM27GICResetV1(g->engine);
  else s=VZ_KERNEL_BAD_ARGUMENT;
 }
 if(s==VZ_KERNEL_OK && action==1) {
  if(!GICFactoryOutputV15(out,sizeof(*out),true))s=VZ_KERNEL_BAD_ARGUMENT;else *out=result;
 }
 End(&vm->operation);return VM27GICVMResultV11(stage,action,selector,value,s);
}
