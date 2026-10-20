#include "modern_cpu_kernel_lifecycle_v20.h"
#include "modern_cpu_kernel_lifecycle_v16.c"
#include "modern_cpu_kernel_physical_timer_v16.inc"
#include "modern_cpu_kernel_physical_timer_v19.inc"
#include "modern_cpu_kernel_wake_owner_v17.inc"
#include "modern_cpu_kernel_gic_owner_v20.inc"
#include "modern_cpu_kernel_vtimer_mask_v20.inc"
#include "modern_cpu_kernel_gic_run_v20.inc"
VZKernelStatus VZKernelCPUProducerPoisonV20(VZKernelCPU *cpu,const VZKernelRunPendingRequestV14 *q) {
 if(!cpu || !q)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus s=BeginCPUOperation(cpu);if(s==VZ_KERNEL_BUSY)return s;
 if(s==VZ_KERNEL_OK)s=CPUOwnedV5(cpu);
 if(s==VZ_KERNEL_OK && (q->schemaVersion!=1 || q->reserved ||
  q->expectedVMEpoch!=cpu->vm->generation || q->expectedCPUGeneration!=cpu->generation ||
  q->expectedOwnerThread!=cpu->owner || q->expectedPublicIdentity!=cpu->registryEntry->publicIdentity ||
  q->expectedReturnedSlotWord!=cpu->returnedSlot || q->nativeHVISA!=cpu->vm->nativeHVISA ||
  q->validatedKernelProfile!=cpu->vm->ops.validatedKernelProfile))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK)GICPoisonV20(cpu);
 EndOperation(&cpu->operationInProgress);return s;
}
