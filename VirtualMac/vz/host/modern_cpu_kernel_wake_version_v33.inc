/* Replaces only WakeVersionV17 in the frozen lifecycle translation unit.
 * Exact concrete production owners may read under their existing mapping
 * lease. Every rejection retains the previous generic mapping/copy path. */
__attribute__((visibility("hidden"))) _Bool VM27ProductionWakeVersionReadV23(
 const VZKernelLifecycleOps *,const void *,uint64_t *);
static VZKernelStatus WakeVersionV17(VZKernelCPUWakeOwnerV17 *o) {
 VZKernelCPU *cpu=o->cpu;uint64_t version=0;
 VZKernelStatus s=WakeIdentityV17(o);if(s!=VZ_KERNEL_OK)return s;
 if(cpu->nativeContext>UINTPTR_MAX-0x4008)return VZ_KERNEL_CONTEXT_UNREADABLE;
 const void *address=(const void *)(cpu->nativeContext+0x4000);
 if(!VM27ProductionWakeVersionReadV23(&cpu->vm->ops,address,&version) &&
    (!VM27CPUSelfOwnedMappedRangeV1(address,8,0,((void *)0)) ||
     !cpu->vm->ops.readMemory(cpu->vm->ops.context,address,8,&version)))
  return VZ_KERNEL_CONTEXT_UNREADABLE;
 s=WakeIdentityV17(o);if(s!=VZ_KERNEL_OK)return s;
 return version==VZ_KERNEL_NATIVE_CONTEXT_VERSION?VZ_KERNEL_OK:VZ_KERNEL_CONTEXT_VERSION_MISMATCH;
}
