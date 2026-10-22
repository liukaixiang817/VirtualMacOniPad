/* Production21 remains whole. The same synchronous owner operation pins
 * this native6 mapping until native7. Read only the actual native9 exit
 * metadata, with current PID/epoch/version and permissions before/after.
 * No native call, write, client callback, shared mutex or retained snapshot. */
#include "modern_cpu_production_native_ops_v21_owner_boundary.c"
#include "modern_cpu_production_exit_snapshot_v22.h"
static bool ExitSnapshotOwnerV22(ProductionCPUV1 *cpu,
 const VM27OwnedNativeAdmissionV7 *a,uintptr_t context) {
 return cpu && a->token==(uintptr_t)cpu && a->context==context &&
  a->version==VZ_KERNEL_NATIVE_CONTEXT_VERSION && cpu->nativeContext==context &&
  cpu->live && cpu->usable && !cpu->destroying && !cpu->writeFailed &&
  pthread_equal(cpu->pthread,pthread_self());
}
VM27NativeExitSnapshotV22 VM27ProductionExitSnapshotV22(uintptr_t context) {
 VM27NativeExitSnapshotV22 r={0};VM27OwnedNativeAdmissionV7 a={0};
 if(!context || context>UINTPTR_MAX-0x4028 ||
    !VM27CPUOwnedNativeAdmissionV7(&a))return r;
 ProductionCPUV1 *cpu=(ProductionCPUV1 *)a.token;
 if(!ExitSnapshotOwnerV22(cpu,&a,context) ||
    !ContextRangeProductionV10(cpu,(void *)(context+0x4008),4,false))return r;
 VM27NativeExitSnapshotV22 staged={0};
 staged.reason=*(const volatile uint32_t *)(context+0x4008);
 if(staged.reason==1 || staged.reason==6 || staged.reason==8) {
  if(!ContextRangeProductionV10(cpu,(void *)(context+0x400c),4,false) ||
     !ContextRangeProductionV10(cpu,(void *)(context+0x4018),8,false) ||
     !ContextRangeProductionV10(cpu,(void *)(context+0x4020),8,false))return r;
  staged.syndrome=*(const volatile uint32_t *)(context+0x400c);
  staged.virtualAddress=*(const volatile uint64_t *)(context+0x4018);
  staged.physicalAddress=*(const volatile uint64_t *)(context+0x4020);
 }
 VM27OwnedNativeAdmissionV7 after={0};
 if(!VM27CPUOwnedNativeAdmissionV7(&after) ||
    !ExitSnapshotOwnerV22(cpu,&after,context))return r;
 staged.valid=true;return staged;
}
