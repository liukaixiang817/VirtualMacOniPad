/* Reason-only exits keep the original read path exactly. The preceding
 * successful reason read has just validated this private token/owner/version
 * after its actual memory load. Only concrete, callback-free detail reads
 * are grouped; the final post-return boundary remains in both callers. */
#include "modern_cpu_production_exit_snapshot_v22.h"
static bool RunPostReadValuesV78(RunPostAccessV7 *a,VZCPUNativeExitValuesV1 *values) {
 if(!RunPostReadV7(a,0x4008,4,&values->rawReason))return false;
 values->knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
 if(values->rawReason!=1 && values->rawReason!=6 && values->rawReason!=8)return true;
 if(VM27ProductionOwnerBoundaryEligibleV21(&a->cpu->vm->ops)) {
  VM27NativeExitSnapshotV22 snapshot=VM27ProductionExitSnapshotV22(a->cpu->nativeContext);
  if(snapshot.valid && snapshot.reason==values->rawReason) {
   if(!RunPostOwnedV7(a))return false;
   values->syndrome32=snapshot.syndrome;
   values->virtualAddress=snapshot.virtualAddress;
   values->physicalAddress=snapshot.physicalAddress;
   values->knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
   return true;
  }
 }
 if(!RunPostReadV7(a,0x400c,4,&values->syndrome32) ||
    !RunPostReadV7(a,0x4018,8,&values->virtualAddress) ||
    !RunPostReadV7(a,0x4020,8,&values->physicalAddress))return false;
 values->knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
 return true;
}
