/* Called only inside the existing CPU operation and private post-return
 * token. Generic callbacks keep exactly the original per-field boundaries.
 * The concrete production group is local to this call, never cached in TLS. */
#include "modern_cpu_production_exit_snapshot_v22.h"
static bool RunPostReadValuesV77(RunPostAccessV7 *a,VZCPUNativeExitValuesV1 *values) {
 if(VM27ProductionOwnerBoundaryEligibleV21(&a->cpu->vm->ops)) {
  if(!RunPostOwnedV7(a))return false;
  VM27NativeExitSnapshotV22 snapshot=VM27ProductionExitSnapshotV22(a->cpu->nativeContext);
  if(snapshot.valid) {
   if(!RunPostOwnedV7(a))return false;
   values->rawReason=snapshot.reason;
   values->knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
   if(snapshot.reason==1 || snapshot.reason==6 || snapshot.reason==8) {
    values->syndrome32=snapshot.syndrome;
    values->virtualAddress=snapshot.virtualAddress;
    values->physicalAddress=snapshot.physicalAddress;
    values->knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
   }
   return true;
  }
 }
 if(!RunPostReadV7(a,0x4008,4,&values->rawReason))return false;
 values->knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
 if(values->rawReason==1 || values->rawReason==6 || values->rawReason==8) {
  if(!RunPostReadV7(a,0x400c,4,&values->syndrome32) ||
     !RunPostReadV7(a,0x4018,8,&values->virtualAddress) ||
     !RunPostReadV7(a,0x4020,8,&values->physicalAddress))return false;
  values->knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
 }
 return true;
}
