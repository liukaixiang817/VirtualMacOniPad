/* Bounded observations of existing Run receipts; no CPU/context accesses. */
#include <errno.h>
#include <stdio.h>
static unsigned VM27RunDiagnosticReserveV29(_Atomic unsigned *counter,unsigned limit) {
 unsigned sequence=atomic_load_explicit(counter,memory_order_relaxed);
 while(sequence<limit && !atomic_compare_exchange_weak_explicit(counter,&sequence,sequence+1,
  memory_order_relaxed,memory_order_relaxed)){}
 return sequence<limit?sequence+1:0;
}
static void VM27RunDiagnosticReceiptV31(const char *stage,unsigned sequence,
 const VZKernelRunPublicReceiptV20 *r,unsigned status,bool resume,uint64_t ticks) {
 if(!sequence)return;
 int saved=errno;const VZKernelRunStepReceiptV7 *step=&r->pending.step;
 uint32_t known=step->nativeValues.knownFields;
 if((known&VZ_CPU_EXIT_ALL_KNOWN_V1)==VZ_CPU_EXIT_ALL_KNOWN_V1) {
  dprintf(2,"[Independent27HV] run-receipt stage=%s ordinal=%u ticks=%llu status=0x%08x known=0x%x raw=0x%x ESR=0x%08x VA=0x%016llx PA=0x%016llx resume=%u publicProduced=%u publicReason=%u nativeInvoked=%u nativeReturn=0x%08x postIdentity=%u poison=%u withdrawn=%u token=%llu epoch=%llu generation=%llu owner=%llu mutation=%u ordinaryHVC=%u HVCX0Known=%u HVCX0=0x%016llx CPSRKnown=%u CPSR=0x%08x\n",
   stage,sequence,(unsigned long long)ticks,status,known,step->nativeValues.rawReason,step->nativeValues.syndrome32,
   (unsigned long long)step->nativeValues.virtualAddress,(unsigned long long)step->nativeValues.physicalAddress,
   resume,r->publicExitProduced,r->publicExitProduced?r->publicExit.reason:UINT32_MAX,
   step->lifecycle.nativeInvoked,(unsigned)step->lifecycle.nativeReturn,step->postReturnIdentityValidated,
   r->pending.mutationPoisoned,r->pending.identityWithdrawn,(unsigned long long)step->runToken,
   (unsigned long long)step->vmEpoch,(unsigned long long)step->cpuGeneration,(unsigned long long)step->ownerThread,
   r->runStateMutationAttempted,r->ordinaryHVCProduced,r->nativeHVCX0Read,
   (unsigned long long)(r->nativeHVCX0Read?r->nativeHVCX0:0),r->nativeHVCCPSRRead,
   r->nativeHVCCPSRRead?r->nativeHVCCPSR:0);
 }else if(known&VZ_CPU_EXIT_REASON_KNOWN_V1) {
  dprintf(2,"[Independent27HV] run-receipt stage=%s ordinal=%u ticks=%llu status=0x%08x known=0x%x raw=0x%x ESR=unknown VA=unknown PA=unknown resume=%u publicProduced=%u publicReason=%u nativeInvoked=%u nativeReturn=0x%08x postIdentity=%u poison=%u withdrawn=%u token=%llu\n",
   stage,sequence,(unsigned long long)ticks,status,known,step->nativeValues.rawReason,resume,r->publicExitProduced,
   r->publicExitProduced?r->publicExit.reason:UINT32_MAX,step->lifecycle.nativeInvoked,
   (unsigned)step->lifecycle.nativeReturn,step->postReturnIdentityValidated,r->pending.mutationPoisoned,
   r->pending.identityWithdrawn,(unsigned long long)step->runToken);
 }else {
  dprintf(2,"[Independent27HV] run-receipt stage=%s ordinal=%u ticks=%llu status=0x%08x known=0x%x raw=unknown ESR=unknown VA=unknown PA=unknown resume=%u publicProduced=%u publicReason=%u nativeInvoked=%u nativeReturn=0x%08x postIdentity=%u poison=%u withdrawn=%u\n",
   stage,sequence,(unsigned long long)ticks,status,known,resume,r->publicExitProduced,r->publicExitProduced?r->publicExit.reason:UINT32_MAX,
   step->lifecycle.nativeInvoked,(unsigned)step->lifecycle.nativeReturn,step->postReturnIdentityValidated,
   r->pending.mutationPoisoned,r->pending.identityWithdrawn);
 }
 errno=saved;
}
