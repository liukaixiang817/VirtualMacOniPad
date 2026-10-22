/* One successful attachment already owns a real retained CPU borrow. Only its
 * recorded pthread can change its identity/attached/closing fields. Destroy
 * refuses attached CPUs and detach withdraws this TLS record before it starts.
 * Reuse that owner-thread lifetime for validation, not interrupt arbitration. */
#define VM27GICAttachCPUV1 VM27GICAttachOriginalV10
#define VM27GICDetachCPUV1 VM27GICDetachOriginalV10
#define VM27GICValidateTimerOwnerV1 VM27GICValidateOriginalV10
#include "modern_gic_v3_engine_v9_physical_batch.c"
#undef VM27GICAttachCPUV1
#undef VM27GICDetachCPUV1
#undef VM27GICValidateTimerOwnerV1

typedef struct {VM27GICV3V1 *g;GICCPU *cpu;} GICTimerOwnerV10;
static _Thread_local GICTimerOwnerV10 TimerOwnerV10;
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICAttachCPUV1(
 VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,uint64_t mpidr) {
 VZKernelStatus status=VM27GICAttachOriginalV10(g,q,mpidr);
 if(status==VZ_KERNEL_OK) {
  LockGIC(g);int slot=FindCPU(g,q,false);
  if(slot>=0 && g->cpus[slot].retainedCPU)TimerOwnerV10=(GICTimerOwnerV10){g,&g->cpus[slot]};
  UnlockGIC(g);
 }
 return status;
}
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDetachCPUV1(
 VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q) {
 /* Even BUSY or a failed release starts closing in the original detach.
  * Forget before that attempt; every failure keeps the original cleanup. */
 if(TimerOwnerV10.g==g)TimerOwnerV10=(GICTimerOwnerV10){0};
 return VM27GICDetachOriginalV10(g,q);
}
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICValidateTimerOwnerV1(
 void *owner,const VZKernelRunPendingRequestV14 *q) {
 VM27GICV3V1 *g=owner;GICCPU *c=TimerOwnerV10.cpu;
 if(g && q && TimerOwnerV10.g==g && c && c->attached && !c->closing && c->retainedCPU &&
    pthread_equal(c->owner,pthread_self()) && IdentityShape(q,g->config.vmEpoch) &&
    SameIdentity(q,&c->identity))return VZ_KERNEL_OK;
 /* Non-owning threads, other controllers, changed generations, and generic
  * fixtures retain the original locked lookup and its exact error result. */
 return VM27GICValidateOriginalV10(owner,q);
}
