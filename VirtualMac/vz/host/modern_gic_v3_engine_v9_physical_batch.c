#include "modern_gic_v3_engine_v8_owner_wake.c"
#include "modern_gic_physical_batch_v9.h"
VZKernelStatus VM27GICRouteAndDeadlineV9(void *owner,
 const VZKernelRunPendingRequestV14 *q,bool asserted,bool arm,uint64_t deadline,
 VM27GICPhysicalBoundaryV9 boundary,void *context,VM27GICPhysicalBatchResultV9 *out) {
 VM27GICV3V1 *g=owner;
 if(!g || !q || !boundary || !context || !OutputGIC(g,out,sizeof(*out)) ||
    !Separate(q,sizeof(*q),out,sizeof(*out)))return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICPhysicalBatchResultV9 r={0};
 LockGIC(g);int slot=FindCPU(g,q,false);
 if(slot<0){UnlockGIC(g);return VZ_KERNEL_NOT_LIVE;}
 GICCPU *c=&g->cpus[slot];GICInterrupt *i=&c->privateIRQ[VM27_GIC_PHYSICAL_TIMER_INTID_V1];
 if(i->edge && asserted && !i->level)i->latched=true;
 i->level=asserted;r.irq=Lines(g,(uint32_t)slot).irq;
 /* Pin before dropping the mutex. Closing/quiesce/destroy cannot release the
  * attachment while either the actual native boundary or scheduler runs. */
 ++g->callbacks;++c->callbacks;UnlockGIC(g);
 VZKernelStatus status=boundary(context);
 r.routeComplete=status==VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK) {
  r.deadlineAttempted=true;
  /* An owner-thread boundary can synchronously start its own detach.
   * Callback pins prevent reuse; only this same pthread can set closing on
   * an attached CPU, so this read cannot race a foreign owner. Preserve the
   * old deadline entry's closing rejection without another mutex round trip. */
  status=c->closing?VZ_KERNEL_NOT_LIVE:
      g->bindings.scheduleDeadline(g->bindings.context,q,arm,deadline);
 }
 LockGIC(g);--g->callbacks;--c->callbacks;
 if(r.deadlineAttempted && status==VZ_KERNEL_OK)c->deadlineQuiesced=false;
 UnlockGIC(g);*out=r;return status;
}
