#include "modern_gic_v3_engine_v18_wake_subset.c"
#include "modern_gic_state_v1.h"

/* No pthread, pointer, native slot, VM epoch, borrow, callback or cache is saved.
 * uint32/64 fields make padding explicit and reject unknown format versions. */
typedef struct {
 uint64_t route;
 uint32_t flags,priority,activeCPU,reserved;
} GICIRQStateV1;
typedef struct {
 uint64_t affinity;
 uint32_t present,sleeping;
 GICIRQStateV1 irq[32];
 uint32_t pmr,bpr[2],group[2],eoiMode,commonBPR,activePriority[2],stackCount;
 uint32_t stack[32],stackPriority[32],stackGroup[32];
} GICCPUStateV1;
typedef struct {
 uint64_t magic,bytes,distributorBase,redistributorBase,msiBase;
 uint32_t version,maxCPUs,ipaBits,msiFirst,msiCount,msiConfigured,group[2];
 GICCPUStateV1 cpu[VM27_GIC_CPUS_V1];
 GICIRQStateV1 shared[VM27_GIC_INTIDS_V1-32];
} GICStateV1;
#define GIC_STATE_MAGIC_V1 UINT64_C(0x3153474337324d56)
size_t VM27GICStateBytesV1(void){return sizeof(GICStateV1);}
static GICIRQStateV1 IRQSaveV19(const GICInterrupt *i) {
 return (GICIRQStateV1){i->route,(i->group1?1u:0)|(i->enabled?2u:0)|
  (i->edge?4u:0)|(i->latched?8u:0)|(i->level?16u:0)|(i->active?32u:0),
  i->priority,i->activeCPU,0};
}
static bool IRQValidV19(const GICIRQStateV1 *i,const GICStateV1 *s) {
 return !(i->flags&~63u) && i->priority<=255 && !i->reserved &&
  (i->activeCPU==UINT32_MAX || (i->activeCPU<s->maxCPUs && s->cpu[i->activeCPU].present));
}
static GICInterrupt IRQLoadV19(const GICIRQStateV1 *i,const uint32_t *map) {
 return (GICInterrupt){.group1=(i->flags&1)!=0,.enabled=(i->flags&2)!=0,
  .edge=(i->flags&4)!=0,.latched=(i->flags&8)!=0,.level=(i->flags&16)!=0,
  .active=(i->flags&32)!=0,.priority=(uint8_t)i->priority,.route=i->route,
  .activeCPU=i->activeCPU==UINT32_MAX?UINT32_MAX:map[i->activeCPU]};
}
static bool StateValidV19(const GICStateV1 *s,VM27GICV3V1 *g,uint32_t *map) {
 if(s->magic!=GIC_STATE_MAGIC_V1 || s->version!=1 || s->bytes!=sizeof(*s) ||
  s->maxCPUs!=g->config.maxCPUs || s->ipaBits!=g->config.ipaBits ||
  s->distributorBase!=g->config.distributorBase || s->redistributorBase!=g->config.redistributorBase ||
  s->msiBase!=g->config.msiBase || s->msiFirst!=g->config.msiFirst ||
  s->msiCount!=g->config.msiCount || s->msiConfigured!=(uint32_t)g->config.msiConfigured ||
  s->group[0]>1 || s->group[1]>1)return false;
 uint64_t matched=0;
 for(uint32_t n=0;n<VM27_GIC_CPUS_V1;++n) {
  const GICCPUStateV1 *c=&s->cpu[n];map[n]=UINT32_MAX;
  if(c->present>1 || (n>=s->maxCPUs && c->present))return false;
  if(!c->present)continue;
  if(c->sleeping>1 || c->pmr>255 || c->bpr[0]>7 || c->bpr[1]>7 ||
   c->group[0]>1 || c->group[1]>1 || c->eoiMode>1 || c->commonBPR>1 || c->stackCount>32)return false;
  for(uint32_t j=0;j<g->config.maxCPUs;++j)if(g->cpus[j].attached && g->cpus[j].affinity==c->affinity) {
   if(map[n]!=UINT32_MAX || (matched&(UINT64_C(1)<<j)))return false;
   map[n]=j;matched|=UINT64_C(1)<<j;
  }
  if(map[n]==UINT32_MAX)return false;
  for(uint32_t j=0;j<32;++j)if(!IRQValidV19(&c->irq[j],s) ||
   (j<c->stackCount && (c->stack[j]>=VM27_GIC_INTIDS_V1 || c->stackPriority[j]>255 || c->stackGroup[j]>1)))return false;
 }
 for(uint32_t j=0;j<g->config.maxCPUs;++j)if(g->cpus[j].attached && !(matched&(UINT64_C(1)<<j)))return false;
 for(uint32_t j=0;j<VM27_GIC_INTIDS_V1-32;++j)if(!IRQValidV19(&s->shared[j],s))return false;
 return true;
}
VZKernelStatus VM27GICStateTransferV1(VM27GICV3V1 *g,void *data,size_t bytes,bool restore) {
 if(!g || bytes!=sizeof(GICStateV1) || !OutputGIC(g,data,bytes))return VZ_KERNEL_BAD_ARGUMENT;
 GICStateV1 *s=data;LockGIC(g);bool busy=g->callbacks!=0;
 for(uint32_t n=0;n<g->config.maxCPUs;++n)busy|=g->cpus[n].running || g->cpus[n].closing ||
  atomic_load_explicit(&g->cpus[n].callbacks,memory_order_acquire)!=0 || (restore && g->cpus[n].ran);
 if(busy){UnlockGIC(g);return VZ_KERNEL_BUSY;}
 uint32_t map[VM27_GIC_CPUS_V1];
 if(restore && !StateValidV19(s,g,map)){UnlockGIC(g);return VZ_KERNEL_BAD_ARGUMENT;}
 if(!restore) {
  memset(s,0,sizeof(*s));s->magic=GIC_STATE_MAGIC_V1;s->bytes=sizeof(*s);s->version=1;
  s->maxCPUs=g->config.maxCPUs;s->ipaBits=g->config.ipaBits;
  s->distributorBase=g->config.distributorBase;s->redistributorBase=g->config.redistributorBase;
  s->msiBase=g->config.msiBase;s->msiFirst=g->config.msiFirst;s->msiCount=g->config.msiCount;
  s->msiConfigured=g->config.msiConfigured;s->group[0]=g->groupEnabled[0];s->group[1]=g->groupEnabled[1];
  for(uint32_t n=0;n<g->config.maxCPUs;++n) {
   GICCPU *c=&g->cpus[n];GICCPUStateV1 *d=&s->cpu[n];if(!c->attached)continue;
   d->present=1;d->affinity=c->affinity;d->sleeping=c->sleeping;
   d->pmr=c->pmr;d->bpr[0]=c->bpr[0];d->bpr[1]=c->bpr[1];
   d->group[0]=c->groupEnabled[0];d->group[1]=c->groupEnabled[1];
   d->eoiMode=c->eoiMode;d->commonBPR=c->commonBPR;
   d->activePriority[0]=c->activePriority[0];d->activePriority[1]=c->activePriority[1];d->stackCount=c->stackCount;
   for(uint32_t j=0;j<32;++j){d->irq[j]=IRQSaveV19(&c->privateIRQ[j]);
    d->stack[j]=c->stack[j];d->stackPriority[j]=c->stackPriority[j];d->stackGroup[j]=c->stackGroup[j];}
  }
  for(uint32_t j=0;j<VM27_GIC_INTIDS_V1-32;++j)s->shared[j]=IRQSaveV19(&g->shared[j]);
 } else {
  InvalidateSnapshotsV13(g);g->groupEnabled[0]=s->group[0];g->groupEnabled[1]=s->group[1];
  memset(g->enabledShared,0,sizeof(g->enabledShared));
  for(uint32_t n=0;n<s->maxCPUs;++n) {
   GICCPUStateV1 *d=&s->cpu[n];if(!d->present)continue;GICCPU *c=&g->cpus[map[n]];
   c->sleeping=d->sleeping;c->pmr=(uint8_t)d->pmr;c->bpr[0]=(uint8_t)d->bpr[0];c->bpr[1]=(uint8_t)d->bpr[1];
   c->groupEnabled[0]=d->group[0];c->groupEnabled[1]=d->group[1];c->eoiMode=d->eoiMode;c->commonBPR=d->commonBPR;
   c->activePriority[0]=d->activePriority[0];c->activePriority[1]=d->activePriority[1];c->stackCount=d->stackCount;
   c->enabledPrivate=0;c->snapshotValid=false;InvalidateLocalSnapshotV16(g,c);
   for(uint32_t j=0;j<32;++j){c->privateIRQ[j]=IRQLoadV19(&d->irq[j],map);
    if(c->privateIRQ[j].enabled)c->enabledPrivate|=UINT32_C(1)<<j;
    c->stack[j]=d->stack[j];c->stackPriority[j]=(uint8_t)d->stackPriority[j];c->stackGroup[j]=d->stackGroup[j];}
  }
  for(uint32_t j=32;j<VM27_GIC_INTIDS_V1;++j){g->shared[j-32]=IRQLoadV19(&s->shared[j-32],map);
   if(g->shared[j-32].enabled)g->enabledShared[j/64]|=UINT64_C(1)<<(j&63);}
 }
 UnlockGIC(g);return VZ_KERNEL_OK;
}
