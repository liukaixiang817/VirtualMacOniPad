#include "modern_gic_v3_engine_v2.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
 bool group1,enabled,edge,latched,level,active;
 uint8_t priority;
 uint64_t route;
 uint32_t activeCPU;
} GICInterrupt;
typedef struct {
 bool attached,closing,deadlineQuiesced,ran,running,sleeping;
 pthread_t owner;
 VZKernelRunPendingRequestV14 identity;
 void *retainedCPU;
 uint64_t affinity;
 GICInterrupt privateIRQ[32];
 uint8_t pmr,bpr[2];
 bool groupEnabled[2],eoiMode,commonBPR;
 uint32_t activePriority[2];
 uint32_t stack[32],stackCount;
 uint8_t stackPriority[32];
 bool stackGroup[32];
 uint32_t callbacks;
} GICCPU;
struct VM27GICV3V1 {
 pthread_mutex_t mutex;
 VM27GICConfigV1 config;
 VM27GICBindingsV1 bindings;
 GICCPU cpus[VM27_GIC_CPUS_V1];
 GICInterrupt shared[VM27_GIC_INTIDS_V1-32];
 bool groupEnabled[2],topologyFinal;
 uint32_t callbacks;
};
static void LockGIC(VM27GICV3V1 *g) {if(pthread_mutex_lock(&g->mutex))abort();}
static void UnlockGIC(VM27GICV3V1 *g) {if(pthread_mutex_unlock(&g->mutex))abort();}
static bool Separate(const void *a,size_t an,const void *b,size_t bn) {
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 return x && y && an<=UINTPTR_MAX-x && bn<=UINTPTR_MAX-y && (x+an<=y || y+bn<=x);
}
static bool OutputGIC(VM27GICV3V1 *g,const void *p,size_t n) {
 return p && n && n<=UINTPTR_MAX-(uintptr_t)p && Separate(p,n,g,sizeof(*g));
}
bool VM27GICOutputRangeDisjointV1(VM27GICV3V1 *g,const void *p,size_t bytes) {
 return g && OutputGIC(g,p,bytes);
}
static bool IdentityShape(const VZKernelRunPendingRequestV14 *q,uint64_t epoch) {
 return q && q->schemaVersion==1 && q->validatedKernelProfile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  (q->nativeHVISA==1 || q->nativeHVISA==2) && !q->reserved && q->expectedVMEpoch==epoch &&
  q->expectedPublicIdentity && q->expectedOwnerThread && q->expectedCPUGeneration;
}
static bool SameIdentity(const VZKernelRunPendingRequestV14 *a,const VZKernelRunPendingRequestV14 *b) {
 return a->schemaVersion==b->schemaVersion && a->validatedKernelProfile==b->validatedKernelProfile &&
  a->nativeHVISA==b->nativeHVISA && a->reserved==b->reserved && a->expectedVMEpoch==b->expectedVMEpoch &&
  a->expectedPublicIdentity==b->expectedPublicIdentity && a->expectedOwnerThread==b->expectedOwnerThread &&
  a->expectedCPUGeneration==b->expectedCPUGeneration && a->expectedReturnedSlotWord==b->expectedReturnedSlotWord;
}
static uint64_t Affinity(uint64_t mpidr) {return mpidr&UINT64_C(0xff00ffffff);}
static uint32_t PackedAffinity(uint64_t affinity) {
 return (uint32_t)(affinity&UINT64_C(0xffffff))|(uint32_t)((affinity>>8)&UINT64_C(0xff000000));
}
static int FindCPU(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,bool closing) {
 if(!IdentityShape(q,g->config.vmEpoch))return -1;
 for(uint32_t i=0;i<g->config.maxCPUs;++i) {
  GICCPU *c=&g->cpus[i];
  if(c->attached && SameIdentity(q,&c->identity) && (closing || !c->closing) &&
   pthread_equal(c->owner,pthread_self()))return (int)i;
 }
 return -1;
}
static GICInterrupt *Interrupt(VM27GICV3V1 *g,uint32_t cpu,uint32_t id) {
 return id<32?&g->cpus[cpu].privateIRQ[id]:id<VM27_GIC_INTIDS_V1?&g->shared[id-32]:NULL;
}
static bool Pending(const GICInterrupt *i) {return i->latched || (!i->edge && i->level);}
static uint8_t GroupPriority(uint8_t priority,uint8_t bpr) {
 unsigned bits=(unsigned)bpr+1;return bits>=8?0:(uint8_t)(priority&~((1u<<bits)-1u));
}
static uint8_t RunningPriority(GICCPU *c) {
 uint8_t priority=UINT8_MAX;
 uint32_t bits=c->activePriority[0]|c->activePriority[1];
 for(uint32_t n=0;n<32;++n)if(bits&(UINT32_C(1)<<n)){priority=(uint8_t)(n<<3);break;}
 for(uint32_t n=0;n<c->stackCount;++n)if(c->stackPriority[n]<priority)priority=c->stackPriority[n];
 return priority;
}
static bool RouteMatches(VM27GICV3V1 *g,uint32_t cpu,GICInterrupt *i) {
 if(i->route&(UINT64_C(1)<<31)) {
  // IRM selects one eligible awake redistributor, deterministically. It never
  // fans a shared active interrupt out to all CPUs.
  for(uint32_t n=0;n<g->config.maxCPUs;++n)if(g->cpus[n].attached && !g->cpus[n].closing &&
   !g->cpus[n].sleeping)return n==cpu;
  return false;
 }
 return Affinity(i->route)==g->cpus[cpu].affinity;
}
static uint32_t Highest(VM27GICV3V1 *g,uint32_t cpu,bool group1) {
 GICCPU *c=&g->cpus[cpu];uint32_t best=1023;uint8_t priority=UINT8_MAX;
 if(c->closing || c->sleeping || !g->groupEnabled[group1] || !c->groupEnabled[group1])return best;
 uint8_t running=RunningPriority(c);
 for(uint32_t id=0;id<VM27_GIC_INTIDS_V1;++id) {
  GICInterrupt *i=Interrupt(g,cpu,id);
  if(i->group1!=group1 || !i->enabled || i->active || !Pending(i) ||
   i->priority>=c->pmr || (id>=32 && !RouteMatches(g,cpu,i)))continue;
  uint8_t bpr=c->bpr[group1 && !c->commonBPR];
  if(running!=UINT8_MAX && GroupPriority(i->priority,bpr)>=GroupPriority(running,bpr))continue;
  if(best==1023 || i->priority<priority){best=id;priority=i->priority;}
 }
 return best;
}
static VM27GICLinesV1 Lines(VM27GICV3V1 *g,uint32_t cpu) {
 uint32_t g0=Highest(g,cpu,false),g1=Highest(g,cpu,true);
 return (VM27GICLinesV1){g1!=1023,g0!=1023,g0,g1};
}
static VZKernelStatus WakeAttached(VM27GICV3V1 *g) {
 // Callback pins the allocation and attachment while the mutex is dropped.
 // Cross-thread sources cannot release an owner's retained borrow.
 VZKernelStatus first=VZ_KERNEL_OK;
 for(uint32_t n=0;n<g->config.maxCPUs;++n) {
  LockGIC(g);GICCPU *c=&g->cpus[n];
  bool notify=c->attached && !c->closing && (Lines(g,n).irq || Lines(g,n).fiq);
  VZKernelRunPendingRequestV14 q=c->identity;
  if(notify){++g->callbacks;++c->callbacks;}
  UnlockGIC(g);
  if(!notify)continue;
  VZKernelStatus status=g->bindings.wakeCPU(g->bindings.context,&q);
  LockGIC(g);--g->callbacks;--c->callbacks;UnlockGIC(g);
  if(first==VZ_KERNEL_OK && status!=VZ_KERNEL_OK)first=status;
 }
 return first;
}
static bool Region(uint64_t base,uint64_t bytes,uint32_t ipaBits) {
 uint64_t end=UINT64_C(1)<<ipaBits;
 return !(base&(UINT64_C(0xffff))) && base<end && bytes<=end-base;
}
static bool Nonoverlap(uint64_t a,uint64_t an,uint64_t b,uint64_t bn) {return a+an<=b || b+bn<=a;}
VZKernelStatus VM27GICCreateV1(const VM27GICConfigV1 *input,const VM27GICBindingsV1 *bindings,
 VM27GICV3V1 **out) {
 if(!input || !bindings || !out || !Separate(input,sizeof(*input),bindings,sizeof(*bindings)) ||
  !Separate(out,sizeof(*out),input,sizeof(*input)) || !Separate(out,sizeof(*out),bindings,sizeof(*bindings)))
  return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICConfigV1 c=*input;VM27GICBindingsV1 b=*bindings;
 uint64_t redistBytes=(uint64_t)c.maxCPUs*VM27_GIC_REDIST_BYTES_V1;
 if(c.schemaVersion!=1 || c.reserved || !c.vmEpoch || !c.maxCPUs || c.maxCPUs>VM27_GIC_CPUS_V1 ||
  c.ipaBits!=36 || !Region(c.distributorBase,VM27_GIC_DIST_BYTES_V1,c.ipaBits) ||
  (c.redistributorBase&(VM27_GIC_REDIST_ALIGNMENT_V2-1)) || !Region(c.redistributorBase,redistBytes,c.ipaBits) ||
  !Nonoverlap(c.distributorBase,VM27_GIC_DIST_BYTES_V1,c.redistributorBase,redistBytes) ||
  !b.retainCPU || !b.releaseCPU || !b.wakeCPU || !b.scheduleDeadline || !b.drainDeadline)
  return VZ_KERNEL_BAD_ARGUMENT;
 if(c.msiConfigured) {
  if(!c.msiCount || c.msiFirst<32 || c.msiFirst>=VM27_GIC_INTIDS_V1 ||
   c.msiCount>VM27_GIC_INTIDS_V1-c.msiFirst || !Region(c.msiBase,VM27_GIC_MSI_BYTES_V1,c.ipaBits) ||
   !Nonoverlap(c.msiBase,VM27_GIC_MSI_BYTES_V1,c.distributorBase,VM27_GIC_DIST_BYTES_V1) ||
   !Nonoverlap(c.msiBase,VM27_GIC_MSI_BYTES_V1,c.redistributorBase,redistBytes))return VZ_KERNEL_BAD_ARGUMENT;
 } else if(c.msiBase || c.msiFirst || c.msiCount)return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICV3V1 *g=calloc(1,sizeof(*g));if(!g)return VZ_KERNEL_OUT_OF_MEMORY;
 if(pthread_mutex_init(&g->mutex,NULL)){free(g);return VZ_KERNEL_OUT_OF_MEMORY;}
 g->config=c;g->bindings=b;
 for(uint32_t i=0;i<VM27_GIC_INTIDS_V1-32;++i){g->shared[i].priority=0x80;g->shared[i].activeCPU=UINT32_MAX;}
 *out=g;return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICDestroyV1(VM27GICV3V1 *g) {
 if(!g)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);bool busy=g->callbacks!=0;
 for(uint32_t i=0;i<g->config.maxCPUs;++i)busy|=g->cpus[i].attached;
 UnlockGIC(g);if(busy)return VZ_KERNEL_BUSY;
 if(pthread_mutex_destroy(&g->mutex))return VZ_KERNEL_BUSY;
 memset(g,0,sizeof(*g));free(g);return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICAttachCPUV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *input,uint64_t mpidr) {
 if(!g || !input || !OutputGIC(g,input,sizeof(*input)))return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelRunPendingRequestV14 q=*input;
 if(!IdentityShape(&q,g->config.vmEpoch))return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int freeSlot=-1;bool busy=g->topologyFinal;
 for(uint32_t n=0;n<g->config.maxCPUs;++n) {
  if(!g->cpus[n].attached && freeSlot<0)freeSlot=(int)n;
  if(g->cpus[n].attached && g->cpus[n].identity.expectedPublicIdentity==q.expectedPublicIdentity)busy=true;
 }
 if(busy || freeSlot<0){UnlockGIC(g);return VZ_KERNEL_BUSY;}
 // Reserve before calling into the actual factory, so synchronous reentry
 // cannot publish a duplicate or make teardown free this allocation.
 GICCPU *cpu=&g->cpus[freeSlot];cpu->attached=true;cpu->closing=true;
 cpu->identity=q;cpu->affinity=Affinity(mpidr);cpu->owner=pthread_self();
 ++g->callbacks;++cpu->callbacks;UnlockGIC(g);
 void *retained=NULL;VZKernelStatus status=g->bindings.retainCPU(g->bindings.context,&q,&retained);
 LockGIC(g);--g->callbacks;--cpu->callbacks;
 if(status==VZ_KERNEL_OK && !retained)status=VZ_KERNEL_NOT_LIVE;
 if(status!=VZ_KERNEL_OK) {
  // A failed retain that produced a cleanup handle is never silently freed.
  if(retained)cpu->retainedCPU=retained;else memset(cpu,0,sizeof(*cpu));
  UnlockGIC(g);return status;
 }
 cpu->retainedCPU=retained;cpu->closing=false;cpu->pmr=0;cpu->bpr[0]=cpu->bpr[1]=2;
 for(uint32_t n=0;n<32;++n){cpu->privateIRQ[n].priority=0x80;cpu->privateIRQ[n].edge=n<16;
  cpu->privateIRQ[n].activeCPU=UINT32_MAX;}
 UnlockGIC(g);return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICSetAffinityV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,uint64_t mpidr) {
 if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);VZKernelStatus status=slot<0?VZ_KERNEL_NOT_LIVE:
  g->topologyFinal && g->cpus[slot].affinity!=Affinity(mpidr)?VZ_KERNEL_BUSY:VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK) {
  // CPU creation may precede the caller's real MPIDR setter. Duplicate reset
  // affinities are temporary and are rejected before any guest execution.
  // Rewriting the same real MPIDR during restore preserves final topology.
  g->cpus[slot].affinity=Affinity(mpidr);
 }
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICBeginRunV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q) {
 if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);VZKernelStatus status=slot<0?VZ_KERNEL_NOT_LIVE:
  g->cpus[slot].running?VZ_KERNEL_BUSY:VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK) {
  for(uint32_t n=0;n<g->config.maxCPUs;++n)if(g->cpus[n].attached && !g->cpus[n].closing)
   for(uint32_t m=n+1;m<g->config.maxCPUs;++m)if(g->cpus[m].attached && !g->cpus[m].closing &&
    g->cpus[n].affinity==g->cpus[m].affinity)status=VZ_KERNEL_BAD_ARGUMENT;
  if(status==VZ_KERNEL_OK){g->topologyFinal=true;g->cpus[slot].ran=true;g->cpus[slot].running=true;}
 }
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICEndRunV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q) {
 if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,true);VZKernelStatus status=slot<0?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK)g->cpus[slot].running=false;
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICResetV1(VM27GICV3V1 *g) {
 if(!g)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);bool busy=g->callbacks!=0;
 for(uint32_t n=0;n<g->config.maxCPUs;++n)busy|=g->cpus[n].running;
 if(busy){UnlockGIC(g);return VZ_KERNEL_BUSY;}
 g->groupEnabled[0]=g->groupEnabled[1]=false;
 for(uint32_t n=0;n<VM27_GIC_INTIDS_V1-32;++n) {
  g->shared[n]=(GICInterrupt){.priority=0x80,.activeCPU=UINT32_MAX};
 }
 for(uint32_t n=0;n<g->config.maxCPUs;++n) {
  GICCPU *c=&g->cpus[n];if(!c->attached)continue;
  c->sleeping=false;c->pmr=0;c->bpr[0]=c->bpr[1]=2;
  c->groupEnabled[0]=c->groupEnabled[1]=c->eoiMode=c->commonBPR=false;
  c->stackCount=0;c->activePriority[0]=c->activePriority[1]=0;
  memset(c->stack,0,sizeof(c->stack));memset(c->stackPriority,0,sizeof(c->stackPriority));
  memset(c->stackGroup,0,sizeof(c->stackGroup));
  for(uint32_t i=0;i<32;++i)c->privateIRQ[i]=(GICInterrupt){.edge=i<16,.priority=0x80,.activeCPU=UINT32_MAX};
 }
 UnlockGIC(g);return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICGetLinesV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,VM27GICLinesV1 *out) {
 if(!g || !q || !OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);VZKernelStatus status=slot<0?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK)*out=Lines(g,(uint32_t)slot);
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICValidateTimerOwnerV1(void *owner,const VZKernelRunPendingRequestV14 *q) {
 VM27GICV3V1 *g=owner;if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);bool valid=FindCPU(g,q,false)>=0;UnlockGIC(g);return valid?VZ_KERNEL_OK:VZ_KERNEL_NOT_LIVE;
}
VZKernelStatus VM27GICRoutePhysicalTimerV1(void *owner,const VZKernelRunPendingRequestV14 *q,
 bool asserted,bool *out) {
 VM27GICV3V1 *g=owner;
 if(!g || !q || !OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);VZKernelStatus status=slot<0?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
 if(status==VZ_KERNEL_OK) {
  GICInterrupt *i=&g->cpus[slot].privateIRQ[VM27_GIC_PHYSICAL_TIMER_INTID_V1];
  if(i->edge && asserted && !i->level)i->latched=true;
  i->level=asserted;*out=Lines(g,(uint32_t)slot).irq;
 }
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICUpdatePhysicalDeadlineV1(void *owner,const VZKernelRunPendingRequestV14 *q,
 bool arm,uint64_t deadline) {
 VM27GICV3V1 *g=owner;if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);
 if(slot<0){UnlockGIC(g);return VZ_KERNEL_NOT_LIVE;}
 GICCPU *c=&g->cpus[slot];++g->callbacks;++c->callbacks;UnlockGIC(g);
 VZKernelStatus status=g->bindings.scheduleDeadline(g->bindings.context,q,arm,deadline);
 LockGIC(g);--g->callbacks;--c->callbacks;if(status==VZ_KERNEL_OK)c->deadlineQuiesced=false;
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICQuiescePhysicalTimerV1(void *owner,const VZKernelRunPendingRequestV14 *q) {
 VM27GICV3V1 *g=owner;if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,true);
 if(slot<0){UnlockGIC(g);return VZ_KERNEL_NOT_LIVE;}
 GICCPU *c=&g->cpus[slot];if(c->callbacks){UnlockGIC(g);return VZ_KERNEL_BUSY;}
 if(c->deadlineQuiesced){UnlockGIC(g);return VZ_KERNEL_OK;}
 ++g->callbacks;++c->callbacks;UnlockGIC(g);
 VZKernelStatus status=g->bindings.drainDeadline(g->bindings.context,q);
 LockGIC(g);--g->callbacks;--c->callbacks;
 if(status==VZ_KERNEL_OK){c->deadlineQuiesced=true;GICInterrupt *i=&c->privateIRQ[30];i->level=false;i->latched=false;}
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICDetachCPUV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q) {
 if(!g || !q)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,true);
 if(slot<0){UnlockGIC(g);return VZ_KERNEL_NOT_LIVE;}
 GICCPU *c=&g->cpus[slot];c->closing=true;
 if(c->callbacks || c->running){UnlockGIC(g);return VZ_KERNEL_BUSY;}
 UnlockGIC(g);VZKernelStatus status=VM27GICQuiescePhysicalTimerV1(g,q);
 if(status!=VZ_KERNEL_OK)return status;
 LockGIC(g);if(c->callbacks){UnlockGIC(g);return VZ_KERNEL_BUSY;}
 void *token=c->retainedCPU;++g->callbacks;++c->callbacks;UnlockGIC(g);
 status=token?g->bindings.releaseCPU(g->bindings.context,token):VZ_KERNEL_OK;
 LockGIC(g);--g->callbacks;--c->callbacks;
 if(status==VZ_KERNEL_OK) {
  for(uint32_t i=0;i<VM27_GIC_INTIDS_V1-32;++i)if(g->shared[i].active && g->shared[i].activeCPU==(uint32_t)slot)
   {g->shared[i].active=false;g->shared[i].activeCPU=UINT32_MAX;}
  memset(c,0,sizeof(*c));
 }
 UnlockGIC(g);return status;
}
VZKernelStatus VM27GICSetSPIV1(VM27GICV3V1 *g,uint32_t id,bool level) {
 if(!g || id<32 || id>=VM27_GIC_INTIDS_V1)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);
 if(g->config.msiConfigured && id>=g->config.msiFirst && id-g->config.msiFirst<g->config.msiCount)
  {UnlockGIC(g);return VZ_KERNEL_BAD_ARGUMENT;}
 GICInterrupt *i=&g->shared[id-32];
 // The public SPI API defines each true call as an edge for an edge source.
 if(i->edge){if(level)i->latched=true;}else i->level=level;
 UnlockGIC(g);return WakeAttached(g);
}
VZKernelStatus VM27GICSendMSIV1(VM27GICV3V1 *g,uint64_t address,uint32_t id) {
 if(!g)return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);bool valid=g->config.msiConfigured && address==g->config.msiBase+0x40 &&
  id>=g->config.msiFirst && id-g->config.msiFirst<g->config.msiCount;
 if(valid)g->shared[id-32].latched=true;
 UnlockGIC(g);return valid?WakeAttached(g):VZ_KERNEL_BAD_ARGUMENT;
}

static bool ArrayRegister(VM27GICV3V1 *g,uint32_t cpu,uint64_t offset,uint32_t bytes,
 bool write,uint64_t value,uint64_t *out,bool privateOnly) {
 uint32_t start=0,count=0,kind=0;uint64_t base=0;
 static const uint32_t bases[]={0x80,0x100,0x180,0x200,0x280,0x300,0x380};
 for(unsigned k=0;k<sizeof(bases)/sizeof(bases[0]);++k) {
  if(offset>=bases[k] && offset<bases[k]+(privateOnly?4u:128u)) {
   if(bytes!=4 || (offset&3))return false;
   start=(uint32_t)(offset-bases[k])*8;count=32;kind=k+1;base=bases[k];break;
  }
 }
 if(offset>=0x400 && offset<(privateOnly?0x420u:0x800u)) {
  if(bytes>8 || (offset&(bytes-1)))return false;
  start=(uint32_t)(offset-0x400);count=bytes;kind=8;
 } else if(offset>=0xc00 && offset<(privateOnly?0xc08u:0xd00u)) {
  if(bytes!=4 || (offset&3))return false;
  start=(uint32_t)(offset-0xc00)*4;count=16;kind=9;
 }
 if(!kind)return false;
 uint64_t result=0;
 for(uint32_t n=0;n<count;++n) {
  uint32_t id=start+n;
  if(id>=VM27_GIC_INTIDS_V1 || (privateOnly?id>=32:id<32))continue;
  GICInterrupt *i=Interrupt(g,cpu,id);
  if(kind==8) {
   if(write)i->priority=(uint8_t)(value>>(n*8))&0xf8;
   else result|=(uint64_t)i->priority<<(n*8);
  } else if(kind==9) {
   if(write && id>=16)i->edge=((value>>(n*2))&2)!=0;
   else if(!write && i->edge)result|=UINT64_C(2)<<(n*2);
  } else {
   bool set=((value>>n)&1)!=0;
   if(!write) {
    bool bit=kind==1?i->group1:kind==2 || kind==3?i->enabled:
     kind==4 || kind==5?Pending(i):i->active;
    if(bit)result|=UINT64_C(1)<<n;
   } else if(kind==1)i->group1=set;
   else if(set) {
    if(kind==2 || kind==3)i->enabled=kind==2;
    else if(kind==4 || kind==5)i->latched=kind==4;
    else {i->active=kind==6;i->activeCPU=kind==6?cpu:UINT32_MAX;}
   }
  }
 }
 (void)base;if(!write)*out=result;return true;
}
static bool Distributor(VM27GICV3V1 *g,uint32_t cpu,uint64_t offset,uint32_t bytes,
 bool write,uint64_t value,uint64_t *out) {
 if(ArrayRegister(g,cpu,offset,bytes,write,value,out,false))return true;
 if(offset>=0x6100 && offset<0x6000+VM27_GIC_INTIDS_V1*8u && !(offset&7) && bytes==8) {
  uint32_t id=(uint32_t)((offset-0x6000)/8);GICInterrupt *i=&g->shared[id-32];
  if(write)i->route=value&UINT64_C(0xff80ffffff);else *out=i->route;return true;
 }
 if(bytes!=4 || (offset&3))return false;
 if(offset==0) {
  if(write){g->groupEnabled[0]=(value&1)!=0;g->groupEnabled[1]=(value&2)!=0;}
  else *out=UINT64_C(0x60)|(g->groupEnabled[0]?1:0)|(g->groupEnabled[1]?2:0);
 } else if(offset==4) {
  if(!write)*out=UINT64_C(31)|(UINT64_C(9)<<19)|(UINT64_C(1)<<24);
 } else if(offset==8 || offset==0xc || offset==0x10 || offset==0xffd0 || offset==0xffd4 ||
  offset==0xffd8 || offset==0xffdc || offset==0xffe0 || offset==0xffe4 || offset==0xffec ||
  offset==0xfff0 || offset==0xfff4 || offset==0xfff8 || offset==0xfffc) {
  if(!write)*out=0;
 } else if(offset==0xffe8){if(!write)*out=0x30;}
 else if((offset>=0xd00 && offset<0xd80) || (offset>=0xe00 && offset<0xe80)) {
  // Single security state: group modifier/NS access registers are RAZ/WI.
  if(!write)*out=0;
 } else return false;
 return true;
}
static bool Redistributor(VM27GICV3V1 *g,uint32_t cpu,uint64_t offset,uint32_t bytes,
 bool write,uint64_t value,uint64_t *out) {
 GICCPU *c=&g->cpus[cpu];if(!c->attached || c->closing)return false;
 if(offset>=0x10000)return ArrayRegister(g,cpu,offset-0x10000,bytes,write,value,out,true) ||
  (((offset>=0x10d00 && offset<0x10d80) || (offset>=0x10e00 && offset<0x10e80)) &&
   bytes==4 && !(offset&3) && (write || (*out=0,true)));
 if(offset==8 && bytes==8) {
  uint32_t last=cpu;
  for(uint32_t n=cpu+1;n<g->config.maxCPUs;++n)if(g->cpus[n].attached)last=n;
  if(!write)*out=((uint64_t)PackedAffinity(c->affinity)<<32)|((uint64_t)cpu<<8)|
   (cpu==last?UINT64_C(1)<<4:0);
  return true;
 }
 if(bytes!=4 || (offset&3))return false;
 if(offset==0x14) {
  if(write)c->sleeping=(value&2)!=0;
  else *out=c->sleeping?6:0;
 } else if(offset==0 || offset==4 || offset==0x10 || offset==0xffd0 || offset==0xffd4 ||
  offset==0xffd8 || offset==0xffdc || offset==0xffe0 || offset==0xffe4 || offset==0xffec ||
  offset==0xfff0 || offset==0xfff4 || offset==0xfff8 || offset==0xfffc) {
  if(!write)*out=0;
 } else if(offset==0xffe8){if(!write)*out=0x30;}
 else return false;
 return true;
}
static VZKernelStatus MMIOEffect(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint64_t ipa,uint32_t bytes,bool write,uint64_t value,uint64_t *out,bool *committed) {
 if(!g || !q || (!write && (!OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))) ||
  (bytes!=1 && bytes!=2 && bytes!=4 && bytes!=8) || (ipa&(bytes-1)))return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);
 if(slot<0){UnlockGIC(g);return VZ_KERNEL_NOT_LIVE;}
 bool handled=false;uint64_t result=0;
 if(ipa>=g->config.distributorBase && ipa-g->config.distributorBase<VM27_GIC_DIST_BYTES_V1 &&
  bytes<=VM27_GIC_DIST_BYTES_V1-(ipa-g->config.distributorBase))
  handled=Distributor(g,(uint32_t)slot,ipa-g->config.distributorBase,bytes,write,value,&result);
 else if(ipa>=g->config.redistributorBase && ipa-g->config.redistributorBase<
  (uint64_t)g->config.maxCPUs*VM27_GIC_REDIST_BYTES_V1) {
  uint64_t delta=ipa-g->config.redistributorBase;
  handled=Redistributor(g,(uint32_t)(delta/VM27_GIC_REDIST_BYTES_V1),delta%VM27_GIC_REDIST_BYTES_V1,
   bytes,write,value,&result);
 } else if(g->config.msiConfigured && ipa>=g->config.msiBase &&
  ipa-g->config.msiBase<VM27_GIC_MSI_BYTES_V1 && bytes==4) {
  uint64_t offset=ipa-g->config.msiBase;
  if(offset==8){handled=true;result=((uint64_t)g->config.msiFirst<<16)|g->config.msiCount;}
  else if(offset==0x40 && write && !(value>>32) && value>=g->config.msiFirst &&
   value-g->config.msiFirst<g->config.msiCount){g->shared[value-32].latched=true;handled=true;}
 }
 if(handled && !write)*out=result;
 if(handled && committed)*committed=write;
 UnlockGIC(g);if(!handled)return VZ_KERNEL_UNSUPPORTED;
 return write?WakeAttached(g):VZ_KERNEL_OK;
}
VZKernelStatus VM27GICMMIOV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint64_t ipa,uint32_t bytes,bool write,uint64_t value,uint64_t *out) {
 return MMIOEffect(g,q,ipa,bytes,write,value,out,NULL);
}
VZKernelStatus VM27GICDistributorRegV1(VM27GICV3V1 *g,uint16_t reg,bool write,uint64_t value,uint64_t *out) {
 if(!g || (!write && !OutputGIC(g,out,sizeof(*out))))return VZ_KERNEL_BAD_ARGUMENT;
 uint32_t bytes=reg>=0x6100 && reg<0x6000+VM27_GIC_INTIDS_V1*8u?8:4;
 LockGIC(g);uint64_t result=0;bool handled=Distributor(g,0,reg,bytes,write,value,&result);
 if(handled && !write)*out=result;
 UnlockGIC(g);return !handled?VZ_KERNEL_UNSUPPORTED:write?WakeAttached(g):VZ_KERNEL_OK;
}
VZKernelStatus VM27GICRedistributorRegV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint32_t reg,bool write,uint64_t value,uint64_t *out) {
 if(!g || !q || (!write && (!OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))))
  return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);bool handled=false;uint64_t result=0;
 if(slot>=0)handled=Redistributor(g,(uint32_t)slot,reg,reg==8?8:4,write,value,&result);
 if(handled && !write)*out=result;
 UnlockGIC(g);return slot<0?VZ_KERNEL_NOT_LIVE:!handled?VZ_KERNEL_UNSUPPORTED:
  write?WakeAttached(g):VZ_KERNEL_OK;
}
VZKernelStatus VM27GICRedistributorBaseV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,uint64_t *out) {
 if(!g || !q || !OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))
  return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);
 if(slot>=0)*out=g->config.redistributorBase+(uint64_t)slot*VM27_GIC_REDIST_BYTES_V1;
 UnlockGIC(g);return slot<0?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
}
static VZKernelStatus Acknowledge(VM27GICV3V1 *g,uint32_t cpu,bool group1,uint64_t *out) {
 GICCPU *c=&g->cpus[cpu];uint32_t id=Highest(g,cpu,group1);
 if(id==1023){*out=id;return VZ_KERNEL_OK;}
 if(c->stackCount>=32)return VZ_KERNEL_UNSUPPORTED;
 GICInterrupt *i=Interrupt(g,cpu,id);i->latched=false;i->active=true;i->activeCPU=cpu;
 c->activePriority[group1]|=UINT32_C(1)<<(i->priority>>3);
 c->stack[c->stackCount]=id;c->stackPriority[c->stackCount]=i->priority;
 c->stackGroup[c->stackCount]=group1;++c->stackCount;*out=id;return VZ_KERNEL_OK;
}
static VZKernelStatus EndInterrupt(VM27GICV3V1 *g,uint32_t cpu,bool group1,uint64_t value) {
 uint32_t id=(uint32_t)(value&0xffffff);if(id>=1020 && id<=1023)return VZ_KERNEL_OK;
 if(value>>24 || id>=VM27_GIC_INTIDS_V1)return VZ_KERNEL_BAD_ARGUMENT;
 GICCPU *c=&g->cpus[cpu];
 if(!c->stackCount || c->stack[c->stackCount-1]!=id || c->stackGroup[c->stackCount-1]!=group1)
  return VZ_KERNEL_BAD_ARGUMENT;
 c->activePriority[group1]&=~(UINT32_C(1)<<(c->stackPriority[c->stackCount-1]>>3));
 --c->stackCount;
 if(!c->eoiMode){GICInterrupt *i=Interrupt(g,cpu,id);i->active=false;i->activeCPU=UINT32_MAX;}
 return VZ_KERNEL_OK;
}
static VZKernelStatus GenerateSGI(VM27GICV3V1 *g,uint32_t source,uint64_t value,bool group1) {
 uint32_t id=(uint32_t)((value>>24)&15);bool irm=(value&(UINT64_C(1)<<40))!=0;
 uint8_t aff1=(uint8_t)(value>>16),aff2=(uint8_t)(value>>32),aff3=(uint8_t)(value>>48);
 // RSS is not advertised; a nonzero range selector is refused.
 if(value&(UINT64_C(15)<<44))return VZ_KERNEL_UNSUPPORTED;
 for(uint32_t n=0;n<g->config.maxCPUs;++n) {
  GICCPU *c=&g->cpus[n];if(!c->attached || c->closing)continue;
  uint8_t aff0=(uint8_t)c->affinity;
  bool target=irm?n!=source:((uint8_t)(c->affinity>>8)==aff1 && (uint8_t)(c->affinity>>16)==aff2 &&
   (uint8_t)(c->affinity>>32)==aff3 && aff0<16 && ((value>>aff0)&1));
  if(target && c->privateIRQ[id].group1==group1)c->privateIRQ[id].latched=true;
 }
 return VZ_KERNEL_OK;
}
static VZKernelStatus ICCEffect(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint16_t reg,bool write,uint64_t value,uint64_t *out,bool *committed) {
 if(!g || !q || (!write && (!OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))))
  return VZ_KERNEL_BAD_ARGUMENT;
 LockGIC(g);int slot=FindCPU(g,q,false);
 if(slot<0){UnlockGIC(g);return VZ_KERNEL_NOT_LIVE;}
 GICCPU *c=&g->cpus[slot];uint64_t result=0;VZKernelStatus status=VZ_KERNEL_OK;
 switch(reg) {
  case 0xc230:if(write)c->pmr=(uint8_t)value&0xf8;else result=c->pmr;break; // PMR
  case 0xc643:case 0xc663:{bool group1=reg==0xc663;
   if(write)c->bpr[group1]=(uint8_t)(value&7)<2?2:(uint8_t)(value&7);else result=c->bpr[group1];break;}
  case 0xc664:if(write){c->eoiMode=(value&2)!=0;c->commonBPR=(value&1)!=0;}
   else result=(UINT64_C(4)<<8)|(c->eoiMode?2:0)|(c->commonBPR?1:0);break;
  case 0xc665:if(!write)result=7;break; // SRE/DIB/DFB; system interface only.
  case 0xc666:case 0xc667:{bool group1=reg==0xc667;
   if(write)c->groupEnabled[group1]=(value&1)!=0;else result=c->groupEnabled[group1];break;}
  case 0xc640:case 0xc660:if(write)status=VZ_KERNEL_BAD_ARGUMENT;
   else status=Acknowledge(g,(uint32_t)slot,reg==0xc660,&result);break;
  case 0xc641:case 0xc661:if(!write)status=VZ_KERNEL_BAD_ARGUMENT;
   else status=EndInterrupt(g,(uint32_t)slot,reg==0xc661,value);break;
  case 0xc642:case 0xc662:if(write)status=VZ_KERNEL_BAD_ARGUMENT;
   else result=Highest(g,(uint32_t)slot,reg==0xc662);break;
  case 0xc65b:if(write)status=VZ_KERNEL_BAD_ARGUMENT;else result=RunningPriority(c);break;
  case 0xc659: // DIR
   if(!write || value>>24 || (uint32_t)value>=VM27_GIC_INTIDS_V1)status=VZ_KERNEL_BAD_ARGUMENT;
   else {GICInterrupt *i=Interrupt(g,(uint32_t)slot,(uint32_t)value);
    if(!i->active || i->activeCPU!=(uint32_t)slot)status=VZ_KERNEL_BAD_ARGUMENT;
    else {i->active=false;i->activeCPU=UINT32_MAX;}}
   break;
  case 0xc65d:case 0xc65f:if(!write)status=VZ_KERNEL_BAD_ARGUMENT;
   else status=GenerateSGI(g,(uint32_t)slot,value,reg==0xc65d);break;
  case 0xc644:case 0xc645:case 0xc646:case 0xc647:
  case 0xc648:case 0xc649:case 0xc64a:case 0xc64b: {
   bool group1=reg>=0xc648;uint32_t index=reg-(group1?0xc648u:0xc644u);
   if(!index){if(write)c->activePriority[group1]=(uint32_t)value;else result=c->activePriority[group1];}
   else if(!write)result=0;
   break;
  }
  default:status=VZ_KERNEL_UNSUPPORTED;break;
 }
 if(status==VZ_KERNEL_OK && !write)*out=result;
 if(status==VZ_KERNEL_OK && committed)*committed=write || reg==0xc640 || reg==0xc660;
 UnlockGIC(g);
 return status==VZ_KERNEL_OK && write?WakeAttached(g):status;
}
VZKernelStatus VM27GICICCRegV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint16_t reg,bool write,uint64_t value,uint64_t *out) {return ICCEffect(g,q,reg,write,value,out,NULL);}
VZKernelStatus VM27GICHandleAbortV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint32_t esr,uint64_t ipa,uint64_t source,VM27GICTrapResultV1 *out) {
 if(!g || !q || !OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))
  return VZ_KERNEL_BAD_ARGUMENT;
 // Data abort from a lower EL, valid decoded single transfer, translation
 // fault only. Do not consume access/permission/alignment/external faults.
 uint32_t ec=esr>>26,dfsc=esr&63;
 if(ec!=0x24 || !(esr&(1u<<25)) || !(esr&(1u<<24)) || dfsc<4 || dfsc>7 ||
  (esr&((1u<<7)|(1u<<8)|(1u<<9)|(1u<<10)|(1u<<13))))return VZ_KERNEL_UNSUPPORTED;
 VM27GICTrapResultV1 r={.write=(esr&(1u<<6))!=0,.signExtend=(esr&(1u<<21))!=0,
  .is64Bit=(esr&(1u<<15))!=0,.registerIndex=(esr>>16)&31,.bytes=1u<<((esr>>22)&3)};
 if((r.bytes==8 && !r.is64Bit) || (r.write && r.signExtend))return VZ_KERNEL_UNSUPPORTED;
 VZKernelStatus status=MMIOEffect(g,q,ipa,r.bytes,r.write,r.registerIndex==31?0:source,&r.readValue,
  &r.controllerStateCommitted);
 if(status!=VZ_KERNEL_OK) {if(r.controllerStateCommitted){r.handled=true;*out=r;}return status;}
 if(!r.write) {
  if(r.bytes<8) {
   unsigned bits=r.bytes*8;r.readValue&=(UINT64_C(1)<<bits)-1;
   if(r.signExtend && (r.readValue&(UINT64_C(1)<<(bits-1))))r.readValue|=~((UINT64_C(1)<<bits)-1);
  }
  if(!r.is64Bit)r.readValue=(uint32_t)r.readValue;
 }
 r.handled=true;*out=r;return status;
}
VZKernelStatus VM27GICHandleSystemV1(VM27GICV3V1 *g,const VZKernelRunPendingRequestV14 *q,
 uint32_t esr,uint64_t source,VM27GICTrapResultV1 *out) {
 if(!g || !q || !OutputGIC(g,out,sizeof(*out)) || !Separate(q,sizeof(*q),out,sizeof(*out)))
  return VZ_KERNEL_BAD_ARGUMENT;
 if(esr>>26!=0x18 || !(esr&(1u<<25)))return VZ_KERNEL_UNSUPPORTED;
 // EC18 ISS packs op0/op2/op1/CRn/Rt/CRm in different positions than the
 // architectural 16-bit SYS encoding. Preserve all selector bits exactly.
 uint16_t selector=(uint16_t)((((esr>>20)&3)<<14)|(((esr>>14)&7)<<11)|
  (((esr>>10)&15)<<7)|(((esr>>1)&15)<<3)|((esr>>17)&7));
 VM27GICTrapResultV1 r={.write=(esr&1)==0,.is64Bit=true,.registerIndex=(esr>>5)&31,.bytes=8};
 VZKernelStatus status=ICCEffect(g,q,selector,r.write,r.registerIndex==31?0:source,&r.readValue,
  &r.controllerStateCommitted);
 if(status!=VZ_KERNEL_OK) {if(r.controllerStateCommitted){r.handled=true;*out=r;}return status;}
 r.handled=true;*out=r;return status;
}
