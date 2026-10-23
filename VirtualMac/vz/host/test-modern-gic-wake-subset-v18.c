/* Differential arbitration against the exact preceding implementation.
 * Exercises valid boundary values and independently randomized enable indexes,
 * routing, groups, preemption, priorities and active stacks. No native HV. */
#include "modern_gic_v3_engine_v18_wake_subset.c"
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
static uint8_t ReferenceRunningPriority(GICCPU *c) {
 uint8_t priority=UINT8_MAX;
 uint32_t bits=c->activePriority[0]|c->activePriority[1];
 for(uint32_t n=0;n<32;++n)if(bits&(UINT32_C(1)<<n)){priority=(uint8_t)(n<<3);break;}
 for(uint32_t n=0;n<c->stackCount;++n)if(c->stackPriority[n]<priority)priority=c->stackPriority[n];
 return priority;
}

static uint32_t ReferenceNextEnabledV7(VM27GICV3V1 *g,uint32_t cpu,uint32_t after) {
 if(after>=VM27_GIC_INTIDS_V1)return VM27_GIC_INTIDS_V1;
 uint32_t word=after/64;unsigned bit=after&63;
 uint64_t bits=(word==0?g->cpus[cpu].enabledPrivate:0)|g->enabledShared[word];
 bits&=UINT64_MAX<<bit;
 for(;;) {
  if(bits) {
   uint32_t id=word*64+(uint32_t)__builtin_ctzll(bits);
   return id<VM27_GIC_INTIDS_V1?id:VM27_GIC_INTIDS_V1;
  }
  if(++word>=(VM27_GIC_INTIDS_V1+63)/64)return VM27_GIC_INTIDS_V1;
  bits=g->enabledShared[word];
 }
}

static uint32_t ReferenceHighest(VM27GICV3V1 *g,uint32_t cpu,bool group1) {
 GICCPU *c=&g->cpus[cpu];uint32_t best=1023;uint8_t priority=UINT8_MAX;
 if(c->closing || c->sleeping || !g->groupEnabled[group1] || !c->groupEnabled[group1])return best;
 uint8_t running=ReferenceRunningPriority(c);
 for(uint32_t id=ReferenceNextEnabledV7(g,cpu,0);id<VM27_GIC_INTIDS_V1;id=ReferenceNextEnabledV7(g,cpu,id+1)) {
  GICInterrupt *i=Interrupt(g,cpu,id);
  if(i->group1!=group1 || !i->enabled || i->active || !Pending(i) ||
   i->priority>=c->pmr || (id>=32 && !RouteMatches(g,cpu,i)))continue;
  uint8_t bpr=c->bpr[group1 && !c->commonBPR];
  if(running!=UINT8_MAX && GroupPriority(i->priority,bpr)>=GroupPriority(running,bpr))continue;
  if(best==1023 || i->priority<priority){best=id;priority=i->priority;}
 }
 return best;
}

static VM27GICLinesV1 ReferenceLines(VM27GICV3V1 *g,uint32_t cpu) {
 uint32_t g0=ReferenceHighest(g,cpu,false),g1=ReferenceHighest(g,cpu,true);
 return (VM27GICLinesV1){g1!=1023,g0!=1023,g0,g1};
}

static bool ReferenceWakePendingV30(VM27GICV3V1 *g,uint32_t cpu) {
 GICCPU *c=&g->cpus[cpu];
 if(c->closing)return false;
 for(uint32_t id=ReferenceNextEnabledV7(g,cpu,0);id<VM27_GIC_INTIDS_V1;id=ReferenceNextEnabledV7(g,cpu,id+1)) {
  GICInterrupt *i=Interrupt(g,cpu,id);
  if(i->enabled && Pending(i) && (id<32 || RouteMatches(g,cpu,i)))return true;
 }
 return false;
}
static uint64_t randomState=UINT64_C(0x817261727);
static uint32_t Random(void){randomState^=randomState<<13;randomState^=randomState>>7;randomState^=randomState<<17;return (uint32_t)randomState;}
static uint64_t queries;
static void Check(bool equal,unsigned state,unsigned cpu,const char *kind){++queries;if(!equal){fprintf(stderr,"differential mismatch state=%u cpu=%u query=%s\n",state,cpu,kind);abort();}}
static void FillInterrupt(GICInterrupt *i,unsigned density){
 *i=(GICInterrupt){.enabled=(Random()%density)==0,.group1=(Random()&1)!=0,.edge=(Random()&1)!=0,.latched=(Random()&7)==0,.level=(Random()&7)==0,.active=(Random()&7)==0,.priority=(uint8_t)Random(),.route=(Random()&1)?(UINT64_C(1)<<31):(Random()&7)};
}
static void Randomize(VM27GICV3V1 *g,unsigned state){
 memset(g,0,sizeof(*g));g->config.maxCPUs=4;g->groupEnabled[0]=(Random()&7)!=0;g->groupEnabled[1]=(Random()&7)!=0;
 unsigned density=(state%3==0)?1:((state%3==1)?8:64);
 for(unsigned cpu=0;cpu<4;++cpu){GICCPU *c=&g->cpus[cpu];c->affinity=cpu;c->attached=true;c->closing=(Random()&31)==0;c->sleeping=(Random()&15)==0;c->pmr=(uint8_t)Random();c->bpr[0]=Random()&7;c->bpr[1]=Random()&7;c->commonBPR=(Random()&1)!=0;c->groupEnabled[0]=(Random()&7)!=0;c->groupEnabled[1]=(Random()&7)!=0;
 c->activePriority[0]=(state&1)?Random():0;c->activePriority[1]=(state&1)?Random():0;c->stackCount=Random()%33;
 for(unsigned j=0;j<c->stackCount;++j)c->stackPriority[j]=(uint8_t)Random();
 for(unsigned id=0;id<32;++id){FillInterrupt(&c->privateIRQ[id],density);if(c->privateIRQ[id].enabled)c->enabledPrivate|=UINT32_C(1)<<id;}
 }
 for(unsigned id=32;id<VM27_GIC_INTIDS_V1;++id){GICInterrupt *i=&g->shared[id-32];FillInterrupt(i,density);if(i->enabled)g->enabledShared[id/64]|=UINT64_C(1)<<(id&63);}
 // Compare even with superfluous index bits; arbitration must still consult
 // each interrupt's real enabled flag and bound the incomplete final word.
 if((state&15)==0){g->enabledShared[0]|=Random();g->enabledShared[15]|=UINT64_C(15)<<60;}
}
static VZKernelStatus RecordWake(void *context,const VZKernelRunPendingRequestV14 *q){
 unsigned *seen=context;unsigned slot=(unsigned)q->expectedPublicIdentity;
 if(slot>=4 || seen[slot]++)abort();
 return slot==2?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
}
static VZKernelStatus ReferenceWakeAttachedV17(VM27GICV3V1 *g,uint64_t targets) {
 // Callback pins the allocation and attachment while the mutex is dropped.
 // Cross-thread sources cannot release an owner's retained borrow.
 VZKernelStatus first=VZ_KERNEL_OK;
 for(uint32_t n=0;n<g->config.maxCPUs;++n) {
  if(!(targets&(UINT64_C(1)<<n)))continue;
  LockGIC(g);GICCPU *c=&g->cpus[n];
  /* This pthread is already executing this CPU's public Run loop. Its
   * pending/line poll runs again before native entry, so waking itself only
   * adds a redundant native-context version write and registry traversal.
   * A source on another pthread, or a CPU outside Run, still uses wakeCPU. */
  bool ownerExecuting=c->running && pthread_equal(c->owner,pthread_self());
  VM27GICLinesV1 lines={0};
  if(c->attached && !c->closing && !ownerExecuting)lines=Lines(g,n);
  bool notify=c->attached && !c->closing && !ownerExecuting &&
      (lines.irq || lines.fiq || WakePendingV30(g,n));
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

static uint64_t Nano(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static volatile uint64_t checksum;
static VZKernelStatus BenchWake(void *context,const VZKernelRunPendingRequestV14 *q){
 (void)context;checksum+=q->expectedPublicIdentity;return VZ_KERNEL_OK;
}
static void BenchmarkWake(VM27GICV3V1 *g,bool dense){
 memset(g,0,sizeof(*g));g->mutex=OS_UNFAIR_LOCK_INIT;g->config.maxCPUs=4;
 g->groupEnabled[0]=g->groupEnabled[1]=true;g->bindings.wakeCPU=BenchWake;
 for(unsigned cpu=0;cpu<4;++cpu){
  GICCPU *c=&g->cpus[cpu];c->attached=true;c->owner=pthread_self();
  c->affinity=cpu;c->groupEnabled[0]=c->groupEnabled[1]=true;c->pmr=248;c->identity.expectedPublicIdentity=cpu+1;
  for(unsigned id=0;id<32;++id){c->privateIRQ[id].priority=128;c->privateIRQ[id].group1=true;if(dense||id==1||id==27||id==30)SetEnabledV7(g,cpu,id,true);}
  c->privateIRQ[1].latched=true;
 }
 if(dense)for(unsigned id=32;id<VM27_GIC_INTIDS_V1;++id){g->shared[id-32].priority=128;g->shared[id-32].group1=true;SetEnabledV7(g,0,id,true);}
 unsigned count=dense?10000:200000;
 for(unsigned round=0;round<3;++round){uint64_t elapsed[2]={0};
  for(unsigned phase=0;phase<2;++phase){bool old=(phase^(round&1))==0;uint64_t start=Nano();
   for(unsigned k=0;k<count;++k){__asm__ volatile(""::"r"(g):"memory");
    VZKernelStatus status=old?ReferenceWakeAttachedV17(g,15):WakeAttachedMaskV15(g,15);if(status)abort();
   }
   elapsed[old?0:1]=Nano()-start;
  }
  printf("WAKE_BENCH %s round=%u old_ns=%.2f new_ns=%.2f speedup=%.3f\n",dense?"dense":"sparse",round,(double)elapsed[0]/count,(double)elapsed[1]/count,(double)elapsed[0]/elapsed[1]);
 }
}

int main(void){
 VM27GICV3V1 *g=calloc(1,sizeof(*g));if(!g)return 2;
 for(unsigned state=0;state<12000;++state){
  Randomize(g,state);g->mutex=OS_UNFAIR_LOCK_INIT;
  unsigned expected[4]={0},seen[4]={0};uint64_t targets=Random()&15;
  VZKernelStatus expectedStatus=VZ_KERNEL_OK;
  g->bindings.context=seen;g->bindings.wakeCPU=RecordWake;
  for(unsigned cpu=0;cpu<4;++cpu){
   GICCPU *c=&g->cpus[cpu];
   c->attached=(Random()&7)!=0;c->owner=pthread_self();c->running=(Random()&1)!=0;
   c->identity.expectedPublicIdentity=cpu;
   VM27GICLinesV1 lines=ReferenceLines(g,cpu);
   bool pending=ReferenceWakePendingV30(g,cpu);
   Check(!(lines.irq||lines.fiq)||pending,state,cpu,"line-subset-of-wake");
   bool notify=(targets&(UINT64_C(1)<<cpu)) && c->attached && !c->closing && !c->running &&
    (lines.irq||lines.fiq||pending);
   expected[cpu]=notify;
   if(notify && cpu==2)expectedStatus=VZ_KERNEL_NATIVE_ERROR;
  }
  VZKernelStatus result=WakeAttachedMaskV15(g,targets);
  Check(result==expectedStatus,state,0,"callback-error");
  Check(g->callbacks==0,state,0,"global-pins-drained");
  for(unsigned cpu=0;cpu<4;++cpu){
   Check(seen[cpu]==expected[cpu],state,cpu,"notification-mask");
   Check(g->cpus[cpu].callbacks==0,state,cpu,"owner-pins-drained");
  }
 }
 printf("Wake subset and actual notification masks states=12000 CPUs=4 queries=%" PRIu64 " PASS; native HV not executed\n",queries);
 BenchmarkWake(g,false);BenchmarkWake(g,true);
 free(g);return checksum?0:3;
}
