/* Differential arbitration against the exact preceding implementation.
 * Exercises valid boundary values and independently randomized enable indexes,
 * routing, groups, preemption, priorities and active stacks. No native HV. */
#include "modern_gic_v3_engine_v17_single_pass.c"
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
static uint64_t Nano(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static volatile uint64_t checksum;
static void Benchmark(VM27GICV3V1 *g,const char *name,bool dense,bool both){
 memset(g,0,sizeof(*g));g->config.maxCPUs=4;g->groupEnabled[0]=both;g->groupEnabled[1]=true;GICCPU *c=&g->cpus[0];c->attached=true;c->groupEnabled[0]=both;c->groupEnabled[1]=true;c->pmr=248;
 for(unsigned id=0;id<VM27_GIC_INTIDS_V1;++id){GICInterrupt *i=Interrupt(g,0,id);i->group1=both?(id&1)!=0:true;i->priority=(uint8_t)((id%20)*8);i->route=0;i->latched=(id%7)==0;if(dense || id==1 || id==27 || id==30 || id==40)SetEnabledV7(g,0,id,true);}
 unsigned count=dense?100000:1000000;
 for(unsigned round=0;round<3;++round){uint64_t elapsed[2];
  for(unsigned phase=0;phase<2;++phase){bool old=(phase^(round&1))==0;uint64_t start=Nano();
   for(unsigned k=0;k<count;++k){c->privateIRQ[1].latched=(k&1)!=0;__asm__ volatile(""::"r"(g):"memory");VM27GICLinesV1 lines=old?ReferenceLines(g,0):Lines(g,0);checksum+=lines.highestGroup0+lines.highestGroup1;}
   elapsed[old?0:1]=Nano()-start;
  }
  printf("BENCH %s round=%u old_ns=%.2f new_ns=%.2f speedup=%.3f\n",name,round,(double)elapsed[0]/count,(double)elapsed[1]/count,(double)elapsed[0]/elapsed[1]);
 }
}
int main(void){VM27GICV3V1 *g=calloc(1,sizeof(*g));if(!g)return 2;
 for(unsigned state=0;state<12000;++state){Randomize(g,state);for(unsigned cpu=0;cpu<4;++cpu){Check(RunningPriority(&g->cpus[cpu])==ReferenceRunningPriority(&g->cpus[cpu]),state,cpu,"running");Check(Highest(g,cpu,false)==ReferenceHighest(g,cpu,false),state,cpu,"group0");Check(Highest(g,cpu,true)==ReferenceHighest(g,cpu,true),state,cpu,"group1");VM27GICLinesV1 a=Lines(g,cpu),b=ReferenceLines(g,cpu);Check(a.irq==b.irq && a.fiq==b.fiq && a.highestGroup0==b.highestGroup0 && a.highestGroup1==b.highestGroup1,state,cpu,"lines");Check(WakePendingV30(g,cpu)==ReferenceWakePendingV30(g,cpu),state,cpu,"wake");}}
 printf("Differential states=12000 CPUs=4 comparedQueries=%" PRIu64 " PASS; native HV not executed\n",queries);
 Benchmark(g,"sparse-group1",false,false);Benchmark(g,"sparse-both",false,true);Benchmark(g,"dense-both",true,true);free(g);return checksum?0:3;}
