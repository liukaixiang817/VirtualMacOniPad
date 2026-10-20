#include "modern_gic_v3_engine_v7_enabled_index.c"
#include <stdio.h>
static unsigned checks;
#define CHECK(x) do { ++checks;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint32_t ReferenceHighest(VM27GICV3V1 *g,uint32_t cpu,bool group1) {
 GICCPU *c=&g->cpus[cpu];uint32_t best=1023;uint8_t priority=255;
 if(c->closing||c->sleeping||!g->groupEnabled[group1]||!c->groupEnabled[group1])return best;
 uint8_t running=RunningPriority(c);
 for(uint32_t id=0;id<VM27_GIC_INTIDS_V1;id++) {
  GICInterrupt *i=Interrupt(g,cpu,id);
  if(i->group1!=group1||!i->enabled||i->active||!Pending(i)||i->priority>=c->pmr||(id>=32&&!RouteMatches(g,cpu,i)))continue;
  uint8_t bpr=c->bpr[group1&&!c->commonBPR];
  if(running!=255&&GroupPriority(i->priority,bpr)>=GroupPriority(running,bpr))continue;
  if(best==1023||i->priority<priority){best=id;priority=i->priority;}
 }
 return best;
}
static bool ReferenceWake(VM27GICV3V1 *g,uint32_t cpu) {
 if(g->cpus[cpu].closing)return false;
 for(uint32_t id=0;id<VM27_GIC_INTIDS_V1;id++){GICInterrupt *i=Interrupt(g,cpu,id);if(i->enabled&&Pending(i)&&(id<32||RouteMatches(g,cpu,i)))return true;}
 return false;
}
static uint32_t rng=817;
static uint32_t Next(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
int main(void) {
 VM27GICV3V1 *g=calloc(1,sizeof(*g));CHECK(g!=NULL);CHECK(pthread_mutex_init(&g->mutex,NULL)==0);g->config.maxCPUs=4;
 for(unsigned round=0;round<1000;round++) {
  memset(g->enabledShared,0,sizeof(g->enabledShared));
  for(unsigned cpu=0;cpu<4;cpu++) {
   GICCPU *c=&g->cpus[cpu];c->enabledPrivate=0;c->attached=true;c->affinity=cpu;c->closing=(Next()%16)==0;c->sleeping=(Next()%8)==0;c->groupEnabled[0]=Next()&1;c->groupEnabled[1]=Next()&1;c->pmr=(uint8_t)Next();c->commonBPR=Next()&1;c->bpr[0]=Next()%8;c->bpr[1]=Next()%8;c->stackCount=0;c->activePriority[0]=(Next()&1)?(1u<<(Next()%32)):0;c->activePriority[1]=0;
  }
  g->groupEnabled[0]=Next()&1;g->groupEnabled[1]=Next()&1;
  for(unsigned cpu=0;cpu<4;cpu++)for(unsigned id=0;id<VM27_GIC_INTIDS_V1;id++) {
   if(cpu&&id>=32)continue;GICInterrupt *i=Interrupt(g,cpu,id);uint32_t r=Next();*i=(GICInterrupt){.group1=r&1,.edge=r&2,.latched=r&4,.level=r&8,.active=(r&31)==0,.priority=(uint8_t)(Next()&0xf8),.route=(r&32)?(1ull<<31):Next()%4};SetEnabledV7(g,cpu,id,(r&15)==0);
  }
  for(unsigned cpu=0;cpu<4;cpu++) {
   for(unsigned group=0;group<2;group++)CHECK(Highest(g,cpu,group)==ReferenceHighest(g,cpu,group));CHECK(WakePendingV30(g,cpu)==ReferenceWake(g,cpu));
   for(unsigned bank=0;bank<32;bank++) {
    uint64_t out=0;uint32_t bits=Next();CHECK(ArrayRegister(g,cpu,0x100+4*bank,4,true,bits,&out,false));CHECK(ArrayRegister(g,cpu,0x180+4*bank,4,true,~bits,&out,false));
   }
   uint64_t out=0;CHECK(ArrayRegister(g,cpu,0x100,4,true,Next(),&out,true));CHECK(ArrayRegister(g,cpu,0x180,4,true,Next(),&out,true));
  }
  for(unsigned cpu=0;cpu<4;cpu++) {
   for(unsigned id=0;id<VM27_GIC_INTIDS_V1;id++) {bool indexed=id<32?(g->cpus[cpu].enabledPrivate>>(id&31))&1:(g->enabledShared[id/64]>>(id&63))&1;CHECK(indexed==Interrupt(g,cpu,id)->enabled);}
   for(unsigned group=0;group<2;group++)CHECK(Highest(g,cpu,group)==ReferenceHighest(g,cpu,group));CHECK(WakePendingV30(g,cpu)==ReferenceWake(g,cpu));
  }
 }
 for(unsigned cpu=0;cpu<4;cpu++)g->cpus[cpu].running=false;
 CHECK(VM27GICResetV1(g)==VZ_KERNEL_OK);
 for(unsigned cpu=0;cpu<4;cpu++){CHECK(NextEnabledV7(g,cpu,0)==VM27_GIC_INTIDS_V1);}
 CHECK(pthread_mutex_destroy(&g->mutex)==0);free(g);printf("GIC enabled-index differential and register mutation checks=%u failures=0\n",checks);return 0;
}
