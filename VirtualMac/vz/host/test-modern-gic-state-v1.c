#include "modern_gic_v3_engine_v19_state.c"
#include <stdio.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"GIC state failure line %d: %s\n",__LINE__,#x);abort();}}while(0)
static VM27GICV3V1 *Fixture(bool reverse) {
 VM27GICV3V1 *g=calloc(1,sizeof(*g));CHECK(g);g->mutex=OS_UNFAIR_LOCK_INIT;
 g->config=(VM27GICConfigV1){.maxCPUs=4,.ipaBits=36,.vmEpoch=reverse?100:1,
  .distributorBase=0x10000,.redistributorBase=0x20000,.msiBase=0x100000,.msiFirst=32,.msiCount=64,.msiConfigured=true};
 for(unsigned n=0;n<4;++n){GICCPU *c=&g->cpus[n];c->attached=true;c->owner=pthread_self();
  c->affinity=reverse?3-n:n;c->identity.expectedPublicIdentity=100+n;
  for(unsigned j=0;j<32;++j)c->privateIRQ[j]=(GICInterrupt){.priority=128,.activeCPU=UINT32_MAX};}
 for(unsigned j=0;j<VM27_GIC_INTIDS_V1-32;++j)g->shared[j]=(GICInterrupt){.priority=128,.activeCPU=UINT32_MAX};
 return g;
}
int main(void) {
 VM27GICV3V1 *old=Fixture(false),*fresh=Fixture(true);
 old->groupEnabled[0]=old->groupEnabled[1]=true;
 for(unsigned n=0;n<4;++n){GICCPU *c=&old->cpus[n];c->pmr=248;c->bpr[0]=2;c->bpr[1]=3;
  c->groupEnabled[0]=c->groupEnabled[1]=true;c->eoiMode=true;c->ran=true;
  c->stackCount=1;c->stack[0]=27;c->stackPriority[0]=32+n;c->stackGroup[0]=true;
  c->privateIRQ[27]=(GICInterrupt){.enabled=true,.group1=true,.level=true,.active=true,.priority=32+n,.activeCPU=n};
  c->enabledPrivate=UINT32_C(1)<<27;}
 old->cpus[2].sleeping=true;old->shared[20]=(GICInterrupt){.enabled=true,.group1=true,.latched=true,
  .priority=64,.route=1,.active=true,.activeCPU=1};old->enabledShared[0]=UINT64_C(1)<<52;
 size_t bytes=VM27GICStateBytesV1();GICStateV1 *state=malloc(bytes),*copy=malloc(bytes);CHECK(state && copy);
 CHECK(VM27GICStateTransferV1(old,state,bytes,false)==VZ_KERNEL_OK);memcpy(copy,state,bytes);
 old->cpus[0].pmr=0;CHECK(state->cpu[0].pmr==248);
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_OK);
 CHECK(fresh->config.vmEpoch==100 && fresh->cpus[3].identity.expectedPublicIdentity==103);
 CHECK(fresh->cpus[3].pmr==248 && fresh->cpus[1].sleeping && fresh->cpus[3].stack[0]==27);
 CHECK(fresh->shared[20].activeCPU==2 && fresh->cpus[3].privateIRQ[27].activeCPU==3);
 CHECK(fresh->enabledShared[0]==(UINT64_C(1)<<52) && fresh->cpus[2].enabledPrivate==(UINT32_C(1)<<27));
 CHECK(!memcmp(copy,state,bytes));
 state->version=2;fresh->cpus[3].pmr=99;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BAD_ARGUMENT && fresh->cpus[3].pmr==99);
 memcpy(state,copy,bytes);state->cpu[0].stackCount=33;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BAD_ARGUMENT);
 memcpy(state,copy,bytes);state->cpu[0].affinity=state->cpu[1].affinity;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BAD_ARGUMENT);
 memcpy(state,copy,bytes);state->shared[20].activeCPU=63;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BAD_ARGUMENT);
 memcpy(state,copy,bytes);state->cpu[0].irq[0].flags=128;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VM27GICStateTransferV1(fresh,state,bytes-1,true)==VZ_KERNEL_BAD_ARGUMENT);
 memcpy(state,copy,bytes);fresh->cpus[0].running=true;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BUSY);
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,false)==VZ_KERNEL_BUSY);
 fresh->cpus[0].running=false;fresh->cpus[0].ran=true;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,true)==VZ_KERNEL_BUSY);
 fresh->cpus[0].ran=false;fresh->callbacks=1;
 CHECK(VM27GICStateTransferV1(fresh,state,bytes,false)==VZ_KERNEL_BUSY);
 free(copy);free(state);free(fresh);free(old);puts("PASS: actual GIC state round trip, affinity rebinding, immutable capture, malformed rejection and stopped-CPU guards");return 0;
}
