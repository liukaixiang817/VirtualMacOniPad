#include "modern_gic_v3_engine_v8_owner_wake.c"
#include <stdio.h>
static unsigned calls,checks;
static VZKernelStatus configured=VZ_KERNEL_OK;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"line%d %s\n",__LINE__,#x);exit(1);}}while(0)
static VZKernelStatus Wake(void *unused,const VZKernelRunPendingRequestV14 *q){(void)unused;CHECK(q->expectedPublicIdentity==817);++calls;return configured;}
static void *Foreign(void *opaque){VM27GICV3V1 *g=opaque;CHECK(WakeAttached(g)==VZ_KERNEL_BUSY);return NULL;}
int main(void){
 VM27GICV3V1 *g=calloc(1,sizeof(*g));CHECK(g!=NULL);CHECK(!pthread_mutex_init(&g->mutex,NULL));g->config.maxCPUs=1;g->bindings.wakeCPU=Wake;
 GICCPU *c=&g->cpus[0];c->attached=true;c->owner=pthread_self();c->identity.expectedPublicIdentity=817;c->pmr=255;
 c->privateIRQ[1].latched=true;SetEnabledV7(g,0,1,true);
 CHECK(WakeAttached(g)==VZ_KERNEL_OK);CHECK(calls==1);
 calls=0;c->running=true;CHECK(WakeAttached(g)==VZ_KERNEL_OK);CHECK(calls==0);CHECK(WakePendingV30(g,0));CHECK(c->callbacks==0 && g->callbacks==0);
 configured=VZ_KERNEL_BUSY;pthread_t worker;CHECK(!pthread_create(&worker,NULL,Foreign,g));CHECK(!pthread_join(worker,NULL));CHECK(calls==1);CHECK(c->callbacks==0 && g->callbacks==0);
 calls=0;c->running=false;CHECK(WakeAttached(g)==VZ_KERNEL_BUSY);CHECK(calls==1);
 calls=0;c->closing=true;CHECK(WakeAttached(g)==VZ_KERNEL_OK);CHECK(calls==0);
 c->closing=false;c->privateIRQ[1].latched=false;CHECK(WakeAttached(g)==VZ_KERNEL_OK);CHECK(calls==0);
 CHECK(!pthread_mutex_destroy(&g->mutex));free(g);printf("owner-running skip, foreign-thread wake/error, stopped/closing CPU checks=%u PASS\n",checks);return 0;
}
