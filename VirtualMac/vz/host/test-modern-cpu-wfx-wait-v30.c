#include "modern_gic_v3_engine_v3.h"
#include "modern_cpu_wfx_wait_v30.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"WFx check line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static unsigned checks;
typedef struct {VM27WFxWaitV30 wait;_Atomic bool cancel;bool setCancel;} Fixture;
static VZKernelStatus Poll(void *p,bool *ready) {*ready=atomic_load(&((Fixture *)p)->cancel);return VZ_KERNEL_OK;}
static void *SignalLater(void *p) {
 Fixture *f=p;struct timespec delay={0,20000000};nanosleep(&delay,NULL);
 if(f->setCancel)atomic_store(&f->cancel,true);
 return (void *)(uintptr_t)VM27WFxSignalV30(&f->wait,VZ_KERNEL_OK);
}
static VZKernelStatus Retain(void *p,const VZKernelRunPendingRequestV14 *q,void **out) {(void)p;(void)q;*out=malloc(1);return *out?VZ_KERNEL_OK:VZ_KERNEL_OUT_OF_MEMORY;}
static VZKernelStatus Release(void *p,void *v) {(void)p;free(v);return VZ_KERNEL_OK;}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q) {(void)p;(void)q;return VZ_KERNEL_OK;}
static VZKernelStatus Schedule(void *p,const VZKernelRunPendingRequestV14 *q,bool a,uint64_t t) {(void)p;(void)q;(void)a;(void)t;return VZ_KERNEL_OK;}
static VZKernelStatus Drain(void *p,const VZKernelRunPendingRequestV14 *q) {(void)p;(void)q;return VZ_KERNEL_OK;}
int main(void) {
 Fixture f={0};CHECK(VM27WFxInitV30(&f.wait)==VZ_KERNEL_OK);
 CHECK(VM27WFxArmV30(&f.wait,Poll,&f)==VZ_KERNEL_OK);
 pthread_t t;CHECK(!pthread_create(&t,NULL,SignalLater,&f));
 struct timespec a,b;CHECK(!clock_gettime(CLOCK_MONOTONIC,&a));
 CHECK(VM27WFxAwaitV30(&f.wait,Poll,&f)==VZ_KERNEL_OK);
 CHECK(!clock_gettime(CLOCK_MONOTONIC,&b));CHECK(!pthread_join(t,NULL));
 CHECK((b.tv_sec-a.tv_sec)*1000000000LL+b.tv_nsec-a.tv_nsec>=10000000LL);
 CHECK(VM27WFxArmV30(&f.wait,Poll,&f)==VZ_KERNEL_OK);
 CHECK(VM27WFxSignalV30(&f.wait,VZ_KERNEL_OK)==VZ_KERNEL_OK); // before cond_wait
 CHECK(VM27WFxAwaitV30(&f.wait,Poll,&f)==VZ_KERNEL_OK);
 f.setCancel=true;CHECK(VM27WFxArmV30(&f.wait,Poll,&f)==VZ_KERNEL_OK);
 CHECK(!pthread_create(&t,NULL,SignalLater,&f));
 CHECK(VM27WFxAwaitV30(&f.wait,Poll,&f)==VZ_KERNEL_OK);CHECK(!pthread_join(t,NULL));
 CHECK(atomic_load(&f.cancel));
 CHECK(VM27WFxSignalV30(&f.wait,VZ_KERNEL_NATIVE_ERROR)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(VM27WFxAwaitV30(&f.wait,Poll,&f)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(VM27WFxDestroyV30(&f.wait)==VZ_KERNEL_OK);
 VM27GICBindingsV1 bindings={NULL,Retain,Release,Wake,Schedule,Drain};
 VM27GICConfigV1 cfg={.schemaVersion=1,.maxCPUs=1,.ipaBits=36,.vmEpoch=17,
  .distributorBase=0x10000000,.redistributorBase=0x11000000};
 VM27GICV3V1 *g=NULL;CHECK(VM27GICCreateV1(&cfg,&bindings,&g)==VZ_KERNEL_OK);
 VZKernelRunPendingRequestV14 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,17,81,9020,9,0};
 CHECK(VM27GICAttachCPUV1(g,&q,0)==VZ_KERNEL_OK);
 CHECK(VM27GICRedistributorRegV1(g,&q,0x10100,true,UINT64_C(1)<<30,NULL)==VZ_KERNEL_OK);
 bool aggregate=false;CHECK(VM27GICRoutePhysicalTimerV1(g,&q,true,&aggregate)==VZ_KERNEL_OK);
 VM27GICLinesV1 lines={0};CHECK(VM27GICGetLinesV1(g,&q,&lines)==VZ_KERNEL_OK);
 CHECK(!lines.irq && !lines.fiq); // PMR/group defaults suppress actual injection.
 bool pending=false;CHECK(VM27GICHasWakePendingV30(g,&q,&pending)==VZ_KERNEL_OK && pending);
 CHECK(VM27GICRoutePhysicalTimerV1(g,&q,false,&aggregate)==VZ_KERNEL_OK);
 CHECK(VM27GICHasWakePendingV30(g,&q,&pending)==VZ_KERNEL_OK && !pending);
 CHECK(VM27GICDetachCPUV1(g,&q)==VZ_KERNEL_OK);CHECK(VM27GICDestroyV1(g)==VZ_KERNEL_OK);
 printf("WFx focused real CV/early wake/cancel/masked pending checks=%u passed\n",checks);return 0;
}
