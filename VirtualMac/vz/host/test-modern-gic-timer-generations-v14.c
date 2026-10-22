#include "modern_gic_v3_engine_v14_timer_generations.c"
#include <stdio.h>
#include <sched.h>
#include <stdatomic.h>
static _Atomic unsigned checks;
#define CHECK(x) do{atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"line%d %s\n",__LINE__,#x);abort();}}while(0)
typedef struct {VM27GICV3V1 *g;VZKernelRunPendingRequestV14 q;unsigned calls,boundaries;bool arm,closeInBoundary,rejectBoundary,inspectPins,releaseFail;uint64_t deadline;VZKernelStatus schedulerStatus;} Test;
static VZKernelStatus Retain(void *p,const VZKernelRunPendingRequestV14 *q,void **out){(void)p;*out=(void *)(uintptr_t)q->expectedPublicIdentity;return VZ_KERNEL_OK;}
static VZKernelStatus Release(void *p,void *token){CHECK(token!=NULL);return p&&((Test *)p)->releaseFail?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q){(void)p;(void)q;return VZ_KERNEL_OK;}
static VZKernelStatus Quiet(void *p,const VZKernelRunPendingRequestV14 *q){(void)p;(void)q;return VZ_KERNEL_OK;}
static VZKernelStatus Schedule(void *opaque,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t deadline){
 Test *t=opaque;CHECK(SameIdentity(q,&t->q));++t->calls;t->arm=arm;t->deadline=deadline;
 if(t->inspectPins){CHECK(os_unfair_lock_trylock(&t->g->mutex));CHECK(t->g->callbacks>0);int slot=FindCPU(t->g,q,false);CHECK(slot>=0);CHECK(t->g->cpus[slot].callbacks>0);os_unfair_lock_unlock(&t->g->mutex);CHECK(VM27GICQuiescePhysicalTimerV1(t->g,q)==VZ_KERNEL_BUSY);CHECK(VM27GICResetV1(t->g)==VZ_KERNEL_BUSY);CHECK(VM27GICDestroyV1(t->g)==VZ_KERNEL_BUSY);}
 return t->schedulerStatus;
}
static VZKernelStatus Boundary(void *opaque){
 Test *t=opaque;++t->boundaries;CHECK(os_unfair_lock_trylock(&t->g->mutex));CHECK(t->g->callbacks>0);os_unfair_lock_unlock(&t->g->mutex);
 if(t->closeInBoundary)CHECK(VM27GICDetachCPUV1(t->g,&t->q)==VZ_KERNEL_BUSY);
 return t->rejectBoundary?VZ_KERNEL_UNSUPPORTED:VZ_KERNEL_OK;
}
static VZKernelRunPendingRequestV14 Identity(unsigned id){return (VZKernelRunPendingRequestV14){.schemaVersion=1,.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1,.nativeHVISA=2,.expectedVMEpoch=817,.expectedPublicIdentity=100+id,.expectedOwnerThread=200+id,.expectedCPUGeneration=300+id};}
static void Init(Test *t,unsigned id){
 memset(t,0,sizeof(*t));t->q=Identity(id);VM27GICConfigV1 cfg={.schemaVersion=1,.maxCPUs=4,.ipaBits=36,.vmEpoch=817,.distributorBase=0x100000,.redistributorBase=0x200000};
 VM27GICBindingsV1 b={t,Retain,Release,Wake,Schedule,Quiet};CHECK(VM27GICCreateV1(&cfg,&b,&t->g)==VZ_KERNEL_OK);CHECK(VM27GICAttachCPUV1(t->g,&t->q,id)==VZ_KERNEL_OK);
}
static void Done(Test *t){CHECK(t->g->callbacks==0);CHECK(VM27GICDetachCPUV1(t->g,&t->q)==VZ_KERNEL_OK);CHECK(VM27GICDestroyV1(t->g)==VZ_KERNEL_OK);}
static uint32_t seed=817;
static uint32_t Random(void){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
static void Configure(VM27GICV3V1 *g){
 g->groupEnabled[0]=Random()&1;g->groupEnabled[1]=Random()&1;GICCPU *c=&g->cpus[0];
 c->pmr=(uint8_t)Random();c->groupEnabled[0]=Random()&1;c->groupEnabled[1]=Random()&1;c->sleeping=(Random()&15)==0;c->commonBPR=Random()&1;c->bpr[0]=Random()%8;c->bpr[1]=Random()%8;c->activePriority[0]=(Random()&1)?1u<<(Random()%32):0;c->activePriority[1]=0;
 memset(g->enabledShared,0,sizeof(g->enabledShared));c->enabledPrivate=0;
 for(uint32_t id=0;id<VM27_GIC_INTIDS_V1;++id){GICInterrupt *i=Interrupt(g,0,id);*i=(GICInterrupt){.group1=Random()&1,.edge=Random()&1,.latched=Random()&1,.level=Random()&1,.active=(Random()&15)==0,.priority=(uint8_t)(Random()&0xf8),.route=Random()%4};SetEnabledV7(g,0,id,(Random()&7)==0);}
}
static void Differential(void){
 Test a,b;Init(&a,0);Init(&b,0);a.inspectPins=b.inspectPins=true;
 for(unsigned n=0;n<700;++n){
  Configure(a.g);GICCPU *ac=&a.g->cpus[0],*bc=&b.g->cpus[0];
  memcpy(b.g->shared,a.g->shared,sizeof(a.g->shared));memcpy(b.g->enabledShared,a.g->enabledShared,sizeof(a.g->enabledShared));memcpy(b.g->groupEnabled,a.g->groupEnabled,sizeof(a.g->groupEnabled));
  /* Both real attachments have the same owner and identity; copy only the
   * interrupt/arbitration state, never a pthread mutex or retained token. */
  memcpy(bc->privateIRQ,ac->privateIRQ,sizeof(ac->privateIRQ));bc->enabledPrivate=ac->enabledPrivate;bc->pmr=ac->pmr;memcpy(bc->bpr,ac->bpr,sizeof(ac->bpr));memcpy(bc->groupEnabled,ac->groupEnabled,sizeof(ac->groupEnabled));memcpy(bc->activePriority,ac->activePriority,sizeof(ac->activePriority));bc->sleeping=ac->sleeping;bc->commonBPR=ac->commonBPR;
  ac->deadlineQuiesced=bc->deadlineQuiesced=true;bool asserted=Random()&1,arm=Random()&1;uint64_t deadline=Random();bool irq=false;
  a.schedulerStatus=b.schedulerStatus=(n%13==0)?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
  CHECK(VM27GICRoutePhysicalTimerV1(a.g,&a.q,asserted,&irq)==VZ_KERNEL_OK);VZKernelStatus old=VM27GICUpdatePhysicalDeadlineV1(a.g,&a.q,arm,deadline);
  VM27GICPhysicalBatchResultV9 r={0};CHECK(VM27GICRouteAndDeadlineV9(b.g,&b.q,asserted,arm,deadline,Boundary,&b,&r)==old);
  CHECK(r.routeComplete&&r.deadlineAttempted&&r.irq==irq);CHECK(a.arm==b.arm&&a.deadline==b.deadline&&a.calls==b.calls);CHECK(ac->deadlineQuiesced==bc->deadlineQuiesced);CHECK(!memcmp(ac->privateIRQ,bc->privateIRQ,sizeof(ac->privateIRQ)));CHECK(!a.g->callbacks&&!b.g->callbacks&&!ac->callbacks&&!bc->callbacks);
 }
 Done(&a);Done(&b);
}
static void *WrongThread(void *opaque){Test *t=opaque;CHECK(VM27GICValidateTimerOwnerV1(t->g,&t->q)==VZ_KERNEL_NOT_LIVE);VM27GICPhysicalBatchResultV9 r={0};CHECK(VM27GICRouteAndDeadlineV9(t->g,&t->q,true,true,1,Boundary,t,&r)==VZ_KERNEL_NOT_LIVE);return NULL;}
static void Boundaries(void){
 Test t;Init(&t,0);t.inspectPins=true;VM27GICPhysicalBatchResultV9 r={0};
 CHECK(VM27GICRouteAndDeadlineV9(t.g,&t.q,true,true,99,Boundary,&t,(void *)&t.q)==VZ_KERNEL_BAD_ARGUMENT);CHECK(!t.calls&&!t.boundaries);
 VZKernelRunPendingRequestV14 bad=t.q;bad.expectedCPUGeneration++;CHECK(VM27GICRouteAndDeadlineV9(t.g,&bad,true,true,99,Boundary,&t,&r)==VZ_KERNEL_NOT_LIVE);
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,WrongThread,&t));CHECK(!pthread_join(thread,NULL));CHECK(!t.calls&&!t.boundaries);
 t.rejectBoundary=true;CHECK(VM27GICRouteAndDeadlineV9(t.g,&t.q,true,true,99,Boundary,&t,&r)==VZ_KERNEL_UNSUPPORTED);CHECK(!r.routeComplete&&!r.deadlineAttempted&&!t.calls);CHECK(t.g->cpus[0].privateIRQ[30].level);CHECK(!t.g->callbacks&&!t.g->cpus[0].callbacks);
 t.rejectBoundary=false;t.closeInBoundary=true;CHECK(VM27GICRouteAndDeadlineV9(t.g,&t.q,true,true,99,Boundary,&t,&r)==VZ_KERNEL_NOT_LIVE);CHECK(r.routeComplete&&r.deadlineAttempted&&!t.calls);CHECK(t.g->cpus[0].closing);CHECK(!t.g->callbacks&&!t.g->cpus[0].callbacks);Done(&t);
}
typedef struct {VM27GICV3V1 *g;unsigned id;_Atomic(unsigned) *ready;} Worker;
static VZKernelStatus ConcurrentSchedule(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t deadline){(void)p;CHECK(arm==(bool)(deadline&1));CHECK(q->expectedPublicIdentity>=100&&q->expectedPublicIdentity<104);return VZ_KERNEL_OK;}
static VZKernelStatus ConcurrentBoundary(void *p){Worker *w=p;os_unfair_lock_lock(&w->g->mutex);CHECK(w->g->callbacks>0);os_unfair_lock_unlock(&w->g->mutex);return VZ_KERNEL_OK;}
static void *RunWorker(void *opaque){Worker *w=opaque;VZKernelRunPendingRequestV14 q=Identity(w->id);CHECK(VM27GICAttachCPUV1(w->g,&q,w->id)==VZ_KERNEL_OK);atomic_fetch_add(w->ready,1);while(atomic_load(w->ready)!=4)sched_yield();CHECK(VM27GICBeginRunV1(w->g,&q)==VZ_KERNEL_OK);for(uint64_t n=0;n<1500;++n){CHECK(VM27GICValidateTimerOwnerV1(w->g,&q)==VZ_KERNEL_OK);VM27GICPhysicalBatchResultV9 r={0};CHECK(VM27GICRouteAndDeadlineV9(w->g,&q,(n/25)&1,n&1,n,ConcurrentBoundary,w,&r)==VZ_KERNEL_OK);CHECK(r.routeComplete&&r.deadlineAttempted);}CHECK(VM27GICEndRunV1(w->g,&q)==VZ_KERNEL_OK);CHECK(VM27GICDetachCPUV1(w->g,&q)==VZ_KERNEL_OK);return NULL;}
typedef struct {VM27GICV3V1 *g;_Atomic(bool) stop;} ResetObserver;
static void *ObserveReset(void *p){
 ResetObserver *o=p;
 while(!atomic_load_explicit(&o->stop,memory_order_acquire)){
  VZKernelStatus status=VM27GICResetV1(o->g);
  CHECK(status==VZ_KERNEL_OK || status==VZ_KERNEL_BUSY);
  sched_yield();
 }
 return NULL;
}
static void Concurrent(void){Test t;memset(&t,0,sizeof(t));VM27GICConfigV1 cfg={.schemaVersion=1,.maxCPUs=4,.ipaBits=36,.vmEpoch=817,.distributorBase=0x100000,.redistributorBase=0x200000};VM27GICBindingsV1 b={NULL,Retain,Release,Wake,ConcurrentSchedule,Quiet};CHECK(VM27GICCreateV1(&cfg,&b,&t.g)==VZ_KERNEL_OK);ResetObserver observer={.g=t.g};atomic_init(&observer.stop,false);pthread_t resetThread;CHECK(!pthread_create(&resetThread,NULL,ObserveReset,&observer));_Atomic(unsigned) ready;atomic_init(&ready,0);Worker w[4];pthread_t th[4];for(unsigned i=0;i<4;++i){w[i]=(Worker){t.g,i,&ready};CHECK(!pthread_create(&th[i],NULL,RunWorker,&w[i]));}for(unsigned i=0;i<4;++i)CHECK(!pthread_join(th[i],NULL));atomic_store_explicit(&observer.stop,true,memory_order_release);CHECK(!pthread_join(resetThread,NULL));CHECK(!t.g->callbacks);CHECK(VM27GICDestroyV1(t.g)==VZ_KERNEL_OK);}
static void OwnerValidation(void){
 Test a,b;Init(&a,0);CHECK(TimerOwnerV10.g==a.g&&TimerOwnerV10.cpu==&a.g->cpus[0]);
 /* A healthy owner validation completes while this pthread holds the GIC
  * mutex: it cannot secretly acquire that mutex or enter a native callback. */
 os_unfair_lock_lock(&a.g->mutex);CHECK(VM27GICValidateTimerOwnerV1(a.g,&a.q)==VZ_KERNEL_OK);os_unfair_lock_unlock(&a.g->mutex);
 VZKernelRunPendingRequestV14 q=a.q;q.expectedCPUGeneration++;CHECK(VM27GICValidateTimerOwnerV1(a.g,&q)==VZ_KERNEL_NOT_LIVE);q=a.q;q.nativeHVISA=1;CHECK(VM27GICValidateTimerOwnerV1(a.g,&q)==VZ_KERNEL_NOT_LIVE);
 CHECK(VM27GICValidateTimerOwnerV1(NULL,&q)==VZ_KERNEL_BAD_ARGUMENT);CHECK(VM27GICValidateTimerOwnerV1(a.g,NULL)==VZ_KERNEL_BAD_ARGUMENT);
 q=a.q;q.schemaVersion=0;CHECK(VM27GICAttachCPUV1(a.g,&q,1)==VZ_KERNEL_BAD_ARGUMENT);CHECK(TimerOwnerV10.g==a.g);
 Init(&b,1);CHECK(TimerOwnerV10.g==b.g);CHECK(VM27GICValidateTimerOwnerV1(a.g,&a.q)==VZ_KERNEL_OK);Done(&b);CHECK(!TimerOwnerV10.g&&!TimerOwnerV10.cpu);CHECK(VM27GICValidateTimerOwnerV1(a.g,&a.q)==VZ_KERNEL_OK);Done(&a);
 Init(&a,0);CHECK(VM27GICBeginRunV1(a.g,&a.q)==VZ_KERNEL_OK);CHECK(VM27GICDetachCPUV1(a.g,&a.q)==VZ_KERNEL_BUSY);CHECK(!TimerOwnerV10.g&&!TimerOwnerV10.cpu);CHECK(VM27GICValidateTimerOwnerV1(a.g,&a.q)==VZ_KERNEL_NOT_LIVE);CHECK(VM27GICEndRunV1(a.g,&a.q)==VZ_KERNEL_OK);Done(&a);
 Init(&a,0);a.releaseFail=true;CHECK(VM27GICDetachCPUV1(a.g,&a.q)==VZ_KERNEL_NATIVE_ERROR);CHECK(!TimerOwnerV10.g&&!TimerOwnerV10.cpu);CHECK(a.g->cpus[0].attached&&a.g->cpus[0].retainedCPU&&a.g->cpus[0].closing);CHECK(VM27GICValidateTimerOwnerV1(a.g,&a.q)==VZ_KERNEL_NOT_LIVE);CHECK(VM27GICDestroyV1(a.g)==VZ_KERNEL_BUSY);a.releaseFail=false;Done(&a);
}

static void ICC(Test *t,uint16_t reg,uint64_t value){CHECK(VM27GICICCRegV1(t->g,&t->q,reg,true,value,NULL)==VZ_KERNEL_OK);}
static void Dist(Test *t,uint16_t reg,uint64_t value){CHECK(VM27GICDistributorRegV1(t->g,reg,true,value,NULL)==VZ_KERNEL_OK);}
static void Redist(Test *t,uint32_t reg,uint64_t value){CHECK(VM27GICRedistributorRegV1(t->g,&t->q,reg,true,value,NULL)==VZ_KERNEL_OK);}
static VM27GICLinesV1 CheckLines(Test *t,bool irq,bool fiq,uint32_t g0,uint32_t g1){
 VM27GICLinesV1 actual={0};CHECK(VM27GICGetLinesV1(t->g,&t->q,&actual)==VZ_KERNEL_OK);
 CHECK(actual.irq==irq&&actual.fiq==fiq&&actual.highestGroup0==g0&&actual.highestGroup1==g1);
 LockGIC(t->g);VM27GICLinesV1 expected=Lines(t->g,0);UnlockGIC(t->g);
 CHECK(actual.irq==expected.irq&&actual.fiq==expected.fiq&&actual.highestGroup0==expected.highestGroup0&&actual.highestGroup1==expected.highestGroup1);
 return actual;
}
static void Physical(Test *t,bool asserted,bool expected){bool irq=!expected;CHECK(VM27GICRoutePhysicalTimerV1(t->g,&t->q,asserted,&irq)==VZ_KERNEL_OK);CHECK(irq==expected);}
static void Virtual(Test *t,bool asserted,bool expected){bool irq=!expected;CHECK(VM27GICRouteVirtualTimerV35(t->g,&t->q,asserted,&irq)==VZ_KERNEL_OK);CHECK(irq==expected);}
static void Ack(Test *t,uint32_t id){uint64_t actual=UINT64_MAX;CHECK(VM27GICICCRegV1(t->g,&t->q,0xc660,false,0,&actual)==VZ_KERNEL_OK);CHECK(actual==id);}
static void SnapshotMutations(void){
 Test t={0};t.q=Identity(0);VM27GICConfigV1 cfg={.schemaVersion=1,.maxCPUs=1,.ipaBits=36,.vmEpoch=817,.distributorBase=0x100000,.redistributorBase=0x200000,.msiConfigured=true,.msiBase=0x300000,.msiFirst=64,.msiCount=16};
 VM27GICBindingsV1 b={&t,Retain,Release,Wake,Schedule,Quiet};CHECK(VM27GICCreateV1(&cfg,&b,&t.g)==VZ_KERNEL_OK);CHECK(VM27GICAttachCPUV1(t.g,&t.q,0)==VZ_KERNEL_OK);
 Dist(&t,0,3);Redist(&t,0x10080,(UINT64_C(1)<<30)|(UINT64_C(1)<<27)|8);Redist(&t,0x10100,(UINT64_C(1)<<30)|(UINT64_C(1)<<27)|8);ICC(&t,0xc230,0xf8);ICC(&t,0xc667,1);ICC(&t,0xc666,1);
 CHECK(VM27GICBeginRunV1(t.g,&t.q)==VZ_KERNEL_OK);CheckLines(&t,false,false,1023,1023);CHECK(SnapshotOwnerV13(t.g,&t.q)==&t.g->cpus[0]);
 uint64_t generation=atomic_load(&t.g->stateGeneration);VM27GICPhysicalBatchResultV9 r={0};
 for(unsigned n=0;n<1000;++n){
  Physical(&t,false,false);Virtual(&t,false,false);CheckLines(&t,false,false,1023,1023);
  CHECK(VM27GICRouteAndDeadlineV9(t.g,&t.q,false,n&1,n,Boundary,&t,&r)==VZ_KERNEL_OK);CHECK(r.routeComplete&&r.deadlineAttempted&&!r.irq);
 }
 uint64_t globalBefore=atomic_load(&t.g->stateGeneration);
 Physical(&t,true,true);Virtual(&t,true,true);Physical(&t,false,true);Virtual(&t,false,false);
 CHECK(atomic_load(&t.g->stateGeneration)==globalBefore);
 uint64_t beforeRead=atomic_load(&t.g->stateGeneration),pmr=0;
 CHECK(VM27GICICCRegV1(t.g,&t.q,0xc230,false,0,&pmr)==VZ_KERNEL_OK);
 CHECK(pmr==0xf8&&atomic_load(&t.g->stateGeneration)==beforeRead);
 CHECK(t.calls==1000&&t.boundaries==1000);CHECK(atomic_load(&t.g->stateGeneration)==generation);
 // A valid cached observation must not wait on arbitration held by its owner.
 LockGIC(t.g);VM27GICLinesV1 cached={0};CHECK(VM27GICGetLinesV1(t.g,&t.q,&cached)==VZ_KERNEL_OK);CHECK(!cached.irq&&!cached.fiq);UnlockGIC(t.g);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,WrongThread,&t));CHECK(!pthread_join(foreign,NULL));
 VZKernelRunPendingRequestV14 bad=t.q;bad.expectedCPUGeneration++;CHECK(VM27GICGetLinesV1(t.g,&bad,&cached)==VZ_KERNEL_NOT_LIVE);
 CHECK(VM27GICGetLinesV1(t.g,&t.q,(void *)&t.q)==VZ_KERNEL_BAD_ARGUMENT);
 Physical(&t,true,true);CheckLines(&t,true,false,1023,30);ICC(&t,0xc230,0);CheckLines(&t,false,false,1023,1023);ICC(&t,0xc230,0xf8);CheckLines(&t,true,false,1023,30);
 Ack(&t,30);CheckLines(&t,false,false,1023,1023);ICC(&t,0xc661,30);CheckLines(&t,true,false,1023,30);Physical(&t,false,false);
 Virtual(&t,true,true);CheckLines(&t,true,false,1023,27);Virtual(&t,false,false);
 ICC(&t,0xc65d,(UINT64_C(3)<<24)|1);CheckLines(&t,true,false,1023,3);Ack(&t,3);CheckLines(&t,false,false,1023,1023);ICC(&t,0xc661,3);
 Dist(&t,0x84,1u<<8);Dist(&t,0x104,1u<<8);CHECK(VM27GICSetSPIV1(t.g,40,true)==VZ_KERNEL_OK);CheckLines(&t,true,false,1023,40);
 Dist(&t,0x6140,1);CheckLines(&t,false,false,1023,1023);Dist(&t,0x6140,0);CheckLines(&t,true,false,1023,40);
 Redist(&t,0x14,2);CheckLines(&t,false,false,1023,1023);Redist(&t,0x14,0);CheckLines(&t,true,false,1023,40);
 Dist(&t,0x428,0xf8);CheckLines(&t,false,false,1023,1023);Dist(&t,0x428,0x80);CheckLines(&t,true,false,1023,40);
 ICC(&t,0xc667,0);CheckLines(&t,false,false,1023,1023);ICC(&t,0xc667,1);CheckLines(&t,true,false,1023,40);
 CHECK(VM27GICMMIOV1(t.g,&t.q,0x100000,4,true,0,NULL)==VZ_KERNEL_OK);CheckLines(&t,false,false,1023,1023);CHECK(VM27GICMMIOV1(t.g,&t.q,0x100000,4,true,3,NULL)==VZ_KERNEL_OK);CheckLines(&t,true,false,1023,40);
 Dist(&t,0x84,0);CheckLines(&t,false,true,40,1023);Dist(&t,0x184,1u<<8);CheckLines(&t,false,false,1023,1023);Dist(&t,0x104,1u<<8);CheckLines(&t,false,true,40,1023);CHECK(VM27GICSetSPIV1(t.g,40,false)==VZ_KERNEL_OK);CheckLines(&t,false,false,1023,1023);
 Dist(&t,0x88,1);Dist(&t,0x108,1);CHECK(VM27GICSendMSIV1(t.g,0x300040,64)==VZ_KERNEL_OK);CheckLines(&t,true,false,1023,64);Ack(&t,64);ICC(&t,0xc661,64);CheckLines(&t,false,false,1023,1023);
 Physical(&t,true,true);CHECK(VM27GICQuiescePhysicalTimerV1(t.g,&t.q)==VZ_KERNEL_OK);CheckLines(&t,false,false,1023,1023);
 CHECK(VM27GICResetV1(t.g)==VZ_KERNEL_BUSY);CHECK(VM27GICEndRunV1(t.g,&t.q)==VZ_KERNEL_OK);CHECK(!SnapshotOwnerV13(t.g,&t.q));CHECK(VM27GICResetV1(t.g)==VZ_KERNEL_OK);CheckLines(&t,false,false,1023,1023);
 CHECK(VM27GICBeginRunV1(t.g,&t.q)==VZ_KERNEL_OK);CheckLines(&t,false,false,1023,1023);
 LockGIC(t.g);atomic_store(&t.g->stateGeneration,UINT64_MAX);InvalidateSnapshotsV13(t.g);UnlockGIC(t.g);CHECK(!atomic_load(&t.g->snapshotsEnabled));CheckLines(&t,false,false,1023,1023);Physical(&t,false,false);CHECK(atomic_load(&t.g->stateGeneration)==UINT64_MAX);CHECK(!SnapshotOwnerV13(t.g,&t.q));
 CHECK(VM27GICEndRunV1(t.g,&t.q)==VZ_KERNEL_OK);Done(&t);
}

int main(void){Differential();Boundaries();Concurrent();OwnerValidation();SnapshotMutations();printf("real GIC snapshots, IRQ mutations, closing, differential and four-owner concurrency checks=%u PASS; nativeHV execution not claimed\n",atomic_load(&checks));return 0;}
