/* Real four-pthread GIC owners; callbacks record notifications, not native HV.
 * Verify local writes cannot kick unrelated running CPUs with pending work,
 * while affinity SGI, broadcast, shared EOI and actual target failures remain. */
#include "modern_gic_v3_engine_v16_local_icc_generations.c"
#include <stdio.h>
#include <sched.h>
static _Atomic unsigned checks;
#define CHECK(x) do{atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"line%d %s\n",__LINE__,#x);abort();}}while(0)
typedef struct {
 VM27GICV3V1 *g;_Atomic unsigned attached,ready,wakes[4],snapshotCommand,snapshotAck;_Atomic int failures[4];
 pthread_mutex_t mutex;pthread_cond_t condition;bool stop;
} Fixture;
typedef struct {Fixture *fixture;unsigned id;} Worker;
static VZKernelRunPendingRequestV14 ID(unsigned id){return (VZKernelRunPendingRequestV14){.schemaVersion=1,.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1,.nativeHVISA=2,.expectedVMEpoch=817,.expectedPublicIdentity=100+id,.expectedOwnerThread=200+id,.expectedCPUGeneration=300+id};}
static VZKernelStatus Retain(void *p,const VZKernelRunPendingRequestV14 *q,void **out){(void)p;*out=(void *)(uintptr_t)q->expectedPublicIdentity;return VZ_KERNEL_OK;}
static VZKernelStatus Release(void *p,void *token){(void)p;CHECK(token!=NULL);return VZ_KERNEL_OK;}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q){Fixture *f=p;unsigned id=(unsigned)(q->expectedPublicIdentity-100);CHECK(id<4);atomic_fetch_add(&f->wakes[id],1);return (VZKernelStatus)atomic_load(&f->failures[id]);}
static VZKernelStatus Deadline(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t deadline){(void)p;(void)q;(void)arm;(void)deadline;return VZ_KERNEL_OK;}
static VZKernelStatus Quiet(void *p,const VZKernelRunPendingRequestV14 *q){(void)p;(void)q;return VZ_KERNEL_OK;}
static GICCPU *CPU(Fixture *f,unsigned id){for(unsigned n=0;n<4;++n)if(f->g->cpus[n].identity.expectedPublicIdentity==100+id)return &f->g->cpus[n];abort();}
static void *OwnCPU(void *p) {
 Worker *w=p;Fixture *f=w->fixture;VZKernelRunPendingRequestV14 q=ID(w->id);
 CHECK(VM27GICAttachCPUV1(f->g,&q,w->id)==VZ_KERNEL_OK);
 atomic_fetch_add_explicit(&f->attached,1,memory_order_release);
 while(atomic_load_explicit(&f->attached,memory_order_acquire)!=3)sched_yield();
 CHECK(VM27GICBeginRunV1(f->g,&q)==VZ_KERNEL_OK);
 atomic_fetch_add_explicit(&f->ready,1,memory_order_release);
 for(unsigned phase=1;phase<=4;++phase) {
  while(atomic_load_explicit(&f->snapshotCommand,memory_order_acquire)<phase)sched_yield();
  if(phase==1) {VM27GICLinesV1 lines={0};CHECK(VM27GICGetLinesV1(f->g,&q,&lines)==VZ_KERNEL_OK);CHECK(SnapshotOwnerV13(f->g,&q));}
  else if(phase<4)CHECK(SnapshotOwnerV13(f->g,&q));
  else CHECK(!SnapshotOwnerV13(f->g,&q));
  atomic_fetch_add_explicit(&f->snapshotAck,1,memory_order_release);
 }
 pthread_mutex_lock(&f->mutex);while(!f->stop)pthread_cond_wait(&f->condition,&f->mutex);pthread_mutex_unlock(&f->mutex);
 CHECK(VM27GICEndRunV1(f->g,&q)==VZ_KERNEL_OK);CHECK(VM27GICDetachCPUV1(f->g,&q)==VZ_KERNEL_OK);return NULL;
}
static void SnapshotPhase(Fixture *f,unsigned phase) {
 atomic_store_explicit(&f->snapshotCommand,phase,memory_order_release);
 while(atomic_load_explicit(&f->snapshotAck,memory_order_acquire)<phase*3)sched_yield();
}

static void Clear(Fixture *f){for(unsigned n=0;n<4;++n)atomic_store(&f->wakes[n],0);}
static void Counts(Fixture *f,unsigned a,unsigned b,unsigned c,unsigned d){static unsigned stage;++stage;unsigned expected[]={a,b,c,d};for(unsigned n=0;n<4;++n){if(atomic_load(&f->wakes[n])!=expected[n])fprintf(stderr,"stage%u cpu%u wakes actual=%u expected=%u\n",stage,n,atomic_load(&f->wakes[n]),expected[n]);CHECK(atomic_load(&f->wakes[n])==expected[n]);}CHECK(f->g->callbacks==0);for(unsigned n=0;n<4;++n)CHECK(f->g->cpus[n].callbacks==0);}
static void Write(Fixture *f,uint16_t reg,uint64_t value,VZKernelStatus expected){VZKernelRunPendingRequestV14 q=ID(0);CHECK(VM27GICICCRegV1(f->g,&q,reg,true,value,NULL)==expected);}
static void Ack(Fixture *f,uint32_t expected){VZKernelRunPendingRequestV14 q=ID(0);uint64_t value=UINT64_MAX;CHECK(VM27GICICCRegV1(f->g,&q,0xc660,false,0,&value)==VZ_KERNEL_OK);CHECK(value==expected);}
int main(void){
 Fixture f={0};CHECK(!pthread_mutex_init(&f.mutex,NULL));CHECK(!pthread_cond_init(&f.condition,NULL));
 VM27GICConfigV1 cfg={.schemaVersion=1,.maxCPUs=4,.ipaBits=36,.vmEpoch=817,.distributorBase=0x100000,.redistributorBase=0x200000};
 VM27GICBindingsV1 bindings={&f,Retain,Release,Wake,Deadline,Quiet};CHECK(VM27GICCreateV1(&cfg,&bindings,&f.g)==VZ_KERNEL_OK);
 VZKernelRunPendingRequestV14 source=ID(0);CHECK(VM27GICAttachCPUV1(f.g,&source,0)==VZ_KERNEL_OK);
 Worker workers[3];pthread_t threads[3];for(unsigned n=0;n<3;++n){workers[n]=(Worker){&f,n+1};CHECK(!pthread_create(&threads[n],NULL,OwnCPU,&workers[n]));}
 while(atomic_load_explicit(&f.ready,memory_order_acquire)!=3)sched_yield();
 CHECK(VM27GICBeginRunV1(f.g,&source)==VZ_KERNEL_OK);
 LockGIC(f.g);InvalidateSnapshotsV13(f.g);f.g->groupEnabled[0]=f.g->groupEnabled[1]=true;
 for(unsigned n=0;n<4;++n){GICCPU *c=&f.g->cpus[n];c->pmr=0xf8;c->groupEnabled[0]=c->groupEnabled[1]=true;for(unsigned id=1;id<=5;++id){c->privateIRQ[id].group1=id!=5;c->privateIRQ[id].priority=0x80;SetEnabledV7(f.g,n,id,true);}c->privateIRQ[1].latched=true;}
 CPU(&f,0)->privateIRQ[1].level=true;UnlockGIC(f.g);
 // Repeated local ICC writes and private EOI must not notify unrelated CPUs.
 SnapshotPhase(&f,1);
 uint64_t globalBefore=atomic_load(&f.g->stateGeneration);
 Clear(&f);for(unsigned n=0;n<20;++n){Write(&f,0xc230,0xf8,VZ_KERNEL_OK);Write(&f,0xc663,2,VZ_KERNEL_OK);Write(&f,0xc667,1,VZ_KERNEL_OK);Write(&f,0xc648,0,VZ_KERNEL_OK);}Counts(&f,0,0,0,0);CHECK(atomic_load(&f.g->stateGeneration)==globalBefore);SnapshotPhase(&f,2);
 Ack(&f,1);Write(&f,0xc661,1,VZ_KERNEL_OK);Counts(&f,0,0,0,0);CHECK(atomic_load(&f.g->stateGeneration)==globalBefore);SnapshotPhase(&f,3);
 // Outside Run, newly pending local SGI2 still requires its wake/error.
 LockGIC(f.g);InvalidateSnapshotsV13(f.g);CPU(&f,0)->privateIRQ[2].latched=true;UnlockGIC(f.g);
 CHECK(VM27GICEndRunV1(f.g,&source)==VZ_KERNEL_OK);Clear(&f);Write(&f,0xc230,0xf8,VZ_KERNEL_OK);Counts(&f,1,0,0,0);
 atomic_store(&f.failures[0],VZ_KERNEL_NATIVE_ERROR);Clear(&f);Write(&f,0xc230,0xf8,VZ_KERNEL_NATIVE_ERROR);Counts(&f,1,0,0,0);atomic_store(&f.failures[0],0);CHECK(VM27GICBeginRunV1(f.g,&source)==VZ_KERNEL_OK);
 Clear(&f);Write(&f,0xc65d,(UINT64_C(3)<<24)|(UINT64_C(1)<<2),VZ_KERNEL_OK);Counts(&f,0,0,1,0);CHECK(CPU(&f,2)->privateIRQ[3].latched&&!CPU(&f,1)->privateIRQ[3].latched&&!CPU(&f,3)->privateIRQ[3].latched);
 Clear(&f);Write(&f,0xc65d,(UINT64_C(4)<<24)|(UINT64_C(1)<<40),VZ_KERNEL_OK);Counts(&f,0,1,1,1);
 Clear(&f);Write(&f,0xc65f,(UINT64_C(5)<<24)|(UINT64_C(1)<<1),VZ_KERNEL_OK);Counts(&f,0,1,0,0);
 LockGIC(f.g);CPU(&f,3)->privateIRQ[3].group1=false;UnlockGIC(f.g);Clear(&f);Write(&f,0xc65d,(UINT64_C(3)<<24)|(UINT64_C(1)<<3),VZ_KERNEL_OK);Counts(&f,0,0,0,0);
 // Shared interrupt EOI retains the former all-attached notification policy.
 LockGIC(f.g);InvalidateSnapshotsV13(f.g);GICInterrupt *spi=&f.g->shared[40-32];spi->group1=true;spi->priority=0x10;spi->route=UINT64_C(1)<<31;spi->level=true;SetEnabledV7(f.g,0,40,true);UnlockGIC(f.g);
 Ack(&f,40);Clear(&f);Write(&f,0xc661,40,VZ_KERNEL_OK);Counts(&f,0,1,1,1);
 atomic_store(&f.failures[2],VZ_KERNEL_NATIVE_ERROR);Clear(&f);Write(&f,0xc65d,(UINT64_C(3)<<24)|(UINT64_C(1)<<2),VZ_KERNEL_NATIVE_ERROR);Counts(&f,0,0,1,0);atomic_store(&f.failures[2],0);
 SnapshotPhase(&f,4);
 CHECK(VM27GICEndRunV1(f.g,&source)==VZ_KERNEL_OK);pthread_mutex_lock(&f.mutex);f.stop=true;pthread_cond_broadcast(&f.condition);pthread_mutex_unlock(&f.mutex);for(unsigned n=0;n<3;++n)CHECK(!pthread_join(threads[n],NULL));CHECK(VM27GICDetachCPUV1(f.g,&source)==VZ_KERNEL_OK);CHECK(VM27GICDestroyV1(f.g)==VZ_KERNEL_OK);CHECK(!pthread_cond_destroy(&f.condition));CHECK(!pthread_mutex_destroy(&f.mutex));
 printf("four actual owner pthreads: local ICC/private EOI isolation, outside-Run wake, affinity/group/broadcast SGIs, shared EOI, callback pins/errors checks=%u PASS; native HV not executed\n",atomic_load(&checks));return 0;
}
