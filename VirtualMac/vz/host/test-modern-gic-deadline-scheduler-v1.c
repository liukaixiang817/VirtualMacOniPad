#include "modern_gic_deadline_scheduler_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>

static unsigned checks;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"deadline check %u failed line %d: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
typedef struct {
 pthread_mutex_t mutex;
 pthread_cond_t changed;
 _Atomic bool failRead,failWake;
 _Atomic uint64_t earlyCounter;
 unsigned wakes,failedSamples,counterReads;
 bool early;
} Clock;
static bool Counter(void *p,uint64_t *out) {
 Clock *c=p;
 pthread_mutex_lock(&c->mutex);++c->counterReads;pthread_cond_broadcast(&c->changed);pthread_mutex_unlock(&c->mutex);
 if(atomic_load(&c->failRead)) {
  pthread_mutex_lock(&c->mutex);++c->failedSamples;pthread_cond_broadcast(&c->changed);pthread_mutex_unlock(&c->mutex);
  return false;
 }
 if(c->early){*out=atomic_load(&c->earlyCounter);return true;}
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return false;
 *out=(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;return true;
}
static bool Frequency(void *p,uint64_t *out) {(void)p;*out=UINT64_C(1000000000);return true;}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q) {
 Clock *c=p;if(q->expectedVMEpoch!=17 || q->expectedPublicIdentity!=81)return VZ_KERNEL_BAD_ARGUMENT;
 pthread_mutex_lock(&c->mutex);++c->wakes;pthread_cond_broadcast(&c->changed);pthread_mutex_unlock(&c->mutex);
 return atomic_load(&c->failWake)?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
}
static bool Wait(Clock *c,unsigned count,unsigned event) {
 struct timespec until;if(clock_gettime(CLOCK_REALTIME,&until))return false;++until.tv_sec;
 pthread_mutex_lock(&c->mutex);
 while((event==2?c->counterReads:event==1?c->failedSamples:c->wakes)<count) {
  int error=pthread_cond_timedwait(&c->changed,&c->mutex,&until);
  if(error){pthread_mutex_unlock(&c->mutex);return false;}
 }
 pthread_mutex_unlock(&c->mutex);return true;
}
static VZKernelStatus AwaitSticky(VM27GICDeadlineSchedulerV1 *s,
 const VZKernelRunPendingRequestV14 *q) {
 struct timespec start,now,pause={0,1000000};
 if(clock_gettime(CLOCK_MONOTONIC,&start))return VZ_KERNEL_NATIVE_ERROR;
 for(;;) {
  VZKernelStatus status=VM27GICDeadlineScheduleV1(s,q,false,0);
  if(status!=VZ_KERNEL_OK)return status;
  if(clock_gettime(CLOCK_MONOTONIC,&now))return VZ_KERNEL_NATIVE_ERROR;
  if(now.tv_sec-start.tv_sec>1)return VZ_KERNEL_BUSY;
  nanosleep(&pause,NULL);
 }
}
typedef struct {VM27GICDeadlineSchedulerV1 *s;VZKernelRunPendingRequestV14 q;VZKernelStatus status;} Foreign;
static void *ForeignDrain(void *p) {Foreign *f=p;f->status=VM27GICDeadlineDrainV1(f->s,&f->q);return NULL;}
int main(void) {
 Clock c={.mutex=PTHREAD_MUTEX_INITIALIZER,.changed=PTHREAD_COND_INITIALIZER};
 VZKernelRunPendingRequestV14 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,17,81,9020,9,0};
 VM27GICDeadlineBindingsV1 b={&c,&c,Counter,Frequency,Wake};VM27GICDeadlineSchedulerV1 *s=NULL;
 CHECK(VM27GICDeadlineCreateV1(17,&b,&s)==VZ_KERNEL_OK);CHECK(s!=NULL);
 CHECK(!VM27GICDeadlineOutputDisjointV1(s,s,1));CHECK(VM27GICDeadlineOutputDisjointV1(s,&q,sizeof(q)));
 uint64_t now=0;CHECK(Counter(&c,&now));
 CHECK(VM27GICDeadlineScheduleV1(s,&q,true,now+UINT64_C(1000000))==VZ_KERNEL_OK);
 CHECK(Wait(&c,1,false));CHECK(c.wakes==1);
 CHECK(VM27GICDeadlineDestroyV1(s)==VZ_KERNEL_BUSY);
 VZKernelRunPendingRequestV14 bad=q;bad.expectedCPUGeneration++;
 CHECK(VM27GICDeadlineScheduleV1(s,&bad,false,0)==VZ_KERNEL_WRONG_THREAD);
 Foreign f={s,q,VZ_KERNEL_OK};pthread_t thread;CHECK(!pthread_create(&thread,NULL,ForeignDrain,&f));
 CHECK(!pthread_join(thread,NULL));CHECK(f.status==VZ_KERNEL_WRONG_THREAD);
 CHECK(VM27GICDeadlineScheduleV1(s,&q,false,0)==VZ_KERNEL_OK);
 CHECK(VM27GICDeadlineDrainV1(s,&q)==VZ_KERNEL_OK);
 CHECK(VM27GICDeadlineDrainV1(s,&q)==VZ_KERNEL_OK);
 // Arm first against a genuinely early counter. The real dispatch event must
 // re-arm rather than lose the deadline when the sampled counter is early.
 c.early=true;atomic_store(&c.earlyCounter,0);
 CHECK(VM27GICDeadlineScheduleV1(s,&q,true,UINT64_C(1000000))==VZ_KERNEL_OK);
 pthread_mutex_lock(&c.mutex);unsigned reads=c.counterReads;pthread_mutex_unlock(&c.mutex);
 CHECK(Wait(&c,reads+1,2));
 atomic_store(&c.earlyCounter,UINT64_C(1000000));CHECK(Wait(&c,2,false));
 CHECK(VM27GICDeadlineDrainV1(s,&q)==VZ_KERNEL_OK);
 // A failed asynchronous wake is sticky and propagates to the next owner
 // poll. The error is not silently interpreted as timer delivery success.
 c.early=false;atomic_store(&c.failWake,true);CHECK(Counter(&c,&now));
 CHECK(VM27GICDeadlineScheduleV1(s,&q,true,now+UINT64_C(1000000))==VZ_KERNEL_OK);
 CHECK(Wait(&c,3,false));
 CHECK(AwaitSticky(s,&q)==VZ_KERNEL_NATIVE_ERROR);
 // Drain also synchronizes with the callback's final stored status.
 CHECK(VM27GICDeadlineDrainV1(s,&q)==VZ_KERNEL_OK);atomic_store(&c.failWake,false);
 // A counter failure on the actual dispatch thread wakes the owner to report
 // the sticky error. It cannot leave a blocked native Run waiting forever.
 CHECK(Counter(&c,&now));
 CHECK(VM27GICDeadlineScheduleV1(s,&q,true,now+UINT64_C(10000000))==VZ_KERNEL_OK);
 atomic_store(&c.failRead,true);
 CHECK(Wait(&c,4,false));CHECK(Wait(&c,1,true));
 CHECK(AwaitSticky(s,&q)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(VM27GICDeadlineDrainV1(s,&q)==VZ_KERNEL_OK);
 atomic_store(&c.failRead,true);
 CHECK(VM27GICDeadlineScheduleV1(s,&q,true,now+UINT64_C(1000000))==VZ_KERNEL_CONTEXT_UNREADABLE);
 atomic_store(&c.failRead,false);
 CHECK(VM27GICDeadlineDestroyV1(s)==VZ_KERNEL_OK);
 CHECK(!pthread_cond_destroy(&c.changed));CHECK(!pthread_mutex_destroy(&c.mutex));
 printf("{\"checks\":%u,\"realDispatchTimersPassed\":true,\"hostWakeCallbacks\":%u,\"deviceExecuted\":false,\"native10Executed\":false}\n",checks,c.wakes);
 return 0;
}
