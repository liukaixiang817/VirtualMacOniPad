#include "modern_gic_deadline_scheduler_v1.h"
#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

typedef struct DeadlineEntry DeadlineEntry;
struct VM27GICDeadlineSchedulerV1 {
 pthread_mutex_t mutex;
 pthread_cond_t changed;
 dispatch_queue_t queue;
 pthread_t owner;
 uint64_t epoch;
 VM27GICDeadlineBindingsV1 binding;
 DeadlineEntry *entries;
};
struct DeadlineEntry {
 DeadlineEntry *next;
 VM27GICDeadlineSchedulerV1 *scheduler;
 VZKernelRunPendingRequestV14 identity;
 pthread_t owner;
 dispatch_source_t source;
 uint64_t deadline;
 unsigned callbacks;
 VZKernelStatus asynchronousStatus;
 bool armed,closing,cancelled;
};
static void LockDeadline(VM27GICDeadlineSchedulerV1 *s) {if(pthread_mutex_lock(&s->mutex))abort();}
static void UnlockDeadline(VM27GICDeadlineSchedulerV1 *s) {if(pthread_mutex_unlock(&s->mutex))abort();}
static bool SeparateDeadline(const void *a,size_t an,const void *b,size_t bn) {
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 return x && y && an<=UINTPTR_MAX-x && bn<=UINTPTR_MAX-y && (x+an<=y || y+bn<=x);
}
static bool SameDeadlineIdentity(const VZKernelRunPendingRequestV14 *a,const VZKernelRunPendingRequestV14 *b) {
 return a->schemaVersion==b->schemaVersion && a->validatedKernelProfile==b->validatedKernelProfile &&
  a->nativeHVISA==b->nativeHVISA && a->reserved==b->reserved && a->expectedVMEpoch==b->expectedVMEpoch &&
  a->expectedPublicIdentity==b->expectedPublicIdentity && a->expectedOwnerThread==b->expectedOwnerThread &&
  a->expectedCPUGeneration==b->expectedCPUGeneration && a->expectedReturnedSlotWord==b->expectedReturnedSlotWord;
}
static bool ShapeDeadline(VM27GICDeadlineSchedulerV1 *s,const VZKernelRunPendingRequestV14 *q) {
 return q->schemaVersion==1 && q->validatedKernelProfile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  (q->nativeHVISA==1 || q->nativeHVISA==2) && !q->reserved && q->expectedVMEpoch==s->epoch &&
  q->expectedPublicIdentity && q->expectedOwnerThread && q->expectedCPUGeneration;
}
static DeadlineEntry *FindDeadline(VM27GICDeadlineSchedulerV1 *s,const VZKernelRunPendingRequestV14 *q) {
 for(DeadlineEntry *e=s->entries;e;e=e->next)if(e->identity.expectedPublicIdentity==q->expectedPublicIdentity)return e;
 return NULL;
}
static void DeadlineFired(void *context) {
 DeadlineEntry *e=context;VM27GICDeadlineSchedulerV1 *s=e->scheduler;
 LockDeadline(s);
 if(e->closing || !e->armed || e->asynchronousStatus!=VZ_KERNEL_OK){UnlockDeadline(s);return;}
 ++e->callbacks;uint64_t deadline=e->deadline;VZKernelRunPendingRequestV14 q=e->identity;
 UnlockDeadline(s);
 uint64_t now=0,frequency=0,delay=0;bool sampled=s->binding.readCounter(s->binding.clockContext,&now);
 bool early=sampled && now<deadline;
 VZKernelStatus sampleStatus=sampled?VZ_KERNEL_OK:VZ_KERNEL_CONTEXT_UNREADABLE;
 if(early) {
  if(!s->binding.readFrequency(s->binding.clockContext,&frequency) || !frequency)
   sampleStatus=VZ_KERNEL_CONTEXT_UNREADABLE;
  else {
   __uint128_t ns=((__uint128_t)(deadline-now)*UINT64_C(1000000000)+frequency-1)/frequency;
   if(ns>INT64_MAX)sampleStatus=VZ_KERNEL_UNSUPPORTED;else delay=(uint64_t)ns;
  }
 }
 LockDeadline(s);
 // A queued old event must not wake an entry that has been cancelled or moved
 // to a new future deadline. Compare the current counter and current deadline.
 bool current=!e->closing && e->armed && e->deadline==deadline;
 bool wake=current && (sampleStatus!=VZ_KERNEL_OK || now>=e->deadline);
 if(current && sampleStatus!=VZ_KERNEL_OK)e->asynchronousStatus=sampleStatus;
 if(early && current && sampleStatus==VZ_KERNEL_OK)
  dispatch_source_set_timer(e->source,dispatch_time(DISPATCH_TIME_NOW,(int64_t)delay),DISPATCH_TIME_FOREVER,0);
 if(wake)e->armed=false;
 UnlockDeadline(s);
 VZKernelStatus status=wake?s->binding.wakeCPU(s->binding.wakeContext,&q):VZ_KERNEL_OK;
 LockDeadline(s);
 if(status!=VZ_KERNEL_OK && e->asynchronousStatus==VZ_KERNEL_OK)e->asynchronousStatus=status;
 --e->callbacks;if(pthread_cond_broadcast(&s->changed))abort();UnlockDeadline(s);
}
static void DeadlineCancelled(void *context) {
 DeadlineEntry *e=context;VM27GICDeadlineSchedulerV1 *s=e->scheduler;
 LockDeadline(s);e->cancelled=true;if(pthread_cond_broadcast(&s->changed))abort();UnlockDeadline(s);
 // No access to e or s occurs after releasing the mutex. Owner drain may now
 // release this source/entry; libdispatch retains its executing handler.
}
VZKernelStatus VM27GICDeadlineCreateV1(uint64_t epoch,const VM27GICDeadlineBindingsV1 *input,
 VM27GICDeadlineSchedulerV1 **out) {
 if(!epoch || !input || !out || !SeparateDeadline(input,sizeof(*input),out,sizeof(*out)))return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICDeadlineBindingsV1 b=*input;
 if(!b.readCounter || !b.readFrequency || !b.wakeCPU)return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICDeadlineSchedulerV1 *s=calloc(1,sizeof(*s));if(!s)return VZ_KERNEL_OUT_OF_MEMORY;
 if(pthread_mutex_init(&s->mutex,NULL)){free(s);return VZ_KERNEL_OUT_OF_MEMORY;}
 if(pthread_cond_init(&s->changed,NULL)){pthread_mutex_destroy(&s->mutex);free(s);return VZ_KERNEL_OUT_OF_MEMORY;}
 s->queue=dispatch_queue_create("VirtualMac.independent27.physical-timer",DISPATCH_QUEUE_SERIAL);
 if(!s->queue){pthread_cond_destroy(&s->changed);pthread_mutex_destroy(&s->mutex);free(s);return VZ_KERNEL_OUT_OF_MEMORY;}
 s->epoch=epoch;s->binding=b;s->owner=pthread_self();*out=s;return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICDeadlineScheduleV1(void *context,const VZKernelRunPendingRequestV14 *input,
 bool arm,uint64_t deadline) {
 VM27GICDeadlineSchedulerV1 *s=context;if(!s || !input)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelRunPendingRequestV14 q=*input;if(!ShapeDeadline(s,&q))return VZ_KERNEL_BAD_ARGUMENT;
 uint64_t now=0,frequency=0,delay=0;
 if(arm) {
  if(!s->binding.readCounter(s->binding.clockContext,&now) ||
   !s->binding.readFrequency(s->binding.clockContext,&frequency) || !frequency)return VZ_KERNEL_CONTEXT_UNREADABLE;
  uint64_t ticks=deadline>now?deadline-now:0;
  __uint128_t numerator=(__uint128_t)ticks*UINT64_C(1000000000)+frequency-1;
  __uint128_t ns=numerator/frequency;
  if(ns>INT64_MAX)return VZ_KERNEL_UNSUPPORTED;
  delay=(uint64_t)ns;
 }
 LockDeadline(s);DeadlineEntry *e=FindDeadline(s,&q);
 if(e && (!SameDeadlineIdentity(&q,&e->identity) || !pthread_equal(e->owner,pthread_self())))
  {UnlockDeadline(s);return VZ_KERNEL_WRONG_THREAD;}
 if(e && (e->closing || e->asynchronousStatus!=VZ_KERNEL_OK)) {
  VZKernelStatus status=e->closing?VZ_KERNEL_NOT_LIVE:e->asynchronousStatus;
  UnlockDeadline(s);return status;
 }
 if(!e) {
  e=calloc(1,sizeof(*e));if(!e){UnlockDeadline(s);return VZ_KERNEL_OUT_OF_MEMORY;}
  e->scheduler=s;e->identity=q;e->owner=pthread_self();
  e->source=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,s->queue);
  if(!e->source){free(e);UnlockDeadline(s);return VZ_KERNEL_OUT_OF_MEMORY;}
  dispatch_set_context(e->source,e);
  dispatch_source_set_event_handler_f(e->source,DeadlineFired);
  dispatch_source_set_cancel_handler_f(e->source,DeadlineCancelled);
  dispatch_source_set_timer(e->source,DISPATCH_TIME_FOREVER,DISPATCH_TIME_FOREVER,0);
  e->next=s->entries;s->entries=e;dispatch_resume(e->source);
 }
 e->deadline=deadline;e->armed=arm;
 dispatch_source_set_timer(e->source,arm?dispatch_time(DISPATCH_TIME_NOW,(int64_t)delay):DISPATCH_TIME_FOREVER,
  DISPATCH_TIME_FOREVER,0);
 UnlockDeadline(s);return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICDeadlineDrainV1(void *context,const VZKernelRunPendingRequestV14 *input) {
 VM27GICDeadlineSchedulerV1 *s=context;if(!s || !input)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelRunPendingRequestV14 q=*input;if(!ShapeDeadline(s,&q))return VZ_KERNEL_BAD_ARGUMENT;
 LockDeadline(s);DeadlineEntry *e=FindDeadline(s,&q);
 if(!e){UnlockDeadline(s);return VZ_KERNEL_OK;} // no source has ever been armed for this validated identity
 if(!SameDeadlineIdentity(&q,&e->identity) || !pthread_equal(e->owner,pthread_self()))
  {UnlockDeadline(s);return VZ_KERNEL_WRONG_THREAD;}
 bool cancel=!e->closing;e->closing=true;e->armed=false;UnlockDeadline(s);
 if(cancel)dispatch_source_cancel(e->source);
 struct timespec until;if(clock_gettime(CLOCK_REALTIME,&until))return VZ_KERNEL_NATIVE_ERROR;
 ++until.tv_sec;
 LockDeadline(s);
 while(!e->cancelled || e->callbacks) {
  int error=pthread_cond_timedwait(&s->changed,&s->mutex,&until);
  if(error==ETIMEDOUT){UnlockDeadline(s);return VZ_KERNEL_BUSY;}
  if(error){UnlockDeadline(s);return VZ_KERNEL_NATIVE_ERROR;}
 }
 DeadlineEntry **link=&s->entries;while(*link && *link!=e)link=&(*link)->next;
 if(!*link)abort();*link=e->next;UnlockDeadline(s);
 dispatch_release(e->source);memset(e,0,sizeof(*e));free(e);return VZ_KERNEL_OK;
}
VZKernelStatus VM27GICDeadlineDestroyV1(VM27GICDeadlineSchedulerV1 *s) {
 if(!s)return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(s->owner,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 LockDeadline(s);bool busy=s->entries!=NULL;UnlockDeadline(s);
 if(busy)return VZ_KERNEL_BUSY;
 if(pthread_cond_destroy(&s->changed) || pthread_mutex_destroy(&s->mutex))return VZ_KERNEL_BUSY;
 dispatch_release(s->queue);memset(s,0,sizeof(*s));free(s);return VZ_KERNEL_OK;
}
bool VM27GICDeadlineOutputDisjointV1(VM27GICDeadlineSchedulerV1 *s,const void *p,size_t bytes) {
 if(!s || !p || !bytes || bytes>UINTPTR_MAX-(uintptr_t)p)return false;
 LockDeadline(s);bool valid=SeparateDeadline(p,bytes,s,sizeof(*s));
 for(DeadlineEntry *e=s->entries;e && valid;e=e->next)valid=SeparateDeadline(p,bytes,e,sizeof(*e));
 UnlockDeadline(s);return valid;
}
