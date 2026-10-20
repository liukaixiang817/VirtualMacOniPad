#ifndef VM27_CPU_WFX_WAIT_V30_H
#define VM27_CPU_WFX_WAIT_V30_H
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

/* An owned CPU wait, separate from GICR_WAKER. The generation closes a wake
 * between observing pending interrupts and actually entering cond_wait. */
typedef struct {
 pthread_mutex_t mutex;
 pthread_cond_t changed;
 uint64_t sequence,armedSequence;
 bool armed;
 VZKernelStatus asynchronousStatus;
} VM27WFxWaitV30;
typedef VZKernelStatus (*VM27WFxPollV30)(void *,bool *);
static VZKernelStatus VM27WFxInitV30(VM27WFxWaitV30 *w) {
 if(pthread_mutex_init(&w->mutex,NULL))return VZ_KERNEL_OUT_OF_MEMORY;
 if(pthread_cond_init(&w->changed,NULL)) {
  pthread_mutex_destroy(&w->mutex);return VZ_KERNEL_OUT_OF_MEMORY;
 }
 return VZ_KERNEL_OK;
}
static VZKernelStatus VM27WFxDestroyV30(VM27WFxWaitV30 *w) {
 if(pthread_cond_destroy(&w->changed) || pthread_mutex_destroy(&w->mutex))return VZ_KERNEL_BUSY;
 return VZ_KERNEL_OK;
}
static VZKernelStatus VM27WFxSignalV30(VM27WFxWaitV30 *w,VZKernelStatus status) {
 if(pthread_mutex_lock(&w->mutex))return VZ_KERNEL_NATIVE_ERROR;
 if(w->asynchronousStatus==VZ_KERNEL_OK && status!=VZ_KERNEL_OK)w->asynchronousStatus=status;
 if(w->sequence==UINT64_MAX)w->asynchronousStatus=VZ_KERNEL_BUSY;else ++w->sequence;
 int error=pthread_cond_broadcast(&w->changed);
 if(error && w->asynchronousStatus==VZ_KERNEL_OK)w->asynchronousStatus=VZ_KERNEL_NATIVE_ERROR;
 VZKernelStatus result=w->asynchronousStatus;
 pthread_mutex_unlock(&w->mutex);return result;
}
static VZKernelStatus VM27WFxArmV30(VM27WFxWaitV30 *w,VM27WFxPollV30 pending,void *context) {
 if(pthread_mutex_lock(&w->mutex))return VZ_KERNEL_NATIVE_ERROR;
 bool ready=false;VZKernelStatus status=pending(context,&ready);
 if(status==VZ_KERNEL_OK)status=w->asynchronousStatus;
 if(status==VZ_KERNEL_OK){w->armed=!ready;w->armedSequence=w->sequence;}
 pthread_mutex_unlock(&w->mutex);return status;
}
static VZKernelStatus VM27WFxAwaitV30(VM27WFxWaitV30 *w,VM27WFxPollV30 poll,void *context) {
 for(;;) {
  if(pthread_mutex_lock(&w->mutex))return VZ_KERNEL_NATIVE_ERROR;
  bool armed=w->armed;VZKernelStatus previous=w->asynchronousStatus;
  pthread_mutex_unlock(&w->mutex);
  if(previous!=VZ_KERNEL_OK || !armed)return previous;
  bool ready=false;VZKernelStatus status=poll(context,&ready);
  if(status!=VZ_KERNEL_OK)return status;
  if(pthread_mutex_lock(&w->mutex))return VZ_KERNEL_NATIVE_ERROR;
  status=w->asynchronousStatus;
  if(status!=VZ_KERNEL_OK || !w->armed || ready || w->sequence!=w->armedSequence) {
   w->armed=false;pthread_mutex_unlock(&w->mutex);return status;
  }
  /* The real physical-timer scheduler signals this condition at its deadline.
   * This one-second maintenance bound revalidates ownership and timer errors;
   * its timeout never causes another native entry or a fabricated interrupt. */
  struct timespec until;
  if(clock_gettime(CLOCK_REALTIME,&until) || until.tv_sec==LONG_MAX) {
   pthread_mutex_unlock(&w->mutex);return VZ_KERNEL_NATIVE_ERROR;
  }
  ++until.tv_sec;
  int error=pthread_cond_timedwait(&w->changed,&w->mutex,&until);
  pthread_mutex_unlock(&w->mutex);
  if(error && error!=ETIMEDOUT)return VZ_KERNEL_NATIVE_ERROR;
 }
}
#endif
