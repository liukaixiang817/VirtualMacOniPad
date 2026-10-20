// Every native trap is a host mock. Actual pthread ownership is exercised.
#include "modern_cpu_kernel_lifecycle_v25.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
#define BUSY ((int32_t)UINT32_C(0xfae94002))
typedef struct Worker Worker;
typedef struct {VZKernelVM *vm;uint64_t liveMask;unsigned creates,destroys;pthread_mutex_t mutex;unsigned char memory[64][0x8000];} Mock;
struct Worker {Mock *mock;pthread_t thread;pthread_mutex_t mutex;pthread_cond_t condition;VZKernelCPU *cpu;VZKernelLifecycleResult result;unsigned command,done;bool failCreate,failDestroy,badVersion;uint64_t slot;int status;};
static _Thread_local Worker *Current;
static uint64_t Thread(void *unused){(void)unused;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t;}
static int32_t Trap(void *opaque,uint64_t op,void *argument){Mock *m=opaque;if(op==1||op==2)return 0;CHECK(Current&&Current->mock==m);Worker *w=Current;
 CHECK(!pthread_mutex_lock(&m->mutex));
 if(op==6){++m->creates;uint64_t *packet=argument;CHECK(packet&&packet[0]<64&&!packet[1]);w->slot=packet[0];
  if(w->failCreate){CHECK(!pthread_mutex_unlock(&m->mutex));return BUSY;}
  CHECK(!(m->liveMask&(UINT64_C(1)<<w->slot)));m->liveMask|=UINT64_C(1)<<w->slot;
  uint64_t version=w->badVersion?0:VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->memory[w->slot]+0x4000,&version,8);packet[1]=(uintptr_t)m->memory[w->slot];
 }else{CHECK(op==7&&!argument);++m->destroys;CHECK(m->liveMask&(UINT64_C(1)<<w->slot));if(w->failDestroy){CHECK(!pthread_mutex_unlock(&m->mutex));return BUSY;}m->liveMask&=~(UINT64_C(1)<<w->slot);}
 CHECK(!pthread_mutex_unlock(&m->mutex));return 0;
}
static bool Read(void *opaque,const void *p,size_t n,void *out){Mock *m=opaque;uintptr_t a=(uintptr_t)p,b=(uintptr_t)m->memory;CHECK(a>=b&&n<=sizeof(m->memory)&&a-b<=sizeof(m->memory)-n);memcpy(out,p,n);return true;}
static void *Work(void *opaque){Worker *w=opaque;Current=w;CHECK(!pthread_mutex_lock(&w->mutex));for(;;){while(!w->command)CHECK(!pthread_cond_wait(&w->condition,&w->mutex));unsigned command=w->command;w->command=0;CHECK(!pthread_mutex_unlock(&w->mutex));
 if(command==1)w->status=VZKernelCPUCreate(w->mock->vm,&w->cpu,&w->result);
 else if(command==2){w->status=VZKernelCPUDestroy(w->cpu,&w->result);if(!w->status){CHECK(!VZKernelCPUFree(w->cpu));w->cpu=NULL;}}
 else if(command==3)w->status=VZKernelCPUContextVersion(w->cpu,&w->result);
 else CHECK(command==4&&!w->cpu);
 CHECK(!pthread_mutex_lock(&w->mutex));w->done=command;CHECK(!pthread_cond_broadcast(&w->condition));if(command==4)break;
 }CHECK(!pthread_mutex_unlock(&w->mutex));return NULL;}
static void StartWorker(Worker *w,Mock *m){memset(w,0,sizeof(*w));w->mock=m;CHECK(!pthread_mutex_init(&w->mutex,NULL));CHECK(!pthread_cond_init(&w->condition,NULL));CHECK(!pthread_create(&w->thread,NULL,Work,w));}
static void Command(Worker *w,unsigned command){CHECK(!pthread_mutex_lock(&w->mutex));w->done=0;w->command=command;CHECK(!pthread_cond_broadcast(&w->condition));while(w->done!=command)CHECK(!pthread_cond_wait(&w->condition,&w->mutex));CHECK(!pthread_mutex_unlock(&w->mutex));}
static void StopWorker(Worker *w){Command(w,4);CHECK(!pthread_join(w->thread,NULL));CHECK(!pthread_cond_destroy(&w->condition));CHECK(!pthread_mutex_destroy(&w->mutex));}
int main(void){Mock *m=calloc(1,sizeof(*m));CHECK(m);CHECK(!pthread_mutex_init(&m->mutex,NULL));VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,Read};VZKernelVMOptions options={36,0,1,false,false};VZKernelLifecycleResult life={0};CHECK(!VZKernelVMCreate(&ops,&options,&m->vm,&life));Worker w[65];for(unsigned i=0;i<65;++i)StartWorker(&w[i],m);
 for(unsigned i=0;i<4;++i){Command(&w[i],1);CHECK(!w[i].status&&w[i].slot==i&&w[i].result.requestedSlot==i&&w[i].result.returnedSlotWord==i);Command(&w[i],3);CHECK(!w[i].status&&w[i].result.requestedSlot==i&&w[i].result.returnedSlotWord==i);}
 w[1].failDestroy=true;Command(&w[1],2);CHECK(w[1].status==VZ_KERNEL_NATIVE_ERROR&&w[1].result.nativeReturn==BUSY&&w[1].result.cpuLive);
 w[4].failCreate=true;Command(&w[4],1);CHECK(w[4].status==VZ_KERNEL_NATIVE_ERROR&&w[4].result.nativeReturn==BUSY&&!w[4].cpu&&w[4].slot==4);
 w[4].failCreate=false;w[4].badVersion=true;Command(&w[4],1);CHECK(w[4].status==VZ_KERNEL_CONTEXT_VERSION_MISMATCH&&w[4].cpu&&w[4].slot==4&&w[4].result.cleanupPending);
 Command(&w[5],1);CHECK(!w[5].status&&w[5].slot==5);Command(&w[4],2);CHECK(!w[4].status);w[4].badVersion=false;Command(&w[6],1);CHECK(!w[6].status&&w[6].slot==4);
 w[1].failDestroy=false;Command(&w[1],2);CHECK(!w[1].status);Command(&w[4],1);CHECK(!w[4].status&&w[4].slot==1);
 for(unsigned i=7;i<65;++i){Command(&w[i],1);CHECK(!w[i].status&&w[i].slot==i-1);}
 unsigned creates=m->creates;Command(&w[1],1);CHECK(w[1].status==VZ_KERNEL_BUSY&&!w[1].cpu&&m->creates==creates&&m->liveMask==UINT64_MAX);
 for(unsigned i=0;i<65;++i){if(w[i].cpu){Command(&w[i],2);CHECK(!w[i].status);}StopWorker(&w[i]);}CHECK(!m->liveMask);CHECK(!VZKernelVMDestroy(m->vm,&life));CHECK(!VZKernelVMFree(m->vm));CHECK(!pthread_mutex_destroy(&m->mutex));free(m);
 puts("{\"fourDistinctOwnerCPUs\":true,\"slots0Through63\":true,\"failedCreateReleased\":true,\"failedDestroyReserved\":true,\"incompleteCreationReserved\":true,\"reuseOnlyAfterNativeDestroyZero\":true,\"full64NoNativeCall\":true,\"allWorkersJoined\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");return 0;}
