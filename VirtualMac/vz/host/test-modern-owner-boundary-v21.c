/* Four actual owner pthreads exercise the real lifecycle helpers. Native HV
 * is never reported as executed by this host-only boundary test. */
#include "modern_cpu_production_native_ops_v21_owner_boundary.c"
#include "modern_cpu_kernel_lifecycle_v75.c"
static _Atomic unsigned checks;
#define CHECK(x) do{atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}}while(0)
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *p){(void)op;(void)p;abort();}
static VZKernelVM testVM;
static _Thread_local unsigned genericCalls;
static uint64_t GenericThread(void *p){++genericCalls;return ProductionThreadV1(p);}
static void *Worker(void *argument) {
 unsigned slot=(unsigned)(uintptr_t)argument;
 void *memory=NULL;CHECK(!posix_memalign(&memory,0x4000,0x8000));memset(memory,0,0x8000);
 uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy((char *)memory+0x4000,&version,8);
 uint64_t thread=ProductionThreadV1(NULL);CHECK(thread);
 VZKernelCPU cpu={.vm=&testVM,.owner=thread,.generation=slot+1,.nativeContext=(uintptr_t)memory,
  .requestedSlot=slot,.returnedSlot=slot,.live=true,.creationPolicySliceComplete=true,
  .creationConfigComplete=true,.runToken=23,.runPostReturnActive=true};
 VZKernelCPURegistryEntryV5 entry={.cpu=&cpu,.vmEpoch=testVM.generation,.cpuGeneration=cpu.generation,
  .ownerPthread=pthread_self(),.publicIdentity=slot+42,.identityIssued=true,.published=true,.creationComplete=true};
 cpu.registryEntry=&entry;atomic_init(&cpu.operationInProgress,true);OwnedCPU=&cpu;
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t bytes=pthread_get_stacksize_np(pthread_self());
 CHECK(VM27CPUOwnedMappingPublishV1(slot,(uintptr_t)&cpu,thread,cpu.nativeContext,3,3,top-bytes,bytes,true));
 VZKernelRunPendingRequestV14 q={1,testVM.ops.validatedKernelProfile,testVM.nativeHVISA,0,
  testVM.generation,entry.publicIdentity,thread,cpu.generation,cpu.returnedSlot};
 VZKernelInitWriter writer={&ProductionV1,ProductionWriteV1};
 for(unsigned i=0;i<200;++i) {
  CHECK(PendingRequestOwnedV14(&cpu,&q)==VZ_KERNEL_OK);
  VZKernelLifecycleResult before={0},after={0};CHECK(Version(&cpu,&before)==VZ_KERNEL_OK);
  InitializationAccess access={&cpu,&writer,&after,VZ_KERNEL_OK};CHECK(InitializationOwned(&access));
  CHECK(!memcmp(&before,&after,sizeof(before)));
  memset(&after,0,sizeof(after));RunPostAccessV7 post={&cpu,testVM.generation,cpu.generation,thread,23,&after,VZ_KERNEL_OK};
  CHECK(RunPostOwnedV7(&post));CHECK(!memcmp(&before,&after,sizeof(before)));
 }
 entry.published=false;CHECK(PendingRequestOwnedV14(&cpu,&q)==VZ_KERNEL_NOT_LIVE);entry.published=true;
 entry.draining=true;CHECK(PendingRequestOwnedV14(&cpu,&q)==VZ_KERNEL_NOT_LIVE);entry.draining=false;
 entry.creationComplete=false;CHECK(PendingRequestOwnedV14(&cpu,&q)==VZ_KERNEL_NOT_LIVE);entry.creationComplete=true;
 ++q.expectedCPUGeneration;CHECK(PendingRequestOwnedV14(&cpu,&q)==VZ_KERNEL_BAD_ARGUMENT);--q.expectedCPUGeneration;
 VZKernelLifecycleResult lifecycle={0};InitializationAccess access={&cpu,&writer,&lifecycle,VZ_KERNEL_OK};
 version=0;memcpy((char *)memory+0x4000,&version,8);CHECK(!InitializationOwned(&access));
 CHECK(access.boundaryStatus==VZ_KERNEL_CONTEXT_VERSION_MISMATCH && lifecycle.nativeContextVersionRead && !lifecycle.nativeContextVersion);
 version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy((char *)memory+0x4000,&version,8);
 RunPostAccessV7 post={&cpu,testVM.generation,cpu.generation,thread,24,&lifecycle,VZ_KERNEL_OK};
 CHECK(!RunPostOwnedV7(&post) && post.status==VZ_KERNEL_NOT_LIVE);
 ++cpu.owner;CHECK(!InitializationOwned(&access) && access.boundaryStatus==VZ_KERNEL_WRONG_THREAD);--cpu.owner;
 /* An arbitrary callback must still execute the original boundary path. */
 VZKernelVM generic={0};generic.ops=testVM.ops;generic.ops.currentThread=GenericThread;
 generic.live=true;generic.generation=testVM.generation;generic.nativeHVISA=2;cpu.vm=&generic;
 CHECK(!VM27ProductionOwnerBoundaryEligibleV21(&generic.ops));CHECK(InitializationOwned(&access));CHECK(genericCalls==1);
 cpu.vm=&testVM;VM27CPUOwnedMappingWithdrawV1(slot,(uintptr_t)&cpu,NULL);OwnedCPU=NULL;free(memory);return NULL;
}
int main(void) {
 testVM.ops=(VZKernelLifecycleOps){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&ProductionV1,ProductionNativeV1,ProductionThreadV1,ProductionReadV1};
 testVM.live=true;testVM.generation=17;testVM.nativeHVISA=2;
 CHECK(!pthread_mutex_init(&testVM.mutex,NULL));CHECK(!pthread_mutex_lock(&testVM.mutex));
 pthread_t workers[4];for(unsigned i=0;i<4;++i)CHECK(!pthread_create(&workers[i],NULL,Worker,(void *)(uintptr_t)i));
 for(unsigned i=0;i<4;++i)CHECK(!pthread_join(workers[i],NULL));
 CHECK(!pthread_mutex_unlock(&testVM.mutex));CHECK(!pthread_mutex_destroy(&testVM.mutex));
 printf("four actual owner pthreads: full lifecycle receipts, native version mismatch, token/generation/publication failures, generic callback retention and shared-mutex independence: %u checks PASS; native HV execution not claimed\n",atomic_load(&checks));
}
