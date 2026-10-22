/* Host-only differential test of the actual production/lifecycle helpers.
 * No HV creation or entry is simulated: an accidental native call aborts. */
#include "modern_cpu_production_native_ops_v22_exit_snapshot.c"
#include "modern_cpu_kernel_lifecycle_v78.c"
static _Atomic unsigned checks;
#define CHECK(x) do{atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}}while(0)
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *p){(void)op;(void)p;abort();}
static VZKernelVM testVM;
static _Thread_local unsigned readCalls,threadCalls,failRead;
static bool SpyRead(void *p,const void *from,size_t n,void *out) {
 (void)p;++readCalls;if(readCalls==failRead)return false;
 memcpy(out,from,n);return true;
}
static uint64_t SpyThread(void *p){(void)p;++threadCalls;return ProductionThreadV1(NULL);}
static void Put(uintptr_t p,unsigned off,uint64_t value,size_t n){memcpy((void *)(p+off),&value,n);}
static bool OriginalReads(RunPostAccessV7 *a,VZCPUNativeExitValuesV1 *v) {
 if(!RunPostReadV7(a,0x4008,4,&v->rawReason))return false;
 v->knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
 if(v->rawReason==1 || v->rawReason==6 || v->rawReason==8) {
  if(!RunPostReadV7(a,0x400c,4,&v->syndrome32) ||
     !RunPostReadV7(a,0x4018,8,&v->virtualAddress) ||
     !RunPostReadV7(a,0x4020,8,&v->physicalAddress))return false;
  v->knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
 }
 return true;
}
static void *Foreign(void *p){CHECK(!VM27ProductionExitSnapshotV22((uintptr_t)p).valid);return NULL;}
static void *Worker(void *argument) {
 unsigned slot=(unsigned)(uintptr_t)argument;
 void *memory=NULL;CHECK(!posix_memalign(&memory,0x4000,0x8000));memset(memory,0,0x8000);
 uintptr_t ctx=(uintptr_t)memory;Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION,8);
 uint64_t owner=ProductionThreadV1(NULL);CHECK(owner);
 ProductionCPUV1 production={.pthread=pthread_self(),.nativeContext=ctx,.thread=owner,
  .slot=slot,.live=true,.usable=true,.contextReadablePages=3,.contextWritablePages=3};
 VZKernelCPU cpu={.vm=&testVM,.owner=owner,.generation=slot+1,.nativeContext=ctx,
  .requestedSlot=slot,.returnedSlot=slot,.live=true,.creationPolicySliceComplete=true,
  .creationConfigComplete=true,.runToken=23,.runPostReturnActive=true};
 VZKernelCPURegistryEntryV5 entry={.cpu=&cpu,.vmEpoch=testVM.generation,.cpuGeneration=cpu.generation,
  .ownerPthread=pthread_self(),.publicIdentity=slot+42,.identityIssued=true,.published=true,.creationComplete=true};
 cpu.registryEntry=&entry;atomic_init(&cpu.operationInProgress,true);OwnedCPU=&cpu;
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t bytes=pthread_get_stacksize_np(pthread_self());
 CHECK(VM27CPUOwnedMappingPublishV1(slot,(uintptr_t)&production,owner,ctx,3,3,top-bytes,bytes,true));
 const uint32_t reasons[]={0,1,2,6,7,8,11,UINT32_MAX};
 for(unsigned trial=0;trial<64;++trial)for(unsigned k=0;k<8;++k) {
  Put(ctx,0x4008,reasons[k],4);Put(ctx,0x400c,0xa19b2034u+trial,4);
  Put(ctx,0x4018,UINT64_C(0xf391286710000000)+trial,8);
  Put(ctx,0x4020,UINT64_C(0xffea123451000000)+trial,8);
  unsigned char before[0x8000];memcpy(before,memory,sizeof(before));
  VZCPUNativeExitValuesV1 expected,actual;memset(&expected,0x91,sizeof(expected));actual=expected;
  VZKernelLifecycleResult oldLife={0},newLife={0};
  RunPostAccessV7 old={&cpu,testVM.generation,cpu.generation,owner,23,&oldLife,VZ_KERNEL_OK},now=old;now.lifecycle=&newLife;
  CHECK(OriginalReads(&old,&expected));CHECK(RunPostReadValuesV78(&now,&actual));
  CHECK(old.status==now.status && !memcmp(&oldLife,&newLife,sizeof(oldLife)));
  CHECK(!memcmp(&expected,&actual,sizeof(actual)));CHECK(!memcmp(before,memory,sizeof(before)));
  VM27NativeExitSnapshotV22 snapshot=VM27ProductionExitSnapshotV22(ctx);
  CHECK(snapshot.valid && snapshot.reason==reasons[k]);
  bool detail=reasons[k]==1 || reasons[k]==6 || reasons[k]==8;
  CHECK(snapshot.syndrome==(detail?0xa19b2034u+trial:0));
  CHECK(snapshot.virtualAddress==(detail?UINT64_C(0xf391286710000000)+trial:0));
  CHECK(snapshot.physicalAddress==(detail?UINT64_C(0xffea123451000000)+trial:0));
 }
 /* No callbacks or shared locks are needed for a concrete snapshot. Refused
  * native admission does not expose values or mutate the context. */
 CHECK(!VM27ProductionExitSnapshotV22(ctx+8).valid);
 CHECK(!VM27ProductionExitSnapshotV22(UINTPTR_MAX-8).valid);
 production.contextReadablePages=1;CHECK(!VM27ProductionExitSnapshotV22(ctx).valid);production.contextReadablePages=3;
 production.usable=false;CHECK(!VM27ProductionExitSnapshotV22(ctx).valid);production.usable=true;
 production.destroying=true;CHECK(!VM27ProductionExitSnapshotV22(ctx).valid);production.destroying=false;
 production.writeFailed=true;CHECK(!VM27ProductionExitSnapshotV22(ctx).valid);production.writeFailed=false;
 Put(ctx,0x4000,0,8);CHECK(!VM27ProductionExitSnapshotV22(ctx).valid);
 VZCPUNativeExitValuesV1 value;memset(&value,0x91,sizeof(value));VZCPUNativeExitValuesV1 before=value;
 VZKernelLifecycleResult life={0};RunPostAccessV7 post={&cpu,testVM.generation,cpu.generation,owner,23,&life,VZ_KERNEL_OK};
 CHECK(!RunPostReadValuesV78(&post,&value) && post.status==VZ_KERNEL_CONTEXT_VERSION_MISMATCH);
 CHECK(!memcmp(&value,&before,sizeof(value)));Put(ctx,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION,8);
 ++post.token;CHECK(!RunPostReadValuesV78(&post,&value) && post.status==VZ_KERNEL_NOT_LIVE);--post.token;
 ++post.generation;CHECK(!RunPostReadValuesV78(&post,&value) && post.status==VZ_KERNEL_NOT_LIVE);--post.generation;
 ++post.vmEpoch;CHECK(!RunPostReadValuesV78(&post,&value) && post.status==VZ_KERNEL_NOT_LIVE);--post.vmEpoch;
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,Foreign,memory));CHECK(!pthread_join(foreign,NULL));
 /* Generic callbacks retain their exact original sequence, partial outputs,
  * lifecycle receipts and failures, including an error at every read. */
 VZKernelVM generic={0};generic.ops=testVM.ops;generic.ops.readMemory=SpyRead;generic.ops.currentThread=SpyThread;
 generic.live=true;generic.generation=testVM.generation;generic.nativeHVISA=2;cpu.vm=&generic;
 for(unsigned k=0;k<8;++k)for(unsigned failure=0;failure<16;++failure) {
  Put(ctx,0x4008,reasons[k],4);VZCPUNativeExitValuesV1 expected,actual;
  memset(&expected,0x91,sizeof(expected));actual=expected;
  VZKernelLifecycleResult oldLife={0},newLife={0};RunPostAccessV7 old=post,now=post;
  old.lifecycle=&oldLife;now.lifecycle=&newLife;old.status=now.status=VZ_KERNEL_OK;
  readCalls=threadCalls=0;failRead=failure;bool oldOK=OriginalReads(&old,&expected);
  unsigned oldReads=readCalls,oldThreads=threadCalls;
  readCalls=threadCalls=0;bool newOK=RunPostReadValuesV78(&now,&actual);
  CHECK(oldOK==newOK && old.status==now.status);
  CHECK(readCalls==oldReads && threadCalls==oldThreads);
  CHECK(!memcmp(&expected,&actual,sizeof(actual)));CHECK(!memcmp(&oldLife,&newLife,sizeof(oldLife)));
 }
 cpu.vm=&testVM;VM27CPUOwnedMappingWithdrawV1(slot,(uintptr_t)&production,NULL);
 CHECK(!VM27ProductionExitSnapshotV22(ctx).valid);OwnedCPU=NULL;free(memory);return NULL;
}
int main(void) {
 testVM.ops=(VZKernelLifecycleOps){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&ProductionV1,ProductionNativeV1,ProductionThreadV1,ProductionReadV1};
 testVM.live=true;testVM.generation=17;testVM.nativeHVISA=2;
 CHECK(!pthread_mutex_init(&testVM.mutex,NULL));CHECK(!pthread_mutex_lock(&testVM.mutex));
 LockProductionV1();pthread_t workers[4];
 for(unsigned i=0;i<4;++i)CHECK(!pthread_create(&workers[i],NULL,Worker,(void *)(uintptr_t)i));
 for(unsigned i=0;i<4;++i)CHECK(!pthread_join(workers[i],NULL));
 UnlockProductionV1();CHECK(!pthread_mutex_unlock(&testVM.mutex));CHECK(!pthread_mutex_destroy(&testVM.mutex));
 printf("four owner exit snapshots: exact values/receipts/source bytes, generic callback sequence and partial failures, permission/version/token/generation/foreign/withdrawal refusal, shared-mutex independence: %u checks PASS; native HV execution not claimed\n",atomic_load(&checks));
}
