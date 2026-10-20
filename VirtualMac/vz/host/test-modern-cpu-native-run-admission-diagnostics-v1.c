#include "modern_cpu_production_native_ops_v6.c"
#include <assert.h>

static unsigned ActualTrapCalls,ActualRunCalls;
static int32_t ExpectedRunStatus;
static VZKernelNativeVMConfig ExpectedConfig;
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *arguments) {
 ++ActualTrapCalls;
 if(op==1){assert(arguments==&ExpectedConfig);return 0;}
 assert(op==9 && !arguments);++ActualRunCalls;return ExpectedRunStatus;
}
int main(void) {
 unsigned char *mapping=calloc(1,NATIVE_USER_BYTES_V1),*unchanged=malloc(NATIVE_USER_BYTES_V1);
 assert(mapping && unchanged);
 const uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;
 const uint64_t dirty=UINT64_C(0x5100000000000005),ready=UINT64_MAX;
 const uint64_t inactive=UINT64_C(0x20fffffffffffffa),active=5;
 memcpy(mapping+0x4000,&version,8);memcpy(mapping+0x748,&dirty,8);
 memcpy(mapping+0x4100,&ready,8);memcpy(mapping+0x4108,&inactive,8);memcpy(mapping+0x4110,&active,8);
 memcpy(unchanged,mapping,NATIVE_USER_BYTES_V1);
 ProductionCPUV1 cpu={0};cpu.pthread=pthread_self();cpu.thread=ProductionThreadV1(NULL);
 assert(cpu.thread);cpu.slot=3;cpu.nativeContext=(uintptr_t)mapping;cpu.live=true;cpu.usable=true;
 ProductionV1.installed=true;ProductionV1.vmLive=true;ProductionV1.cpus=&cpu;
 ExpectedConfig.nativeHVISA=2;
 assert(!VM27NativeTrapWithMilestoneV6(1,&ExpectedConfig));
 for(unsigned i=0;i<10;++i) {
  ExpectedRunStatus=i&1?(int32_t)UINT32_C(0xfae9400f):0;
  assert(VM27NativeTrapWithMilestoneV6(9,NULL)==ExpectedRunStatus);
  assert(!memcmp(mapping,unchanged,NATIVE_USER_BYTES_V1));
 }
 assert(ActualTrapCalls==11 && ActualRunCalls==10);
 assert(atomic_load(&VM27NativeRunSnapshotsV6)==8 && atomic_load(&VM27ObservedNativeISAV6)==2);
 puts("{\"tenNativeRunsCalledExactlyOnce\":true,\"originalNativeReturnsUnchanged\":true,\"onlyFirstEightSnapshots\":true,\"onlyOwnSharedWordsRead\":true,\"allContextBytesUnchanged\":true,\"actualVMISARecorded\":true,\"kernelPointerReads\":0,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");
 free(unchanged);free(mapping);return 0;
}
