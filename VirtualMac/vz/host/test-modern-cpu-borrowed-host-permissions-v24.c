#include "modern_cpu_kernel_lifecycle_v24.h"
#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_kernel_lifecycle_v11.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
static unsigned Checks,NativeCalls[8],ProductionCalls[8];
// These historical HOST object hooks must never be called by this RAM fixture.
// Abort rather than fabricating capability success for any unexpected call.
bool VM27CPUCapabilityTestProfileV2(void){abort();}
uint64_t VM27CPUCapabilityTestOwnerV2(void){abort();}
int VM27CPUCapabilityTestSysctlV2(const char *n,void *o,size_t *s,void *p,size_t z){(void)n;(void)o;(void)s;(void)p;(void)z;abort();}
int VM27CPUCapabilityTestUnmapV2(void *p,size_t n){(void)p;(void)n;abort();}
bool VM27CPUCapabilityTestSDKV2(uint64_t t){(void)t;abort();}
int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t t,void *p){(void)t;(void)p;abort();}
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);return 1;}++Checks;}while(0)
VM27CPUConfigStatusV3 VM27CPUConfigReleaseBorrowV3(VM27CPUConfigBorrowV3 *b){(void)b;abort();}
static uint64_t Thread(void *ignored){(void)ignored;uint64_t t=0;return pthread_threadid_np(NULL,&t)?0:t;}
static int32_t Trap(void *ignored,uint64_t op,void *args){(void)ignored;(void)args;if(op<8)++NativeCalls[op];return 0;}
static bool Read(void *ignored,const void *address,size_t bytes,void *out){(void)ignored;return VM27CPUSelfReadV1(NULL,address,bytes,out);}
// All Hypervisor gates in this fixture are explicitly mocked. The host VM
// protections are checked by genuine vm_region_64; no guest executes.
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *args){(void)args;if(op<8)++ProductionCalls[op];return 0;}
#include "modern_cpu_production_native_ops_v2.c"
int main(void){
 void *host=mmap(NULL,0x4000,PROT_READ,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(host!=MAP_FAILED);
 VZKernelVM *vm=NULL;VZKernelRAMV9 *ram=NULL;VZKernelLifecycleResult life={0};VZKernelRAMResultV9 r={0};
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,NULL,Trap,Thread,Read};
 VZKernelVMOptions options={36,0,1,false,false};CHECK(!VZKernelVMCreate(&ops,&options,&vm,&life));
 CHECK(!VZKernelRAMAdoptHostRangeV11(vm,host,0x4000,&ram,&r));
 CHECK(VZKernelRAMMapV9(ram,0x100000,3,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && !r.nativeInvoked && !NativeCalls[3]);
 CHECK(!VZKernelRAMMapV9(ram,0x100000,5,&r) && r.nativeInvoked && NativeCalls[3]==1);
 CHECK(VZKernelRAMProtectV9(ram,3,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && !r.nativeInvoked && !NativeCalls[5]);
 unsigned char value=1;CHECK(VZKernelRAMWriteV9(ram,0,&value,1,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(!VZKernelRAMUnmapV9(ram,&r));CHECK(!VZKernelRAMFreeV9(ram));ram=NULL;
 CHECK(VM27CPUSelfMappedRangeV1(host,0x4000,false,NULL));
 CHECK(!mprotect(host,0x4000,PROT_NONE));
 CHECK(VZKernelRAMAdoptHostRangeV11(vm,host,0x4000,&ram,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && !ram);
 CHECK(!mprotect(host,0x4000,PROT_READ));
 CHECK(!VZKernelVMDestroy(vm,&life));CHECK(!VZKernelVMFree(vm));
 ProductionV1.installed=true;ProductionV1.vmLive=true;ProductionV1.ownerThread=Thread(NULL);ProductionV1.ownerPthread=pthread_self();
 VZKernelMemoryPacket packet={(uintptr_t)host,0x100000,0x4000,3,0};
 CHECK(ProductionNativeV1(&ProductionV1,3,&packet)==PRODUCTION_BAD_V1 && !ProductionCalls[3]);
 packet.flags=5;CHECK(!ProductionNativeV1(&ProductionV1,3,&packet) && ProductionCalls[3]==1);
 packet.hostAddress=0;packet.flags=3;CHECK(ProductionNativeV1(&ProductionV1,5,&packet)==PRODUCTION_BAD_V1 && !ProductionCalls[5]);
 packet.flags=5;CHECK(!ProductionNativeV1(&ProductionV1,5,&packet));packet.flags=0;CHECK(!ProductionNativeV1(&ProductionV1,4,&packet));
 CHECK(!munmap(host,0x4000));
 printf("actualHostReadOnlyPermissionChecks=%u readExecutePassed=1 writeRejected=1 protectionUpgradeRejected=1 actualNativeHypervisorCalls=0\n",Checks);return 0;
}
