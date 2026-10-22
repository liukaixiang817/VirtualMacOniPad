/* Exercise the actual adapter and real Mach mapping admission on the host.
 * The explicit native trap records calls and returns the selected value;
 * this is not evidence of native CPU creation or guest execution. */
#include "modern_cpu_production_native_ops_v17_owner_native.c"
#include <assert.h>
#include <sys/mman.h>
static unsigned nativeCalls;static uint64_t lastOperation;static int32_t nativeResult;
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *args){assert(!args&&(op==8||op==9));++nativeCalls;lastOperation=op;return nativeResult;}
static void *Foreign(void *unused){(void)unused;VM27OwnedNativeAdmissionV7 a={0};assert(!VM27CPUOwnedNativeAdmissionV7(&a));return NULL;}
int main(void){
 void *ctx=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);assert(ctx!=MAP_FAILED);
 *(uint64_t *)((uintptr_t)ctx+0x4000)=VZ_KERNEL_NATIVE_CONTEXT_VERSION;
 ProductionCPUV1 cpu={.pthread=pthread_self(),.nativeContext=(uintptr_t)ctx,.live=true,.usable=true,.contextReadablePages=3,.contextWritablePages=1};assert(!pthread_threadid_np(NULL,&cpu.thread));
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t bytes=pthread_get_stacksize_np(pthread_self());
 assert(!mprotect((unsigned char *)ctx+0x4000,0x4000,PROT_READ));
 assert(VM27CPUOwnedMappingPublishV1(0,(uintptr_t)&cpu,cpu.thread,(uintptr_t)ctx,3,1,top-bytes,bytes,true));
 ProductionV1.installed=ProductionV1.vmLive=true;ProductionV1.cpus=&cpu;ProductionV1.taskPID=getpid();
 atomic_store(&VM27NativeMilestonesV6,16);atomic_store(&VM27NativeRunSnapshotsV6,8);
 // Both owner entries must finish even while this thread owns the old global lock.
 LockProductionV1();assert(!ProductionNativeV1(&ProductionV1,8,NULL));assert(lastOperation==8&&nativeCalls==1);
 assert(!ProductionNativeV1(&ProductionV1,9,NULL));assert(lastOperation==9&&nativeCalls==2);UnlockProductionV1();
 nativeResult=(int32_t)0xfae94002;assert(ProductionNativeV1(&ProductionV1,8,NULL)==nativeResult);assert(nativeCalls==3);
 pthread_t other;assert(!pthread_create(&other,NULL,Foreign,NULL));assert(!pthread_join(other,NULL));
 cpu.usable=false;assert(ProductionNativeV1(&ProductionV1,8,NULL)==PRODUCTION_BAD_V1);assert(nativeCalls==3);cpu.usable=true;
 cpu.writeFailed=true;assert(ProductionNativeV1(&ProductionV1,9,NULL)==PRODUCTION_BAD_V1);assert(nativeCalls==3);cpu.writeFailed=false;
 VM27OwnedNativeAdmissionV7 *heap=malloc(sizeof(*heap));assert(heap&&!VM27CPUOwnedNativeAdmissionV7(heap));free(heap);
 VM27CPUOwnedMappingWithdrawV1(0,(uintptr_t)&cpu,NULL);VM27OwnedNativeAdmissionV7 a={0};assert(!VM27CPUOwnedNativeAdmissionV7(&a));
 ProductionV1.cpus=NULL;ProductionV1.installed=ProductionV1.vmLive=false;assert(!munmap(ctx,0x8000));
 puts("PASS: actual native8/9 adapter, exact return, mutex independence, real read-only metadata page, foreign owner, unusable/poison and withdrawal; native HV not executed");return 0;
}
