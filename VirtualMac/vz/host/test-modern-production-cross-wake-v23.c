/* Real host mappings and pthreads exercise the concrete provider's read.
 * The CPU records are explicit fixtures; no native HV execution is claimed. */
#include "modern_cpu_production_native_ops_v23_cross_wake.c"
#include <assert.h>
#include <sys/mman.h>
#include <sched.h>
static ProductionCPUV1 reader,target;
static _Atomic unsigned phase;
static _Atomic bool stopTarget;
static unsigned checked,rejected;
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *arguments) {
    (void)op;(void)arguments;abort();
}
static void *Target(void *unused) {
    (void)unused;target.pthread=pthread_self();
    assert(!pthread_threadid_np(NULL,&target.thread));
    atomic_store_explicit(&phase,1,memory_order_release);
    while(atomic_load_explicit(&phase,memory_order_acquire)!=2)sched_yield();
    for(unsigned i=0;i<2048;i++) {
        LockProductionV1();target.destroying=true;UnlockProductionV1();
        assert(!mprotect((void *)(target.nativeContext+0x4000),0x4000,PROT_NONE));
        sched_yield();
        assert(!mprotect((void *)(target.nativeContext+0x4000),0x4000,PROT_READ));
        LockProductionV1();target.destroying=false;UnlockProductionV1();
    }
    atomic_store_explicit(&stopTarget,true,memory_order_release);return NULL;
}
static void Reject(const VZKernelLifecycleOps *ops,const void *address,uint64_t *out) {
    uint64_t before=*out;
    assert(!VM27ProductionWakeVersionReadV23(ops,address,out));
    assert(*out==before);++rejected;
}
int main(void) {
    void *a=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    void *b=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(a!=MAP_FAILED && b!=MAP_FAILED && !((uintptr_t)a&0x3fff) && !((uintptr_t)b&0x3fff));
    reader=(ProductionCPUV1){.pthread=pthread_self(),.nativeContext=(uintptr_t)a,
        .live=true,.usable=true,.contextReadablePages=3,.contextWritablePages=1,.slot=0};
    target=(ProductionCPUV1){.nativeContext=(uintptr_t)b,.live=true,.usable=true,
        .contextReadablePages=3,.contextWritablePages=1,.slot=1};
    assert(!pthread_threadid_np(NULL,&reader.thread));
    uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());
    reader.stackBytes=pthread_get_stacksize_np(pthread_self());reader.stackStart=top-reader.stackBytes;
    reader.stackWritable=VM27CPUSelfMappedRangeV1((void *)reader.stackStart,reader.stackBytes,true,NULL);
    assert(reader.stackWritable);
    *(uint64_t *)((uintptr_t)b+0x4000)=VZ_KERNEL_NATIVE_CONTEXT_VERSION;
    assert(!mprotect((void *)((uintptr_t)b+0x4000),0x4000,PROT_READ));
    reader.next=&target;ProductionV1.cpus=&reader;
    ProductionV1.installed=ProductionV1.vmLive=true;ProductionV1.taskPID=getpid();
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&ProductionV1,
        ProductionNativeV1,ProductionThreadV1,ProductionReadV1};
    pthread_t other;assert(!pthread_create(&other,NULL,Target,NULL));
    while(atomic_load_explicit(&phase,memory_order_acquire)!=1)sched_yield();
    uint64_t value=UINT64_C(0x12345678);
    const void *version=(void *)((uintptr_t)b+0x4000);
    assert(VM27ProductionWakeVersionReadV23(&ops,version,&value));
    assert(value==VZ_KERNEL_NATIVE_CONTEXT_VERSION);++checked;
    Reject(&ops,(const char *)version+8,&value);
    Reject(&ops,(const char *)version-1,&value);
    VZKernelLifecycleOps foreign=ops;foreign.nativeTrap=NULL;Reject(&foreign,version,&value);
    foreign=ops;foreign.context=NULL;Reject(&foreign,version,&value);
    target.contextReadablePages=1;Reject(&ops,version,&value);target.contextReadablePages=3;
    target.usable=false;Reject(&ops,version,&value);target.usable=true;
    target.destroying=true;Reject(&ops,version,&value);target.destroying=false;
    target.writeFailed=true;Reject(&ops,version,&value);target.writeFailed=false;
    reader.usable=false;Reject(&ops,version,&value);reader.usable=true;
    ProductionV1.taskPID=0;Reject(&ops,version,&value);ProductionV1.taskPID=getpid();
    uint64_t *heap=malloc(8);assert(heap);*heap=42;Reject(&ops,version,heap);free(heap);
    assert(!VM27ProductionWakeVersionReadV23(&ops,version,(uint64_t *)a));++rejected;
    assert(!VM27ProductionWakeVersionReadV23(&ops,version,(uint64_t *)version));++rejected;
    /* A fresh actual word, including a bad version, reaches the caller's
     * unchanged version comparison; a cached previous value must not pass. */
    assert(!mprotect((void *)version,0x4000,PROT_READ|PROT_WRITE));
    *(uint64_t *)version=UINT64_C(0xf00d);
    assert(!mprotect((void *)version,0x4000,PROT_READ));
    assert(VM27ProductionWakeVersionReadV23(&ops,version,&value) && value==UINT64_C(0xf00d));++checked;
    assert(!mprotect((void *)version,0x4000,PROT_READ|PROT_WRITE));
    *(uint64_t *)version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;
    assert(!mprotect((void *)version,0x4000,PROT_READ));
    atomic_store_explicit(&phase,2,memory_order_release);
    do {
        value=UINT64_C(0x12345678);
        if(VM27ProductionWakeVersionReadV23(&ops,version,&value)) {
            assert(value==VZ_KERNEL_NATIVE_CONTEXT_VERSION);++checked;
        } else {assert(value==UINT64_C(0x12345678));++rejected;}
    } while(!atomic_load_explicit(&stopTarget,memory_order_acquire));
    assert(!pthread_join(other,NULL));
    target.live=false;assert(!mprotect((void *)version,0x4000,PROT_NONE));Reject(&ops,version,&value);
    ProductionV1.cpus=NULL;ProductionV1.installed=ProductionV1.vmLive=false;
    assert(!munmap(a,0x8000) && !munmap(b,0x8000));
    printf("PASS cross-CPU real readonly version: accepted=%u rejected=%u protectionTransitions=2048 nativeHVExecuted=0\n",checked,rejected);
    return 0;
}
