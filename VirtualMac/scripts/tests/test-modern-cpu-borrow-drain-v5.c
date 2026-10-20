// Actual pthread lifecycle model; every nativeTrap/read callback is a mock.
#include "modern_cpu_kernel_lifecycle_v5.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VZ_BORROW_WHITEBOX
#include "modern_cpu_kernel_lifecycle_v5.c"
#endif
static _Atomic unsigned Checks;
#define CHECK(x) do { ++Checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
typedef struct {
    VZKernelVM *vm;
    VZKernelCPU *cpu;
    VZKernelCPUBorrowV5 *borrow;
    VZKernelLifecycleOps ops;
    VZKernelVMOptions options;
    unsigned char page[0x4130];
    _Atomic unsigned calls, reads, threadCalls;
    bool failCreate, failDestroy, failRead, wrongVersion, reenterBorrow, reenterCreate, spoofOwner;
    _Atomic bool start, stop;
    uint64_t identity;
} Fixture;
static uint64_t ActualThread(void) { return (uint64_t)(uintptr_t)pthread_self(); }
static uint64_t Thread(void *context) {
    Fixture *f=context; ++f->threadCalls;
#ifdef VZ_BORROW_WHITEBOX
    if(f->reenterBorrow && f->vm){CHECK(!pthread_mutex_trylock(&f->vm->mutex));CHECK(!pthread_mutex_unlock(&f->vm->mutex));}
    if(f->spoofOwner)return f->cpu->owner;
#endif
    if(f->reenterBorrow){
        f->reenterBorrow=false;unsigned n=f->calls,r=f->reads,t=f->threadCalls;
        CHECK(VZKernelCPUReleaseBorrowV5(f->borrow)==VZ_KERNEL_BUSY);
        VZKernelCPU *out=(void*)1;
        CHECK(VZKernelCPUBorrowHandleV5(f->borrow,&out)==VZ_KERNEL_BUSY && out==(void*)1);
        CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_BUSY);
        CHECK(VZKernelCPUUnpublishIdentityV5(f->cpu)==VZ_KERNEL_BUSY);
        uint64_t id=99;CHECK(VZKernelCPUPublishIdentityV5(f->cpu,&id)==VZ_KERNEL_BUSY && id==99);
        VZKernelLifecycleResult result;
        CHECK(VZKernelCPUDestroy(f->cpu,&result)==VZ_KERNEL_BUSY && !result.nativeInvoked);
        CHECK(f->calls==n && f->reads==r && f->threadCalls==t);
    }
    if(f->reenterCreate){
        f->reenterCreate=false;
        // This hook must not run at all when the already registered VM exists.
        VZKernelLifecycleResult r;
        CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_OK);
        CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_OK);
        f->vm=NULL;
    }
    return ActualThread();
}
static VZKernelHVReturn Trap(void *context,uint64_t op,void *arg) {
    Fixture *f=context;++f->calls;CHECK(op==1 || op==2 || op==6 || op==7);
    if(op==1){CHECK(arg);return 0;}
    if(op==2){CHECK(!arg);return 0;}
    if(op==6){
        uint64_t *a=arg;CHECK(a && a[0]==0 && a[1]==0);
#ifdef VZ_BORROW_WHITEBOX
        uint64_t id=77;CHECK(OwnedCPU && !OwnedCPU->registryEntry->creationComplete);
        CHECK(VZKernelCPUPublishIdentityV5(OwnedCPU,&id)==VZ_KERNEL_BUSY && id==77);
#endif
        if(f->failCreate)return 0x166;
        a[0]=0;a[1]=(uintptr_t)f->page;return 0;
    }
    CHECK(!arg);return f->failDestroy?0x177:0;
}
static bool Read(void *context,const void *address,size_t bytes,void *out) {
    Fixture *f=context;++f->reads;
    CHECK(address==f->page+0x4000 && bytes==8);
#ifdef VZ_BORROW_WHITEBOX
    uint64_t id=88;CHECK(!OwnedCPU->registryEntry->creationComplete);
    CHECK(VZKernelCPUPublishIdentityV5(OwnedCPU,&id)==VZ_KERNEL_BUSY && id==88);
#endif
    if(f->failRead)return false;
    memcpy(out,address,bytes);return true;
}
static void VMStart(Fixture *f) {
    memset(f,0,sizeof(*f));
    f->ops=(VZKernelLifecycleOps){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,f,Trap,Thread,Read};
    f->options=(VZKernelVMOptions){36,0,1,false,false};
    uint64_t v=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(f->page+0x4000,&v,8);
    VZKernelLifecycleResult r;CHECK(VZKernelVMCreate(&f->ops,&f->options,&f->vm,&r)==VZ_KERNEL_OK && r.nativeInvoked);
}
static void CPUCreate(Fixture *f,VZKernelStatus expected) {
    VZKernelLifecycleResult r;f->cpu=(void*)1;
    CHECK(VZKernelCPUCreate(f->vm,&f->cpu,&r)==expected);
    CHECK(r.nativeInvoked && r.requestedSlot==0);
    CHECK(expected==VZ_KERNEL_NATIVE_ERROR ? !f->cpu : f->cpu && r.cpuLive);
}
static void FixtureFinish(Fixture *f) {
    VZKernelLifecycleResult r;
    if(f->cpu){CHECK(VZKernelCPUDestroy(f->cpu,&r)==VZ_KERNEL_OK && r.nativeInvoked);CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_OK);f->cpu=NULL;}
    CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_OK && r.nativeInvoked);
    CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_OK);f->vm=NULL;
}
static void RefusedLookup(uint64_t id,VZKernelStatus expected) {
    VZKernelCPUBorrowV5 *out=(void*)1;
    CHECK(VZKernelCPUBorrowIdentityV5(id,&out)==expected && out==(void*)1);
}
static void *Foreign(void *context) {
    Fixture *f=context;VZKernelCPU *cpu=(void*)1;
    CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_WRONG_THREAD);
    CHECK(VZKernelCPUReleaseBorrowV5(f->borrow)==VZ_KERNEL_WRONG_THREAD);
    CHECK(VZKernelCPUBorrowHandleV5(f->borrow,&cpu)==VZ_KERNEL_WRONG_THREAD && cpu==(void*)1);
    uint64_t id=99;VZKernelStatus expected=f->spoofOwner?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_WRONG_THREAD;
    CHECK(VZKernelCPUPublishIdentityV5(f->cpu,&id)==expected && id==99);
    CHECK(VZKernelCPUUnpublishIdentityV5(f->cpu)==expected);
    VZKernelCPUBorrowV5 *own=NULL;
    CHECK(VZKernelCPUBorrowIdentityV5(f->identity,&own)==VZ_KERNEL_OK && own);
    CHECK(VZKernelCPUBorrowHandleV5(own,&cpu)==expected && cpu==(void*)1);
    CHECK(VZKernelCPUReleaseBorrowV5(own)==VZ_KERNEL_OK);
    return NULL;
}
static void *Pressure(void *context) {
    Fixture *f=context;
    while(!atomic_load_explicit(&f->start,memory_order_acquire)){}
    for(unsigned i=0;i<2000;++i){
        VZKernelCPUBorrowV5 *b=(void*)1;
        VZKernelStatus s=VZKernelCPUBorrowIdentityV5(f->identity,&b);
        if(s==VZ_KERNEL_OK){
            CHECK(b!=(void*)1);VZKernelCPU *cpu=(void*)1;
            VZKernelStatus access=VZKernelCPUBorrowHandleV5(b,&cpu);
            CHECK((access==VZ_KERNEL_WRONG_THREAD || access==VZ_KERNEL_BUSY) && cpu==(void*)1);
            CHECK(VZKernelCPUReleaseBorrowV5(b)==VZ_KERNEL_OK);
        }else CHECK(s==VZ_KERNEL_BAD_ARGUMENT && b==(void*)1);
    }
    return NULL;
}
static void *CreatePressure(void *context) {
    Fixture *f=context;
    while(!atomic_load_explicit(&f->start,memory_order_acquire)){}
    for(unsigned i=0;i<64;++i){
        VZKernelCPU *cpu=NULL;VZKernelLifecycleResult r;
        CHECK(VZKernelCPUCreate(f->vm,&cpu,&r)==VZ_KERNEL_OK && cpu);
        CHECK(VZKernelCPUDestroy(cpu,&r)==VZ_KERNEL_OK && r.nativeInvoked);
        CHECK(VZKernelCPUFree(cpu)==VZ_KERNEL_OK);
    }
    return NULL;
}
int main(void) {
    unsigned cases=0;Fixture f;VZKernelLifecycleResult r;
    RefusedLookup(1,VZ_KERNEL_NOT_LIVE);RefusedLookup(0,VZ_KERNEL_BAD_ARGUMENT);++cases;
    CHECK(VZKernelCPUReleaseBorrowV5(NULL)==VZ_KERNEL_BAD_ARGUMENT);
    CHECK(VZKernelCPUBorrowHandleV5(NULL,NULL)==VZ_KERNEL_BAD_ARGUMENT);
    CHECK(VZKernelCPUPublishIdentityV5(NULL,NULL)==VZ_KERNEL_BAD_ARGUMENT);
    CHECK(VZKernelCPUUnpublishIdentityV5(NULL)==VZ_KERNEL_BAD_ARGUMENT);++cases;
    VMStart(&f);
    unsigned t=f.threadCalls,n=f.calls;VZKernelVM *other=(void*)1;
    f.reenterCreate=true;
    CHECK(VZKernelVMCreate(&f.ops,&f.options,&other,&r)==VZ_KERNEL_BUSY && !other && !r.nativeInvoked);
    CHECK(f.reenterCreate && f.vm && f.calls==n && f.threadCalls==t);f.reenterCreate=false;++cases;
    CPUCreate(&f,VZ_KERNEL_OK);
    CHECK(VZKernelCPUUnpublishIdentityV5(f.cpu)==VZ_KERNEL_BAD_ARGUMENT);++cases;
#ifdef VZ_BORROW_WHITEBOX
    uint64_t oldNext=NextPublicIdentityV5;NextPublicIdentityV5=UINT64_MAX;uint64_t overflowID=99;
    CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&overflowID)==VZ_KERNEL_BUSY && overflowID==99);
    CHECK(!f.cpu->registryEntry->published && !f.cpu->registryEntry->identityIssued);
    NextPublicIdentityV5=oldNext;++cases;
#endif
    CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&f.identity)==VZ_KERNEL_OK && f.identity!=0);++cases;
    uint64_t first=f.identity,id=99;
    CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&id)==VZ_KERNEL_BUSY && id==99);++cases;
    CHECK(VZKernelCPUBorrowIdentityV5(f.identity,&f.borrow)==VZ_KERNEL_OK && f.borrow);++cases;
    VZKernelCPU *handle=NULL;
    CHECK(VZKernelCPUBorrowHandleV5(f.borrow,&handle)==VZ_KERNEL_OK && handle==f.cpu);++cases;
    n=f.calls;unsigned reads=f.reads;f.reenterBorrow=true;handle=NULL;
    CHECK(VZKernelCPUBorrowHandleV5(f.borrow,&handle)==VZ_KERNEL_OK && handle==f.cpu && !f.reenterBorrow);
    CHECK(f.calls==n && f.reads==reads);++cases;
    pthread_t thread;CHECK(!pthread_create(&thread,NULL,Foreign,&f));CHECK(!pthread_join(thread,NULL));++cases;
#ifdef VZ_BORROW_WHITEBOX
    // Even malformed dead/live bookkeeping cannot free a retained reference.
    f.cpu->live=false;OwnedCPU=NULL;
    CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_BUSY);
    f.cpu->live=true;OwnedCPU=f.cpu;++cases;
    VZKernelCPUBorrowV5 *savedList=f.cpu->registryEntry->borrows;
    f.cpu->registryEntry->borrows=NULL;handle=(void*)1;
    CHECK(VZKernelCPUBorrowHandleV5(f.borrow,&handle)==VZ_KERNEL_NOT_LIVE && handle==(void*)1);
    CHECK(VZKernelCPUReleaseBorrowV5(f.borrow)==VZ_KERNEL_NOT_LIVE);
    f.cpu->registryEntry->borrows=savedList;++cases;
    void *aliases[]={f.cpu,f.vm,f.cpu->registryEntry,f.borrow,(void*)(UINTPTR_MAX-3)};
    for(unsigned i=0;i<sizeof(aliases)/sizeof(aliases[0]);++i){
        CHECK(VZKernelCPUBorrowHandleV5(f.borrow,aliases[i])==VZ_KERNEL_BAD_ARGUMENT);
        CHECK(VZKernelCPUBorrowIdentityV5(f.identity,aliases[i])==VZ_KERNEL_BAD_ARGUMENT);
        // Publish is already issued; alias validation still precedes BUSY.
        CHECK(VZKernelCPUPublishIdentityV5(f.cpu,aliases[i])==VZ_KERNEL_BAD_ARGUMENT);
        ++cases;
    }
    uint64_t saved=f.borrow->cpuGeneration;f.borrow->cpuGeneration^=1;handle=(void*)1;
    CHECK(VZKernelCPUBorrowHandleV5(f.borrow,&handle)==VZ_KERNEL_NOT_LIVE && handle==(void*)1);
    CHECK(VZKernelCPUReleaseBorrowV5(f.borrow)==VZ_KERNEL_NOT_LIVE);f.borrow->cpuGeneration=saved;++cases;
    saved=f.borrow->vmEpoch;f.borrow->vmEpoch^=1;
    CHECK(VZKernelCPUBorrowHandleV5(f.borrow,&handle)==VZ_KERNEL_NOT_LIVE && handle==(void*)1);
    CHECK(VZKernelCPUReleaseBorrowV5(f.borrow)==VZ_KERNEL_NOT_LIVE);f.borrow->vmEpoch=saved;++cases;
    unsigned bc=f.cpu->registryEntry->borrowCount;f.cpu->registryEntry->borrowCount=UINT_MAX;
    RefusedLookup(f.identity,VZ_KERNEL_BUSY);f.cpu->registryEntry->borrowCount=bc;++cases;
    f.spoofOwner=true;CHECK(!pthread_create(&thread,NULL,Foreign,&f));
    // Foreign() starts by CPUFree; actual pthread seal rejects spoofed owner.
    CHECK(!pthread_join(thread,NULL));f.spoofOwner=false;++cases;
#endif
    pthread_t pressure[4],creator;
    for(unsigned i=0;i<4;++i)CHECK(!pthread_create(&pressure[i],NULL,Pressure,&f));
    CHECK(!pthread_create(&creator,NULL,CreatePressure,&f));
    atomic_store_explicit(&f.start,true,memory_order_release);
    for(unsigned i=0;i<300;++i){
        VZCPUPendingInterruptValuesV1 p;
        VZKernelStatus set=VZ_KERNEL_BUSY,read=VZ_KERNEL_BUSY;
        for(unsigned tries=0;set==VZ_KERNEL_BUSY && tries<100000;++tries)
            set=VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,i&1);
        CHECK(set==VZ_KERNEL_OK);
        for(unsigned tries=0;read==VZ_KERNEL_BUSY && tries<100000;++tries)
            read=VZKernelCPUReadPendingInterruptsV3(f.cpu,&p);
        CHECK(read==VZ_KERNEL_OK && p.irqPending==(i&1));
    }
    CHECK(!pthread_join(creator,NULL));++cases;
    VZKernelStatus unpublish=VZ_KERNEL_BUSY;
    for(unsigned tries=0;unpublish==VZ_KERNEL_BUSY && tries<100000;++tries)
        unpublish=VZKernelCPUUnpublishIdentityV5(f.cpu);
    CHECK(unpublish==VZ_KERNEL_OK);
    n=f.calls;CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
    CHECK(f.calls==n && VZKernelCPUFree(f.cpu)==VZ_KERNEL_BUSY);++cases;
    RefusedLookup(f.identity,VZ_KERNEL_BAD_ARGUMENT);++cases;
    for(unsigned i=0;i<4;++i)CHECK(!pthread_join(pressure[i],NULL));++cases;
    CHECK(VZKernelCPUUnpublishIdentityV5(f.cpu)==VZ_KERNEL_OK);++cases;
    id=99;CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&id)==VZ_KERNEL_NOT_LIVE && id==99);++cases;
    handle=(void*)1;CHECK(VZKernelCPUBorrowHandleV5(f.borrow,&handle)==VZ_KERNEL_NOT_LIVE && handle==(void*)1);++cases;
    CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);++cases;
    CHECK(VZKernelCPUReleaseBorrowV5(f.borrow)==VZ_KERNEL_OK);f.borrow=NULL;++cases;
    f.failDestroy=true;n=f.calls;
    CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_NATIVE_ERROR && r.nativeInvoked && r.cpuLive && r.cleanupPending);
    CHECK(f.calls==n+1 && VZKernelCPUFree(f.cpu)==VZ_KERNEL_BUSY);++cases;
    RefusedLookup(first,VZ_KERNEL_BAD_ARGUMENT);++cases;
    f.failDestroy=false;FixtureFinish(&f);RefusedLookup(first,VZ_KERNEL_NOT_LIVE);++cases;
    // Distinct allocation/VM epoch cannot revive the old issued identity.
    VMStart(&f);CPUCreate(&f,VZ_KERNEL_OK);
    CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&f.identity)==VZ_KERNEL_OK && f.identity>first);
    RefusedLookup(first,VZ_KERNEL_BAD_ARGUMENT);FixtureFinish(&f);++cases;
    for(unsigned failure=0;failure<3;++failure){
        VMStart(&f);f.failCreate=failure==0;f.failRead=failure==1;
        if(failure==2){uint64_t version=0xe;memcpy(f.page+0x4000,&version,8);}
        CPUCreate(&f,failure==0?VZ_KERNEL_NATIVE_ERROR:failure==1?VZ_KERNEL_CONTEXT_UNREADABLE:VZ_KERNEL_CONTEXT_VERSION_MISMATCH);
        id=99;CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&id)==(f.cpu?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_BAD_ARGUMENT) && id==99);
        // Fixing the callback afterwards does not retroactively complete create.
        if(f.cpu){f.failRead=false;uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(f.page+0x4000,&version,8);
            CHECK(VZKernelCPUPublishIdentityV5(f.cpu,&id)==VZ_KERNEL_NOT_LIVE && id==99);}
        FixtureFinish(&f);++cases;
    }
    printf("{\"checks\":%u,\"cases\":%u,\"actualPthreads\":true,\"pressureThreads\":4,\"iterationsEach\":2000,\"retainedActualEntry\":true,\"nativeCallsExecuted\":0,\"nativeRun\":false,\"full27Backend\":false}\n",Checks,cases);
    return 0;
}
