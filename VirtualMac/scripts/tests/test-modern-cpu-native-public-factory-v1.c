// Exercises the actual factory + immutable V5 units; every trap/read is a mock.
#include "modern_cpu_native_public_factory_v1.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VM27_FACTORY_WHITEBOX
#include "modern_cpu_native_public_factory_v1.c"
#endif
static _Atomic unsigned Checks;
#define CHECK(x) do { ++Checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define BITS(x) ((uint32_t)(x))
#define BAD UINT32_C(0xfae94003)
#define BUSY UINT32_C(0xfae94002)
#define ERROR UINT32_C(0xfae94001)
typedef struct {
    VM27CPUFactoryVMV1 *vm;
    VM27CPUFactoryIDV1 identity;
    VM27CPUFactoryBorrowV1 *borrow;
    _Atomic unsigned calls, reads, threads, creates, destroys;
    _Atomic bool failCreate, failDestroy, failVM, failRead, reenter;
    _Atomic bool held, release, start;
    unsigned char page[0x4010];
} Fixture;
static uint64_t Thread(void *context) {
    Fixture *f = context; ++f->threads;
    if (atomic_exchange(&f->reenter, false)) {
        unsigned calls=f->calls, reads=f->reads, threads=f->threads;
        VM27CPUFactoryDiagnosticV1 d;
        CHECK(BITS(VM27CPUFactoryOwnerCleanupV1(f->vm,&d))==BUSY);
        CHECK(BITS(VM27CPUFactoryVMDestroyV1(f->vm,&d))==BUSY);
        CHECK(BITS(VM27CPUFactoryVMFreeV1(f->vm))==BUSY);
        VM27CPUFactoryIDV1 id=99; VM27CPUFactoryExitV1 *exit=(void*)1;
        CHECK(BITS(VM27CPUFactoryCreateV1(f->vm,&id,&exit,NULL,&d))==BUSY && id==99 && exit==(void*)1);
        if (f->borrow) {
            CHECK(BITS(VM27CPUFactoryBorrowReleaseV1(f->borrow))==BUSY);
            VM27CPUFactoryViewV1 view={0}, before=view;
            CHECK(BITS(VM27CPUFactoryBorrowViewV1(f->borrow,&view))==BUSY && !memcmp(&view,&before,sizeof(view)));
        }
        CHECK(f->calls==calls && f->reads==reads && f->threads==threads);
    }
    return (uint64_t)(uintptr_t)pthread_self();
}
static int32_t Trap(void *context,uint64_t op,void *arg) {
    Fixture *f=context; ++f->calls;
    CHECK(op==1 || op==2 || op==6 || op==7);
    if (op==1) { CHECK(arg); return 0; }
    if (op==2) { CHECK(!arg); return f->failVM?0x122:0; }
    if (op==6) {
        ++f->creates; uint64_t *packet=arg;
        CHECK(packet && packet[0]==0 && packet[1]==0);
#ifdef VM27_FACTORY_WHITEBOX
        CHECK(Owned && Owned->exitStorage && !Owned->published && !Owned->complete);
        CHECK(atomic_load(&Owned->operation));
        CHECK(!pthread_mutex_trylock(&Registry)); CHECK(!pthread_mutex_unlock(&Registry));
#endif
        if (f->failCreate) return 0x166;
        packet[0]=73; // Deliberately unrelated to the own public identity.
        packet[1]=(uintptr_t)f->page; return 0;
    }
    ++f->destroys; CHECK(!arg); return f->failDestroy?0x177:0;
}
static bool Read(void *context,const void *address,size_t size,void *out) {
    Fixture *f=context; ++f->reads;
    CHECK(address==f->page+0x4000 && size==8);
#ifdef VM27_FACTORY_WHITEBOX
    CHECK(Owned && !Owned->published && !Owned->complete && atomic_load(&Owned->operation));
#endif
    if (f->failRead) return false;
    memcpy(out,address,size); return true;
}
static void Start(Fixture *f) {
    memset(f,0,sizeof(*f));
    uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION; memcpy(f->page+0x4000,&version,8);
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,f,Trap,Thread,Read};
    VZKernelVMOptions options={36,0,1,false,false};
    VM27CPUFactoryDiagnosticV1 d;
    CHECK(VM27CPUFactoryVMCreateV1(&ops,&options,&f->vm,&d)==0);
    CHECK(d.ownStatus==VZ_KERNEL_OK && d.vmEpoch && d.nativeInvoked && !d.nativeReturn);
}
static void Finish(Fixture *f) {
    VM27CPUFactoryDiagnosticV1 d;
    CHECK(VM27CPUFactoryVMDestroyV1(f->vm,&d)==0 && d.nativeInvoked);
    CHECK(VM27CPUFactoryVMFreeV1(f->vm)==0); f->vm=NULL;
}
static VM27CPUFactoryExitV1 *Create(Fixture *f) {
    VM27CPUFactoryExitV1 *exit=NULL; VM27CPUFactoryDiagnosticV1 d;
    CHECK(VM27CPUFactoryCreateV1(f->vm,&f->identity,&exit,NULL,&d)==0);
    CHECK(exit && ((uintptr_t)exit%8)==0 && f->identity && f->identity!=73);
    CHECK(d.nativeInvoked && !d.nativeReturn && d.nativeCPUCreationComplete && !d.exitRecordValid);
    CHECK(d.cleanupPending && d.cpuGeneration && d.vmEpoch);
    return exit;
}
static void *Foreign(void *context) {
    Fixture *f=context; VM27CPUFactoryDiagnosticV1 d;
    // A foreign destroy must not unpublish before its real pthread refusal.
    CHECK(BITS(VM27CPUFactoryDestroyV1(f->identity,&d))==BAD && !d.nativeInvoked);
    CHECK(BITS(VM27CPUFactoryOwnerCleanupV1(f->vm,&d))==BAD);
    CHECK(BITS(VM27CPUFactoryBorrowReleaseV1(f->borrow))==BAD);
    VM27CPUFactoryBorrowV1 *b=NULL;
    CHECK(VM27CPUFactoryBorrowAcquireV1(f->identity,&b)==0 && b);
    VM27CPUFactoryViewV1 v={0}, before=v;
    CHECK(BITS(VM27CPUFactoryBorrowViewV1(b,&v))==BAD && !memcmp(&v,&before,sizeof(v)));
    atomic_store_explicit(&f->held,true,memory_order_release);
    while (!atomic_load_explicit(&f->release,memory_order_acquire)) sched_yield();
    CHECK(VM27CPUFactoryBorrowReleaseV1(b)==0); return NULL;
}
static void *WorkerCPU(void *context) {
    Fixture *f=context;
    while (!atomic_load_explicit(&f->start,memory_order_acquire)) sched_yield();
    VM27CPUFactoryIDV1 id=0; VM27CPUFactoryExitV1 *exit=NULL;
    VM27CPUFactoryDiagnosticV1 d;
    CHECK(VM27CPUFactoryCreateV1(f->vm,&id,&exit,NULL,&d)==0);
    CHECK(id && exit && d.cpuGeneration);
    VM27CPUFactoryBorrowV1 *b=NULL; VM27CPUFactoryViewV1 v;
    CHECK(VM27CPUFactoryBorrowAcquireV1(id,&b)==0);
    CHECK(VM27CPUFactoryBorrowViewV1(b,&v)==0 && v.identity==id && v.exitStorage==exit);
    CHECK(VM27CPUFactoryBorrowReleaseV1(b)==0);
    CHECK(VM27CPUFactoryDestroyV1(id,&d)==0 && d.nativeInvoked && !d.cleanupPending);
    return NULL;
}
int main(void) {
    Fixture f; VM27CPUFactoryDiagnosticV1 d; unsigned scenarios=0;
    VM27CPUFactoryIDV1 id=99; VM27CPUFactoryExitV1 *exit=(void*)1;
    CHECK(BITS(VM27CPUFactoryCreateV1(NULL,&id,&exit,NULL,&d))==BAD && id==99 && exit==(void*)1);
    CHECK(BITS(VM27CPUFactoryBorrowAcquireV1(0,NULL))==BAD); ++scenarios;
    Start(&f); unsigned calls=f.calls, reads=f.reads, threads=f.threads;
    CHECK(BITS(VM27CPUFactoryCreateV1(f.vm,&id,&exit,(void*)1,&d))==0xfae9400fu);
    CHECK(id==99 && exit==(void*)1 && d.ownStatus==VZ_KERNEL_UNSUPPORTED && !d.cleanupPending);
    CHECK(f.calls==calls && f.reads==reads && f.threads==threads); ++scenarios;
    CHECK(BITS(VM27CPUFactoryCreateV1(f.vm,&id,(void*)&id,NULL,&d))==BAD && id==99);
    CHECK(BITS(VM27CPUFactoryCreateV1(f.vm,NULL,&exit,NULL,&d))==BAD); ++scenarios;
    f.reenter=true; exit=Create(&f); CHECK(!f.reenter); ++scenarios;
    memset(exit,0xa5,32); // Own storage only, never native context/write/API.
    unsigned char preserved[32]; memcpy(preserved,exit,32);
    CHECK(VM27CPUFactoryBorrowAcquireV1(f.identity,&f.borrow)==0);
    VM27CPUFactoryViewV1 view;
    f.reenter=true; CHECK(VM27CPUFactoryBorrowViewV1(f.borrow,&view)==0 && !f.reenter);
    CHECK(view.identity==f.identity && view.exitStorage==exit && !view.exitRecordValid);
    CHECK(BITS(VM27CPUFactoryBorrowViewV1(f.borrow,(void*)exit))==BAD && !memcmp(exit,preserved,32));
    CHECK(BITS(VM27CPUFactoryBorrowAcquireV1(f.identity,(void*)exit))==BAD && !memcmp(exit,preserved,32)); ++scenarios;
#ifdef VM27_FACTORY_WHITEBOX
    CHECK(BITS(VM27CPUFactoryCreateV1(f.vm,(void*)Owned,&exit,NULL,&d))==BAD);
    CHECK(BITS(VM27CPUFactoryBorrowViewV1(f.borrow,(void*)f.borrow))==BAD);
    uint64_t epoch=f.borrow->epoch; f.borrow->epoch^=1;
    CHECK(BITS(VM27CPUFactoryBorrowViewV1(f.borrow,&view))==BAD);
    f.borrow->epoch=epoch; ++scenarios;
#endif
    pthread_t foreign; CHECK(!pthread_create(&foreign,NULL,Foreign,&f));
    while (!atomic_load_explicit(&f.held,memory_order_acquire)) sched_yield();
    CHECK(BITS(VM27CPUFactoryDestroyV1(f.identity,&d))==BUSY && !d.nativeInvoked && d.cleanupPending && d.callerDestroyFailureIsFatal);
    VM27CPUFactoryBorrowV1 *unchanged=(void*)1;
    CHECK(BITS(VM27CPUFactoryBorrowAcquireV1(f.identity,&unchanged))==BAD && unchanged==(void*)1);
    VM27CPUFactoryViewV1 before=view;
    CHECK(BITS(VM27CPUFactoryBorrowViewV1(f.borrow,&view))==BAD && !memcmp(&view,&before,sizeof(view)));
    CHECK(BITS(VM27CPUFactoryVMDestroyV1(f.vm,&d))==BUSY);
    CHECK(!memcmp(exit,preserved,32)); ++scenarios;
    CHECK(VM27CPUFactoryBorrowReleaseV1(f.borrow)==0); f.borrow=NULL;
    f.failDestroy=true;
    CHECK(BITS(VM27CPUFactoryOwnerCleanupV1(f.vm,&d))==BUSY && !d.nativeInvoked);
    atomic_store_explicit(&f.release,true,memory_order_release); CHECK(!pthread_join(foreign,NULL));
    CHECK(BITS(VM27CPUFactoryOwnerCleanupV1(f.vm,&d))==ERROR && d.nativeInvoked && d.nativeReturn==0x177 && d.cleanupPending);
    CHECK(!memcmp(exit,preserved,32)); CHECK(BITS(VM27CPUFactoryVMFreeV1(f.vm))==BUSY); ++scenarios;
    f.failDestroy=false; f.reenter=true;
    CHECK(VM27CPUFactoryOwnerCleanupV1(f.vm,&d)==0 && !f.reenter && !d.cleanupPending && d.nativeInvoked);
    CHECK(BITS(VM27CPUFactoryDestroyV1(f.identity,&d))==BAD); Finish(&f); ++scenarios;
    // Each failed native create/read/full64 version lane uses the same product.
    for (unsigned failure=0; failure<3; ++failure) {
        Start(&f); f.failCreate=failure==0; f.failRead=failure==1;
        if (failure==2) { uint64_t lowOnly=0xe; memcpy(f.page+0x4000,&lowOnly,8); }
        id=99; exit=(void*)1;
        CHECK(BITS(VM27CPUFactoryCreateV1(f.vm,&id,&exit,NULL,&d))==ERROR && id==99 && exit==(void*)1);
        CHECK(d.nativeInvoked && d.cleanupPending==(failure!=0) && !d.nativeCPUCreationComplete && !d.exitRecordValid);
        if (failure) {
            CHECK(BITS(VM27CPUFactoryVMDestroyV1(f.vm,&d))==BUSY);
            unsigned creates=f.creates;
            CHECK(BITS(VM27CPUFactoryCreateV1(f.vm,&id,&exit,NULL,&d))==BUSY && f.creates==creates);
            f.failRead=false; uint64_t full=VZ_KERNEL_NATIVE_CONTEXT_VERSION; memcpy(f.page+0x4000,&full,8);
            CHECK(VM27CPUFactoryOwnerCleanupV1(f.vm,&d)==0 && !d.nativeCPUCreationComplete);
        } else CHECK(BITS(VM27CPUFactoryOwnerCleanupV1(f.vm,&d))==BAD);
        Finish(&f); ++scenarios;
    }
    // Simultaneous own live CPUs on two actual worker threads, mock op6 fixed0.
    Start(&f); exit=Create(&f); pthread_t worker;
    CHECK(!pthread_create(&worker,NULL,WorkerCPU,&f)); atomic_store_explicit(&f.start,true,memory_order_release);
    CHECK(!pthread_join(worker,NULL));
    CHECK(VM27CPUFactoryDestroyV1(f.identity,&d)==0 && d.nativeInvoked && !d.cleanupPending);
    f.failVM=true; CHECK(BITS(VM27CPUFactoryVMDestroyV1(f.vm,&d))==ERROR && d.nativeReturn==0x122);
    CHECK(BITS(VM27CPUFactoryVMFreeV1(f.vm))==BUSY);
    f.failVM=false; Finish(&f); ++scenarios;
    printf("{\"checks\":%u,\"scenarios\":%u,\"actualPthreadOwnerAndForeignBorrow\":true,\"linkedActualV5Lifecycle\":true,\"mockTrapOnly\":true,\"deviceOperations\":0,\"nativeCallsExecuted\":0,\"nativeRun\":false,\"validExitProduced\":false,\"full27Backend\":false}\n",Checks,scenarios);
    return 0;
}
