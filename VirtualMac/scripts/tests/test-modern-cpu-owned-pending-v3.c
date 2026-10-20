/* Only local mock traps, fixture memory and actual pthread ownership are used.
 * Whitebox mode includes the alternative unit to exercise otherwise private
 * corruption/cleanup boundaries without adding any product test export. */
#include "modern_cpu_kernel_lifecycle_v3.h"
#include "modern_cpu_kernel_initialization.h"
#include "modern_cpu_kernel_system.h"
#include "modern_cpu_native_fields.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#ifdef VZ_PENDING_WHITEBOX
#include "modern_cpu_kernel_lifecycle_v3.c"
#endif

static _Atomic unsigned Checks;
#define CHECK(x) do { ++Checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
typedef struct {
    unsigned char bytes[0x4130];
    VZKernelVM *vm;
    VZKernelCPU *cpu;
    VZKernelLifecycleResult identity;
    unsigned trapCalls, readCalls, threadCalls, reentries;
    bool currentThreadReentry, readReentry, destroyReentry, failDestroy;
    bool concurrentReentry;
    bool spoofOwnerOnOtherThread, returnZeroThread;
    VZKernelStatus workerSet, workerRead;
    uint32_t isa;
} Fixture;
static void *OtherThread(void *context);

static uint64_t ActualThread(void) {
    return (uint64_t)(uintptr_t)pthread_self();
}
static void Reenter(Fixture *f) {
    ++f->reentries;
    unsigned threads=f->threadCalls, reads=f->readCalls, traps=f->trapCalls;
    CHECK(VZKernelCPUSetPendingInterruptV3(f->cpu,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_BUSY);
    VZCPUPendingInterruptValuesV1 out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    CHECK(VZKernelCPUReadPendingInterruptsV3(f->cpu,&out)==VZ_KERNEL_BUSY);
    CHECK(!memcmp(&out,&before,sizeof(out)));
    VZKernelLifecycleResult r;
    CHECK(VZKernelCPUDestroy(f->cpu,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
    CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_BUSY);
    CHECK(VZKernelCPUContextVersion(f->cpu,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
    CHECK(f->threadCalls==threads && f->readCalls==reads && f->trapCalls==traps);
}
static uint64_t Thread(void *context) {
    Fixture *f=context;++f->threadCalls;
    if(f->currentThreadReentry){f->currentThreadReentry=false;Reenter(f);}
    if(f->concurrentReentry){
        f->concurrentReentry=false;unsigned before=f->threadCalls;
        pthread_t worker;CHECK(!pthread_create(&worker,NULL,OtherThread,f));CHECK(!pthread_join(worker,NULL));
        CHECK(f->workerSet==VZ_KERNEL_BUSY && f->workerRead==VZ_KERNEL_BUSY);
        CHECK(f->threadCalls==before);
    }
    if(f->returnZeroThread)return 0;
    return f->spoofOwnerOnOtherThread ? f->identity.ownerThread : ActualThread();
}
static bool Read(void *context,const void *address,size_t bytes,void *out) {
    Fixture *f=context;++f->readCalls;
    uintptr_t at=(uintptr_t)address-(uintptr_t)f->bytes;
    CHECK(at<=sizeof(f->bytes) && bytes<=sizeof(f->bytes)-at);
    if(f->readReentry){f->readReentry=false;Reenter(f);}
    memcpy(out,address,bytes);return true;
}
static VZKernelHVReturn Trap(void *context,uint64_t op,void *argument) {
    Fixture *f=context;++f->trapCalls;
    CHECK(op==1 || op==2 || op==6 || op==7);
    if(op==6){uint64_t *a=argument;CHECK(a && !a[0] && !a[1]);a[1]=(uintptr_t)f->bytes;}
    if(op==7){CHECK(!argument);if(f->destroyReentry){f->destroyReentry=false;Reenter(f);}if(f->failDestroy)return -1;}
    return 0;
}
static void FixtureStart(Fixture *f,uint32_t isa) {
    memset(f,0,sizeof(*f));f->isa=isa;
    uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(f->bytes+0x4000,&version,8);
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,f,Trap,Thread,Read};
    VZKernelVMOptions q={36,0,isa,false,false};
    CHECK(VZKernelVMCreate(&ops,&q,&f->vm,&f->identity)==VZ_KERNEL_OK);
    CHECK(VZKernelCPUCreate(f->vm,&f->cpu,&f->identity)==VZ_KERNEL_OK);
    CHECK(f->identity.ownerThread==ActualThread());
}
static VZCPUPendingInterruptValuesV1 Value(Fixture *f,unsigned irq,unsigned fiq) {
    unsigned reads=f->readCalls,traps=f->trapCalls;
    VZCPUPendingInterruptValuesV1 out;
    memset(&out,0xa5,sizeof(out));
    CHECK(VZKernelCPUReadPendingInterruptsV3(f->cpu,&out)==VZ_KERNEL_OK);
    CHECK(out.schemaVersion==1 && out.irqPending==irq && out.fiqPending==fiq && !out.reserved);
    CHECK(f->readCalls==reads && f->trapCalls==traps);
    return out;
}
static void Set(Fixture *f,VZCPUPendingInterruptTypeV1 type,uint32_t pending) {
    unsigned reads=f->readCalls,traps=f->trapCalls;
    CHECK(VZKernelCPUSetPendingInterruptV3(f->cpu,type,pending)==VZ_KERNEL_OK);
    CHECK(f->readCalls==reads && f->trapCalls==traps);
}
static void Cleanup(Fixture *f) {
    VZKernelLifecycleResult r;
    if(f->cpu){CHECK(VZKernelCPUDestroy(f->cpu,&r)==VZ_KERNEL_OK);CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_OK);f->cpu=NULL;}
    CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_OK);
    CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_OK);f->vm=NULL;
}
static void *OtherThread(void *context) {
    Fixture *f=context;
    VZCPUPendingInterruptValuesV1 out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    f->workerSet=VZKernelCPUSetPendingInterruptV3(f->cpu,VZ_CPU_PENDING_FIQ_V1,0);
    f->workerRead=VZKernelCPUReadPendingInterruptsV3(f->cpu,&out);
    CHECK(!memcmp(&out,&before,sizeof(out)));
    return NULL;
}

int main(void) {
    unsigned scenarios=0;
    for(uint32_t isa=1;isa<=2;++isa){
        Fixture f;FixtureStart(&f,isa);Value(&f,0,0);++scenarios;
        // All four states are independent and start from own calloc zero.
        for(unsigned irq=0;irq<2;++irq)for(unsigned fiq=0;fiq<2;++fiq){
            Set(&f,VZ_CPU_PENDING_IRQ_V1,irq);Set(&f,VZ_CPU_PENDING_FIQ_V1,fiq);
            Value(&f,irq,fiq);Set(&f,VZ_CPU_PENDING_IRQ_V1,irq);Value(&f,irq,fiq);++scenarios;
        }
        VZCPUPendingInterruptValuesV1 out,before;
        memset(&out,0xa5,sizeof(out));before=out;
        CHECK(VZKernelCPUReadPendingInterruptsV3(NULL,&out)==VZ_KERNEL_BAD_ARGUMENT);
        CHECK(!memcmp(&out,&before,sizeof(out)));
        CHECK(VZKernelCPUReadPendingInterruptsV3(f.cpu,NULL)==VZ_KERNEL_BAD_ARGUMENT);
        CHECK(VZKernelCPUSetPendingInterruptV3(NULL,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_BAD_ARGUMENT);
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,(VZCPUPendingInterruptTypeV1)2,0)==VZ_KERNEL_UNSUPPORTED);
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,(VZCPUPendingInterruptTypeV1)UINT32_MAX,0)==VZ_KERNEL_UNSUPPORTED);
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,2)==VZ_KERNEL_BAD_ARGUMENT);
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_FIQ_V1,UINT32_MAX)==VZ_KERNEL_BAD_ARGUMENT);
        Value(&f,1,1);++scenarios;
        // Exclusion is acquired before the only allowed callback, currentThread.
        f.currentThreadReentry=true;Set(&f,VZ_CPU_PENDING_IRQ_V1,0);
        CHECK(f.reentries==1);Value(&f,0,1);
        f.currentThreadReentry=true;Value(&f,0,1);CHECK(f.reentries==2);++scenarios;
        f.concurrentReentry=true;Value(&f,0,1);++scenarios;
        // Pending callbacks share exclusion with existing native/read lifetime.
        f.readReentry=true;VZKernelLifecycleResult r;
        CHECK(VZKernelCPUContextVersion(f.cpu,&r)==VZ_KERNEL_OK);
        CHECK(f.reentries==3);Value(&f,0,1);++scenarios;
        f.returnZeroThread=true;
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_WRONG_THREAD);
        memset(&out,0xa5,sizeof(out));before=out;
        CHECK(VZKernelCPUReadPendingInterruptsV3(f.cpu,&out)==VZ_KERNEL_WRONG_THREAD);
        CHECK(!memcmp(&out,&before,sizeof(out)));f.returnZeroThread=false;Value(&f,0,1);++scenarios;
        for(unsigned spoof=0;spoof<2;++spoof){
            f.spoofOwnerOnOtherThread=spoof!=0;
            pthread_t worker;CHECK(!pthread_create(&worker,NULL,OtherThread,&f));CHECK(!pthread_join(worker,NULL));
            VZKernelStatus expected=spoof?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_WRONG_THREAD;
            CHECK(f.workerSet==expected && f.workerRead==expected);
            f.spoofOwnerOnOtherThread=false;Value(&f,0,1);++scenarios;
        }
        // Native version failure cannot make an own-state getter read context.
        uint64_t invalid=0;memcpy(f.bytes+0x4000,&invalid,8);
        Set(&f,VZ_CPU_PENDING_IRQ_V1,1);Value(&f,1,1);
        CHECK(VZKernelCPUContextVersion(f.cpu,&r)==VZ_KERNEL_CONTEXT_VERSION_MISMATCH);
        Value(&f,1,1);uint64_t valid=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(f.bytes+0x4000,&valid,8);++scenarios;
        // Failed native destroy preserves both cleanup ownership and pending.
        f.failDestroy=true;f.destroyReentry=true;
        CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_NATIVE_ERROR && r.cpuLive && r.cleanupPending);
        CHECK(f.reentries==4);Value(&f,1,1);CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_BUSY);
        f.failDestroy=false;f.destroyReentry=true;
        CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_OK && !r.cpuLive);
        CHECK(f.reentries==5);memset(&out,0xa5,sizeof(out));before=out;
        CHECK(VZKernelCPUReadPendingInterruptsV3(f.cpu,&out)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_NOT_LIVE);
        CHECK(!memcmp(&out,&before,sizeof(out)));
#ifdef VZ_PENDING_WHITEBOX
        VZCPUPendingInterruptValuesV1 zero={0};CHECK(!memcmp(&f.cpu->pendingInterrupts,&zero,sizeof(zero)));
#endif
        f.returnZeroThread=true;CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_WRONG_THREAD);f.returnZeroThread=false;
        f.currentThreadReentry=true;CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);f.cpu=NULL;CHECK(f.reentries==6);
        CHECK(VZKernelCPUCreate(f.vm,&f.cpu,&f.identity)==VZ_KERNEL_OK);Value(&f,0,0);++scenarios;
        Cleanup(&f);CHECK(f.trapCalls==7);++scenarios;

        // A genuinely successful mock creation with an unconsumable native
        // version still has a live cleanup handle; pending remains own state.
        FixtureStart(&f,isa);CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_OK);
        CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);f.cpu=NULL;
        invalid=0;memcpy(f.bytes+0x4000,&invalid,8);
        CHECK(VZKernelCPUCreate(f.vm,&f.cpu,&f.identity)==VZ_KERNEL_CONTEXT_VERSION_MISMATCH);
        CHECK(f.cpu && f.identity.cpuLive);Value(&f,0,0);Set(&f,VZ_CPU_PENDING_FIQ_V1,1);Value(&f,0,1);
        Cleanup(&f);++scenarios;

        // Old destroyed handle and new CPU must not exchange TLS/generation.
        FixtureStart(&f,isa);Set(&f,VZ_CPU_PENDING_FIQ_V1,1);
        uint64_t oldGeneration=f.identity.generation;VZKernelCPU *old=f.cpu;
        CHECK(VZKernelCPUDestroy(old,&r)==VZ_KERNEL_OK);
        CHECK(VZKernelCPUCreate(f.vm,&f.cpu,&f.identity)==VZ_KERNEL_OK);
        CHECK(f.identity.generation>oldGeneration);Value(&f,0,0);
        CHECK(VZKernelCPUSetPendingInterruptV3(old,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_NOT_LIVE);
        memset(&out,0xa5,sizeof(out));before=out;
        CHECK(VZKernelCPUReadPendingInterruptsV3(old,&out)==VZ_KERNEL_NOT_LIVE);
        CHECK(!memcmp(&out,&before,sizeof(out)));
        CHECK(VZKernelCPUFree(old)==VZ_KERNEL_OK);Value(&f,0,0);Cleanup(&f);++scenarios;

#ifdef VZ_PENDING_WHITEBOX
        // Malformed private values are rejected without a mutation or output.
        FixtureStart(&f,isa);Set(&f,VZ_CPU_PENDING_IRQ_V1,1);Set(&f,VZ_CPU_PENDING_FIQ_V1,1);
        VZCPUPendingInterruptValuesV1 saved=f.cpu->pendingInterrupts;
        for(unsigned bad=0;bad<4;++bad){
            f.cpu->pendingInterrupts=saved;
            if(bad==0)f.cpu->pendingInterrupts.schemaVersion=2;
            if(bad==1)f.cpu->pendingInterrupts.irqPending=2;
            if(bad==2)f.cpu->pendingInterrupts.fiqPending=2;
            if(bad==3)f.cpu->pendingInterrupts.reserved=1;
            VZCPUPendingInterruptValuesV1 malformed=f.cpu->pendingInterrupts;
            CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_BAD_ARGUMENT);
            CHECK(!memcmp(&f.cpu->pendingInterrupts,&malformed,sizeof(malformed)));
            memset(&out,0xa5,sizeof(out));before=out;
            CHECK(VZKernelCPUReadPendingInterruptsV3(f.cpu,&out)==VZ_KERNEL_BAD_ARGUMENT);
            CHECK(!memcmp(&out,&before,sizeof(out)));
            CHECK(!memcmp(&f.cpu->pendingInterrupts,&malformed,sizeof(malformed)));++scenarios;
        }
        f.cpu->pendingInterrupts=saved;
        // Reject whole/partial aliases with both private allocations and wrap.
        void *aliases[]={f.cpu,&f.cpu->pendingInterrupts,(char*)f.cpu+sizeof(*f.cpu)-8,
                         f.vm,(char*)f.vm+sizeof(*f.vm)-8,(void*)(UINTPTR_MAX-8)};
        for(unsigned i=0;i<sizeof(aliases)/sizeof(aliases[0]);++i){
            CHECK(VZKernelCPUReadPendingInterruptsV3(f.cpu,aliases[i])==VZ_KERNEL_BAD_ARGUMENT);
            CHECK(!memcmp(&f.cpu->pendingInterrupts,&saved,sizeof(saved)));Value(&f,1,1);++scenarios;
        }
        // Actual lifetime/TLS/generation boundaries, not supplied claims.
        f.vm->live=false;CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_NOT_LIVE);f.vm->live=true;
        VZKernelCPU *active=f.vm->activeCPU;f.vm->activeCPU=NULL;
        CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_NOT_LIVE);f.vm->activeCPU=active;
        OwnedCPU=NULL;CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_NOT_LIVE);OwnedCPU=f.cpu;
        ++f.cpu->generation;CHECK(VZKernelCPUSetPendingInterruptV3(f.cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_NOT_LIVE);--f.cpu->generation;
        CHECK(!memcmp(&f.cpu->pendingInterrupts,&saved,sizeof(saved)));Value(&f,1,1);++scenarios;
        Cleanup(&f);
#endif
    }
    printf("{\"checks\":%u,\"scenarios\":%u,\"whitebox\":%s,\"deviceOperations\":0,\"nativeCallsExecuted\":0,\"full27Backend\":false}\n",Checks,scenarios,
#ifdef VZ_PENDING_WHITEBOX
        "true"
#else
        "false"
#endif
    );
    return 0;
}
