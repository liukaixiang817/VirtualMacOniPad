/* Local injected mocks only. No actual kernel trap or candidate library load. */
#include "modern_cpu_kernel_lifecycle_v4.h"
#include "modern_cpu_native_fields.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VZ_MULTICPU_WHITEBOX
#include "modern_cpu_kernel_lifecycle_v4.c"
#endif
static _Atomic unsigned Checks;
#define CHECK(x) do { ++Checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
typedef struct Fixture Fixture;
typedef struct Worker Worker;
enum { CREATE=1, INSPECT, CROSS, DESTROY, RELEASE, DEAD, CORRUPT, VERIFY, DEADCROSS, VMSPOOF, EXIT, CREATE_AND_EXIT };
enum { NOHOOK=0, THREADHOOK, READHOOK, DESTROYHOOK, VMTHREADHOOK };
struct Worker {
    Fixture *f; unsigned index;
    pthread_t thread;
    pthread_mutex_t mutex; pthread_cond_t condition;
    unsigned command, done; bool running;
    VZKernelCPU *cpu; VZKernelLifecycleResult identity;
    unsigned char page[0x4130], before[0x4130];
    unsigned hook, creates, destroys, reads, threadCalls;
    bool failCreate, failDestroy, failRead, nullContext, badVersion;
    bool spoofOther, spoofVM; unsigned otherIndex;
    VZKernelStatus status;
};
struct Fixture {
    VZKernelVM *vm; VZKernelLifecycleResult identity;
    VZKernelLifecycleOps ops; VZKernelVMOptions options;
    Worker workers[3]; Worker main;
    _Atomic unsigned trapCalls;
    _Atomic unsigned readCalls;
    _Atomic unsigned threadCalls;
    bool failVMCreate, failVMDestroy;
    pthread_mutex_t blockMutex; pthread_cond_t blockCond;
    bool blockCreate, enteredCreate, releaseCreate;
};
static _Thread_local Worker *Current;
static uint64_t ActualThread(void) { return (uint64_t)(uintptr_t)pthread_self(); }
static void Unlocked(Fixture *f) {
#ifdef VZ_MULTICPU_WHITEBOX
    if(f->vm){CHECK(!pthread_mutex_trylock(&f->vm->mutex));CHECK(!pthread_mutex_unlock(&f->vm->mutex));}
#else
    (void)f;
#endif
}
static void CPUReentry(Worker *w) {
    Fixture *f=w->f; unsigned t=f->trapCalls, reads=f->readCalls, threads=f->threadCalls;
#ifdef VZ_MULTICPU_WHITEBOX
    VZKernelCPU *cpu=w->cpu?w->cpu:OwnedCPU;
#else
    VZKernelCPU *cpu=w->cpu;
#endif
    CHECK(cpu);
    VZKernelLifecycleResult r; VZCPUPendingInterruptValuesV1 out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    CHECK(VZKernelCPUSetPendingInterruptV3(cpu,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_BUSY);
    CHECK(VZKernelCPUReadPendingInterruptsV3(cpu,&out)==VZ_KERNEL_BUSY);
    CHECK(!memcmp(&out,&before,sizeof(out)));
    CHECK(VZKernelCPUContextVersion(cpu,&r)==VZ_KERNEL_BUSY);
    CHECK(VZKernelCPUDestroy(cpu,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
    CHECK(VZKernelCPUFree(cpu)==VZ_KERNEL_BUSY);
    CHECK(f->trapCalls==t && f->readCalls==reads && f->threadCalls==threads);
}
static uint64_t Thread(void *context) {
    Fixture *f=context;Worker *w=Current;CHECK(w && w->f==f);++w->threadCalls;++f->threadCalls;Unlocked(f);
    if(w->hook==THREADHOOK){w->hook=NOHOOK;CPUReentry(w);}
    if(w->hook==VMTHREADHOOK){
        w->hook=NOHOOK;unsigned calls=f->threadCalls;VZKernelVM *out=(void*)1;VZKernelLifecycleResult r;
        CHECK(VZKernelVMCreate(&f->ops,&f->options,&out,&r)==VZ_KERNEL_BUSY && !out && !r.nativeInvoked);
        CHECK(f->threadCalls==calls);
    }
    if(w->spoofVM)return f->identity.ownerThread;
    if(w->spoofOther)return f->workers[w->otherIndex].identity.ownerThread;
    return ActualThread();
}
static bool Read(void *context,const void *address,size_t bytes,void *out) {
    Fixture *f=context;Worker *w=Current;CHECK(w && w->f==f);++w->reads;++f->readCalls;Unlocked(f);
    uintptr_t at=(uintptr_t)address-(uintptr_t)w->page;
    CHECK(at<=sizeof(w->page) && bytes<=sizeof(w->page)-at);
    if(w->hook==READHOOK){w->hook=NOHOOK;CPUReentry(w);}
    if(w->failRead)return false;
    memcpy(out,address,bytes);return true;
}
static VZKernelHVReturn Trap(void *context,uint64_t op,void *argument) {
    Fixture *f=context;Worker *w=Current;CHECK(w && w->f==f);++f->trapCalls;Unlocked(f);
    CHECK(op==1 || op==2 || op==6 || op==7);
    if(op==1){CHECK(argument);return f->failVMCreate?0x121:0;}
    if(op==2){CHECK(!argument);return f->failVMDestroy?0x122:0;}
    if(op==6){
        ++w->creates;uint64_t *a=argument;CHECK(a && a[0]==0 && a[1]==0);
        pthread_mutex_lock(&f->blockMutex);
        if(f->blockCreate){f->enteredCreate=true;pthread_cond_broadcast(&f->blockCond);
            while(!f->releaseCreate)pthread_cond_wait(&f->blockCond,&f->blockMutex);}
        pthread_mutex_unlock(&f->blockMutex);
#ifdef VZ_MULTICPU_WHITEBOX
        if(w->hook==READHOOK){CPUReentry(w);}
#endif
        if(w->failCreate)return 0x126;
        // Every mock returns the same word: this cannot be a public ID.
        a[0]=0;a[1]=w->nullContext?0:(uintptr_t)w->page;return 0;
    }
    ++w->destroys;CHECK(!argument);
    if(w->hook==DESTROYHOOK){w->hook=NOHOOK;CPUReentry(w);}
    return w->failDestroy?0x127:0;
}
static void Pending(Worker *w,unsigned irq,unsigned fiq) {
    unsigned traps=w->f->trapCalls,reads=w->f->readCalls;VZCPUPendingInterruptValuesV1 out;
    CHECK(VZKernelCPUReadPendingInterruptsV3(w->cpu,&out)==VZ_KERNEL_OK);
    CHECK(out.schemaVersion==1 && out.irqPending==irq && out.fiqPending==fiq && !out.reserved);
    CHECK(w->f->trapCalls==traps && w->f->readCalls==reads);
}
static void Inspect(Worker *w) {
    Fixture *f=w->f;VZCPUPendingInterruptValuesV1 out,before;memset(&out,0xa5,sizeof(out));before=out;
    Pending(w,0,0);unsigned traps=f->trapCalls,reads=f->readCalls;
    CHECK(VZKernelCPUSetPendingInterruptV3(w->cpu,VZ_CPU_PENDING_IRQ_V1,w->index&1)==VZ_KERNEL_OK);
    CHECK(VZKernelCPUSetPendingInterruptV3(w->cpu,VZ_CPU_PENDING_FIQ_V1,(w->index+1)&1)==VZ_KERNEL_OK);
    Pending(w,w->index&1,(w->index+1)&1);
    CHECK(VZKernelCPUSetPendingInterruptV3(w->cpu,(VZCPUPendingInterruptTypeV1)2,0)==VZ_KERNEL_UNSUPPORTED);
    CHECK(VZKernelCPUSetPendingInterruptV3(w->cpu,VZ_CPU_PENDING_IRQ_V1,2)==VZ_KERNEL_BAD_ARGUMENT);
    CHECK(VZKernelCPUReadPendingInterruptsV3(NULL,&out)==VZ_KERNEL_BAD_ARGUMENT && !memcmp(&out,&before,sizeof(out)));
    Pending(w,w->index&1,(w->index+1)&1);CHECK(f->trapCalls==traps && f->readCalls==reads);
    w->hook=THREADHOOK;Pending(w,w->index&1,(w->index+1)&1);CHECK(w->hook==NOHOOK);
    w->hook=THREADHOOK;CHECK(VZKernelCPUSetPendingInterruptV3(w->cpu,VZ_CPU_PENDING_IRQ_V1,w->index&1)==VZ_KERNEL_OK);
    VZKernelLifecycleResult r;
    if(!w->badVersion && !w->failRead && !w->nullContext){w->hook=READHOOK;CHECK(VZKernelCPUContextVersion(w->cpu,&r)==VZ_KERNEL_OK);CHECK(w->hook==NOHOOK);}
    // A same-worker second live CPU is rejected before any native callback.
    VZKernelCPU *other=(void*)1;traps=f->trapCalls;
    CHECK(VZKernelCPUCreate(f->vm,&other,&r)==VZ_KERNEL_BUSY && !other && !r.nativeInvoked && f->trapCalls==traps);
}
static void Cross(Worker *w) {
    Worker *other=&w->f->workers[w->otherIndex];CHECK(other->cpu);
    VZCPUPendingInterruptValuesV1 out,before;memset(&out,0xa5,sizeof(out));before=out;
    VZKernelLifecycleResult r;unsigned traps=w->f->trapCalls,reads=w->f->readCalls;
    CHECK(VZKernelCPUReadPendingInterruptsV3(other->cpu,&out)==VZ_KERNEL_WRONG_THREAD && !memcmp(&out,&before,sizeof(out)));
    CHECK(VZKernelCPUSetPendingInterruptV3(other->cpu,VZ_CPU_PENDING_FIQ_V1,0)==VZ_KERNEL_WRONG_THREAD);
    CHECK(VZKernelCPUDestroy(other->cpu,&r)==VZ_KERNEL_WRONG_THREAD && !r.nativeInvoked);
    CHECK(VZKernelCPUFree(other->cpu)==VZ_KERNEL_WRONG_THREAD);
    w->spoofOther=true;
    CHECK(VZKernelCPUReadPendingInterruptsV3(other->cpu,&out)==VZ_KERNEL_NOT_LIVE && !memcmp(&out,&before,sizeof(out)));
    CHECK(VZKernelCPUSetPendingInterruptV3(other->cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_NOT_LIVE);
    CHECK(VZKernelCPUDestroy(other->cpu,&r)==VZ_KERNEL_NOT_LIVE && !r.nativeInvoked);
    CHECK(VZKernelCPUFree(other->cpu)==VZ_KERNEL_WRONG_THREAD);w->spoofOther=false;
    CHECK(w->f->trapCalls==traps && w->f->readCalls==reads);
}
static void Dead(Worker *w) {
    VZCPUPendingInterruptValuesV1 out,before;memset(&out,0xa5,sizeof(out));before=out;
    CHECK(VZKernelCPUReadPendingInterruptsV3(w->cpu,&out)==VZ_KERNEL_NOT_LIVE && !memcmp(&out,&before,sizeof(out)));
    CHECK(VZKernelCPUSetPendingInterruptV3(w->cpu,VZ_CPU_PENDING_IRQ_V1,1)==VZ_KERNEL_NOT_LIVE);
    VZKernelLifecycleResult r;CHECK(VZKernelCPUDestroy(w->cpu,&r)==VZ_KERNEL_NOT_LIVE && !r.nativeInvoked);
#ifdef VZ_MULTICPU_WHITEBOX
    VZCPUPendingInterruptValuesV1 zero={0};CHECK(!memcmp(&w->cpu->pendingInterrupts,&zero,sizeof(zero)));
#endif
}
static void Corrupt(Worker *w) {
#ifdef VZ_MULTICPU_WHITEBOX
    Fixture *f=w->f;VZKernelCPU *cpu=w->cpu;VZCPUPendingInterruptValuesV1 saved=cpu->pendingInterrupts,out,before;
    memset(&out,0xa5,sizeof(out));before=out;
    for(unsigned bad=0;bad<6;++bad){
        if(bad==0)++cpu->generation;
        if(bad==1)++f->vm->generation;
        if(bad==2)cpu->registryEntry->cpuGeneration=0;
        if(bad==3)cpu->registryEntry->vmEpoch=0;
        if(bad==4)cpu->registryEntry->cpu=NULL;
        if(bad==5)OwnedCPU=NULL;
        CHECK(VZKernelCPUReadPendingInterruptsV3(cpu,&out)==VZ_KERNEL_NOT_LIVE && !memcmp(&out,&before,sizeof(out)));
        CHECK(VZKernelCPUSetPendingInterruptV3(cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_NOT_LIVE);
        CHECK(!memcmp(&cpu->pendingInterrupts,&saved,sizeof(saved)));
        VZKernelLifecycleResult r;CHECK(VZKernelCPUDestroy(cpu,&r)==VZ_KERNEL_NOT_LIVE && !r.nativeInvoked);
        if(bad==0)--cpu->generation;
        if(bad==1)--f->vm->generation;
        if(bad==2)cpu->registryEntry->cpuGeneration=cpu->generation;
        if(bad==3)cpu->registryEntry->vmEpoch=f->vm->generation;
        if(bad==4)cpu->registryEntry->cpu=cpu;
        if(bad==5)OwnedCPU=cpu;
    }
    for(unsigned bad=0;bad<4;++bad){
        if(bad==0)cpu->pendingInterrupts.schemaVersion=2;
        if(bad==1)cpu->pendingInterrupts.irqPending=2;
        if(bad==2)cpu->pendingInterrupts.fiqPending=2;
        if(bad==3)cpu->pendingInterrupts.reserved=1;
        VZCPUPendingInterruptValuesV1 malformed=cpu->pendingInterrupts;
        CHECK(VZKernelCPUReadPendingInterruptsV3(cpu,&out)==VZ_KERNEL_BAD_ARGUMENT && !memcmp(&out,&before,sizeof(out)));
        CHECK(VZKernelCPUSetPendingInterruptV3(cpu,VZ_CPU_PENDING_IRQ_V1,0)==VZ_KERNEL_BAD_ARGUMENT);
        CHECK(!memcmp(&cpu->pendingInterrupts,&malformed,sizeof(malformed)));cpu->pendingInterrupts=saved;
    }
    void *aliases[20];unsigned count=0;
    aliases[count++]=f->vm;aliases[count++]=(char*)f->vm+sizeof(*f->vm)-8;aliases[count++]=(void*)(UINTPTR_MAX-8);
    for(VZKernelCPURegistryEntryV4 *entry=f->vm->cpuRegistry;entry;entry=entry->next){
        aliases[count++]=entry;aliases[count++]=(char*)entry+sizeof(*entry)-8;
        aliases[count++]=entry->cpu;aliases[count++]=(char*)entry->cpu+sizeof(*entry->cpu)-8;
    }
    for(unsigned i=0;i<count;++i){CHECK(VZKernelCPUReadPendingInterruptsV3(cpu,aliases[i])==VZ_KERNEL_BAD_ARGUMENT);CHECK(!memcmp(&cpu->pendingInterrupts,&saved,sizeof(saved)));}
    CHECK(count==15);CHECK(f->vm->cpuHandles==3 && f->vm->liveCPUs==3);
#else
    (void)w;
#endif
}
static void *WorkerMain(void *context) {
    Worker *w=context;Current=w;pthread_mutex_lock(&w->mutex);w->running=true;pthread_cond_broadcast(&w->condition);
    for(;;){
        while(!w->command)pthread_cond_wait(&w->condition,&w->mutex);
        unsigned command=w->command;w->command=0;pthread_mutex_unlock(&w->mutex);
        if(command==EXIT)break;
        if(command==CREATE || command==CREATE_AND_EXIT)w->status=VZKernelCPUCreate(w->f->vm,&w->cpu,&w->identity);
        if(command==INSPECT)Inspect(w);
        if(command==CROSS)Cross(w);
        if(command==DESTROY){VZKernelLifecycleResult r;w->status=VZKernelCPUDestroy(w->cpu,&r);CHECK(r.nativeInvoked);}
        if(command==RELEASE){w->hook=THREADHOOK;w->status=VZKernelCPUFree(w->cpu);CHECK(w->hook==NOHOOK);if(w->status==VZ_KERNEL_OK)w->cpu=NULL;}
        if(command==DEAD)Dead(w);
        if(command==CORRUPT)Corrupt(w);
        if(command==VERIFY)Pending(w,w->index&1,(w->index+1)&1);
        if(command==VMSPOOF){
            unsigned traps=w->f->trapCalls;VZKernelLifecycleResult r;w->spoofVM=true;
            CHECK(VZKernelVMDestroy(w->f->vm,&r)==VZ_KERNEL_WRONG_THREAD && !r.nativeInvoked);
            CHECK(VZKernelVMFree(w->f->vm)==VZ_KERNEL_WRONG_THREAD);w->spoofVM=false;
            CHECK(w->f->trapCalls==traps);
        }
        if(command==DEADCROSS){
            Worker *other=&w->f->workers[w->otherIndex];VZCPUPendingInterruptValuesV1 out,before;
            memset(&out,0xa5,sizeof(out));before=out;
            CHECK(VZKernelCPUReadPendingInterruptsV3(other->cpu,&out)==VZ_KERNEL_WRONG_THREAD && !memcmp(&out,&before,sizeof(out)));
            w->spoofOther=true;
            CHECK(VZKernelCPUReadPendingInterruptsV3(other->cpu,&out)==VZ_KERNEL_NOT_LIVE && !memcmp(&out,&before,sizeof(out)));
            CHECK(VZKernelCPUFree(other->cpu)==VZ_KERNEL_WRONG_THREAD);w->spoofOther=false;
        }
        pthread_mutex_lock(&w->mutex);++w->done;pthread_cond_broadcast(&w->condition);
        if(command==CREATE_AND_EXIT){pthread_mutex_unlock(&w->mutex);return NULL;}
    }
    pthread_mutex_lock(&w->mutex);w->running=false;pthread_cond_broadcast(&w->condition);pthread_mutex_unlock(&w->mutex);return NULL;
}
static void Submit(Worker *w,unsigned command) {pthread_mutex_lock(&w->mutex);CHECK(!w->command);w->command=command;pthread_cond_broadcast(&w->condition);pthread_mutex_unlock(&w->mutex);}
static void Await(Worker *w,unsigned done) {pthread_mutex_lock(&w->mutex);while(w->done<done)pthread_cond_wait(&w->condition,&w->mutex);pthread_mutex_unlock(&w->mutex);}
static void Command(Worker *w,unsigned command) {unsigned done=w->done+1;Submit(w,command);Await(w,done);}
static void FixtureStart(Fixture *f,unsigned isa) {
    memset(f,0,sizeof(*f));pthread_mutex_init(&f->blockMutex,NULL);pthread_cond_init(&f->blockCond,NULL);
    f->main.f=f;f->main.index=0;Current=&f->main;
    f->options=(VZKernelVMOptions){36,0,isa,false,false};
    f->ops=(VZKernelLifecycleOps){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,f,Trap,Thread,Read};
    f->main.hook=VMTHREADHOOK;CHECK(VZKernelVMCreate(&f->ops,&f->options,&f->vm,&f->identity)==VZ_KERNEL_OK);CHECK(!f->main.hook);
    for(unsigned i=0;i<3;++i){
        Worker *w=&f->workers[i];w->f=f;w->index=i;pthread_mutex_init(&w->mutex,NULL);pthread_cond_init(&w->condition,NULL);
        memset(w->page,0xa5,sizeof(w->page));uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(w->page+0x4000,&version,8);memcpy(w->before,w->page,sizeof(w->page));
        CHECK(!pthread_create(&w->thread,NULL,WorkerMain,w));pthread_mutex_lock(&w->mutex);while(!w->running)pthread_cond_wait(&w->condition,&w->mutex);pthread_mutex_unlock(&w->mutex);
    }
}
static void VMBusy(Fixture *f,bool cpuLive) {
    unsigned traps=f->trapCalls;VZKernelLifecycleResult r;
    CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked && r.cpuLive==cpuLive && r.vmLive && r.cleanupPending);
    CHECK(r.generation==f->identity.generation);
    CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_BUSY && f->trapCalls==traps);
}
static void FixtureFinish(Fixture *f) {
    for(unsigned i=0;i<3;++i){Worker *w=&f->workers[i];CHECK(!w->cpu);Submit(w,EXIT);CHECK(!pthread_join(w->thread,NULL));pthread_mutex_destroy(&w->mutex);pthread_cond_destroy(&w->condition);CHECK(!memcmp(w->page,w->before,sizeof(w->page)));}
    VZKernelLifecycleResult r;f->failVMDestroy=true;CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_NATIVE_ERROR && r.vmLive);CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_BUSY);
    f->failVMDestroy=false;CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_OK && !r.cpuLive && !r.cleanupPending);CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_OK);f->vm=NULL;
    pthread_mutex_destroy(&f->blockMutex);pthread_cond_destroy(&f->blockCond);
}
int main(int argc,char **argv) {
    unsigned cases=0;
    if(argc==2 && !strcmp(argv[1],"--owner-exit")){
        Fixture f;FixtureStart(&f,1);Worker *w=&f.workers[0];Command(w,CREATE_AND_EXIT);CHECK(w->status==VZ_KERNEL_OK && w->cpu);CHECK(!pthread_join(w->thread,NULL));VMBusy(&f,true);
        VZKernelLifecycleResult r;CHECK(VZKernelCPUDestroy(w->cpu,&r)==VZ_KERNEL_WRONG_THREAD && !r.nativeInvoked);CHECK(VZKernelCPUFree(w->cpu)==VZ_KERNEL_WRONG_THREAD);
        for(unsigned i=1;i<3;++i){Submit(&f.workers[i],EXIT);CHECK(!pthread_join(f.workers[i].thread,NULL));}
        printf("{\"checks\":%u,\"ownerExitCleanupTracked\":true,\"nativeRun\":false,\"nativeMultiAllocationProved\":false,\"full27Backend\":false}\n",Checks);return 0;
    }
    CHECK(argc==1);
    for(unsigned isa=1;isa<=2;++isa){
        Fixture f;FixtureStart(&f,isa);uint64_t epoch=f.identity.generation;
        for(unsigned i=0;i<3;++i){Worker *w=&f.workers[i];Command(w,CREATE);CHECK(w->status==VZ_KERNEL_OK && w->identity.ownerThread && w->identity.generation && w->identity.returnedSlotWord==0);if(i)CHECK(w->identity.generation>f.workers[i-1].identity.generation);++cases;}
        VMBusy(&f,true);CHECK(f.identity.generation==epoch);
        for(unsigned i=0;i<3;++i){Command(&f.workers[i],INSPECT);++cases;}
        for(unsigned i=0;i<3;++i){f.workers[i].otherIndex=(i+1)%3;Command(&f.workers[i],CROSS);++cases;}
        Command(&f.workers[0],CORRUPT);Command(&f.workers[0],VMSPOOF);++cases;
        // A failed owner destroy retains exactly that CPU while siblings survive.
        f.workers[1].failDestroy=true;f.workers[1].hook=DESTROYHOOK;Command(&f.workers[1],DESTROY);CHECK(f.workers[1].status==VZ_KERNEL_NATIVE_ERROR);VMBusy(&f,true);
        Command(&f.workers[1],VERIFY);Command(&f.workers[0],VERIFY);Command(&f.workers[2],VERIFY);
        ++cases;
        for(unsigned j=0;j<3;++j){unsigned i=(j+1)%3;Worker *w=&f.workers[i];w->failDestroy=false;w->hook=DESTROYHOOK;Command(w,DESTROY);CHECK(w->status==VZ_KERNEL_OK);Command(w,DEAD);++cases;}
        VMBusy(&f,false);CHECK(f.identity.generation==epoch);
        // Dead foreign handle refuses free even if currentThread spoofs its owner.
        f.workers[0].otherIndex=1;Command(&f.workers[0],DEADCROSS);
        for(unsigned i=0;i<3;++i){Command(&f.workers[i],RELEASE);CHECK(f.workers[i].status==VZ_KERNEL_OK);++cases;}
        FixtureFinish(&f);
        // Fixed-zero native creation failures don't disturb retained sibling.
        FixtureStart(&f,isa);Command(&f.workers[0],CREATE);CHECK(f.workers[0].status==VZ_KERNEL_OK);
        f.workers[1].failCreate=true;Command(&f.workers[1],CREATE);CHECK(f.workers[1].status==VZ_KERNEL_NATIVE_ERROR && !f.workers[1].cpu);VMBusy(&f,true);++cases;
        for(unsigned failure=0;failure<3;++failure){Worker *w=&f.workers[1];w->failCreate=false;w->failRead=failure==0;w->nullContext=failure==1;w->badVersion=failure==2;
            uint64_t version=w->badVersion?0:VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(w->page+0x4000,&version,8);memcpy(w->before,w->page,sizeof(w->page));
            Command(w,CREATE);CHECK(w->status==(failure==2?VZ_KERNEL_CONTEXT_VERSION_MISMATCH:VZ_KERNEL_CONTEXT_UNREADABLE) && w->cpu && w->identity.cpuLive);Command(w,INSPECT);VMBusy(&f,true);
            Command(w,DESTROY);CHECK(w->status==VZ_KERNEL_OK);VMBusy(&f,true);Command(w,RELEASE);CHECK(w->status==VZ_KERNEL_OK);++cases;
        }
        Command(&f.workers[0],DESTROY);Command(&f.workers[0],RELEASE);FixtureFinish(&f);
        // Contending create is rejected; a distinct live owner remains usable
        // throughout another worker's reserved native callback window.
        FixtureStart(&f,isa);Command(&f.workers[0],CREATE);Command(&f.workers[0],INSPECT);
#ifdef VZ_MULTICPU_WHITEBOX
        uint64_t next=NextCPUGenerationV4;unsigned trapsBefore=f.trapCalls;
        NextCPUGenerationV4=UINT64_MAX;Command(&f.workers[2],CREATE);
        CHECK(f.workers[2].status==VZ_KERNEL_BUSY && !f.workers[2].cpu && f.trapCalls==trapsBefore);NextCPUGenerationV4=next;
        unsigned handles=f.vm->cpuHandles;f.vm->cpuHandles=UINT_MAX;Command(&f.workers[2],CREATE);
        CHECK(f.workers[2].status==VZ_KERNEL_BUSY && !f.workers[2].cpu && f.trapCalls==trapsBefore);f.vm->cpuHandles=handles;
#endif
        f.blockCreate=true;Submit(&f.workers[1],CREATE);pthread_mutex_lock(&f.blockMutex);while(!f.enteredCreate)pthread_cond_wait(&f.blockCond,&f.blockMutex);pthread_mutex_unlock(&f.blockMutex);
        unsigned traps=f.trapCalls;Command(&f.workers[2],CREATE);CHECK(f.workers[2].status==VZ_KERNEL_BUSY && !f.workers[2].cpu && f.trapCalls==traps);
        Command(&f.workers[0],VERIFY);
        VZKernelLifecycleResult r;CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_BUSY);
        pthread_mutex_lock(&f.blockMutex);f.releaseCreate=true;pthread_cond_broadcast(&f.blockCond);pthread_mutex_unlock(&f.blockMutex);Await(&f.workers[1],1);f.blockCreate=false;CHECK(f.workers[1].status==VZ_KERNEL_OK);++cases;
        for(unsigned i=0;i<2;++i){Command(&f.workers[i],DESTROY);Command(&f.workers[i],RELEASE);}FixtureFinish(&f);
#ifdef VZ_MULTICPU_WHITEBOX
        uint64_t oldEpochCounter=NextGeneration;NextGeneration=UINT64_MAX;VZKernelVM *uncreated=(void*)1;traps=f.trapCalls;
        CHECK(VZKernelVMCreate(&f.ops,&f.options,&uncreated,&r)==VZ_KERNEL_BUSY && !uncreated && !r.nativeInvoked && f.trapCalls==traps);NextGeneration=oldEpochCounter;
#endif

    }
    printf("{\"checks\":%u,\"cases\":%u,\"whitebox\":%s,\"actualPthreads\":true,\"fixedOp6RequestZero\":true,\"nativeCallsExecuted\":0,\"nativeRun\":false,\"nativeMultiAllocationProved\":false,\"full27Backend\":false}\n",Checks,cases,
#ifdef VZ_MULTICPU_WHITEBOX
    "true"
#else
    "false"
#endif
    );return 0;
}
