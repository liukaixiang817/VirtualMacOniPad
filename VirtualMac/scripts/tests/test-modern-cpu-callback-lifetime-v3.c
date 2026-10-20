/* Host-only callback/reentrancy model. Every trap and context byte is mocked.
 * --probe modes deliberately reproduce the prior public lifetime contract.
 * The ordinary mode checks the repaired shared exclusion and its release. */
#include "modern_cpu_kernel_initialization.h"
#include "modern_cpu_kernel_system.h"
#include "modern_cpu_native_fields.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
typedef enum { NONE, ON_THREAD, ON_READ, ON_CPU_DESTROY, ON_VM_DESTROY, ON_CREATE, ON_VM_THREAD } Hook;
typedef struct {
    unsigned char bytes[0x4130];
    VZKernelVM *vm;
    VZKernelCPU *cpu;
    VZKernelLifecycleResult identity;
    Hook hook;
    bool probe, readFailure, nativeFailure, writeFailure, skipVMReentry;
    unsigned callbacks, traps, writes;
    VZKernelStatus nestedDestroy, nestedFree;
    uint64_t thread;
    uint32_t isa;
} Fixture;

static VZKernelInitRequest InitRequest(Fixture *f) {
    VZKernelInitRequest q = {0};
    q.schemaVersion=1; q.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1;
    q.expectedOwnerThread=f->identity.ownerThread;
    q.expectedCPUGeneration=f->identity.generation;
    q.expectedReturnedSlotWord=f->identity.returnedSlotWord;
    q.nativeHVISA=f->isa; q.operation=VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY;
    return q;
}
static VZKernelSysRequest SysRequest(Fixture *f) {
    VZKernelSysRequest q = {0};
    q.schemaVersion=1; q.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1;
    q.expectedOwnerThread=f->identity.ownerThread;
    q.expectedCPUGeneration=f->identity.generation;
    q.expectedReturnedSlotWord=f->identity.returnedSlotWord;
    q.nativeHVISA=f->isa; q.action=VZ_KERNEL_SYS_READ; q.identifier=0xc000;
    return q;
}
static bool Write(void *context, void *address, size_t bytes, const void *in) {
    Fixture *f=context; uintptr_t at=(uintptr_t)address-(uintptr_t)f->bytes;
    CHECK(at<=sizeof(f->bytes) && bytes<=sizeof(f->bytes)-at);
    memcpy(address,in,bytes);++f->writes;return !f->writeFailure;
}
static void ReenterCPU(Fixture *f) {
    VZKernelLifecycleResult r;
    ++f->callbacks;
    f->nestedDestroy=VZKernelCPUDestroy(f->cpu,&r);
    CHECK(!f->probe ? f->nestedDestroy==VZ_KERNEL_BUSY && !r.nativeInvoked : true);
    f->nestedFree=VZKernelCPUFree(f->cpu);
    CHECK(!f->probe ? f->nestedFree==VZ_KERNEL_BUSY : true);
    printf("REENTRY destroy=%u free=%u\n",f->nestedDestroy,f->nestedFree);fflush(stdout);
    if(f->probe)return;
    VZKernelNativeSnapshot snapshot,before;
    VZKernelNativeReadDiagnostics d;
    memset(&snapshot,0xa5,sizeof(snapshot));before=snapshot;
    CHECK(VZKernelCPUContextVersion(f->cpu,&r)==VZ_KERNEL_BUSY);
    CHECK(VZKernelCPUReadNativeFields(f->cpu,&snapshot,&d,&r)==VZ_KERNEL_BUSY);
    CHECK(!memcmp(&snapshot,&before,sizeof(snapshot)));
    VZKernelInitRequest iq=InitRequest(f);VZKernelInitWriter writer={f,Write};
    VZKernelInitReceipt ir;
    CHECK(VZKernelCPUApplyInitialization(f->cpu,&iq,&writer,&ir,&r)==VZ_KERNEL_BUSY);
    VZKernelSysRequest sq=SysRequest(f);VZKernelSysReceipt sr;
    uint64_t value=UINT64_C(0xa5a5a5a5a5a5a5a5);
    CHECK(VZKernelCPUAccessSystemRegister(f->cpu,&sq,NULL,&value,&sr,&r)==VZ_KERNEL_BUSY);
    CHECK(value==UINT64_C(0xa5a5a5a5a5a5a5a5));
    if(!f->skipVMReentry){
        CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
        CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_BUSY);
    }
}
static void ReenterVM(Fixture *f) {
    ++f->callbacks;VZKernelLifecycleResult r;VZKernelCPU *other=(void *)1;
    CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_BUSY);
    CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
    CHECK(VZKernelCPUCreate(f->vm,&other,&r)==VZ_KERNEL_BUSY && !other && !r.nativeInvoked);
}
static uint64_t Thread(void *context) {
    Fixture *f=context;
    if(f->hook==ON_THREAD){f->hook=NONE;ReenterCPU(f);}
    if(f->hook==ON_VM_THREAD){f->hook=NONE;ReenterVM(f);}
    return f->thread;
}
static bool Read(void *context,const void *address,size_t bytes,void *out) {
    Fixture *f=context;uintptr_t at=(uintptr_t)address-(uintptr_t)f->bytes;
    CHECK(at<=sizeof(f->bytes) && bytes<=sizeof(f->bytes)-at);
    if(f->hook==ON_READ){f->hook=NONE;ReenterCPU(f);}
    if(f->hook==ON_CREATE){
        f->hook=NONE;++f->callbacks;
        if(f->probe){CHECK(f->cpu);ReenterCPU(f);}
        else {
            CHECK(!f->cpu);VZKernelLifecycleResult r;VZKernelCPU *other=(void *)1;
            CHECK(VZKernelCPUCreate(f->vm,&other,&r)==VZ_KERNEL_BUSY && !other && !r.nativeInvoked);
            CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
            CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_BUSY);
        }
    }
    if(f->readFailure)return false;
    memcpy(out,address,bytes);return true;
}
static VZKernelHVReturn Trap(void *context,uint64_t operation,void *argument) {
    Fixture *f=context;++f->traps;
    CHECK(operation==1 || operation==2 || operation==6 || operation==7);
    if(operation==6){uint64_t *p=argument;CHECK(p && !p[0] && !p[1]);p[1]=(uintptr_t)f->bytes;}
    if(operation==7 && f->hook==ON_CPU_DESTROY){f->hook=NONE;ReenterCPU(f);}
    if(operation==2 && f->hook==ON_VM_DESTROY){
        f->hook=NONE;++f->callbacks;puts("VM destroy callback entered");fflush(stdout);
        f->nestedFree=VZKernelVMFree(f->vm);
        if(!f->probe){
            CHECK(f->nestedFree==VZ_KERNEL_BUSY);VZKernelLifecycleResult r;VZKernelCPU *other=(void *)1;
            CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_BUSY && !r.nativeInvoked);
            CHECK(VZKernelCPUCreate(f->vm,&other,&r)==VZ_KERNEL_BUSY && !other && !r.nativeInvoked);
        }
    }
    return f->nativeFailure ? -1 : 0;
}
static void VMCreate(Fixture *f,uint32_t isa) {
    memset(f,0,sizeof(*f));f->thread=1;f->isa=isa;
    uint64_t v=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(f->bytes+0x4000,&v,8);
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,f,Trap,Thread,Read};
    VZKernelVMOptions options={36,0,isa,false,false};
    CHECK(VZKernelVMCreate(&ops,&options,&f->vm,&f->identity)==VZ_KERNEL_OK);
}
static void CPUCreate(Fixture *f) {
    CHECK(VZKernelCPUCreate(f->vm,&f->cpu,&f->identity)==VZ_KERNEL_OK);
}
static void Policy(Fixture *f) {
    VZKernelInitRequest q=InitRequest(f);VZKernelInitWriter writer={f,Write};VZKernelInitReceipt receipt;
    CHECK(VZKernelCPUApplyInitialization(f->cpu,&q,&writer,&receipt,&f->identity)==VZ_KERNEL_OK);
    CHECK(receipt.creationPolicySliceComplete && !receipt.mutationPoisoned);
}
static void Cleanup(Fixture *f) {
    VZKernelLifecycleResult r;
    if(f->cpu){CHECK(VZKernelCPUDestroy(f->cpu,&r)==VZ_KERNEL_OK);CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_OK);f->cpu=NULL;}
    CHECK(VZKernelVMDestroy(f->vm,&r)==VZ_KERNEL_OK);CHECK(VZKernelVMFree(f->vm)==VZ_KERNEL_OK);f->vm=NULL;
}
static void Invoke(Fixture *f,const char *name) {
    VZKernelLifecycleResult r;
    if(!strcmp(name,"init") || !strcmp(name,"thread")) {
        VZKernelInitRequest q=InitRequest(f);VZKernelInitWriter writer={f,Write};VZKernelInitReceipt receipt;
        CHECK(VZKernelCPUApplyInitialization(f->cpu,&q,&writer,&receipt,&r)==VZ_KERNEL_OK);
    } else if(!strcmp(name,"sys")) {
        VZKernelSysRequest q=SysRequest(f);VZKernelSysReceipt receipt;uint64_t out=UINT64_C(0xa5);
        CHECK(VZKernelCPUAccessSystemRegister(f->cpu,&q,NULL,&out,&receipt,&r)==VZ_KERNEL_OK);
    } else if(!strcmp(name,"snapshot")) {
        VZKernelNativeSnapshot snapshot;VZKernelNativeReadDiagnostics d;
        CHECK(VZKernelCPUReadNativeFields(f->cpu,&snapshot,&d,&r)==VZ_KERNEL_OK);
    } else if(!strcmp(name,"destroy")) {
        CHECK(VZKernelCPUDestroy(f->cpu,&r)==VZ_KERNEL_OK);
        CHECK(VZKernelCPUFree(f->cpu)==VZ_KERNEL_OK);f->cpu=NULL;
    } else {
        CHECK(VZKernelCPUContextVersion(f->cpu,&r)==VZ_KERNEL_OK);
        if(f->probe)CHECK(VZKernelCPUContextVersion(f->cpu,&r)==VZ_KERNEL_OK);
    }
}
int main(int argc,char **argv) {
    Fixture f;
    if(argc==3 && !strcmp(argv[1],"--probe")) {
        const char *name=argv[2];VMCreate(&f,1);f.probe=true;
        if(!strcmp(name,"vm")){f.hook=ON_VM_DESTROY;VZKernelLifecycleResult r;VZKernelVMDestroy(f.vm,&r);return 0;}
        if(!strcmp(name,"create")){f.hook=ON_CREATE;CPUCreate(&f);Invoke(&f,"version");return 0;}
        CPUCreate(&f);if(!strcmp(name,"sys"))Policy(&f);
        f.hook=!strcmp(name,"thread")?ON_THREAD:!strcmp(name,"destroy")?ON_CPU_DESTROY:ON_READ;
        Invoke(&f,name);return 0;
    }
    CHECK(argc==1);unsigned scenarios=0;
    for(uint32_t isa=1;isa<=2;++isa) {
        const char *names[]={"init","sys","version","thread","destroy"};
        for(unsigned i=0;i<5;++i){
            VMCreate(&f,isa);CPUCreate(&f);if(!strcmp(names[i],"sys"))Policy(&f);
            f.hook=!strcmp(names[i],"thread")?ON_THREAD:!strcmp(names[i],"destroy")?ON_CPU_DESTROY:ON_READ;
            Invoke(&f,names[i]);CHECK(f.callbacks==1);Cleanup(&f);CHECK(f.traps==4);++scenarios;
        }
        VMCreate(&f,isa);f.hook=ON_CREATE;CPUCreate(&f);CHECK(f.callbacks==1);Cleanup(&f);++scenarios;
        /* Every pre-validation failure releases exclusion, without writes,
         * mutation poisoning, or pretending actual resources disappeared. */
        VMCreate(&f,isa);CPUCreate(&f);
        VZKernelLifecycleResult r;VZKernelInitRequest iq=InitRequest(&f);
        VZKernelInitWriter writer={&f,Write};VZKernelInitReceipt ir;
        f.readFailure=true;
        CHECK(VZKernelCPUApplyInitialization(f.cpu,&iq,&writer,&ir,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
        CHECK(!ir.attemptedWrites && !ir.mutationPoisoned && ir.cpuCleanupRequired);
        CHECK(VZKernelCPUContextVersion(f.cpu,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
        f.readFailure=false;Policy(&f);VZKernelSysRequest sq=SysRequest(&f);VZKernelSysReceipt sr;uint64_t out=UINT64_C(0xa5);
        f.readFailure=true;
        CHECK(VZKernelCPUAccessSystemRegister(f.cpu,&sq,NULL,&out,&sr,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
        CHECK(out==UINT64_C(0xa5) && !sr.attemptedNativeWrites && !sr.mutationPoisoned && sr.cpuCleanupRequired);
        f.readFailure=false;CHECK(VZKernelCPUAccessSystemRegister(f.cpu,&sq,NULL,&out,&sr,&r)==VZ_KERNEL_OK);
        f.nativeFailure=true;CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_NATIVE_ERROR);
        CHECK(r.cpuLive && r.cleanupPending && VZKernelCPUFree(f.cpu)==VZ_KERNEL_BUSY);
        f.nativeFailure=false;Cleanup(&f);++scenarios;
        VMCreate(&f,isa);f.hook=ON_VM_DESTROY;CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_OK);
        CHECK(f.callbacks==1 && f.traps==2 && VZKernelVMFree(f.vm)==VZ_KERNEL_OK);++scenarios;
        VMCreate(&f,isa);f.nativeFailure=true;CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_NATIVE_ERROR);
        CHECK(r.vmLive && r.cleanupPending && VZKernelVMFree(f.vm)==VZ_KERNEL_BUSY);
        f.nativeFailure=false;Cleanup(&f);++scenarios;
        /* CPU creation runs on its own owner worker, independently of VM owner. */
        VMCreate(&f,isa);f.thread=2;CPUCreate(&f);CHECK(f.identity.ownerThread==2);
        CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_OK);CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);f.cpu=NULL;
        f.thread=1;Cleanup(&f);++scenarios;
        /* All other CPU public entry points guard their currentThread call. */
        const char *threadNames[]={"sys","version","destroy","snapshot"};
        for(unsigned i=0;i<4;++i){
            VMCreate(&f,isa);CPUCreate(&f);if(!strcmp(threadNames[i],"sys"))Policy(&f);
            f.hook=ON_THREAD;Invoke(&f,threadNames[i]);CHECK(f.callbacks==1);
            Cleanup(&f);CHECK(f.traps==4);++scenarios;
        }
        VMCreate(&f,isa);CPUCreate(&f);CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_OK);
        f.skipVMReentry=true;f.hook=ON_THREAD;CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);f.cpu=NULL;
        CHECK(f.callbacks==1);Cleanup(&f);CHECK(f.traps==4);++scenarios;
        /* VM handles also stay alive through currentThread in create/destroy/free. */
        for(unsigned operation=0;operation<3;++operation){
            VMCreate(&f,isa);
            if(operation==2)CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_OK);
            f.hook=ON_VM_THREAD;
            if(operation==0){CPUCreate(&f);Cleanup(&f);}
            else if(operation==1){CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_OK);CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_OK);}
            else CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_OK);
            CHECK(f.callbacks==1);++scenarios;
        }
        /* Native creation followed by an invalid read/version still publishes
         * a real live cleanup handle after the callback, with no stale guard. */
        for(unsigned failure=0;failure<3;++failure){
            VMCreate(&f,isa);f.hook=ON_CREATE;
            f.readFailure=failure==0;f.nativeFailure=failure==2;
            uint64_t version=failure==1?0:VZ_KERNEL_NATIVE_CONTEXT_VERSION;
            memcpy(f.bytes+0x4000,&version,8);
            VZKernelStatus expected=failure==0?VZ_KERNEL_CONTEXT_UNREADABLE:
                failure==1?VZ_KERNEL_CONTEXT_VERSION_MISMATCH:VZ_KERNEL_NATIVE_ERROR;
            CHECK(VZKernelCPUCreate(f.vm,&f.cpu,&f.identity)==expected);
            CHECK(f.identity.nativeInvoked);
            if(failure==2){CHECK(!f.cpu);f.nativeFailure=false;f.hook=NONE;CPUCreate(&f);}
            else CHECK(f.cpu && f.identity.cpuLive && f.identity.cleanupPending && f.callbacks==1);
            f.readFailure=false;Cleanup(&f);++scenarios;
        }
        /* WrongThread refusal must release every acquired guard. Init/SYS
         * still report the owned native resources; read outputs stay intact. */
        VMCreate(&f,isa);CPUCreate(&f);iq=InitRequest(&f);writer=(VZKernelInitWriter){&f,Write};sq=SysRequest(&f);
        f.thread=2;
        CHECK(VZKernelCPUContextVersion(f.cpu,&r)==VZ_KERNEL_WRONG_THREAD);
        VZKernelNativeSnapshot snapshot,before;VZKernelNativeReadDiagnostics d;
        memset(&snapshot,0xa5,sizeof(snapshot));before=snapshot;
        CHECK(VZKernelCPUReadNativeFields(f.cpu,&snapshot,&d,&r)==VZ_KERNEL_WRONG_THREAD);
        CHECK(!memcmp(&snapshot,&before,sizeof(snapshot)));
        CHECK(VZKernelCPUApplyInitialization(f.cpu,&iq,&writer,&ir,&r)==VZ_KERNEL_WRONG_THREAD);
        CHECK(ir.cpuCleanupRequired && !ir.mutationPoisoned && !ir.attemptedWrites);
        out=UINT64_C(0xa5);
        CHECK(VZKernelCPUAccessSystemRegister(f.cpu,&sq,NULL,&out,&sr,&r)==VZ_KERNEL_WRONG_THREAD);
        CHECK(sr.cpuCleanupRequired && !sr.mutationPoisoned && out==UINT64_C(0xa5));
        CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_WRONG_THREAD);
        CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_WRONG_THREAD);
        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_WRONG_THREAD);
        CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_WRONG_THREAD);
        f.thread=1;Cleanup(&f);++scenarios;
        VMCreate(&f,isa);CPUCreate(&f);iq=InitRequest(&f);writer=(VZKernelInitWriter){&f,Write};sq=SysRequest(&f);
        CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_OK);
        CHECK(VZKernelCPUContextVersion(f.cpu,&r)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelCPUReadNativeFields(f.cpu,&snapshot,&d,&r)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelCPUApplyInitialization(f.cpu,&iq,&writer,&ir,&r)==VZ_KERNEL_NOT_LIVE && !ir.cpuCleanupRequired);
        CHECK(VZKernelCPUAccessSystemRegister(f.cpu,&sq,NULL,&out,&sr,&r)==VZ_KERNEL_NOT_LIVE && !sr.cpuCleanupRequired);
        CHECK(VZKernelCPUDestroy(f.cpu,&r)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_OK);
        VZKernelCPU *other=(void *)1;CHECK(VZKernelCPUCreate(f.vm,&other,&r)==VZ_KERNEL_NOT_LIVE && !other);
        CHECK(VZKernelVMDestroy(f.vm,&r)==VZ_KERNEL_NOT_LIVE);
        CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_BUSY);
        CHECK(VZKernelCPUFree(f.cpu)==VZ_KERNEL_OK);CHECK(VZKernelVMFree(f.vm)==VZ_KERNEL_OK);++scenarios;
        /* A false writer may have already copied: poison remains truthful,
         * operation exclusion is released and real owner teardown still works. */
        VMCreate(&f,isa);CPUCreate(&f);Policy(&f);sq=SysRequest(&f);
        sq.action=VZ_KERNEL_SYS_WRITE;sq.value=UINT64_C(0x12345678);f.writeFailure=true;
        CHECK(VZKernelCPUAccessSystemRegister(f.cpu,&sq,&writer,NULL,&sr,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);
        CHECK(sr.attemptedNativeWrites==1 && !sr.completedNativeWrites && sr.mutationPoisoned && sr.cpuCleanupRequired);
        uint64_t copied;memcpy(&copied,f.bytes+0x698,8);CHECK(copied==sq.value);
        CHECK(VZKernelCPUAccessSystemRegister(f.cpu,&sq,&writer,NULL,&sr,&r)==VZ_KERNEL_BUSY && sr.mutationPoisoned);
        f.writeFailure=false;Cleanup(&f);++scenarios;
    }
    CHECK(scenarios==48);printf("PASS: %u callback lifetime/release/failure/owner scenarios; local mocks only\n",scenarios);return 0;
}
