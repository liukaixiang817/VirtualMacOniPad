#include "modern_cpu_native_public_factory_v4.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
#include "modern_cpu_kernel_system_private.h"
#include <CoreFoundation/CoreFoundation.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {++Checks;if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);abort();}}while(0)
static unsigned Checks;
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out){(void)out;abort();}
typedef struct {
    unsigned char *memory;
    unsigned op1,op2,op6,op7,op8,reads,writes,fieldReads;
    int32_t eightReturn;
    bool reentry,badPostVersion,failWriteAfterCopy;
    uint32_t offsets[64];
    VM27CPUFactoryVMV2 *vm;VM27CPUFactoryBorrowV2 *borrow;VM27CPUFactoryIDV2 id;
} Mock;
static uint64_t Thread(void *p){(void)p;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t;}
static int32_t Trap(void *p,uint64_t op,void *args){
    Mock *m=p;
    if(op==1){++m->op1;CHECK(args);return 0;}
    if(op==2){++m->op2;CHECK(!args);return 0;}
    if(op==6){++m->op6;CHECK(args && !((uint64_t *)args)[0] && !((uint64_t *)args)[1]);
        ((uint64_t *)args)[1]=(uintptr_t)m->memory;uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;
        memcpy(m->memory+0x4000,&magic,8);return 0;}
    if(op==7){++m->op7;CHECK(!args);return 0;}
    CHECK(op==8 && !args);++m->op8;
    if(m->reentry){
        VZKernelSysReceipt r;memset(&r,0xa5,sizeof(r));VZKernelSysReceipt old=r;
        uint64_t value=42;
        CHECK(VM27CPUFactoryBorrowAccessSystemV4(m->borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,NULL)==(int32_t)UINT32_C(0xfae94002));
        CHECK(value==42 && !memcmp(&r,&old,sizeof(r)));
        CHECK(VM27CPUFactoryBorrowReleaseV2(m->borrow)==(int32_t)UINT32_C(0xfae94002));
        CHECK(VM27CPUFactoryOwnerCleanupV2(m->vm,NULL)==(int32_t)UINT32_C(0xfae94002));
        CHECK(VM27CPUFactoryVMDestroyV2(m->vm,NULL)==(int32_t)UINT32_C(0xfae94002));
        CHECK(VM27CPUFactoryVMFreeV2(m->vm)==(int32_t)UINT32_C(0xfae94002));
    }
    if(m->badPostVersion){uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION^(UINT64_C(1)<<32);memcpy(m->memory+0x4000,&magic,8);}
    // Successful mock8 deliberately does NOT set ready4100. Actual original
    // callers proceed directly after rc0; no invented readiness default.
    return m->eightReturn;
}
static bool Read(void *p,const void *address,size_t bytes,void *out){
    Mock *m=p;++m->reads;uintptr_t off=(uintptr_t)address-(uintptr_t)m->memory;
    CHECK(off<=0x8000 && bytes<=0x8000-off);
    if(off==0x400)++m->fieldReads;
    return VM27CPUSelfReadV1(NULL,address,bytes,out);
}
static bool Write(void *p,void *address,size_t bytes,const void *value){
    Mock *m=p;uintptr_t off=(uintptr_t)address-(uintptr_t)m->memory;
    CHECK(off<=0x8000 && bytes<=0x8000-off && m->writes<64);
    m->offsets[m->writes++]=(uint32_t)off;
    bool wrote=VM27CPUSelfWriteV1(NULL,address,bytes,value);
    return wrote && !m->failWriteAfterCopy;
}
static uint64_t Get(Mock *m,unsigned offset){uint64_t v;memcpy(&v,m->memory+offset,8);return v;}
static void Put(Mock *m,unsigned offset,uint64_t v){memcpy(m->memory+offset,&v,8);}
static void Start(Mock *m,VM27CPUConfigHandleV3 config){
    m->memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m->memory!=MAP_FAILED);
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,Read};
    VZKernelVMOptions options={36,0,1,false,false};VZKernelInitWriter writer={m,Write};
    CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m->vm,NULL));
    VM27CPUFactoryExitV2 *exit=NULL;CHECK(!VM27CPUFactoryCreateV2(m->vm,&m->id,&exit,config.object,NULL));
    CHECK(exit && !VM27CPUFactoryBorrowAcquireV2(m->id,&m->borrow));
    m->writes=0;m->reads=0;
}
static void Finish(Mock *m){
    CHECK(!VM27CPUFactoryBorrowReleaseV2(m->borrow));
    CHECK(!VM27CPUFactoryOwnerCleanupV2(m->vm,NULL));
    CHECK(!VM27CPUFactoryVMDestroyV2(m->vm,NULL));CHECK(!VM27CPUFactoryVMFreeV2(m->vm));
    CHECK(m->op1==1 && m->op2==1 && m->op6==1 && m->op7==1);
    CHECK(!munmap(m->memory,0x8000));
}
typedef struct {Mock *mock;unsigned calls;} Foreign;
static void *ForeignThread(void *p){
    Foreign *f=p;VM27CPUFactoryBorrowV2 *b=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(f->mock->id,&b));
    uint64_t value=77;VZKernelSysReceipt r={0};VM27CPUFactoryDiagnosticV2 d={0};
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(b,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d)==(int32_t)UINT32_C(0xfae94003));
    CHECK(value==77 && f->mock->op8==f->calls && d.ownStatus==VZ_KERNEL_WRONG_THREAD);
    CHECK(!VM27CPUFactoryBorrowReleaseV2(b));return NULL;
}
static bool UnusedRead(void *p,uint32_t off,size_t bytes,void *out){(void)p;(void)off;(void)bytes;(void)out;abort();}
static bool UnusedWrite(void *p,uint32_t off,size_t bytes,const void *value){(void)p;(void)off;(void)bytes;(void)value;abort();}
int main(void){
    setvbuf(stdout,NULL,_IOLBF,0);puts("MAIN own SYS Factory4; all native callbacks mocked; actual self-task Mach memory APIs");
    // A reused legacy private receipt must retain V2's false invocation flag.
    VZKernelSysFeatureCache cache={0};VZKernelSysReceipt legacyReceipt={0};legacyReceipt.nativeOp8Invoked=true;
    VZKernelSysRequest legacyRequest={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,0,0,0,1,VZ_KERNEL_SYS_WRITE,0xc020,3};
    VZKernelInitAccess legacyAccess={NULL,(bool (*)(void *,uint32_t,size_t,void *))NULL,(bool (*)(void *,uint32_t,size_t,const void *))NULL};
    // Engine requires two callbacks even on own feature-cache routes. These
    // function shapes are defined below and abort if that pure path calls one.
    legacyAccess.readAt=UnusedRead;legacyAccess.writeAt=UnusedWrite;
    CHECK(VZKernelSysApplyVerifiedRoute(&legacyRequest,&legacyAccess,&cache,NULL,&legacyReceipt)==VZ_KERNEL_OK);
    CHECK(!legacyReceipt.nativeOp8Invoked && cache.values[0]==3);
    VM27CPUConfigHandleV3 config={0};CHECK(!VM27CPUConfigCreateV3(&config));
    Mock m={0};Start(&m,config);VZKernelSysReceipt r={0};VM27CPUFactoryDiagnosticV2 d={0};uint64_t value=0;
    Put(&m,0x400,0x1234);Put(&m,0x748,0);Put(&m,0x4100,0);
    CHECK(!VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d));
    CHECK(value==0x1234 && m.op8==1 && r.nativeOp8Invoked && r.nativeOp8Required && Get(&m,0x4100)==0);
    CHECK(d.nativeInvoked && d.nativeReturn==0 && m.fieldReads==1);
    Put(&m,0x748,1);
    CHECK(!VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d));CHECK(m.op8==1 && !r.nativeOp8Invoked);
    CHECK(!VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_WRITE,0xc080,0xbeef,NULL,&r,&d));
    CHECK(m.op8==2 && r.nativeOp8Invoked && m.writes==2 && m.offsets[0]==0x400 && m.offsets[1]==0x748 && Get(&m,0x400)==0xbeef && Get(&m,0x748)==1);
    Put(&m,0x4100,1);CHECK(!VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_WRITE,0xc080,9,NULL,&r,&d));CHECK(m.op8==2);
    Foreign f={&m,m.op8};pthread_t t;CHECK(!pthread_create(&t,NULL,ForeignThread,&f));CHECK(!pthread_join(t,NULL));
    unsigned beforeReads=m.reads;VZKernelSysReceipt before=r;
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xc080,0,(uint64_t *)config.object,&r,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(m.reads==beforeReads && !memcmp(&r,&before,sizeof(r)));
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_WRITE,0xc080,0,NULL,(VZKernelSysReceipt *)config.object,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(m.reads==beforeReads);
    Put(&m,0x748,0);Put(&m,0x4100,0);m.eightReturn=-17;unsigned fieldReads=m.fieldReads,writes=m.writes;
    value=0x1122;CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d)==(int32_t)UINT32_C(0xfae94001));
    CHECK(value==0x1122 && m.fieldReads==fieldReads && m.writes==writes && r.nativeOp8Invoked && d.nativeReturn==-17);
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_WRITE,0xc080,0xbabe,NULL,&r,&d)==(int32_t)UINT32_C(0xfae94001));CHECK(m.writes==writes);
    m.eightReturn=0;m.reentry=true;
    CHECK(!VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d));m.reentry=false;
    unsigned calls=m.op8;CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xffff0000,0,&value,&r,&d)==(int32_t)UINT32_C(0xfae9400f));CHECK(m.op8==calls);
    m.badPostVersion=true;value=88;
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d)==(int32_t)UINT32_C(0xfae94001));CHECK(value==88);
    Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);m.badPostVersion=false;Finish(&m);
    Mock poisoned={0};Start(&poisoned,config);Put(&poisoned,0x4100,1);poisoned.failWriteAfterCopy=true;
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(poisoned.borrow,VZ_KERNEL_SYS_WRITE,0xc080,0xabcd,NULL,&r,&d)==(int32_t)UINT32_C(0xfae94001));
    CHECK(Get(&poisoned,0x400)==0xabcd && r.mutationPoisoned && r.cpuCleanupRequired && poisoned.op8==0);
    VM27CPUFactoryBorrowV2 *denied=NULL;CHECK(VM27CPUFactoryBorrowAcquireV2(poisoned.id,&denied)==(int32_t)UINT32_C(0xfae94003));CHECK(!denied);
    Finish(&poisoned);
    Mock hole={0};Start(&hole,config);CHECK(!mprotect(hole.memory+0x4000,0x4000,PROT_NONE));value=99;
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(hole.borrow,VZ_KERNEL_SYS_READ,0xc080,0,&value,&r,&d)==(int32_t)UINT32_C(0xfae94001));CHECK(value==99 && hole.op8==0);
    CHECK(!mprotect(hole.memory+0x4000,0x4000,PROT_READ|PROT_WRITE));Finish(&hole);
    Mock readonly={0};Start(&readonly,config);Put(&readonly,0x4100,1);CHECK(!mprotect(readonly.memory+0x4000,0x4000,PROT_READ));
    CHECK(!VM27CPUFactoryBorrowAccessSystemV4(readonly.borrow,VZ_KERNEL_SYS_WRITE,0xc080,0x55,NULL,&r,&d));
    CHECK(Get(&readonly,0x400)==0x55 && readonly.op8==0);CHECK(!mprotect(readonly.memory+0x4000,0x4000,PROT_READ|PROT_WRITE));Finish(&readonly);
    Mock deniedWrite={0};Start(&deniedWrite,config);Put(&deniedWrite,0x4100,1);
    CHECK(!mprotect(deniedWrite.memory,0x4000,PROT_READ));
    CHECK(VM27CPUFactoryBorrowAccessSystemV4(deniedWrite.borrow,VZ_KERNEL_SYS_WRITE,0xc080,42,NULL,&r,&d)==(int32_t)UINT32_C(0xfae94001));
    CHECK(deniedWrite.writes==0 && deniedWrite.op8==0 && r.mutationPoisoned);
    CHECK(!mprotect(deniedWrite.memory,0x4000,0x3));Finish(&deniedWrite);
    CFRelease((CFTypeRef)config.object);uint64_t made=0,destroyed=0;VM27CPUConfigTestCountsV3(&made,&destroyed);CHECK(made==1 && destroyed==1);
    printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",Checks,(unsigned long long)made,(unsigned long long)destroyed);
    return 0;
}
