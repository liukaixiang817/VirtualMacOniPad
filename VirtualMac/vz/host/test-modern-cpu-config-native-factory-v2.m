#include "modern_cpu_native_public_factory_v2.h"
#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do { ++Checks; if (!(v)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v); abort(); } } while (0)
static unsigned Checks, CapabilityCalls;
static VM27CPUTLBICapabilityValueV1 TestCapability;
static VM27CPUConfigHandleV3 QueryReentry;
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out) {
    ++CapabilityCalls;
    if (QueryReentry.object) {
        VM27CPUConfigBorrowV3 *sentinel=(void *)(uintptr_t)0x1234;
        CHECK(VM27CPUConfigSetTLBIV3(QueryReentry,0)==VM27_CPU_CONFIG_BUSY_V3);
        CHECK(VM27CPUConfigBorrowObjectV3(QueryReentry.object,&sentinel)==VM27_CPU_CONFIG_BUSY_V3);
        CHECK(sentinel==(void *)(uintptr_t)0x1234);
    }
    *out=TestCapability;
}
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
typedef struct {
    unsigned char memory[0x5000];
    unsigned op1,op2,op6,op7,reads,writes;
    unsigned failWrite,postConfigVersionReads; bool badVersion,failCreate,failDestroy,reenter,corruptPublishVersion;
    uint32_t offsets[32]; uint64_t values[32];
    VM27CPUFactoryVMV2 *vm;
} Mock;
static uint64_t Thread(void *opaque) { (void)opaque; uint64_t value=0; CHECK(!pthread_threadid_np(NULL,&value)); return value; }
static int32_t Trap(void *opaque,uint64_t op,void *args) {
    Mock *m=opaque;
    if(op==1) { ++m->op1; CHECK(args && ((uint64_t *)args)[0]==0); return 0; }
    if(op==2) { ++m->op2; CHECK(!args); return 0; }
    if(op==6) {
        ++m->op6; CHECK(args && ((uint64_t *)args)[0]==0 && ((uint64_t *)args)[1]==0);
        if(m->failCreate)return -1;
        ((uint64_t *)args)[1]=(uintptr_t)m->memory;
        uint64_t version=m->badVersion ? 0xe : VZ_KERNEL_NATIVE_CONTEXT_VERSION;
        memcpy(m->memory+0x4000,&version,8); return 0;
    }
    CHECK(op==7 && !args); ++m->op7; return m->failDestroy ? -1 : 0;
}
static bool Read(void *opaque,const void *p,size_t n,void *out) {
    Mock *m=opaque; ++m->reads; uintptr_t off=(uintptr_t)p-(uintptr_t)m->memory;
    CHECK(off<=sizeof(m->memory) && n<=sizeof(m->memory)-off);
    if(off==0x4000 && n==8 && m->corruptPublishVersion && m->writes==7 && ++m->postConfigVersionReads==2) {
        uint64_t wrong=0xe;memcpy(out,&wrong,8);return true;
    }
    memcpy(out,p,n); return true;
}
static bool Write(void *opaque,void *p,size_t n,const void *value) {
    Mock *m=opaque; uintptr_t off=(uintptr_t)p-(uintptr_t)m->memory;
    CHECK(off<=sizeof(m->memory) && n<=sizeof(m->memory)-off && m->writes<32);
    m->offsets[m->writes]=(uint32_t)off; m->values[m->writes]=0; memcpy(&m->values[m->writes],value,n<8?n:8); ++m->writes;
    if(m->reenter) {
        CHECK(VM27CPUFactoryOwnerCleanupV2(m->vm,NULL)==(int32_t)UINT32_C(0xfae94002));
        CHECK(VM27CPUFactoryVMDestroyV2(m->vm,NULL)==(int32_t)UINT32_C(0xfae94002));
        CHECK(VM27CPUFactoryVMFreeV2(m->vm)==(int32_t)UINT32_C(0xfae94002));
    }
    memcpy(p,value,n); return m->failWrite!=m->writes;
}
static uint64_t Word(Mock *m,unsigned off) { uint64_t value;memcpy(&value,m->memory+off,8);return value; }
static void CreateVM(Mock *m) {
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,Read};
    VZKernelVMOptions options={36,0,1,false,false}; VZKernelInitWriter writer={m,Write};
    CHECK(VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m->vm,NULL)==0);
}
static void FreeVM(Mock *m) { CHECK(VM27CPUFactoryVMDestroyV2(m->vm,NULL)==0); CHECK(VM27CPUFactoryVMFreeV2(m->vm)==0); }
typedef struct { VM27CPUFactoryIDV2 id; Mock *mock; } Foreign;
static void *ForeignThread(void *opaque) {
    Foreign *f=opaque; VM27CPUFactoryBorrowV2 *borrow=NULL;
    CHECK(VM27CPUFactoryBorrowAcquireV2(f->id,&borrow)==0);
    VZKernelInitWriter writer={f->mock,Write}; VZKernelInitReceipt receipt;
    memset(&receipt,0xa5,sizeof(receipt)); VZKernelInitReceipt before=receipt;
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SCALAR,0,42,0,&writer,&receipt,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(!memcmp(&receipt,&before,sizeof(receipt)));
    CHECK(VM27CPUFactoryBorrowReleaseV2(borrow)==0); return NULL;
}
int main(void) {
    setvbuf(stdout,NULL,_IOLBF,0); printf("MAIN own OSv3 + native-factory-source V2; all native traps mocked\n");
    VM27CPUConfigHandleV3 a={0},b={0}; CHECK(VM27CPUConfigCreateV3(&a)==0); CHECK(VM27CPUConfigCreateV3(&b)==0);
    VZKernelLifecycleOps noCall={0};VZKernelInitWriter noWriter={0};
    // A live config is protected even when no factory VM is registered.
    Mock admission={0};noCall=(VZKernelLifecycleOps){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&admission,Trap,Thread,Read};noWriter=(VZKernelInitWriter){&admission,Write};
    unsigned char first[48];memcpy(first,a.object,48);
    CHECK(VM27CPUFactoryVMCreateV2(&noCall,NULL,&noWriter,(VM27CPUFactoryVMV2 **)a.object,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(!memcmp(first,a.object,48) && admission.op1==0);
    CHECK(VM27CPUFactoryVMDestroyV2((void *)(uintptr_t)1,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryVMFreeV2((void *)(uintptr_t)1)==(int32_t)UINT32_C(0xfae94003));
    unsigned char saved[48];memcpy(saved,b.object,48);
    CHECK(VM27CPUConfigCopyV3(a,(VM27CPUConfigSnapshotV3 *)b.object)==VM27_CPU_CONFIG_BAD_ARGUMENT_V3);
    CHECK(!memcmp(saved,b.object,48)); CHECK(VM27CPUConfigSetTLBIV3(a,0)==0 && CapabilityCalls==0);
    CHECK(VM27CPUConfigSetTLBIV3(a,1)==VM27_CPU_CONFIG_UNSUPPORTED_V3);
    TestCapability=(VM27CPUTLBICapabilityValueV1){true,false}; CHECK(VM27CPUConfigSetTLBIV3(a,1)==VM27_CPU_CONFIG_UNSUPPORTED_V3);
    TestCapability=(VM27CPUTLBICapabilityValueV1){true,true}; QueryReentry=a;
    CHECK(VM27CPUConfigSetTLBIObjectV3(a.object,true)==0); QueryReentry=(VM27CPUConfigHandleV3){0};
    CHECK(VM27CPUConfigSetVMKeyV3(a,UINT64_C(0x123456789abcdef0),UINT64_C(0x0fedcba987654321))==0);
    CHECK(VM27CPUConfigSetFGTV3(a,1)==0);
    VM27CPUConfigBorrowV3 *configBorrow=NULL;
    CHECK(VM27CPUConfigBorrowObjectV3(a.object,&configBorrow)==0);
    CHECK(VM27CPUFactoryVMCreateV2(&noCall,NULL,&noWriter,(VM27CPUFactoryVMV2 **)configBorrow,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(admission.op1==0);
    VM27CPUConfigSnapshotV3 initial={0};CHECK(VM27CPUConfigReadBorrowV3(configBorrow,&initial)==0);
    CHECK(initial.trapTLBISW==1 && initial.supportKnown==1 && initial.fineGrainedTraps==1);
    CHECK(VM27CPUConfigSetVMKeyV3(a,7,8)==0);
    VM27CPUConfigSnapshotV3 stable={0}; CHECK(VM27CPUConfigReadBorrowV3(configBorrow,&stable)==0 && !memcmp(&stable,&initial,sizeof(stable)));
    CHECK(VM27CPUConfigReleaseBorrowV3(configBorrow)==0);
    CHECK(VM27CPUConfigSetVMKeyV3(a,initial.vmKeyLow,initial.vmKeyHigh)==0);
    Mock good={0}; good.reenter=true; good.memory[0x4030]=0x10; CreateVM(&good);
    VM27CPUFactoryIDV2 id=UINT64_C(0xfedcba);VM27CPUFactoryExitV2 *exit=(void *)(uintptr_t)0x1234;
    VM27CPUFactoryDiagnosticV2 diagnostic={0};
    memcpy(first,a.object,48);
    CHECK(VM27CPUFactoryCreateV2(good.vm,(VM27CPUFactoryIDV2 *)a.object,&exit,a.object,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryCreateV2(good.vm,&id,(VM27CPUFactoryExitV2 **)((unsigned char *)a.object+16),a.object,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryCreateV2(good.vm,&id,&exit,a.object,(VM27CPUFactoryDiagnosticV2 *)a.object)==(int32_t)UINT32_C(0xfae94003));
    CHECK(!memcmp(first,a.object,48) && id==UINT64_C(0xfedcba) && exit==(void *)(uintptr_t)0x1234 && good.op6==0);
    CHECK(VM27CPUFactoryCreateV2(good.vm,&id,&exit,a.object,&diagnostic)==0);
    CHECK(id && id!=UINT64_C(0xfedcba) && exit && diagnostic.cpuGeneration && diagnostic.vmEpoch);
    CHECK(diagnostic.nativeInvoked && diagnostic.nativeReturn==0 && diagnostic.creationConfigComplete && diagnostic.nativeKeyPolicyApplied);
    CHECK(!diagnostic.nativeFeatureProfileApplied && !diagnostic.TLBIExecutionHandlerImplemented && !diagnostic.exitRecordValid);
    CHECK(!diagnostic.creationReceipt.runAllowed && !diagnostic.creationReceipt.architecturalResetComplete);
    CHECK(good.writes==7 && good.offsets[0]==0x6e8 && good.values[0]==initial.vmKeyLow && good.offsets[1]==0x6e0 && good.values[1]==initial.vmKeyHigh);
    CHECK(Word(&good,0x6e8)==initial.vmKeyLow && Word(&good,0x6e0)==initial.vmKeyHigh);
    Foreign foreign={id,&good};pthread_t worker;CHECK(!pthread_create(&worker,NULL,ForeignThread,&foreign));CHECK(!pthread_join(worker,NULL));
    good.reenter=false;
    VM27CPUFactoryBorrowV2 *borrow=NULL;CHECK(VM27CPUFactoryBorrowAcquireV2(id,&borrow)==0);
    CHECK(VM27CPUFactoryBorrowAcquireV2(id,(VM27CPUFactoryBorrowV2 **)a.object)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryBorrowViewV2(borrow,(VM27CPUFactoryViewV2 *)a.object)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryBorrowReleaseV2((void *)(uintptr_t)1)==(int32_t)UINT32_C(0xfae94003));
    VM27CPUFactoryViewV2 view={0};CHECK(VM27CPUFactoryBorrowViewV2(borrow,&view)==0 && view.cpuGeneration==diagnostic.cpuGeneration && view.exitStorage==exit);
    VZKernelInitWriter writer={&good,Write};VZKernelInitReceipt receipt={0};
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SCALAR,0,1,0,&writer,(VZKernelInitReceipt *)a.object,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SCALAR,0,1,0,&writer,&receipt,(VM27CPUFactoryDiagnosticV2 *)a.object)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryDestroyV2(id,(VM27CPUFactoryDiagnosticV2 *)a.object)==(int32_t)UINT32_C(0xfae94003));
    CHECK(!memcmp(first,a.object,48) && good.writes==7 && good.op7==0);
    CHECK(VM27CPUFactoryBorrowViewV2((void *)(uintptr_t)1,&view)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryBorrowApplyV2((void *)(uintptr_t)1,VZ_KERNEL_INIT_SCALAR,0,1,0,&writer,&receipt,NULL)==(int32_t)UINT32_C(0xfae94003));
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SCALAR,31,0x1111222233334444,0,&writer,&receipt,NULL)==0);
    CHECK(Word(&good,0x108)==UINT64_C(0x1111222233334444));
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SCALAR,32,UINT64_C(0xffffffff12345678),0,&writer,&receipt,NULL)==0);
    uint32_t narrow;memcpy(&narrow,good.memory+0x344,4);CHECK(narrow==0x12345678);
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SIMD,0,0x1111,0x2222,&writer,&receipt,NULL)==0);
    CHECK(Word(&good,0x140)==0x1111 && Word(&good,0x148)==0x2222);
    CHECK(VM27CPUFactoryDestroyV2(id,&diagnostic)==(int32_t)UINT32_C(0xfae94002));
    CHECK(good.op7==0 && diagnostic.cleanupPending);
    CHECK(VM27CPUFactoryBorrowReleaseV2(borrow)==0);CHECK(VM27CPUFactoryOwnerCleanupV2(good.vm,NULL)==0);CHECK(good.op7==1);FreeVM(&good);
    CFRelease((CFTypeRef)a.object); CFRelease((CFTypeRef)b.object);
    for(unsigned kind=0;kind<3;++kind) {
        Mock failure={0};failure.failCreate=kind==0;failure.badVersion=kind==1;failure.failWrite=kind==2?4:0;CreateVM(&failure);
        id=0xabcdef;exit=(void *)(uintptr_t)0x1234;memset(&diagnostic,0,sizeof(diagnostic));
        CHECK(VM27CPUFactoryCreateV2(failure.vm,&id,&exit,NULL,&diagnostic)==(int32_t)UINT32_C(0xfae94001));
        CHECK(id==0xabcdef && exit==(void *)(uintptr_t)0x1234 && !diagnostic.creationConfigComplete);
        if(kind) {
            CHECK(diagnostic.cleanupPending && diagnostic.cpuGeneration);
            if(kind==2) CHECK(diagnostic.creationReceipt.mutationPoisoned && diagnostic.creationReceipt.attemptedWrites==4);
            failure.failDestroy=true;CHECK(VM27CPUFactoryOwnerCleanupV2(failure.vm,NULL)==(int32_t)UINT32_C(0xfae94001));
            CHECK(VM27CPUFactoryVMDestroyV2(failure.vm,NULL)==(int32_t)UINT32_C(0xfae94002));
            failure.failDestroy=false;CHECK(VM27CPUFactoryOwnerCleanupV2(failure.vm,NULL)==0);CHECK(failure.op7==2);
        } else CHECK(failure.op7==0 && !diagnostic.cleanupPending);
        FreeVM(&failure);
    }
    // Configuration completes, then the publication's own full64 read fails.
    Mock publish={0};publish.memory[0x4030]=0x10;publish.corruptPublishVersion=true;CreateVM(&publish);
    id=0xabcdef;exit=(void *)(uintptr_t)0x1234;
    CHECK(VM27CPUFactoryCreateV2(publish.vm,&id,&exit,NULL,&diagnostic)==(int32_t)UINT32_C(0xfae94001));
    CHECK(id==0xabcdef && exit==(void *)(uintptr_t)0x1234 && diagnostic.cleanupPending && diagnostic.creationConfigComplete);
    CHECK(publish.postConfigVersionReads==2 && publish.op7==0);
    CHECK(VM27CPUFactoryOwnerCleanupV2(publish.vm,NULL)==0);FreeVM(&publish);
    // A later scalar writer can copy bytes and then report failure. Drain the
    // published identity; retain the borrow, CPU, exit allocation for cleanup.
    Mock partial={0};CreateVM(&partial);
    CHECK(VM27CPUFactoryCreateV2(partial.vm,&id,&exit,NULL,&diagnostic)==0);
    borrow=NULL;CHECK(VM27CPUFactoryBorrowAcquireV2(id,&borrow)==0);
    writer=(VZKernelInitWriter){&partial,Write};partial.failWrite=partial.writes+1;
    CHECK(VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_SCALAR,0,0x5555,0,&writer,&receipt,NULL)==(int32_t)UINT32_C(0xfae94001));
    CHECK(receipt.attemptedWrites==1 && receipt.mutationPoisoned && Word(&partial,8)==0x5555 && partial.op7==0);
    VM27CPUFactoryBorrowV2 *unchanged=(void *)(uintptr_t)0x1234;
    CHECK(VM27CPUFactoryBorrowAcquireV2(id,&unchanged)==(int32_t)UINT32_C(0xfae94003) && unchanged==(void *)(uintptr_t)0x1234);
    memset(&view,0xa5,sizeof(view));VM27CPUFactoryViewV2 beforeView=view;
    CHECK(VM27CPUFactoryBorrowViewV2(borrow,&view)==(int32_t)UINT32_C(0xfae94003) && !memcmp(&view,&beforeView,sizeof(view)));
    CHECK(VM27CPUFactoryOwnerCleanupV2(partial.vm,NULL)==(int32_t)UINT32_C(0xfae94002) && partial.op7==0);
    CHECK(VM27CPUFactoryBorrowReleaseV2(borrow)==0);CHECK(VM27CPUFactoryOwnerCleanupV2(partial.vm,NULL)==0 && partial.op7==1);FreeVM(&partial);
    uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);CHECK(created==destroyed && created==7);
    printf("{\"checks\":%u,\"created\":%llu,\"destroyed\":%llu,\"mockOnlyNativeCallbacks\":true,\"nativeCalls\":0,\"deviceOperations\":0,\"runImplemented\":false,\"full27Backend\":false}\n",Checks,(unsigned long long)created,(unsigned long long)destroyed);
    return 0;
}
