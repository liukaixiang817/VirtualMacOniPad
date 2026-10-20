#include "modern_cpu_public_register_setters_v1.h"
#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Hypervisor/hv_vcpu_types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Use the installed genuine macOS27 SDK types at the caller boundary. The
// fixture links own source and a mocked kernel; it never calls Hypervisor.
_Static_assert(__builtin_types_compatible_p(VM27CPURegisterSIMDV1,
    hv_simd_fp_uchar16_t), "genuine SDK by-value vector type");
_Static_assert(__builtin_types_compatible_p(VM27CPUFactoryIDV2, hv_vcpu_t),
    "genuine SDK LP64 CPU ID type");
_Static_assert(sizeof(hv_reg_t) == sizeof(uint32_t), "SDK scalar identifier width");
_Static_assert(HV_REG_X0 == 0 && HV_REG_PC == 31 && HV_REG_FPCR == 32 &&
    HV_REG_FPSR == 33 && HV_REG_CPSR == 34, "genuine SDK scalar namespace");
_Static_assert(HV_SIMD_FP_REG_Q0 == 0 && HV_SIMD_FP_REG_Q31 == 31,
    "genuine SDK SIMD namespace");
static unsigned Checks;
#define CHECK(v) do { ++Checks; if (!(v)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v); abort(); } } while (0)
static const int32_t Busy = (int32_t)UINT32_C(0xfae94002);
static const int32_t BadArgument = (int32_t)UINT32_C(0xfae94003);
static const int32_t Unsupported = (int32_t)UINT32_C(0xfae9400f);
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out) {
    (void)out; abort(); // TLBI enable is not used or silently stubbed supported.
}
extern void VM27CPUConfigTestCountsV3(uint64_t *, uint64_t *);

typedef struct {
    unsigned char memory[0x5000];
    unsigned creates, destroys, vmCreates, vmDestroys, reads, writes;
    uint32_t offsets[256]; size_t widths[256]; unsigned char values[256][16];
    unsigned failWrite; bool reenter;
    VM27CPUFactoryVMV2 *vm; VM27CPUFactoryIDV2 id;
} Kernel;
static uint64_t Thread(void *context) {
    (void)context; uint64_t thread = 0; CHECK(!pthread_threadid_np(NULL,&thread)); return thread;
}
static int32_t Trap(void *context, uint64_t operation, void *arguments) {
    Kernel *k = context;
    if (operation == 1) { ++k->vmCreates; CHECK(arguments && ((uint64_t *)arguments)[0] == 0); return 0; }
    if (operation == 2) { ++k->vmDestroys; CHECK(!arguments); return 0; }
    if (operation == 6) {
        ++k->creates; CHECK(arguments && !((uint64_t *)arguments)[0] && !((uint64_t *)arguments)[1]);
        ((uint64_t *)arguments)[1] = (uintptr_t)k->memory;
        uint64_t version = VZ_KERNEL_NATIVE_CONTEXT_VERSION;
        memcpy(k->memory + 0x4000,&version,8); return 0;
    }
    CHECK(operation == 7 && !arguments); ++k->destroys; return 0;
}
static bool Read(void *context, const void *address, size_t bytes, void *output) {
    Kernel *k=context; ++k->reads; uintptr_t offset=(uintptr_t)address-(uintptr_t)k->memory;
    CHECK(offset<=sizeof(k->memory) && bytes<=sizeof(k->memory)-offset);
    memcpy(output,address,bytes); return true;
}
static bool Write(void *context, void *address, size_t bytes, const void *input) {
    Kernel *k=context; uintptr_t offset=(uintptr_t)address-(uintptr_t)k->memory;
    CHECK(k->writes<256 && bytes<=16 && offset<=sizeof(k->memory) && bytes<=sizeof(k->memory)-offset);
    unsigned ordinal=k->writes++;
    k->offsets[ordinal]=(uint32_t)offset; k->widths[ordinal]=bytes;
    memcpy(k->values[ordinal],input,bytes);
    if (k->reenter) {
        VZKernelInitWriter writer={k,Write}; VZKernelInitReceipt receipt;
        memset(&receipt,0xa5,sizeof(receipt)); VZKernelInitReceipt before=receipt;
        CHECK(VM27CPUSetScalarRegisterV1(k->id,HV_REG_X0,42,&writer,&receipt,NULL)==Busy);
        CHECK(!memcmp(&receipt,&before,sizeof(receipt)));
        CHECK(VM27CPURegisterSettersDrainV1()==Busy);
        CHECK(VM27CPUFactoryDestroyV2(k->id,NULL)==Busy);
        CHECK(!VM27CPURegisterSettersHasPendingReleaseV1());
    }
    // A reported failed write may already have changed memory. Cleanup must
    // preserve the poisoned CPU instead of inventing a rollback.
    memcpy(address,input,bytes); return k->failWrite != k->writes;
}
static uint64_t Word(const Kernel *k, unsigned offset) {
    uint64_t value; memcpy(&value,k->memory+offset,8); return value;
}
static void Start(Kernel *k, const void *configuration) {
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,k,Trap,Thread,Read};
    VZKernelVMOptions options={36,0,1,false,false}; VZKernelInitWriter writer={k,Write};
    CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&k->vm,NULL));
    VM27CPUFactoryExitV2 *exit=NULL; VM27CPUFactoryDiagnosticV2 diagnostic={0};
    CHECK(!VM27CPUFactoryCreateV2(k->vm,&k->id,&exit,configuration,&diagnostic));
    CHECK(k->id && exit && diagnostic.cpuGeneration && diagnostic.nativeKeyPolicyApplied);
    CHECK(!diagnostic.exitRecordValid && !diagnostic.nativeFeatureProfileApplied &&
        !diagnostic.TLBIExecutionHandlerImplemented && !diagnostic.creationReceipt.runAllowed);
}
static void Finish(Kernel *k) {
    CHECK(!VM27CPUFactoryOwnerCleanupV2(k->vm,NULL));
    CHECK(!VM27CPUFactoryVMDestroyV2(k->vm,NULL)); CHECK(!VM27CPUFactoryVMFreeV2(k->vm));
    CHECK(k->creates==1 && k->destroys==1 && k->vmCreates==1 && k->vmDestroys==1);
}
static void *ForeignThread(void *opaque) {
    Kernel *k=opaque; VZKernelInitWriter writer={k,Write}; VZKernelInitReceipt receipt;
    memset(&receipt,0xa5,sizeof(receipt)); VZKernelInitReceipt before=receipt;
    CHECK(VM27CPUSetScalarRegisterV1(k->id,HV_REG_X0,99,&writer,&receipt,NULL)==BadArgument);
    CHECK(!memcmp(&receipt,&before,sizeof(receipt)));
    CHECK(!VM27CPURegisterSettersHasPendingReleaseV1()); CHECK(!VM27CPURegisterSettersDrainV1());
    return NULL;
}
int main(void) {
    setvbuf(stdout,NULL,_IOLBF,0);
    puts("MAIN own public setters + actual OSv3/factoryV2/V6/initv3 source; native callbacks mocked");
    VM27CPUConfigHandleV3 config={0}; CHECK(!VM27CPUConfigCreateV3(&config));
    CHECK(!VM27CPUConfigSetVMKeyV3(config,0x11223344,0x55667788));
    Kernel k={0}; Start(&k,config.object);
    CHECK(Word(&k,0x6e8)==0x11223344 && Word(&k,0x6e0)==0x55667788);
    VZKernelInitWriter writer={&k,Write}; VZKernelInitReceipt receipt={0};
    unsigned creationWrites=k.writes; k.reenter=true;
    // Calls are typed from the genuine SDK namespace and cross the wrapper,
    // factory borrow registry, actual owner checks, and initializer boundary.
    CHECK(!VM27CPUSetScalarRegisterV1(k.id,HV_REG_PC,UINT64_C(0x123456789abcdef0),&writer,&receipt,NULL));
    CHECK(Word(&k,0x108)==UINT64_C(0x123456789abcdef0) && receipt.attemptedWrites==1);
    CHECK(k.writes==creationWrites+1 && k.offsets[k.writes-1]==0x108 && k.widths[k.writes-1]==8);
    k.reenter=false;
    CHECK(!VM27CPUSetScalarRegisterV1(k.id,HV_REG_FPCR,UINT64_C(0xffffeeee12345678),&writer,&receipt,NULL));
    uint32_t narrow=0; memcpy(&narrow,k.memory+0x344,4); CHECK(narrow==0x12345678 && k.widths[k.writes-1]==4);
    hv_simd_fp_uchar16_t vector;
    for (unsigned i=0;i<16;++i) vector[i]=(unsigned char)(3+11*i);
    CHECK(!VM27CPUSetSIMDRegisterV1(k.id,HV_SIMD_FP_REG_Q31,vector,&writer,&receipt,NULL));
    CHECK(!memcmp(k.memory+0x330,&vector,16) && k.widths[k.writes-1]==16);
    // Control0 aliases the synchronization word: the requested write must
    // occur before the two original dirty-bit updates.
    unsigned begin=k.writes; uint64_t control=UINT64_C(0x8765432100000010);
    CHECK(!VM27CPUSetControlRegisterV1(k.id,0,control,&writer,&receipt,NULL));
    CHECK(k.writes==begin+4 && k.offsets[begin]==0x670 && k.offsets[begin+1]==0x678 &&
        k.offsets[begin+2]==0x670 && k.offsets[begin+3]==0x748);
    CHECK(Word(&k,0x670)==(control|(UINT64_C(1)<<18)));
    CHECK(Word(&k,0x678)&(UINT64_C(1)<<56)); CHECK(Word(&k,0x748)&4);
    memset(&receipt,0xa5,sizeof(receipt)); VZKernelInitReceipt before=receipt;
    unsigned writes=k.writes;
    CHECK(VM27CPUSetScalarRegisterV1(k.id,35,1,&writer,&receipt,NULL)==Unsupported);
    CHECK(VM27CPUSetSIMDRegisterV1(k.id,32,vector,&writer,&receipt,NULL)==Unsupported);
    CHECK(VM27CPUSetControlRegisterV1(k.id,17,1,&writer,&receipt,NULL)==Unsupported);
    CHECK(VM27CPUSetScalarRegisterV1(0,HV_REG_X0,1,&writer,&receipt,NULL)==BadArgument);
    VZKernelInitWriter foreignWriter={NULL,Write};
    CHECK(VM27CPUSetScalarRegisterV1(k.id,HV_REG_X0,1,&foreignWriter,&receipt,NULL)==BadArgument);
    CHECK(k.writes==writes && !memcmp(&receipt,&before,sizeof(receipt)));
    unsigned char savedConfig[48]; memcpy(savedConfig,config.object,sizeof(savedConfig));
    CHECK(VM27CPUSetScalarRegisterV1(k.id,HV_REG_X0,1,&writer,
        (VZKernelInitReceipt *)config.object,NULL)==BadArgument);
    CHECK(VM27CPUSetScalarRegisterV1(k.id,HV_REG_X0,1,&writer,&receipt,
        (VM27CPUFactoryDiagnosticV2 *)config.object)==BadArgument);
    CHECK(k.writes==writes && !memcmp(savedConfig,config.object,sizeof(savedConfig)) &&
        !memcmp(&receipt,&before,sizeof(receipt)));
    pthread_t foreign; CHECK(!pthread_create(&foreign,NULL,ForeignThread,&k)); CHECK(!pthread_join(foreign,NULL));
    CHECK(k.writes==writes && !VM27CPURegisterSettersHasPendingReleaseV1());
    CHECK(!VM27CPURegisterSettersDrainV1());
    // Fault after publication must unpublish and release the wrapper's borrow
    // while retaining owner cleanup and the real mutated context.
    k.failWrite=k.writes+2;
    CHECK(VM27CPUSetControlRegisterV1(k.id,6,0x1234,&writer,&receipt,NULL)!=0);
    CHECK(receipt.mutationPoisoned && receipt.attemptedWrites==2 && receipt.completedWrites==1);
    CHECK(!VM27CPURegisterSettersHasPendingReleaseV1());
    memset(&receipt,0xa5,sizeof(receipt)); before=receipt; writes=k.writes;
    CHECK(VM27CPUSetScalarRegisterV1(k.id,HV_REG_X0,1,&writer,&receipt,NULL)==BadArgument);
    CHECK(k.writes==writes && !memcmp(&receipt,&before,sizeof(receipt)));
    Finish(&k);
    CFRelease((CFTypeRef)config.object);
    uint64_t created=0,destroyed=0; VM27CPUConfigTestCountsV3(&created,&destroyed);
    CHECK(created==1 && destroyed==1);
    printf("{\"checks\":%u,\"actualCFObjectsCreated\":%llu,\"actualCFObjectsDestroyed\":%llu,\"mockOnlyNativeCallbacks\":true,\"nativeRunCalls\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",
        Checks,(unsigned long long)created,(unsigned long long)destroyed);
    return 0;
}
