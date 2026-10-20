// Finite own CPU creation/register/cleanup fixture. No guest mapping, RUN,
// cancellation or public control0 handoff exists. All outputs are local owned
// C storage; no private allocation is supplied as an output buffer.
#include "modern_cpu_public_register_setters_v1.h"
#include "modern_cpu_config_os_object_v3.h"
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern int32_t VM27OwnedCreationNativeTrapV1(uint64_t, void *);
extern void VM27CPUConfigTestCountsV3(uint64_t *, uint64_t *);
_Static_assert(sizeof(vm_address_t)==8 && sizeof(vm_size_t)==8,
    "The supported iOS vm_* SDK messages use LP64 address and size fields");
typedef struct {
    void *context;
    uint64_t owner;
    unsigned op1,op2,op6,op7,writes,reads;
    bool cpuExists;
} Fixture;
static bool profileString(const char *key,const char *expected) {
    char text[128]={0};size_t bytes=sizeof(text);
    return !sysctlbyname(key,text,&bytes,NULL,0) && bytes>0 && bytes<=sizeof(text) &&
        text[bytes-1]==0 && !strcmp(text,expected);
}
static uint64_t currentThread(void *opaque) {
    (void)opaque; uint64_t thread=0;
    return pthread_threadid_np(NULL,&thread)==0 ? thread : 0;
}
static bool range(Fixture *f,const void *pointer,size_t bytes) {
    uintptr_t base=(uintptr_t)f->context,address=(uintptr_t)pointer;
    return base && bytes && address>=base && address-base<=0x4040 &&
        bytes<=0x4040-(address-base) && currentThread(f)==f->owner;
}
static bool readMemory(void *opaque,const void *pointer,size_t bytes,void *out) {
    Fixture *f=opaque;
    if (!out || !range(f,pointer,bytes)) return false;
    vm_size_t copied=0;
    kern_return_t status=vm_read_overwrite(mach_task_self(),
        (vm_address_t)pointer,(vm_size_t)bytes,(vm_address_t)out,&copied);
    ++f->reads; return status==KERN_SUCCESS && copied==bytes;
}
static bool writeMemory(void *opaque,void *pointer,size_t bytes,const void *value) {
    Fixture *f=opaque;
    if (!value || !range(f,pointer,bytes) || bytes>16) return false;
    size_t offset=(uintptr_t)pointer-(uintptr_t)f->context;
    bool allowed=(bytes==8 && (offset==8 || offset==0x108 || offset==0x670 ||
        offset==0x678 || offset==0x6e0 || offset==0x6e8 || offset==0x748)) ||
        (bytes==4 && offset==0x344) || (bytes==16 && offset==0x330);
    if (!allowed) return false;
    uint64_t version=0;
    if (!readMemory(f,(unsigned char *)f->context+0x4000,8,&version) ||
        version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION) return false;
    ++f->writes;
    // The write targets only the mapping returned by this child's successful
    // native6. vm_write may fail after mutation; V6 preserves poisoned
    // cleanup instead of a fictitious rollback.
    kern_return_t status=vm_write(mach_task_self(),(vm_address_t)pointer,
        (vm_offset_t)value,(mach_msg_type_number_t)bytes);
    unsigned char copied[16];
    bool readback=status==KERN_SUCCESS && readMemory(f,pointer,bytes,copied) &&
        !memcmp(copied,value,bytes);
    printf("WRITE offset=%zu bytes=%zu machStatus=%d readback=%u\n",offset,bytes,status,readback);
    return readback;
}
static int32_t nativeTrap(void *opaque,uint64_t operation,void *arguments) {
    Fixture *f=opaque;
    if (currentThread(f)!=f->owner) return (int32_t)UINT32_C(0xfae94003);
    if (operation==1) {
        if (f->op1 || f->op2 || f->op6 || f->op7 || !arguments) return -1;
        const VZKernelNativeVMConfig *config=arguments;
        if (config->reserved || config->ipaLimit!=(UINT64_C(1)<<36) ||
            config->ipaGranule || config->reserved20 || config->nativeHVISA!=1 ||
            config->reserved28) return -1;
        ++f->op1;
    } else if (operation==6) {
        if (f->op1!=1 || f->op6 || f->op2 || !arguments ||
            ((uint64_t *)arguments)[0] || ((uint64_t *)arguments)[1]) return -1;
        ++f->op6;
    } else if (operation==7) {
        if (!f->cpuExists || f->op7 || arguments) return -1;
        ++f->op7;
    } else if (operation==2) {
        if (f->op1!=1 || f->op2 || f->cpuExists || arguments) return -1;
        ++f->op2;
    } else return (int32_t)UINT32_C(0xfae9400f);
    printf("NATIVE_BEGIN operation=%llu owner=%llu\n",(unsigned long long)operation,(unsigned long long)f->owner);
    int32_t status=VM27OwnedCreationNativeTrapV1(operation,arguments);
    if (operation==6 && status==0) {
        f->context=(void *)(uintptr_t)((uint64_t *)arguments)[1];f->cpuExists=true;
    } else if (operation==7 && status==0) {f->cpuExists=false;f->context=NULL;}
    printf("NATIVE_END operation=%llu status=0x%08x\n",(unsigned long long)operation,(uint32_t)status);
    return status;
}
int main(void) {
    setvbuf(stdout,NULL,_IOLBF,0);
    puts("MAIN own creation/register/cleanup v1; no map/run/cancel/control0 setter");
    if (getuid()!=0 || geteuid()!=0 || !profileString("hw.machine","iPad14,6") ||
        !profileString("kern.osrelease","22.1.0") || !profileString("kern.osversion","20B101")) return 71;
    Fixture fixture={0};fixture.owner=currentThread(NULL); if (!fixture.owner) return 72;
    VM27CPUConfigHandleV3 config={0};
    if (VM27CPUConfigCreateV3(&config)!=VM27_CPU_CONFIG_OK_V3) return 73;
    VM27CPUConfigSnapshotV3 snapshot={0};
    bool configOK=VM27CPUConfigCopyV3(config,&snapshot)==VM27_CPU_CONFIG_OK_V3 &&
        !snapshot.vmKeyLow && !snapshot.vmKeyHigh && !snapshot.fineGrainedTraps && !snapshot.trapTLBISW;
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&fixture,nativeTrap,currentThread,readMemory};
    VZKernelVMOptions options={36,0,1,false,false}; VZKernelInitWriter writer={&fixture,writeMemory};
    VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryIDV2 identity=0;VM27CPUFactoryExitV2 *exit=NULL;
    VM27CPUFactoryDiagnosticV2 diagnostic={0};
    int32_t vmStatus=configOK ? VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&vm,&diagnostic) : -1;
    int32_t createStatus=-1,scalarStatus=-1,narrowStatus=-1,vectorStatus=-1;
    bool scalarReadback=false,narrowReadback=false,vectorReadback=false,versionRead=false;
    uint64_t version=0;VZKernelInitReceipt receipt={0};
    if (!vmStatus) {
        createStatus=VM27CPUFactoryCreateV2(vm,&identity,&exit,config.object,&diagnostic);
        if (!createStatus) {
            versionRead=readMemory(&fixture,(unsigned char *)fixture.context+0x4000,8,&version);
            scalarStatus=VM27CPUSetScalarRegisterV1(identity,0,UINT64_C(0x1122334455667788),&writer,&receipt,NULL);
            uint64_t scalar=0;scalarReadback=!scalarStatus && readMemory(&fixture,
                (unsigned char *)fixture.context+8,8,&scalar) && scalar==UINT64_C(0x1122334455667788);
            narrowStatus=scalarReadback ? VM27CPUSetScalarRegisterV1(identity,32,
                UINT64_C(0xffffeeee12345678),&writer,&receipt,NULL) : -1;
            uint32_t narrow=0;narrowReadback=!narrowStatus && readMemory(&fixture,
                (unsigned char *)fixture.context+0x344,4,&narrow) && narrow==0x12345678;
            VM27CPURegisterSIMDV1 vector;for (unsigned i=0;i<16;++i) vector[i]=(unsigned char)(i*11+3);
            vectorStatus=narrowReadback ? VM27CPUSetSIMDRegisterV1(identity,31,vector,&writer,&receipt,NULL) : -1;
            unsigned char copied[16];vectorReadback=!vectorStatus && readMemory(&fixture,
                (unsigned char *)fixture.context+0x330,16,copied) && !memcmp(copied,&vector,16);
        }
    }
    // Cleanup uses the original owner even after partially successful create.
    int32_t drainStatus=VM27CPURegisterSettersDrainV1();
    int32_t cleanupStatus=vm ? VM27CPUFactoryOwnerCleanupV2(vm,NULL) : 0;
    int32_t destroyStatus=vm && !cleanupStatus ? VM27CPUFactoryVMDestroyV2(vm,NULL) : -1;
    int32_t freeStatus=vm && !destroyStatus ? VM27CPUFactoryVMFreeV2(vm) : -1;
    CFRelease((CFTypeRef)config.object);
    uint64_t objectsCreated=0,objectsDestroyed=0;VM27CPUConfigTestCountsV3(&objectsCreated,&objectsDestroyed);
    bool passed=!vmStatus && !createStatus && diagnostic.cpuGeneration && diagnostic.creationConfigComplete &&
        !diagnostic.exitRecordValid && !diagnostic.nativeFeatureProfileApplied && !diagnostic.TLBIExecutionHandlerImplemented &&
        versionRead && version==VZ_KERNEL_NATIVE_CONTEXT_VERSION && scalarReadback && narrowReadback && vectorReadback &&
        !drainStatus && !cleanupStatus && !destroyStatus && !freeStatus &&
        fixture.op1==1 && fixture.op2==1 && fixture.op6==1 && fixture.op7==1 && !fixture.cpuExists &&
        objectsCreated==1 && objectsDestroyed==1 && !VM27CPURegisterSettersHasPendingReleaseV1();
    printf("RESULT {\"passed\":%s,\"vmStatus\":%d,\"createStatus\":%d,\"scalarStatus\":%d,\"narrowStatus\":%d,\"vectorStatus\":%d,\"owner\":%llu,\"cpuGeneration\":%llu,\"version\":%llu,\"writes\":%u,\"reads\":%u,\"cleanupStatus\":%d,\"destroyStatus\":%d,\"freeStatus\":%d,\"objectsCreated\":%llu,\"objectsDestroyed\":%llu,\"native1\":%u,\"native2\":%u,\"native6\":%u,\"native7\":%u,\"native9\":0,\"guestInstructions\":0,\"exitValid\":false,\"full27Backend\":false}\n",
        passed?"true":"false",vmStatus,createStatus,scalarStatus,narrowStatus,vectorStatus,
        (unsigned long long)fixture.owner,(unsigned long long)diagnostic.cpuGeneration,(unsigned long long)version,
        fixture.writes,fixture.reads,cleanupStatus,destroyStatus,freeStatus,
        (unsigned long long)objectsCreated,(unsigned long long)objectsDestroyed,fixture.op1,fixture.op2,fixture.op6,fixture.op7);
    return passed ? 0 : 74;
}
