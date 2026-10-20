// One owned CPU and one caller-owned 16KiB BRK page. This executable remains
// inert until Root reviews/signs it and supplies a separate 20s process watchdog.
// It is an instruction diagnostic, not complete architectural reset or guest boot.
#include "vm27_hv_public_vm_bootstrap_v4.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_os_object_v3.h"
#include <CoreFoundation/CoreFoundation.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern int32_t VM27OwnedBRKNativeTrapV1(uint64_t, void *);
extern void VM27CPUConfigTestCountsV3(uint64_t *, uint64_t *);
extern void VM27HVVMTestConfigCountsV1(uint64_t *, uint64_t *);

#define PAGE_BYTES UINT64_C(16384)
#define GUEST_IPA UINT64_C(0x40000000)
#define GUEST_BRK UINT32_C(0xd4200000)
#define BRK_SYNDROME UINT32_C(0xf2000000)
// These are explicitly supplied diagnostic values from saved production
// observations. Old reset109 reads a frame; it does not establish constants.
#define DIAGNOSTIC_PSTATE UINT64_C(0x3c5)
#define DIAGNOSTIC_SCTLR UINT64_C(0x30800180)
#define NATIVE_ISA UINT32_C(2)
#define FAILURE ((int32_t)UINT32_C(0xfae94003))

_Static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_vcpu_exit_t)==32,"SDK CPU/exit ABI");
_Static_assert(sizeof(VZKernelNativeVMConfig)==32 && sizeof(VZKernelMemoryPacket)==40,"Native packet ABI");
_Static_assert(sizeof(vm_address_t)==8 && sizeof(vm_size_t)==8,"Real LP64 vm_* SDK ABI");

typedef struct {
    void *context,*allocation,*host;
    size_t allocationBytes;
    uint64_t owner;
    unsigned calls[10],reads,writes;
    bool vmExists,cpuExists,mapped,runArmed,writeFailed;
} Probe;

static uint64_t Thread(void *opaque) {
    (void)opaque;uint64_t value=0;
    return pthread_threadid_np(NULL,&value)==0 ? value : 0;
}
static bool ProfileString(const char *key,const char *expected) {
#if VM27_BRK_FIXTURE_HOST_FAULTS
    (void)key;(void)expected;return true;
#else
    char value[128]={0};size_t bytes=sizeof(value);
    return !sysctlbyname(key,value,&bytes,NULL,0) && bytes>0 && bytes<=sizeof(value) &&
        value[bytes-1]==0 && !strcmp(value,expected);
#endif
}
static bool OwnedRange(Probe *p,const void *address,size_t bytes) {
    uintptr_t base=(uintptr_t)p->context,value=(uintptr_t)address;
    return p->cpuExists && base && Thread(p)==p->owner && bytes && value>=base &&
        value-base<=0x4108 && bytes<=0x4108-(value-base);
}
static bool Read(void *opaque,const void *address,size_t bytes,void *out) {
    Probe *p=opaque;
    if(!out || p->reads>=2048 || !OwnedRange(p,address,bytes))return false;
    ++p->reads;vm_size_t copied=0;
    return vm_read_overwrite(mach_task_self(),(vm_address_t)address,(vm_size_t)bytes,
        (vm_address_t)out,&copied)==KERN_SUCCESS && copied==bytes;
}
static bool Write(void *opaque,void *address,size_t bytes,const void *value) {
    Probe *p=opaque;
    if(!value || p->writeFailed || p->writes>=16 || !OwnedRange(p,address,bytes))return false;
    size_t offset=(uintptr_t)address-(uintptr_t)p->context;
    bool allowed=(bytes==8 && (offset==0x108 || offset==0x400 || offset==0x670 ||
        offset==0x678 || offset==0x6e0 || offset==0x6e8 || offset==0x748)) ||
        (bytes==4 && offset==0x110);
    if(!allowed)return false;
    uint64_t version=0;
    if(!Read(p,(unsigned char *)p->context+0x4000,8,&version) ||
        version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION)return false;
    ++p->writes;
    kern_return_t status=vm_write(mach_task_self(),(vm_address_t)address,
        (vm_offset_t)value,(mach_msg_type_number_t)bytes);
    unsigned char copied[8];bool exact=status==KERN_SUCCESS && Read(p,address,bytes,copied) &&
        !memcmp(copied,value,bytes);
    if(!exact)p->writeFailed=true;
    printf("{\"kind\":\"write\",\"offset\":%zu,\"bytes\":%zu,\"machStatus\":%d,\"readback\":%s}\n",
        offset,bytes,status,exact?"true":"false");
    return exact;
}
static bool CodeExact(Probe *p) {
    if(!p->host)return false;
    const uint32_t *words=p->host;
    for(size_t i=0;i<PAGE_BYTES/4;++i)if(words[i]!=GUEST_BRK)return false;
    return true;
}
static int32_t Native(void *opaque,uint64_t operation,void *arguments) {
    Probe *p=opaque;
    if(operation<1 || operation>9 || operation==5 || p->calls[operation] ||
        Thread(p)!=p->owner)return FAILURE;
    if(operation==1) {
        if(p->vmExists || !arguments)return FAILURE;
        const VZKernelNativeVMConfig *q=arguments;
        if(q->reserved || q->ipaLimit!=(UINT64_C(1)<<36) || q->ipaGranule ||
            q->reserved20 || q->nativeHVISA!=NATIVE_ISA || q->reserved28)return FAILURE;
    } else if(operation==3 || operation==4) {
        if(!p->vmExists || p->cpuExists || !arguments)return FAILURE;
        const VZKernelMemoryPacket *q=arguments;
        if(q->hostAddress!=(operation==3?(uintptr_t)p->host:0) ||
            q->guestAddress!=GUEST_IPA || q->bytes!=PAGE_BYTES || q->spaceWord ||
            q->flags!=(operation==3?5u:0u) || (operation==3 && !CodeExact(p)))return FAILURE;
    } else if(operation==6) {
        if(!p->vmExists || !p->mapped || p->cpuExists || !arguments ||
            ((uint64_t *)arguments)[0] || ((uint64_t *)arguments)[1])return FAILURE;
    } else if(operation==8) {
        if(arguments || !p->cpuExists || !p->mapped || p->calls[9] || p->writeFailed)return FAILURE;
    } else if(operation==9) {
        if(arguments || !p->vmExists || !p->cpuExists || !p->mapped ||
            !p->runArmed || p->writeFailed || !CodeExact(p))return FAILURE;
    } else if(operation==7) {
        if(arguments || !p->cpuExists)return FAILURE;
    } else if(operation==2) {
        if(arguments || !p->vmExists || p->cpuExists || p->mapped ||
            (p->calls[3] && !p->calls[4]))return FAILURE;
    } else return FAILURE;
    ++p->calls[operation];
    printf("{\"kind\":\"nativeBegin\",\"operation\":%llu,\"owner\":%llu}\n",
        (unsigned long long)operation,(unsigned long long)p->owner);
    int32_t status=VM27OwnedBRKNativeTrapV1(operation,arguments);
    if(!status) {
        if(operation==1)p->vmExists=true;
        else if(operation==3)p->mapped=true;
        else if(operation==4)p->mapped=false;
        else if(operation==6){p->context=(void *)(uintptr_t)((uint64_t *)arguments)[1];p->cpuExists=true;}
        else if(operation==7){p->context=NULL;p->cpuExists=false;}
        else if(operation==2)p->vmExists=false;
    }
    printf("{\"kind\":\"nativeEnd\",\"operation\":%llu,\"returnBits\":%u}\n",
        (unsigned long long)operation,(uint32_t)status);
    return status;
}
static void Status(const char *stage,int32_t value) {
    printf("{\"kind\":\"status\",\"stage\":\"%s\",\"returnBits\":%u}\n",stage,(uint32_t)value);
}
static bool AllocatePage(Probe *p) {
    // Extra space guarantees 16KiB alignment in Mac host-only fault fixtures.
    // All pages remain inaccessible except this exact middle 16KiB range.
    p->allocationBytes=5*(size_t)PAGE_BYTES;
    p->allocation=mmap(NULL,p->allocationBytes,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(p->allocation==MAP_FAILED){p->allocation=NULL;return false;}
    uintptr_t middle=((uintptr_t)p->allocation+PAGE_BYTES*2-1)&~(PAGE_BYTES-1);
    p->host=(void *)middle;
    if(mprotect(p->host,PAGE_BYTES,PROT_READ|PROT_WRITE))return false;
    uint32_t *words=p->host;
    for(size_t i=0;i<PAGE_BYTES/4;++i)words[i]=GUEST_BRK;
    sys_icache_invalidate(p->host,PAGE_BYTES);
    return CodeExact(p) && VM27CPUSelfMappedRangeV1(p->host,PAGE_BYTES,true,NULL);
}

int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IOLBF,0);
    if(argc!=2 || strcmp(argv[1],"--owned-brk-one-step-v1"))return 64;
    puts("{\"kind\":\"scope\",\"nativeISA\":2,\"pageBytes\":16384,\"native9Maximum\":1,\"architecturalResetComplete\":false,\"full27Backend\":false}");
    bool profile=ProfileString("hw.machine","iPad14,6") &&
        ProfileString("kern.osrelease","22.1.0") && ProfileString("kern.osversion","20B101");
#if !VM27_BRK_FIXTURE_HOST_FAULTS
    struct rlimit cpuLimit={0},coreLimit={0};
    profile=profile && getuid()==0 && geteuid()==0 && getpagesize()==PAGE_BYTES &&
        !getrlimit(RLIMIT_CPU,&cpuLimit) && !getrlimit(RLIMIT_CORE,&coreLimit) &&
        cpuLimit.rlim_cur<=5 && coreLimit.rlim_cur==0;
#endif
    if(!profile)return 71;
    Probe p={0};p.owner=Thread(NULL);if(!p.owner)return 72;
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&p,Native,Thread,Read};
    VZKernelInitWriter writer={&p,Write};
    hv_vm_config_t vmConfig=NULL;hv_vcpu_config_t cpuConfig=NULL;
    VM27CPUFactoryVMV2 *ownedVM=NULL;VM27CPUFactoryBorrowV2 *borrow=NULL;
    hv_vcpu_t identity=0;hv_vcpu_exit_t *exit=NULL;
    bool installed=false,vmCreated=false,cpuCreated=false,mapAttempted=false,armed=false,oracle=false;
    bool cpuCleanupAttempted=false,unmapAttempted=false,vmDestroyAttempted=false,hostReleased=false;
    int32_t install=-1,createVM=-1,map=-1,createCPU=-1,run=-1,release=-1;
    int32_t cpuCleanup=-1,unmap=-1,destroyVM=-1,uninstall=-1,drain=-1;
    uint64_t beforePC=0,beforePSTATE=0,beforeSCTLRCache=0,pc=0,pstate=0,sctlr=0,postPC=0;
    uint32_t beforeSyndrome=0;bool beforeKnown=false;
    VM27CPUFactoryRunDiagnosticV3 diagnostic={0};
    if(!AllocatePage(&p))goto cleanup;
    install=VM27HVVMInstallNativeOpsV1(&ops,&writer);Status("install",install);
    if(install)goto cleanup;installed=true;
    vmConfig=hv_vm_config_create();cpuConfig=hv_vcpu_config_create();
    uint32_t maxIPA=0,selectedIPA=0;
    int32_t configure=_hv_vm_config_set_isa(vmConfig,NATIVE_ISA);Status("selectNativeISA2",configure);
    if(configure || hv_vm_config_get_max_ipa_size(&maxIPA) || maxIPA!=36 ||
        hv_vm_config_get_ipa_size(vmConfig,&selectedIPA) || selectedIPA!=36)goto cleanup;
    createVM=hv_vm_create(vmConfig);Status("createVM",createVM);
    if(createVM)goto cleanup;vmCreated=true;
    if(VM27HVVMGetOwnedVMV1(&ownedVM) || !ownedVM)goto cleanup;
    mapAttempted=true;map=hv_vm_map(p.host,GUEST_IPA,PAGE_BYTES,5);Status("map",map);
    if(map)goto cleanup;
    createCPU=hv_vcpu_create(&identity,&exit,cpuConfig);Status("createCPU",createCPU);
    cpuCreated=!createCPU;
    if(createCPU || !identity || !exit || !p.cpuExists)goto cleanup;
    if(hv_vcpu_get_reg(identity,(hv_reg_t)31,&beforePC) ||
        hv_vcpu_get_reg(identity,(hv_reg_t)34,&beforePSTATE) ||
        !Read(&p,(unsigned char *)p.context+0x400,8,&beforeSCTLRCache) ||
        !Read(&p,(unsigned char *)p.context+0x400c,4,&beforeSyndrome))goto cleanup;
    beforeKnown=true;
    printf("{\"kind\":\"before\",\"PC\":%llu,\"PSTATE\":%llu,\"SCTLRRawCache\":%llu,\"syndrome\":%u,\"SCTLRLogicalValueClaimed\":false}\n",
        (unsigned long long)beforePC,(unsigned long long)beforePSTATE,
        (unsigned long long)beforeSCTLRCache,beforeSyndrome);
    int32_t setSYS=hv_vcpu_set_sys_reg(identity,(hv_sys_reg_t)0xc080,DIAGNOSTIC_SCTLR);
    Status("setSCTLR",setSYS);if(setSYS)goto cleanup;
    int32_t setPSTATE=hv_vcpu_set_reg(identity,(hv_reg_t)34,DIAGNOSTIC_PSTATE);
    Status("setPSTATE",setPSTATE);if(setPSTATE)goto cleanup;
    int32_t setPC=hv_vcpu_set_reg(identity,(hv_reg_t)31,GUEST_IPA);Status("setPC",setPC);
    if(setPC || hv_vcpu_get_sys_reg(identity,(hv_sys_reg_t)0xc080,&sctlr) ||
        hv_vcpu_get_reg(identity,(hv_reg_t)34,&pstate) || hv_vcpu_get_reg(identity,(hv_reg_t)31,&pc))goto cleanup;
    armed=sctlr==DIAGNOSTIC_SCTLR && pstate==DIAGNOSTIC_PSTATE && pc==GUEST_IPA &&
        beforeKnown && beforeSyndrome!=BRK_SYNDROME && CodeExact(&p) && !p.writeFailed;
    printf("{\"kind\":\"arm\",\"armed\":%s,\"PC\":%llu,\"PSTATE\":%llu,\"SCTLR\":%llu,\"completeReset\":false}\n",
        armed?"true":"false",(unsigned long long)pc,(unsigned long long)pstate,(unsigned long long)sctlr);
    if(!armed)goto cleanup;
    if(VM27CPUFactoryBorrowAcquireV2(identity,&borrow))goto cleanup;
    p.runArmed=true;run=VM27CPUFactoryRunOwnedStepV3(borrow,&diagnostic);p.runArmed=false;
    Status("ownedSingleRun",run);
    release=VM27CPUFactoryBorrowReleaseV2(borrow);Status("releaseRunBorrow",release);
    if(!release)borrow=NULL;
    int32_t postRead=release ? -1 : hv_vcpu_get_reg(identity,(hv_reg_t)31,&postPC);
    const VZKernelRunStepReceiptV7 *step=&diagnostic.step;
    const VZCPUNativeExitValuesV1 *native=&step->nativeValues;
    oracle=!run && !release && !postRead && p.calls[9]==1 && step->lifecycle.nativeInvoked &&
        !step->lifecycle.nativeReturn && step->postReturnIdentityValidated && step->runToken &&
        step->ownerThread==p.owner && native->knownFields==VZ_CPU_EXIT_ALL_KNOWN_V1 &&
        native->syndrome32==BRK_SYNDROME && step->reductionValid && step->publicExceptionProduced &&
        diagnostic.exitStoragePublished && exit->reason==1 && exit->exception.syndrome==BRK_SYNDROME &&
        postPC==GUEST_IPA && CodeExact(&p);
    printf("{\"kind\":\"runReceipt\",\"returnBits\":%u,\"nativeReturnBits\":%u,\"rawReason\":%u,\"knownFields\":%u,\"syndrome\":%u,\"virtualAddress\":%llu,\"physicalAddress\":%llu,\"owner\":%llu,\"generation\":%llu,\"vmEpoch\":%llu,\"runToken\":%llu,\"postReturnIdentityValidated\":%s,\"postPC\":%llu,\"instructionOracle\":%s}\n",
        (uint32_t)run,native->nativeReturnBits,native->rawReason,native->knownFields,native->syndrome32,
        (unsigned long long)native->virtualAddress,(unsigned long long)native->physicalAddress,
        (unsigned long long)step->ownerThread,(unsigned long long)step->cpuGeneration,
        (unsigned long long)step->vmEpoch,(unsigned long long)step->runToken,
        step->postReturnIdentityValidated?"true":"false",(unsigned long long)postPC,oracle?"true":"false");
cleanup:
    // No repeated native9,7,4 or2 after an uncertain failure. Retain the
    // actual backing until successful4; otherwise process teardown owns it.
    // A failed unpublished native6 is reclaimed through the same owner VM.
    drain=VM27CPUFactoryPublicDrainBorrowV6();Status("drainPublicBorrow",drain);
    if(!borrow && ownedVM && (cpuCreated || p.cpuExists)) {
        cpuCleanupAttempted=true;cpuCleanup=VM27CPUFactoryOwnerCleanupV2(ownedVM,NULL);
        Status("ownerCPUCleanup",cpuCleanup);
    }
    if(mapAttempted && p.calls[3] && !p.cpuExists && !borrow) {
        unmapAttempted=true;unmap=hv_vm_unmap(GUEST_IPA,PAGE_BYTES);Status("unmap",unmap);
    }
    if(vmCreated && !p.cpuExists && !borrow && (!p.calls[3] || (unmapAttempted && !unmap))) {
        vmDestroyAttempted=true;destroyVM=hv_vm_destroy();Status("destroyVM",destroyVM);
    }
    if(cpuConfig)CFRelease((CFTypeRef)cpuConfig);
    if(vmConfig)CFRelease((CFTypeRef)vmConfig);
    if(installed){uninstall=VM27HVVMUninstallNativeOpsV1();Status("uninstall",uninstall);}
    if(p.allocation && !p.cpuExists && !borrow && (!p.calls[3] || (unmapAttempted && !unmap))) {
        hostReleased=munmap(p.allocation,p.allocationBytes)==0;p.allocation=NULL;p.host=NULL;
    }
    uint64_t cpuCFMade=0,cpuCFFreed=0,vmCFMade=0,vmCFFreed=0;
    VM27CPUConfigTestCountsV3(&cpuCFMade,&cpuCFFreed);VM27HVVMTestConfigCountsV1(&vmCFMade,&vmCFFreed);
    bool clean=cpuCleanupAttempted && !cpuCleanup && unmapAttempted && !unmap &&
        vmDestroyAttempted && !destroyVM && !uninstall && !drain && hostReleased && !borrow &&
        !p.cpuExists && !p.vmExists && !p.mapped && p.calls[1]==1 && p.calls[2]==1 &&
        p.calls[3]==1 && p.calls[4]==1 && p.calls[6]==1 && p.calls[7]==1 && p.calls[8]<=1 &&
        p.calls[9]==1 && cpuCFMade==1 && cpuCFFreed==1 && vmCFMade==1 && vmCFFreed==1;
    printf("{\"kind\":\"result\",\"instructionOracle\":%s,\"cleanupComplete\":%s,\"passed\":%s,\"native1\":%u,\"native2\":%u,\"native3\":%u,\"native4\":%u,\"native6\":%u,\"native7\":%u,\"native8\":%u,\"native9\":%u,\"writes\":%u,\"reads\":%u,\"callerBackingReleased\":%s,\"cpuCFMade\":%llu,\"cpuCFFreed\":%llu,\"vmCFMade\":%llu,\"vmCFFreed\":%llu,\"full27Backend\":false,\"guestBooted\":false}\n",
        oracle?"true":"false",clean?"true":"false",oracle&&clean?"true":"false",
        p.calls[1],p.calls[2],p.calls[3],p.calls[4],p.calls[6],p.calls[7],p.calls[8],p.calls[9],p.writes,p.reads,
        hostReleased?"true":"false",(unsigned long long)cpuCFMade,(unsigned long long)cpuCFFreed,
        (unsigned long long)vmCFMade,(unsigned long long)vmCFFreed);
    return oracle && clean ? 0 : 74;
}
