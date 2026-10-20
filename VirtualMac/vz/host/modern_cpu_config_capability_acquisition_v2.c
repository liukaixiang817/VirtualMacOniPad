#include "modern_cpu_config_capability_acquisition_v2.h"
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t, void *);
// Original 510c..5288 passes these two packed u32 fields in X0 and consumes a
// boolean in W0. Apple dyld_priv.h declares the same struct-by-value ABI.
typedef struct {uint32_t platform,version;} VM27DyldBuildVersionV2;
_Static_assert(sizeof(VM27DyldBuildVersionV2)==8 &&
    _Alignof(VM27DyldBuildVersionV2)==4,"Actual dyld version struct ABI");
extern bool dyld_program_sdk_at_least(VM27DyldBuildVersionV2);
static pthread_once_t OnceV2 = PTHREAD_ONCE_INIT;
static VM27CPUCapabilitiesV2 ValueV2;
static _Thread_local bool AcquiringV2;
#if VM27_CPU_CAPABILITY_TESTING
extern bool VM27CPUCapabilityTestProfileV2(void);
extern uint64_t VM27CPUCapabilityTestOwnerV2(void);
extern int VM27CPUCapabilityTestSysctlV2(const char *,void *,size_t *,void *,size_t);
extern int VM27CPUCapabilityTestUnmapV2(void *,size_t);
extern bool VM27CPUCapabilityTestSDKV2(uint64_t);
#define ACQUIRE_SYSCTL VM27CPUCapabilityTestSysctlV2
#define ACQUIRE_UNMAP VM27CPUCapabilityTestUnmapV2
#define ACQUIRE_SDK VM27CPUCapabilityTestSDKV2
#else
#define ACQUIRE_SYSCTL sysctlbyname
#define ACQUIRE_UNMAP munmap
static bool ActualSDKV2(uint64_t token) {
    VM27DyldBuildVersionV2 version={(uint32_t)token,(uint32_t)(token>>32)};
    return dyld_program_sdk_at_least(version);
}
#define ACQUIRE_SDK ActualSDKV2
static bool SysStringV2(const char *key,char *out,size_t bytes) {
    size_t actual=bytes;memset(out,0,bytes);
    return sysctlbyname(key,out,&actual,NULL,0)==0 && actual && actual<=bytes && memchr(out,0,actual);
}
#endif
static bool ProfileV2(void) {
#if VM27_CPU_CAPABILITY_TESTING
    return VM27CPUCapabilityTestProfileV2();
#else
    char release[32],build[32],machine[32];
    return geteuid()==0 && sysconf(_SC_PAGESIZE)==16384 &&
        SysStringV2("kern.osrelease",release,sizeof(release)) &&
        SysStringV2("kern.osversion",build,sizeof(build)) &&
        SysStringV2("hw.machine",machine,sizeof(machine)) &&
        !strcmp(release,"22.1.0") && !strcmp(build,"20B101") &&
        (!strcmp(machine,"iPad14,3") || !strcmp(machine,"iPad14,4") ||
         !strcmp(machine,"iPad14,5") || !strcmp(machine,"iPad14,6"));
#endif
}
static uint64_t OwnerV2(void) {
#if VM27_CPU_CAPABILITY_TESTING
    return VM27CPUCapabilityTestOwnerV2();
#else
    uint64_t owner=0;return pthread_threadid_np(NULL,&owner)==0?owner:0;
#endif
}
static bool CanaryV2(const unsigned char *p,size_t bytes) {
    for(size_t i=0;i<bytes;++i)if(p[i]!=0xa5)return false;
    return true;
}
static void AcquireV2(void) {
    const size_t page=16384,capacity=352,tail=32,total=3*page;
    uint64_t owner=OwnerV2();pthread_t thread=pthread_self();
    if(!ProfileV2() || !owner)return;
    unsigned char *region=mmap(NULL,total,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED)return;
    unsigned char *middle=region+page,*buffer=middle+page-capacity-tail;
    VM27CPUCapabilitiesV2 staged={0};bool kernelKnown=false;
    if(mprotect(middle,page,PROT_READ|PROT_WRITE)==0) {
        memset(middle,0xa5,page);memset(buffer,0,capacity);
        if(!((uintptr_t)buffer%32) && CanaryV2(middle,(size_t)(buffer-middle)) && CanaryV2(buffer+capacity,tail)) {
            // The only kernel request here. No VM/CPU/map/sync/Run operation.
            int32_t nativeReturn=VM27CPUConfigCapabilityKernelQueryV1(0,buffer);
            kernelKnown=nativeReturn==0 && CanaryV2(middle,(size_t)(buffer-middle)) &&
                CanaryV2(buffer+capacity,page-(size_t)(buffer+capacity-middle));
            if(kernelKnown) {
                memcpy(&staged.IPA.rawFieldA,buffer+0x149,8);
                memcpy(&staged.IPA.rawFieldB,buffer+0x151,8);
                staged.IPA.known=true;
                VZKernelCapabilitySeedInput input={0};VZKernelCapabilitySeedReceipt receipt={0};
                input.schemaVersion=1;input.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1;
                input.capabilityPrefix=buffer;input.prefixBytes=VZ_KERNEL_CAPABILITY_CONSUMED_PREFIX_BYTES;
                for(unsigned i=0;i<3;++i)
                    input.sdkPredicateResults[i]=ACQUIRE_SDK(VZ_KERNEL_FEATURE_SEED_SDK_TOKEN)?1u:0u;
                staged.featureSeedKnown=VZKernelComputeNativeCapabilitySeed(&input,&staged.featureSeed,&receipt)==VZ_KERNEL_OK;
                VM27CPUTLBICapabilityInputV1 tlbi={0};tlbi.schemaVersion=1;tlbi.actualOwnerThread=owner;
                tlbi.queryCalls=1;tlbi.nativeReturn=nativeReturn;tlbi.guardedContextKnown=true;
                memcpy(&tlbi.hostContextWord40,buffer+0x40,8);
                int vmm=-1;size_t bytes=sizeof(vmm);
                tlbi.sysctlReturn=ACQUIRE_SYSCTL("kern.hv_vmm_present",&vmm,&bytes,NULL,0);
                tlbi.sysctlOutputBytes=bytes;tlbi.vmmPresent=vmm;
                (void)VM27CPUInterpretTLBICapabilityV1(&tlbi,&staged.TLBI);
                kernelKnown=OwnerV2()==owner && pthread_equal(thread,pthread_self());
            }
        }
    }
    // A failed exterior, owner or cleanup boundary never publishes a seed.
    // Every public getter stages its own value and preserves it on UNKNOWN.
    if(ACQUIRE_UNMAP(region,total)!=0)kernelKnown=false;
    if(kernelKnown)ValueV2=staged;
}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *out) {
    if(!out)return;
    if(AcquiringV2){*out=(VM27CPUCapabilitiesV2){0};return;}
    AcquiringV2=true;int result=pthread_once(&OnceV2,AcquireV2);AcquiringV2=false;
    *out=result==0?ValueV2:(VM27CPUCapabilitiesV2){0};
}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out) {
    if(!out)return;VM27CPUCapabilitiesV2 value={0};VM27CPUConfigAcquireCapabilitiesV2(&value);*out=value.TLBI;
}
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *out) {
    if(!out)return;VM27CPUCapabilitiesV2 value={0};VM27CPUConfigAcquireCapabilitiesV2(&value);*out=value.IPA;
}
