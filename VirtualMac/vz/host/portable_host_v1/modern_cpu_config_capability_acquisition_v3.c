#include "modern_cpu_config_capability_acquisition_v2.h"
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>


/* V3 keeps the inherited hidden V2 consumer ABI and the one guarded op0
 * acquisition. UID admission is now the actual owned App/child profile,
 * authenticated by native code identity and native Boolean entitlements.
 * No CS_PLATFORM_BINARY assertion is inferred from an ad hoc signature. */
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef,audit_token_t);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef,CFStringRef,CFErrorRef *);
extern int csops_audittoken(pid_t,unsigned int,void *,size_t,audit_token_t *);
#if TARGET_OS_IPHONE && (VM27_CPU_CAPABILITY_TESTING || VM27_CPU_CAPABILITY_ADMISSION_TESTING)
#error "Capability admission fixture hooks are forbidden on iOS"
#endif
#if VM27_CPU_CAPABILITY_ADMISSION_TESTING
extern uid_t VM27CPUCapabilityAdmissionTestUIDV3(void);
extern uid_t VM27CPUCapabilityAdmissionTestEUIDV3(void);
extern pid_t VM27CPUCapabilityAdmissionTestPIDV3(void);
extern kern_return_t VM27CPUCapabilityAdmissionTestAuditV3(audit_token_t *,mach_msg_type_number_t *);
extern int VM27CPUCapabilityAdmissionTestCodeV3(pid_t,unsigned int,void *,size_t,audit_token_t *);
extern SecTaskRef VM27CPUCapabilityAdmissionTestTaskV3(CFAllocatorRef,audit_token_t);
extern CFTypeRef VM27CPUCapabilityAdmissionTestValueV3(SecTaskRef,CFStringRef,CFErrorRef *);
#define SELF_UID_V3 VM27CPUCapabilityAdmissionTestUIDV3
#define SELF_EUID_V3 VM27CPUCapabilityAdmissionTestEUIDV3
#define SELF_PID_V3 VM27CPUCapabilityAdmissionTestPIDV3
#define SELF_AUDIT_V3 VM27CPUCapabilityAdmissionTestAuditV3
#define SELF_CODE_V3 VM27CPUCapabilityAdmissionTestCodeV3
#define SELF_TASK_V3 VM27CPUCapabilityAdmissionTestTaskV3
#define SELF_VALUE_V3 VM27CPUCapabilityAdmissionTestValueV3
#else
#define SELF_UID_V3 getuid
#define SELF_EUID_V3 geteuid
#define SELF_PID_V3 getpid
#define SELF_CODE_V3 csops_audittoken
#define SELF_TASK_V3 SecTaskCreateWithAuditToken
#define SELF_VALUE_V3 SecTaskCopyValueForEntitlement
static kern_return_t ActualAuditV3(audit_token_t *token,mach_msg_type_number_t *count) {
    return task_info(mach_task_self(),TASK_AUDIT_TOKEN,(task_info_t)token,count);
}
#define SELF_AUDIT_V3 ActualAuditV3
#endif
static bool IdentityV3(pid_t pid,uid_t uid,const audit_token_t *token) {
    return pid>1 && (uid==0 || uid==501) && SELF_PID_V3()==pid &&
        SELF_EUID_V3()==uid && SELF_UID_V3()==uid && token->val[5]==(uint32_t)pid &&
        token->val[1]==uid && token->val[3]==uid && token->val[7]!=0;
}
static bool NativeTrueV3(SecTaskRef task,CFStringRef key,bool *failed) {
    CFErrorRef error=NULL;CFTypeRef value=SELF_VALUE_V3(task,key,&error);
    bool yes=value && !error && CFGetTypeID(value)==CFBooleanGetTypeID() &&
        CFBooleanGetValue((CFBooleanRef)value);
    if(error){*failed=true;CFRelease(error);}if(value)CFRelease(value);return yes;
}
static bool NativeQueryAdmissionV3(void) {
    uid_t uid=SELF_EUID_V3();pid_t pid=SELF_PID_V3();
    if((uid!=0 && uid!=501) || SELF_UID_V3()!=uid || pid<=1)return false;
    audit_token_t token={{0}},after={{0}};mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
    if(SELF_AUDIT_V3(&token,&count)!=KERN_SUCCESS || count!=TASK_AUDIT_TOKEN_COUNT ||
        !IdentityV3(pid,uid,&token))return false;
    uint32_t status=0;unsigned char digest[20]={0},again[20]={0};
    if(SELF_CODE_V3(pid,0,&status,sizeof(status),&token) || !(status&UINT32_C(1)) ||
        SELF_CODE_V3(pid,5,digest,sizeof(digest),&token))return false;
    bool nonzero=false;for(size_t i=0;i<sizeof(digest);++i)nonzero|=digest[i]!=0;
    if(!nonzero)return false;
    SecTaskRef task=SELF_TASK_V3(kCFAllocatorDefault,token);if(!task)return false;
    bool failed=false;
    bool platform=NativeTrueV3(task,CFSTR("platform-application"),&failed);
    bool hypervisor=NativeTrueV3(task,CFSTR("com.apple.private.hypervisor"),&failed);
    if(!hypervisor && !failed)hypervisor=NativeTrueV3(task,CFSTR("com.apple.security.hypervisor"),&failed);
    bool virtualization=NativeTrueV3(task,CFSTR("com.apple.private.virtualization"),&failed);
    if(!virtualization && !failed)virtualization=NativeTrueV3(task,CFSTR("com.apple.security.virtualization"),&failed);
    CFRelease(task);
    if(failed || !platform || !hypervisor || !virtualization)return false;
    count=TASK_AUDIT_TOKEN_COUNT;status=0;
    return SELF_AUDIT_V3(&after,&count)==KERN_SUCCESS && count==TASK_AUDIT_TOKEN_COUNT &&
        !memcmp(&token,&after,sizeof(token)) && IdentityV3(pid,uid,&after) &&
        !SELF_CODE_V3(pid,0,&status,sizeof(status),&after) && (status&UINT32_C(1)) &&
        !SELF_CODE_V3(pid,5,again,sizeof(again),&after) && !memcmp(digest,again,sizeof(digest));
}

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
#endif
#include "vm_host_profile_read_v1.h"
static bool ProfileV2(void) {
#if VM27_CPU_CAPABILITY_TESTING
    return VM27CPUCapabilityTestProfileV2() && NativeQueryAdmissionV3();
#else
    return NativeQueryAdmissionV3() && VM27HostCurrentABI20B101MatchesV1();
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
                kernelKnown=OwnerV2()==owner && pthread_equal(thread,pthread_self()) && NativeQueryAdmissionV3();
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
