#define VM27_CPU_CAPABILITY_TESTING 1
#define VM27_CPU_CAPABILITY_ADMISSION_TESTING 1
#include "modern_cpu_config_capability_acquisition_v3.c"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
static struct {
    uid_t uid,realUID;
    pid_t pid;
    unsigned rights,auditCalls,codeCalls,taskCreates,valueCalls,queryCalls,unmaps;
    unsigned auditFailure,auditShort,auditMismatch,codeFault;
    bool taskFailure;
    const char *nonBooleanKey,*errorKey;
} M;
static CFDictionaryRef HeldTask;
static unsigned Checks;
static void Check(bool value,const char *what) {
    ++Checks;if(!value){fprintf(stderr,"FAIL %s check=%u\n",what,Checks);exit(2);}
}
static void Reset(void) {
    if(HeldTask){Check(CFGetRetainCount(HeldTask)==1,"native task reference released");CFRelease(HeldTask);HeldTask=NULL;}
    memset(&M,0,sizeof(M));M.uid=M.realUID=501;M.pid=213;M.rights=1|2|8;
}
uid_t VM27CPUCapabilityAdmissionTestUIDV3(void){return M.realUID;}
uid_t VM27CPUCapabilityAdmissionTestEUIDV3(void){return M.uid;}
pid_t VM27CPUCapabilityAdmissionTestPIDV3(void){return M.pid;}
kern_return_t VM27CPUCapabilityAdmissionTestAuditV3(audit_token_t *out,mach_msg_type_number_t *count) {
    ++M.auditCalls;if(M.auditCalls==M.auditFailure)return KERN_FAILURE;
    *out=(audit_token_t){{0,M.uid,0,M.realUID,0,(uint32_t)M.pid,1,19}};
    if(M.auditCalls==M.auditShort)--*count;
    if(M.auditMismatch==1)++out->val[5];
    if(M.auditMismatch==2)++out->val[1];
    if(M.auditMismatch==3)++out->val[3];
    if(M.auditMismatch==4)out->val[7]=0;
    if(M.auditMismatch==5 && M.auditCalls==2)++out->val[7];
    return KERN_SUCCESS;
}
int VM27CPUCapabilityAdmissionTestCodeV3(pid_t pid,unsigned int op,void *out,size_t bytes,audit_token_t *token) {
    Check(pid==M.pid && token->val[5]==(uint32_t)pid,"csops uses exact native self audit PID");
    ++M.codeCalls;unsigned cycle=(M.codeCalls-1)%4+1;
    if((M.codeFault==1 && cycle==1) || (M.codeFault==3 && cycle==2) ||
       (M.codeFault==5 && cycle==3) || (M.codeFault==7 && cycle==4))return -1;
    if(op==0) {
        Check(bytes==sizeof(uint32_t),"actual native CS status ABI");
        *(uint32_t *)out=((M.codeFault==2 && cycle==1) || (M.codeFault==6 && cycle==3))?0:1;
    } else {
        Check(op==5 && bytes==20,"actual native kernel CDHash ABI");
        memset(out,(M.codeFault==4)?0:(M.codeFault==8 && cycle==4)?0x22:0x11,bytes);
    }
    return 0;
}
SecTaskRef VM27CPUCapabilityAdmissionTestTaskV3(CFAllocatorRef allocator,audit_token_t token) {
    Check(token.val[7]==19,"SecTask uses admitted audit identity");++M.taskCreates;
    if(M.taskFailure)return NULL;
    if(HeldTask){Check(CFGetRetainCount(HeldTask)==1,"previous actual task reference drained");CFRelease(HeldTask);HeldTask=NULL;}
    HeldTask=CFDictionaryCreate(allocator,NULL,NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    return (SecTaskRef)CFRetain(HeldTask);
}
CFTypeRef VM27CPUCapabilityAdmissionTestValueV3(SecTaskRef task,CFStringRef key,CFErrorRef *error) {
    Check((CFTypeRef)task==HeldTask,"entitlement reads owned native task");++M.valueCalls;
    char name[128];Check(CFStringGetCString(key,name,sizeof(name),kCFStringEncodingUTF8),"native entitlement key string");
    if(M.errorKey && !strcmp(name,M.errorKey)){*error=CFErrorCreate(NULL,kCFErrorDomainPOSIX,EACCES,NULL);return NULL;}
    if(M.nonBooleanKey && !strcmp(name,M.nonBooleanKey))return CFRetain(CFSTR("true"));
    unsigned bit=!strcmp(name,"platform-application")?1:
        !strcmp(name,"com.apple.private.hypervisor")?2:
        !strcmp(name,"com.apple.security.hypervisor")?4:
        !strcmp(name,"com.apple.private.virtualization")?8:
        !strcmp(name,"com.apple.security.virtualization")?16:0;
    return bit && (M.rights&bit)?CFRetain(kCFBooleanTrue):NULL;
}
bool VM27CPUCapabilityTestProfileV2(void){return true;}
uint64_t VM27CPUCapabilityTestOwnerV2(void){return 37;}
int VM27CPUCapabilityTestSysctlV2(const char *key,void *out,size_t *bytes,void *set,size_t n) {
    Check(!strcmp(key,"kern.hv_vmm_present") && !set && !n && *bytes==sizeof(int),"true typed inherited sysctl predicate");
    *(int *)out=0;return 0;
}
int VM27CPUCapabilityTestUnmapV2(void *at,size_t bytes){++M.unmaps;return munmap(at,bytes);}
bool VM27CPUCapabilityTestSDKV2(uint64_t value){Check(value==VZ_KERNEL_FEATURE_SEED_SDK_TOKEN,"inherited actual SDK token");return false;}
int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t op,void *buffer) {
    Check(op==0 && !((uintptr_t)buffer%32),"single typed native0 guarded packet");++M.queryCalls;
    unsigned char *p=buffer;uint64_t max=36;memcpy(p+0x149,&max,8);memcpy(p+0x151,&max,8);return 0;
}
int main(void) {
    Reset();Check(NativeQueryAdmissionV3(),"mobile501 real Boolean private rights admitted");
    Reset();M.uid=M.realUID=0;Check(NativeQueryAdmissionV3(),"root0 real Boolean private rights admitted");
    Reset();M.rights=1|4|16;Check(NativeQueryAdmissionV3(),"genuine public rights admitted");
    Reset();M.uid=M.realUID=502;Check(!NativeQueryAdmissionV3() && !M.auditCalls,"other UID refused before native audit");
    Reset();M.realUID=0;Check(!NativeQueryAdmissionV3(),"different real/effective identity refused");
    Reset();M.pid=1;Check(!NativeQueryAdmissionV3(),"nonapplication PID refused");
    for(unsigned i=1;i<=5;i++){Reset();M.auditMismatch=i;Check(!NativeQueryAdmissionV3(),"exact audit PID/EUID/RUID/version/freshness enforced");}
    for(unsigned i=1;i<=2;i++){Reset();M.auditFailure=i;Check(!NativeQueryAdmissionV3(),"native audit failure refused");}
    for(unsigned i=1;i<=2;i++){Reset();M.auditShort=i;Check(!NativeQueryAdmissionV3(),"native audit count ABI enforced");}
    for(unsigned i=1;i<=8;i++){Reset();M.codeFault=i;Check(!NativeQueryAdmissionV3(),"code identity/status/digest failures refused");}
    Reset();M.taskFailure=true;Check(!NativeQueryAdmissionV3(),"native SecTask failure refused");
    for(unsigned rights=0;rights<=3;rights++){Reset();M.rights=rights;Check(!NativeQueryAdmissionV3(),"incomplete entitlement set refused");}
    const char *keys[]={"platform-application","com.apple.private.hypervisor","com.apple.private.virtualization"};
    for(unsigned i=0;i<3;i++){Reset();M.nonBooleanKey=keys[i];Check(!NativeQueryAdmissionV3(),"string true is not native Boolean entitlement");}
    for(unsigned i=0;i<3;i++){Reset();M.errorKey=keys[i];M.rights=31;Check(!NativeQueryAdmissionV3(),"native entitlement errors cannot be hidden by alternative rights");}
    Reset();VM27CPUCapabilitiesV2 first={0},second={0};VM27CPUConfigAcquireCapabilitiesV2(&first);
    Check(first.IPA.known && first.featureSeedKnown && first.IPA.rawFieldA==36 && first.IPA.rawFieldB==36,"admitted mobile501 publishes actual guarded packet transform");
    Check(M.queryCalls==1 && M.unmaps==1,"one true op0 attempt and complete guarded-map release");
    VM27CPUConfigAcquireCapabilitiesV2(&second);Check(!memcmp(&first,&second,sizeof(first)) && M.queryCalls==1,"one process acquisition cache keeps original provenance");
    VM27CPURawIPAPairV2 pair={0};VM27CPUConfigAcquireRawIPAPairV2(&pair);Check(pair.known && pair.rawFieldA==36 && M.queryCalls==1,"inherited typed raw-IPA caller uses same acquisition");
    Reset();Check(M.queryCalls==0,"all admission models are host-only");
    printf("{\"checks\":%u,\"actualNativeOperations\":0,\"guardedNative0ModelCalls\":1,\"UIDs\":[0,501],\"sourceTestingOnIOSAllowed\":false}\n",Checks);
    return 0;
}
