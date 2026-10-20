// A distinct capability-query-only helper. No VM/CPU/map/Run native operation.
#include "modern_cpu_tlbi_capability_values_v1.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern kern_return_t mach_vm_read_overwrite(vm_map_t,mach_vm_address_t,
    mach_vm_size_t,mach_vm_address_t,mach_vm_size_t *);
extern int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t,void *);
__attribute__((used,visibility("hidden"))) const volatile unsigned char VM27CPUConfigCapabilityExpectedUUIDV1[16]=
    {0x56,0x4d,0x43,0x46,0x47,0x51,0x55,0x45,0x52,0x59,0x31,0x8c,0x31,0x7a,0xe5,0x69};
static const unsigned char TrapBytes[12]={0x90,0x00,0x80,0x92,0x01,0x10,0x00,0xd4,0xc0,0x03,0x5f,0xd6};
int main(void);
static bool Read(const void *p,size_t n,void *out) {
    if(!p || !out || !n || (uintptr_t)p>UINTPTR_MAX-n)return false;
    mach_vm_size_t copied=0;
    return mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)(uintptr_t)p,n,
        (mach_vm_address_t)(uintptr_t)out,&copied)==KERN_SUCCESS && copied==n;
}
static void Hex(const unsigned char *p,size_t n) {for(size_t i=0;i<n;++i)printf("%02x",p[i]);}
static bool SysString(const char *key,char *out,size_t n) {
    size_t actual=n;memset(out,0,n);
    return sysctlbyname(key,out,&actual,NULL,0)==0 && actual>0 && actual<=n && memchr(out,0,actual);
}
static bool Profile(void) {
    char release[32]={0},build[32]={0},machine[32]={0};
    bool valid=SysString("kern.osrelease",release,sizeof(release)) &&
        SysString("kern.osversion",build,sizeof(build)) && SysString("hw.machine",machine,sizeof(machine));
    valid=valid && !strcmp(release,"22.1.0") && !strcmp(build,"20B101") &&
        (!strcmp(machine,"iPad14,3") || !strcmp(machine,"iPad14,4") ||
         !strcmp(machine,"iPad14,5") || !strcmp(machine,"iPad14,6"));
    printf("{\"kind\":\"profile\",\"release\":\"%s\",\"build\":\"%s\",\"machine\":\"%s\",\"known\":%s}\n",
        release,build,machine,valid?"true":"false");return valid;
}
static bool Census(void) {
    unsigned forbidden=0;uint32_t count=_dyld_image_count();
    if(!count || count>=512)return false;
    for(uint32_t i=0;i<count;++i) {
        const char *name=_dyld_get_image_name(i);if(!name){++forbidden;continue;}
        if(strstr(name,"Hypervisor.framework/") || strstr(name,"Virtualization.framework/") ||
            strstr(name,"VirtualMachineMonitor.framework/") || strstr(name,"VM27CPUFactory") ||
            strstr(name,"VM27CPUConfig.dylib"))++forbidden;
        printf("{\"kind\":\"image\",\"index\":%u,\"path\":\"%s\"}\n",i,name);
    }
    printf("{\"kind\":\"census\",\"images\":%u,\"forbidden\":%u}\n",count,forbidden);
    return count>0 && count<512 && forbidden==0;
}
static bool OwnFrame(void) {
    const void *entry=ptrauth_strip((void *)VM27CPUConfigCapabilityKernelQueryV1,ptrauth_key_function_pointer);
    const void *anchor=ptrauth_strip((void *)main,ptrauth_key_function_pointer);
    Dl_info trap={0},own={0};
    if(dladdr(entry,&trap)!=1 || dladdr(anchor,&own)!=1 || !trap.dli_fbase ||
        trap.dli_fbase!=own.dli_fbase || !trap.dli_fname)return false;
    const char *leaf=strrchr(trap.dli_fname,'/');leaf=leaf?leaf+1:trap.dli_fname;
    if(strcmp(leaf,"ordinary-cpu-config-capability-v1"))return false;
    struct mach_header_64 h;unsigned char actual[12];
    if(!Read(own.dli_fbase,sizeof(h),&h) || h.magic!=MH_MAGIC_64 || h.filetype!=MH_EXECUTE ||
        h.cputype!=CPU_TYPE_ARM64 || (h.cpusubtype & ~CPU_SUBTYPE_MASK)!=CPU_SUBTYPE_ARM64E ||
        h.ncmds<1 || h.ncmds>128 || h.sizeofcmds<24 || h.sizeofcmds>65536)return false;
    unsigned char *cmds=malloc(h.sizeofcmds);if(!cmds)return false;
    bool valid=Read((const unsigned char *)own.dli_fbase+sizeof(h),h.sizeofcmds,cmds);
    size_t at=0;unsigned uuidCount=0;unsigned char uuid[16]={0};
    for(uint32_t i=0;valid && i<h.ncmds;++i) {
        struct load_command c;
        if(at>h.sizeofcmds || h.sizeofcmds-at<sizeof(c)){valid=false;break;}
        memcpy(&c,cmds+at,sizeof(c));
        if(c.cmdsize<8 || c.cmdsize%8 || c.cmdsize>h.sizeofcmds-at){valid=false;break;}
        if(c.cmd==LC_UUID) {
            if(c.cmdsize!=24 || ++uuidCount!=1){valid=false;break;}
            memcpy(uuid,cmds+at+8,16);
            for(unsigned j=0;j<16;++j)if(uuid[j]!=VM27CPUConfigCapabilityExpectedUUIDV1[j])valid=false;
        }
        at+=c.cmdsize;
    }
    valid=valid && at==h.sizeofcmds && uuidCount==1 && Read(entry,12,actual) && !memcmp(actual,TrapBytes,12);
    free(cmds);
    printf("{\"kind\":\"ownFrame\",\"sameActualMain\":%s,\"UUID\":\"",valid?"true":"false");Hex(uuid,16);
    printf("\",\"trap12Exact\":%s,\"path\":\"%s\"}\n",valid?"true":"false",trap.dli_fname);return valid;
}
static bool Canary(const unsigned char *p,size_t n) {for(size_t i=0;i<n;++i)if(p[i]!=0xa5)return false;return true;}
static uint64_t LE64(const unsigned char *p) {uint64_t v=0;for(unsigned i=0;i<8;++i)v|=(uint64_t)p[i]<<(8*i);return v;}
static int Query(uint64_t owner) {
    const size_t page=16384,capacity=352,tail=32,total=3*page;
    if(sysconf(_SC_PAGESIZE)!=(long)page)return 70;
    unsigned char *region=mmap(NULL,total,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED)return 71;
    unsigned char *middle=region+page,*buffer=middle+page-capacity-tail;
    VM27CPUTLBICapabilityInputV1 input={0};input.schemaVersion=1;input.actualOwnerThread=owner;
    input.nativeReturn=(int32_t)UINT32_C(0xfae94001);input.sysctlReturn=-1;
    bool safe=false;unsigned queryCalls=0;int result=72;
    if(mprotect(middle,page,PROT_READ|PROT_WRITE)==0) {
        memset(middle,0xa5,page);memset(buffer,0,capacity);
        bool alignment=((uintptr_t)buffer%32)==0;
        safe=alignment && Canary(middle,(size_t)(buffer-middle)) && Canary(buffer+capacity,tail);
        printf("{\"kind\":\"bufferBefore\",\"capacity\":352,\"alignment32\":%s,\"guardPages\":2,"
            "\"zeroInput\":true,\"exteriorIntact\":%s,\"kernelWriteWidthKnown\":false}\n",alignment?"true":"false",safe?"true":"false");
        if(safe) {
            printf("{\"kind\":\"nativeBegin\",\"operation\":0,\"calls\":1,\"ownerThread\":%llu}\n",(unsigned long long)owner);
            queryCalls=1;input.queryCalls=1;
            input.nativeReturn=VM27CPUConfigCapabilityKernelQueryV1(0,buffer);
            safe=Canary(middle,(size_t)(buffer-middle)) && Canary(buffer+capacity,page-(size_t)(buffer+capacity-middle));
            input.guardedContextKnown=!input.nativeReturn && safe;
            printf("{\"kind\":\"nativeReturn\",\"operation\":0,\"status\":\"0x%08x\",\"exteriorIntact\":%s,"
                "\"kernelWriteWidthKnown\":false}\n",(uint32_t)input.nativeReturn,safe?"true":"false");
            if(input.guardedContextKnown) {
                input.hostContextWord40=LE64(buffer+0x40);
                printf("{\"kind\":\"nativeContext\",\"bytes\":352,\"maskOffset\":64,\"word40\":\"0x%016llx\",\"hex\":\"",(unsigned long long)input.hostContextWord40);
                Hex(buffer,capacity);printf("\"}\n");
                // Unlike the genuine once callback, require the actual result,
                // exact size and bounded value. An unwritten zero is UNKNOWN.
                int vmm=-1;size_t bytes=sizeof(vmm);
                input.sysctlReturn=sysctlbyname("kern.hv_vmm_present",&vmm,&bytes,NULL,0);
                input.sysctlOutputBytes=bytes;input.vmmPresent=vmm;
                printf("{\"kind\":\"vmmQuery\",\"name\":\"kern.hv_vmm_present\",\"return\":%d,\"outputBytes\":%zu,\"value\":%d}\n",
                    input.sysctlReturn,bytes,vmm);
                VM27CPUTLBICapabilityValueV1 value={false,false};
                bool known=VM27CPUInterpretTLBICapabilityV1(&input,&value);
                printf("{\"kind\":\"support\",\"known\":%s,\"supported\":%s,\"mask\":\"0x2c0000000000\","
                    "\"nativeDefaultClaimed\":false,\"configMutationAuthorized\":false}\n",known?"true":"false",known && value.supported?"true":"false");
                if(known)result=0;
            }
        }
    }
    int unmap=munmap(region,total);if(unmap)result=73;
    printf("{\"kind\":\"cleanup\",\"mappingReleased\":%s,\"munmapReturn\":%d}\n",unmap==0?"true":"false",unmap);
    printf("{\"kind\":\"summary\",\"queryComplete\":%s,\"nativeOperation0Calls\":%u,\"nativeVMCalls\":0,\"nativeCPUCalls\":0,"
        "\"nativeMapCalls\":0,\"nativeRunCalls\":0,\"guestInstructions\":0,\"kernelWriteWidthKnown\":false,\"full27Backend\":false}\n",
        result==0?"true":"false",queryCalls);
    return result;
}
int main(void) {
    struct rlimit cpu={5,5},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core))return 64;
    setvbuf(stdout,NULL,_IOLBF,0);
    struct rlimit actualCPU,actualCore;
    if(getrlimit(RLIMIT_CPU,&actualCPU) || getrlimit(RLIMIT_CORE,&actualCore) ||
        actualCPU.rlim_cur!=5 || actualCPU.rlim_max!=5 || actualCore.rlim_cur || actualCore.rlim_max)return 65;
    printf("MAIN ordinary CPU config capability query PID=%d UID=%d EUID=%d CPU=5 CORE=0\n",getpid(),getuid(),geteuid());
    if(geteuid()!=0 || !Profile() || !Census() || !OwnFrame())return 66;
    uint64_t owner=0;if(pthread_threadid_np(NULL,&owner) || !owner)return 67;
    int result=Query(owner);
    if(!Census())return 74;
    return result;
}
