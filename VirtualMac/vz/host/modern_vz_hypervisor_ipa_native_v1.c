#include "modern_vz_hypervisor_ipa_acquisition_v1.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

extern kern_return_t mach_vm_read_overwrite(vm_map_t,mach_vm_address_t,mach_vm_size_t,
    mach_vm_address_t,mach_vm_size_t *);
extern int32_t VZIPA27KernelTrapRaw(uint64_t,void *);
__attribute__((used,visibility("hidden"))) const volatile unsigned char VZIPA27ExpectedUUID[16]=
    {0x56,0x5a,0x49,0x50,0x41,0x55,0x55,0x49,0x44,0x31,0xa5,0x27,0x6c,0x8e,0x11,0x33};
int32_t VZIPA27AcquireNative(uint32_t *,VZFrameworkIPANativeReceiptV1 *);

static bool ReadExact(const void *p,size_t n,void *out) {
    if(!p || !out || !n || (uintptr_t)p>UINTPTR_MAX-n) return false;
    mach_vm_size_t copied=0;
    return mach_vm_read_overwrite(mach_task_self(),(mach_vm_address_t)(uintptr_t)p,n,
        (mach_vm_address_t)(uintptr_t)out,&copied)==KERN_SUCCESS && copied==n;
}
static bool String(const char *key,char *out,size_t capacity) {
    size_t n=capacity;memset(out,0,capacity);
    return sysctlbyname(key,out,&n,NULL,0)==0 && n>0 && n<=capacity && memchr(out,0,n);
}
static bool OwnFrame(void) {
    const void *entry=ptrauth_strip((void *)VZIPA27KernelTrapRaw,ptrauth_key_function_pointer);
    const void *anchor=ptrauth_strip((void *)VZIPA27AcquireNative,ptrauth_key_function_pointer);
    Dl_info trap={0},owner={0};
    if(dladdr(entry,&trap)!=1 || dladdr(anchor,&owner)!=1 || !trap.dli_fbase ||
        owner.dli_fbase!=trap.dli_fbase || !trap.dli_fname) return false;
    const char *leaf=strrchr(trap.dli_fname,'/');leaf=leaf?leaf+1:trap.dli_fname;
    if(strcmp(leaf,"VM27IPALimit.dylib")) return false;
    struct mach_header_64 header;
    if(!ReadExact(trap.dli_fbase,sizeof(header),&header) || header.magic!=MH_MAGIC_64 ||
        header.filetype!=MH_DYLIB || header.cputype!=CPU_TYPE_ARM64 ||
        header.ncmds<1 || header.ncmds>128 || header.sizeofcmds<24 || header.sizeofcmds>65536 ||
        (uintptr_t)trap.dli_fbase>UINTPTR_MAX-sizeof(header)-header.sizeofcmds) return false;
    unsigned char *commands=malloc(header.sizeofcmds);if(!commands) return false;
    bool read=ReadExact((const unsigned char *)trap.dli_fbase+sizeof(header),header.sizeofcmds,commands);
    bool valid=read;unsigned uuidCount=0,idCount=0;size_t at=0;
    for(uint32_t i=0;valid && i<header.ncmds;++i) {
        struct load_command command;
        if(at>header.sizeofcmds || header.sizeofcmds-at<sizeof(command)) {valid=false;break;}
        memcpy(&command,commands+at,sizeof(command));
        if(command.cmdsize<8 || command.cmdsize%8 || command.cmdsize>header.sizeofcmds-at) {valid=false;break;}
        if(command.cmd==LC_UUID) {
            if(command.cmdsize!=sizeof(struct uuid_command) || ++uuidCount!=1) {valid=false;break;}
            unsigned char expected[16];for(unsigned j=0;j<16;++j) expected[j]=VZIPA27ExpectedUUID[j];
            valid=!memcmp(commands+at+8,expected,16);
        }
        if(command.cmd==LC_ID_DYLIB) {
            struct dylib_command id;
            if(command.cmdsize<sizeof(id) || ++idCount!=1) {valid=false;break;}
            memcpy(&id,commands+at,sizeof(id));uint32_t offset=id.dylib.name.offset;
            if(offset<sizeof(id) || offset>=command.cmdsize) {valid=false;break;}
            const char *name=(const char *)(commands+at+offset);
            if(!memchr(name,0,command.cmdsize-offset) || strcmp(name,"@rpath/VM27IPALimit.dylib")) {valid=false;break;}
        }
        at+=command.cmdsize;
    }
    valid=valid && at==header.sizeofcmds && uuidCount==1 && idCount==1;free(commands);
    const unsigned char words[12]={0x90,0x00,0x80,0x92,0x01,0x10,0x00,0xd4,0xc0,0x03,0x5f,0xd6};
    unsigned char actual[12];return valid && ReadExact(entry,12,actual) && !memcmp(actual,words,12);
}
static bool Validate(void *unused,uint64_t *actualThread) {
    (void)unused;char release[32],build[32],machine[32];
    if(!actualThread || !String("kern.osrelease",release,sizeof(release)) || strcmp(release,"22.1.0") ||
        !String("kern.osversion",build,sizeof(build)) || strcmp(build,"20B101") ||
        !String("hw.machine",machine,sizeof(machine))) return false;
    if(strcmp(machine,"iPad14,3") && strcmp(machine,"iPad14,4") && strcmp(machine,"iPad14,5") && strcmp(machine,"iPad14,6")) return false;
    uint64_t thread=0;if(pthread_threadid_np(NULL,&thread) || !thread || !OwnFrame()) return false;
    *actualThread=thread;return true;
}
static int32_t Query(void *unused,void *buffer) {
    (void)unused;return VZIPA27KernelTrapRaw(0,buffer);
}
int32_t VZIPA27AcquireNative(uint32_t *out,VZFrameworkIPANativeReceiptV1 *receipt) {
    const VZFrameworkIPAAcquisitionOpsV1 ops={1,NULL,Validate,Query};
    return VZFrameworkQueryMaxIPANativeV1(&ops,out,receipt);
}
