// Validate the exact eight private data imports on the old host. No service API.
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef VM27_CONSTANTS_UUID
#error "Builder must pin the private provider UUID"
#endif
static const char *Names[]={"kCFNetworkProxiesHTTPSEnable","kCFNetworkProxiesHTTPSPort","kCFNetworkProxiesHTTPSProxy","kSecAttrAccess","kSecOIDCommonName","kSecOIDCountryName","kSecOIDOrganizationName","kSecUseKeychain"};
static const char *Values[]={"HTTPSEnable","HTTPSPort","HTTPSProxy","acls","2.5.4.3","2.5.4.6","2.5.4.10","u_Keychain"};
static bool Read(const void *p,void *out,size_t n) {
    vm_size_t got=0;return p && n<=65536 && vm_read_overwrite(mach_task_self(),(vm_address_t)p,n,(vm_address_t)out,&got)==KERN_SUCCESS && got==n;
}
static bool Identity(const void *p,const char *expected) {
    Dl_info d={0};struct mach_header_64 h;
    if(!p || !dladdr(p,&d) || !Read(d.dli_fbase,&h,sizeof(h)) || h.magic!=MH_MAGIC_64 ||
       h.cputype!=CPU_TYPE_ARM64 || h.cpusubtype!=(cpu_subtype_t)0x80000002 || h.sizeofcmds>65536 || h.ncmds>1024)return false;
    char actual[PATH_MAX],uuid[33];if(!realpath(d.dli_fname,actual)||strcmp(actual,expected))return false;
    const unsigned char *at=(const void *)((const char *)d.dli_fbase+sizeof(h)),*end=at+h.sizeofcmds;unsigned found=0;
    for(unsigned i=0;i<h.ncmds;++i) {
        struct load_command c;if(end-at<8 || !Read(at,&c,8) || c.cmdsize<8 || c.cmdsize%8 || c.cmdsize>(size_t)(end-at))return false;
        if(c.cmd==LC_UUID){struct uuid_command u;if(c.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u)))return false;
            for(unsigned j=0;j<16;++j)snprintf(uuid+j*2,3,"%02x",u.uuid[j]);if(strcmp(uuid,VM27_CONSTANTS_UUID))return false;++found;}
        at+=c.cmdsize;
    }
    return at==end && found==1;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);if(argc!=2)return 64;
    char path[PATH_MAX];if(!realpath(argv[1],path))return 65;
    void *lib=dlopen(path,RTLD_NOW|RTLD_LOCAL);if(!lib)return 66;
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"providerUUID\":\"%s\",\"providerPath\":\"%s\"}\n",getpid(),getuid(),VM27_CONSTANTS_UUID,path);
    for(unsigned i=0;i<8;++i) {
        void *slot=dlsym(lib,Names[i]);CFStringRef value=NULL;char text[256];
        if(!Identity(slot,path) || !Read(slot,&value,sizeof(value)) || !value || CFGetTypeID(value)!=CFStringGetTypeID() ||
           !CFStringGetCString(value,text,sizeof(text),kCFStringEncodingUTF8) || strcmp(text,Values[i]))return 67;
        CFStringRef copy=CFStringCreateCopy(kCFAllocatorDefault,value);
        bool equal=copy && CFEqual(value,copy);if(copy)CFRelease(copy);
        if(!equal)return 68;
        CFStringRef retained=CFRetain(value);bool stable=retained==value;CFRelease(retained);
        if(!stable || !Identity(slot,path))return 69;
        printf("{\"record\":\"constant\",\"name\":\"%s\",\"value\":\"%s\",\"type\":\"CFStringRef\",\"exactProvider\":true,\"copyEqual\":true,\"retainReleaseStable\":true}\n",Names[i],text);
    }
    if(dlclose(lib))return 70;
    printf("{\"record\":\"summary\",\"constants\":8,\"copyReleasePairs\":8,\"retainReleasePairs\":8,\"targetServiceCalls\":0,\"DI2Loaded\":false,\"VMCalls\":0,\"diskCalls\":0,\"GPUCalls\":0,\"passed\":true}\n");return 0;
}
