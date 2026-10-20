#import <Foundation/Foundation.h>
#include "vm27_scoped_display_routes.h"
#include <TargetConditionals.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <string.h>

#if TARGET_OS_IPHONE
static const char *providerPath="/System/Library/Frameworks/QuartzCore.framework/QuartzCore";
static const uint8_t providerUUID[16]={0x04,0x63,0x38,0xbf,0x09,0xcf,0x34,0x14,0xbc,0x93,0x31,0x29,0x6b,0x97,0xeb,0x2d};
static const uintptr_t offsets[3]={110036,1041608,840656};
#else
static const char *providerPath="/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore";
static const uint8_t providerUUID[16]={0x21,0x6f,0x70,0xf6,0xae,0xf9,0x3d,0x60,0x94,0x2b,0xf6,0x4c,0x63,0x6d,0xef,0x69};
static const uintptr_t offsets[3]={401024,491376,310292};
#endif
static const char *names[3]={"mainDisplay","deviceName","displayId"};
static const char *encodings[3]={"@16@0:8","@16@0:8","I16@0:8"};
static pthread_once_t loadOnce=PTHREAD_ONCE_INIT;
static void *systemQuartzCore;
static void loadSystemQuartzCore(void){
    /* Retain the system framework until process exit. Only the load is
     * cached; every getter request revalidates identities and fresh values. */
    systemQuartzCore=dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore",RTLD_NOW|RTLD_LOCAL);
}
static bool identity(Class cls,unsigned index,uintptr_t *canonical){
    SEL sel=sel_registerName(names[index]);Method method=index==0?class_getClassMethod(cls,sel):class_getInstanceMethod(cls,sel);
    if(!method||strcmp(method_getTypeEncoding(method),encodings[index])||method_getNumberOfArguments(method)!=2)return false;
    void *address=ptrauth_strip((void *)method_getImplementation(method),ptrauth_key_function_pointer);
    Dl_info info={0};if(!address||!dladdr(address,&info)||!info.dli_fbase||!info.dli_fname||strcmp(info.dli_fname,providerPath))return false;
    const struct mach_header_64 *h=info.dli_fbase;
    if(h->magic!=MH_MAGIC_64||h->ncmds>1024||h->sizeofcmds>262144||(uintptr_t)address-(uintptr_t)h!=offsets[index])return false;
    const uint8_t *p=(const uint8_t *)(h+1),*end=p+h->sizeofcmds;bool found=false;
    for(uint32_t i=0;i<h->ncmds;i++){
        if(p+sizeof(struct load_command)>end)return false;
        const struct load_command *lc=(const void *)p;if(lc->cmdsize<sizeof(*lc)||p+lc->cmdsize>end)return false;
        if(lc->cmd==LC_UUID){if(found||lc->cmdsize!=sizeof(struct uuid_command)||memcmp(((const struct uuid_command *)lc)->uuid,providerUUID,16))return false;found=true;}
        p+=lc->cmdsize;
    }
    if(!found||p!=end)return false;*canonical=(uintptr_t)address;return true;
}
/* Exact getter identities and object/type ownership are guarded before and
 * after each observed snapshot. Stripped pointers are never invoked. */
static CFStringRef copyObservedMain(uint32_t *displayID){
    if(!displayID)return NULL;
    if(pthread_once(&loadOnce,loadSystemQuartzCore)||!systemQuartzCore)return NULL;
    Class cls=objc_lookUpClass("CADisplay");if(!cls||!class_getImageName(cls)||strcmp(class_getImageName(cls),providerPath))return NULL;
    uintptr_t before[3]={0};for(unsigned i=0;i<3;i++)if(!identity(cls,i,&before[i]))return NULL;
    id display=((id(*)(id,SEL))objc_msgSend)(cls,sel_registerName("mainDisplay"));
    if(!display||object_getClass(display)!=cls)return NULL;
    id name=((id(*)(id,SEL))objc_msgSend)(display,sel_registerName("deviceName"));
    if(!name||CFGetTypeID((__bridge CFTypeRef)name)!=CFStringGetTypeID())return NULL;
    CFStringRef value=(__bridge CFStringRef)name;CFIndex length=CFStringGetLength(value);if(length<=0||length>256)return NULL;
    CFDataRef bytes=CFStringCreateExternalRepresentation(kCFAllocatorDefault,value,kCFStringEncodingUTF8,0);
    if(!bytes)return NULL;CFIndex byteLength=CFDataGetLength(bytes);
    bool valid=byteLength>0&&byteLength<=1024&&!memchr(CFDataGetBytePtr(bytes),0,(size_t)byteLength);CFRelease(bytes);
    if(!valid)return NULL;
    uint32_t current=((uint32_t(*)(id,SEL))objc_msgSend)(display,sel_registerName("displayId"));
    for(unsigned i=0;i<3;i++){uintptr_t after=0;if(!identity(cls,i,&after)||before[i]!=after)return NULL;}
    CFStringRef owned=CFStringCreateCopy(kCFAllocatorDefault,value);if(!owned)return NULL;
    *displayID=current;return owned;
}
uint32_t SLMainDisplayID(void){
    @autoreleasepool{
        uint32_t displayID=0;CFStringRef name=copyObservedMain(&displayID);
        if(!name)return 0;CFRelease(name);return displayID;
    }
}
CFDictionaryRef SLSCopyDisplayInfoDictionary(uint32_t requested){
    @autoreleasepool{
        uint32_t displayID=0;CFStringRef name=copyObservedMain(&displayID);if(!name)return NULL;
        if(requested!=0&&requested!=displayID){CFRelease(name);return NULL;}
        /* This is the single real device-name field consumed by the audited
         * original VZ helper. No other display fields or services are faked. */
        const void *keys[]={CFSTR("CGDisplayCADeviceName")};const void *values[]={name};
        CFDictionaryRef result=CFDictionaryCreate(kCFAllocatorDefault,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        CFRelease(name);return result;
    }
}
