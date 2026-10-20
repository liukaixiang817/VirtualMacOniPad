#import "vm27_owned_uikit_mac_event_filter_v1.h"
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#if defined(VM27_MAC_EVENT_FILTER_FIXTURE_V1) && defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#error "Mac event filter fixture cannot enter iOS products"
#endif
#ifdef VM27_MAC_EVENT_FILTER_FIXTURE_V1
extern BOOL VM27MacEventFilterFixtureProfileV1(void);
#endif
#ifndef VM27_MAC_EVENT_FILTER_FIXTURE_V1
static const uint8_t OriginalUUIDV1[16]={0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
#endif
static BOOL ActualProfileV1(const void **actualBase) {
#ifdef VM27_MAC_EVENT_FILTER_FIXTURE_V1
    if(!VM27MacEventFilterFixtureProfileV1())return NO;
    *actualBase=(__bridge const void *)[VM27OwnedUIKitMacEventFilterV1 class];return YES;
#else
    if(getuid()!=501 || geteuid()!=501 ||
       ![[NSBundle.mainBundle bundleIdentifier] isEqualToString:@"com.mac.virtual.independent27"] ||
       ![[NSBundle.mainBundle objectForInfoDictionaryKey:@"VirtualMacPVGBackendVersion"] isEqualToString:@"27"])return NO;
    Class vm=objc_getClass("VZVirtualMachine"),monitor=objc_getClass("_VZHIDEventMonitor");
    if(!vm || !monitor || class_getInstanceSize(vm)!=384 || class_getInstanceSize(monitor)!=18)return NO;
    Ivar owned=class_getInstanceVariable(vm,"_hidEventMonitor"),filter=class_getInstanceVariable(monitor,"_filter");
    if(!owned || ivar_getOffset(owned)!=224 || strcmp(ivar_getTypeEncoding(owned),"@\"_VZHIDEventMonitor\"") ||
       !filter || ivar_getOffset(filter)!=8 || strcmp(ivar_getTypeEncoding(filter),"@\"_VZHIDEventFilter\""))return NO;
    Method method=class_getInstanceMethod(vm,sel_registerName("initWithConfiguration:queue:"));
    if(!method || strcmp(method_getTypeEncoding(method),"@32@0:8@16@24"))return NO;
    const void *imp=(const void *)ptrauth_strip((void *)method_getImplementation(method),ptrauth_key_function_pointer);
    Dl_info info={0};if(!dladdr(imp,&info) || !info.dli_fbase || !info.dli_fname)return NO;
    static const char path[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/parent-flat/VZ27.dylib";
    if(strcmp(info.dli_fname,path) || (const uint8_t *)imp!=(const uint8_t *)info.dli_fbase+0x14cd04)return NO;
    const struct mach_header_64 *header=info.dli_fbase;
    if(header->magic!=MH_MAGIC_64 || header->ncmds>4096 || header->sizeofcmds>1048576)return NO;
    const uint8_t *at=(const uint8_t *)(header+1),*end=at+header->sizeofcmds;unsigned found=0;
    for(uint32_t i=0;i<header->ncmds;i++) {
        if((size_t)(end-at)<sizeof(struct load_command))return NO;
        const struct load_command *lc=(const void *)at;
        if(lc->cmdsize<8 || lc->cmdsize%8 || lc->cmdsize>(size_t)(end-at))return NO;
        if(lc->cmd==LC_UUID) {
            if(lc->cmdsize!=sizeof(struct uuid_command) || found++ ||
               memcmp(((const struct uuid_command *)lc)->uuid,OriginalUUIDV1,16))return NO;
        }
        at+=lc->cmdsize;
    }
    if(at!=end || found!=1)return NO;
    *actualBase=header;return YES;
#endif
}
static void RejectV1(NSString *reason) __attribute__((noreturn));
static void RejectV1(NSString *reason) {
    @throw [NSException exceptionWithName:@"VM27OwnedUIKitMacEventFilterUnavailable" reason:reason userInfo:nil];
}
static const void *RequireClassProfileV1(Class actualClass) {
    const void *base=NULL;
    if(actualClass!=objc_getClass("VM27OwnedUIKitMacEventFilterV1") ||
       class_getSuperclass(actualClass)!=NSObject.class || !ActualProfileV1(&base))
        RejectV1(@"The named UIKit Mac-event profile does not match the actual owned VZ27 process.");
    return base;
}
@implementation VM27OwnedUIKitMacEventFilterV1 {
    const void *_actualVZBase;
    pid_t _actualPID;
}
+ (BOOL)isEnabled {RequireClassProfileV1(self);return NO;}
+ (BOOL)hasEventTranslators {RequireClassProfileV1(self);return NO;}
- (instancetype)init {
    const void *base=RequireClassProfileV1(object_getClass(self));
    if((self=[super init])) {
        _actualVZBase=base;_actualPID=getpid();
        fprintf(stderr,"VM27 owned UIKit Mac-event monitor instantiated actualPID=%d macHIDEnabled=0 macEventTranslators=0 ordinaryUIKitPacketSendersPreserved=1\n",_actualPID);
    }
    return self;
}
- (void)requireActualOwner {
    const void *base=RequireClassProfileV1(object_getClass(self));
    if(_actualPID!=getpid() || !_actualVZBase || _actualVZBase!=base)
        RejectV1(@"The Mac-event monitor owner or original VZ image epoch changed.");
}
- (NSArray *)getHIDReportsFromHIDEvent:(VM27OwnedIOHIDEventRefV1)event {
    (void)event;[self requireActualOwner];
    RejectV1(@"Raw HID monitor reports, media-key fallback and filtered scrolling are unavailable in this ordinary UIKit profile.");
}
- (NSArray *)getHIDReportsFromNSEvent:(id)event {
    (void)event;[self requireActualOwner];RejectV1(@"Mac NSEvent translation is unavailable in this UIKit profile.");
}
- (void)updateCoordinateTransform:(CGRect)rect isFlipped:(BOOL)flipped {
    (void)rect;(void)flipped;[self requireActualOwner];RejectV1(@"Mac-view event coordinate transforms are unavailable in this UIKit profile.");
}
@end
