// Independent compatibility policy: preserve strong IOUSBHost dependencies,
// implement real descriptor parsing, and reject USB hardware creation explicitly.
// API/struct ABI: macOS27 SDK IOUSBHost and IOKit USB public headers.
// Native class footprints verified by usbh-contract-v1/native-abi.json.
#include "modern_usbh_host_unavailable_compat.h"
#include <string.h>
static void Unavailable(NSError **error) {
    if(error)*error=[NSError errorWithDomain:NSMachErrorDomain code:(int32_t)0xe00002c7
        userInfo:@{NSLocalizedDescriptionKey:@"USB hardware is unavailable in this macOS27 compatibility backend."}];
}
// Owned normal-boot AVP host-mediation offline mode. This never creates an
// AppleUSBUserHCIResources user client or fabricates a controller response.
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
extern int csops(pid_t,unsigned int,void*,size_t);

static char VM27AVPOfflineStateKeyV1;
static BOOL VM27AVPOfflineCallerV1(id receiver,void *caller) {
    static const unsigned char uuid[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    static const unsigned char prefix[32]={0x7f,0x23,0x03,0xd5,0xff,0x03,0x01,0xd1,0xf4,0x4f,0x02,0xa9,0xfd,0x7b,0x03,0xa9,0xfd,0xc3,0x00,0x91,0x08,0x14,0x00,0xd0,0x08,0x11,0x40,0xf9,0xa9,0x4f,0x41,0xa9};
    const char *expected="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
    Dl_info info={0};uint32_t status=0;Class actual=object_getClass(receiver);
    if(getuid()!=501 || geteuid()!=501 || getpid()<=1 || csops(getpid(),0,&status,sizeof(status)) || (status&0x04000001)!=0x04000001 || !actual || strcmp(class_getName(actual),"VZIOUSBHostControllerInterface") || class_getSuperclass(actual)!=[IOUSBHostControllerInterface class] || class_getInstanceSize(actual)!=328 || !dladdr(caller,&info) || !info.dli_fbase || !info.dli_fname || strcmp(info.dli_fname,expected))return NO;
    const unsigned char *base=info.dli_fbase;const struct mach_header_64 *header=(const void*)base;
    if(header->magic!=MH_MAGIC_64 || header->ncmds>128 || header->sizeofcmds>16384 || (uintptr_t)caller-(uintptr_t)base!=0x2449e8 || memcmp(base+0x2449b0,prefix,sizeof(prefix)))return NO;
    const unsigned char *at=base+sizeof(*header),*end=at+header->sizeofcmds;BOOL matched=NO;
    for(uint32_t i=0;i<header->ncmds;i++) {if((size_t)(end-at)<8)return NO;const struct load_command *c=(const void*)at;if(c->cmdsize<8 || c->cmdsize>(size_t)(end-at))return NO;if(c->cmd==LC_UUID){if(c->cmdsize!=24)return NO;matched=!memcmp(at+8,uuid,16);}at+=c->cmdsize;}
    return matched && at==end;
}
@interface VM27OwnedAVPUSBOfflineStateV1 : NSObject {
@public NSData *data;dispatch_queue_t actualQueue;IOUSBHostControllerInterfaceCommandHandler command;IOUSBHostControllerInterfaceDoorbellHandler doorbell;VM27USBInterestCallback interest;NSUInteger rate;NSUUID *identifier;BOOL closed;
@private __weak IOUSBHostControllerInterface *owner;
}
- (instancetype)initWithInterface:(IOUSBHostControllerInterface*)interface data:(NSData*)capabilities queue:(dispatch_queue_t)queue rate:(NSUInteger)hz command:(IOUSBHostControllerInterfaceCommandHandler)c doorbell:(IOUSBHostControllerInterfaceDoorbellHandler)d interest:(VM27USBInterestCallback)i;
@property(readonly) int controllerState;
@property(readonly) IOUSBHostControllerInterface *controllerInterface;
- (BOOL)inspectCommand:(const IOUSBHostCIMessage*)message error:(NSError**)error;
- (BOOL)respondToCommand:(const IOUSBHostCIMessage*)message status:(int)status error:(NSError**)error;
- (void)close;
@end
@implementation VM27OwnedAVPUSBOfflineStateV1
- (instancetype)initWithInterface:(IOUSBHostControllerInterface*)interface data:(NSData*)capabilities queue:(dispatch_queue_t)queue rate:(NSUInteger)hz command:(IOUSBHostControllerInterfaceCommandHandler)c doorbell:(IOUSBHostControllerInterfaceDoorbellHandler)d interest:(VM27USBInterestCallback)i {
    if(!(self=[super init]))return nil;owner=interface;data=[capabilities copy];actualQueue=queue;rate=hz;command=[c copy];doorbell=[d copy];interest=i;identifier=[NSUUID UUID];return self;
}
- (int)controllerState { return 0; /* Actual owned state stays Off: no host power/start command occurred. */ }
- (IOUSBHostControllerInterface*)controllerInterface { return owner; }
- (BOOL)inspectCommand:(const IOUSBHostCIMessage*)m error:(NSError**)e { (void)m;Unavailable(e);return NO; }
- (BOOL)respondToCommand:(const IOUSBHostCIMessage*)m status:(int)s error:(NSError**)e { (void)m;(void)s;Unavailable(e);return NO; }
- (void)close { if(closed)return;closed=YES;command=nil;doorbell=nil;interest=NULL;actualQueue=nil;data=nil;owner=nil; }
@end
static VM27OwnedAVPUSBOfflineStateV1 *VM27AVPStateV1(id object) { return objc_getAssociatedObject(object,&VM27AVPOfflineStateKeyV1); }
static BOOL VM27AVPCapabilitiesV1(NSData *data) {
    if(![data isKindOfClass:[NSData class]] || data.length<32 || data.length>1040 || data.length%16)return NO;
    const IOUSBHostCIMessage *m=data.bytes;unsigned controllers=0,ports=0;uint32_t portMask=0;unsigned count=0;
    for(NSUInteger n=0;n<data.length/16;n++) {unsigned type=m[n].control&0x3f;if((m[n].control&0xc000)!=0xc000)return NO;
        if(type==0){controllers++;count=(m[n].control>>16)&0xff;}
        else if(type==1){unsigned p=(m[n].control>>16)&0xff;if(!p || p>32 || (portMask&(1U<<(p-1))))return NO;portMask|=1U<<(p-1);ports++;}
        else return NO;
    }
    return controllers==1 && count>0 && count<=32 && count==ports;
}

static CFMutableDictionaryRef ClosedMatchingDictionary(void) {
    // A valid IOKit match against this private, non-driver class cannot enumerate
    // physical IOUSBHost devices. Never return an empty all-services dictionary.
    return (CFMutableDictionaryRef)CFBridgingRetain([@{@"IOProviderClass":@"VirtualMac27USBUnavailableNoHardware"} mutableCopy]);
}
static int Range(const IOUSBConfigurationDescriptor *config,uintptr_t *start,uintptr_t *end) {
    if(!config)return 0;uint16_t length=0;memcpy(&length,&config->wTotalLength,2);
    *start=(uintptr_t)config;if(length<sizeof(*config)||*start>UINTPTR_MAX-length)return 0;
    *end=*start+length;return 1;
}
static int Header(uintptr_t value,uintptr_t start,uintptr_t end) {
    if(value<start||value>end||end-value<2)return 0;
    const IOUSBDescriptorHeader *h=(const void *)value;
    return h->bLength>=2 && h->bLength<=end-value;
}
const IOUSBDescriptorHeader *IOUSBGetNextDescriptor(const IOUSBConfigurationDescriptor *config,const IOUSBDescriptorHeader *current) {
    uintptr_t start=0,end=0;if(!Range(config,&start,&end))return NULL;
    uintptr_t at=current?(uintptr_t)current:start;if(!Header(at,start,end))return NULL;
    at+=((const IOUSBDescriptorHeader *)at)->bLength;
    return Header(at,start,end)?(const void *)at:NULL;
}
const IOUSBDescriptorHeader *IOUSBGetNextDescriptorWithType(const IOUSBConfigurationDescriptor *config,const IOUSBDescriptorHeader *current,uint8_t type) {
    const IOUSBDescriptorHeader *next=current;
    while((next=IOUSBGetNextDescriptor(config,next)))if(next->bDescriptorType==type)return next;
    return NULL;
}
const IOUSBDescriptorHeader *IOUSBGetNextAssociatedDescriptorWithType(const IOUSBConfigurationDescriptor *config,const IOUSBDescriptorHeader *parent,const IOUSBDescriptorHeader *current,uint8_t type) {
    uintptr_t start=0,end=0;if(!Range(config,&start,&end)||!Header((uintptr_t)parent,start,end))return NULL;
    if(current&&((uintptr_t)current<(uintptr_t)parent||!Header((uintptr_t)current,start,end)))return NULL;
    if(current&&current!=parent&&current->bDescriptorType==parent->bDescriptorType)return NULL;
    const IOUSBDescriptorHeader *next=current?current:parent;
    while((next=IOUSBGetNextDescriptor(config,next))) {
        if(next->bDescriptorType==parent->bDescriptorType)return NULL;
        if(next->bDescriptorType==type)return next;
    }
    return NULL;
}
const IOUSBInterfaceDescriptor *IOUSBGetNextInterfaceDescriptor(const IOUSBConfigurationDescriptor *config,const IOUSBDescriptorHeader *current) {
    return (const void *)IOUSBGetNextDescriptorWithType(config,current,4);
}
const IOUSBEndpointDescriptor *IOUSBGetNextEndpointDescriptor(const IOUSBConfigurationDescriptor *config,const IOUSBInterfaceDescriptor *interface,const IOUSBDescriptorHeader *current) {
    return (const void *)IOUSBGetNextAssociatedDescriptorWithType(config,(const void *)interface,current,5);
}
uint8_t IOUSBGetEndpointType(const IOUSBEndpointDescriptor *descriptor) { return descriptor?descriptor->bmAttributes&3:0; }
uint8_t IOUSBGetEndpointDirection(const IOUSBEndpointDescriptor *descriptor) {
    return !descriptor||IOUSBGetEndpointType(descriptor)==0?2:descriptor->bEndpointAddress>>7;
}
@implementation IOUSBHostObject
- (instancetype)init { return nil; }
- (instancetype)initWithIOService:(uint32_t)s options:(NSUInteger)o queue:(dispatch_queue_t)q error:(NSError **)e interestHandler:(IOUSBHostInterestHandler)h { (void)s;(void)o;(void)q;(void)h;Unavailable(e);return nil; }
- (instancetype)initWithIOService:(uint32_t)s queue:(dispatch_queue_t)q error:(NSError **)e interestHandler:(IOUSBHostInterestHandler)h { return [self initWithIOService:s options:0 queue:q error:e interestHandler:h]; }
- (void)destroy { /* No hardware resource can be created by this provider. */ }
- (void)destroyWithOptions:(NSUInteger)o { (void)o;[self destroy]; }
- (uint32_t)ioService { return 0; }
- (dispatch_queue_t)queue { return nil; }
@end
@implementation IOUSBHostDevice
+ (CFMutableDictionaryRef)createMatchingDictionaryWithVendorID:(NSNumber *)v productID:(NSNumber *)p bcdDevice:(NSNumber *)b deviceClass:(NSNumber *)c deviceSubclass:(NSNumber *)s deviceProtocol:(NSNumber *)r speed:(NSNumber *)d productIDArray:(NSArray *)a { (void)v;(void)p;(void)b;(void)c;(void)s;(void)r;(void)d;(void)a;return ClosedMatchingDictionary(); }
- (BOOL)configureWithValue:(NSUInteger)v matchInterfaces:(BOOL)m error:(NSError **)e { (void)v;(void)m;Unavailable(e);return NO; }
- (BOOL)configureWithValue:(NSUInteger)v error:(NSError **)e { return [self configureWithValue:v matchInterfaces:NO error:e]; }
- (BOOL)resetWithError:(NSError **)e { Unavailable(e);return NO; }
- (const IOUSBConfigurationDescriptor *)configurationDescriptor { return NULL; }
@end
@implementation IOUSBHostInterface
+ (CFMutableDictionaryRef)createMatchingDictionaryWithVendorID:(NSNumber *)v productID:(NSNumber *)p bcdDevice:(NSNumber *)b interfaceNumber:(NSNumber *)n configurationValue:(NSNumber *)x interfaceClass:(NSNumber *)c interfaceSubclass:(NSNumber *)s interfaceProtocol:(NSNumber *)r speed:(NSNumber *)d productIDArray:(NSArray *)a { (void)v;(void)p;(void)b;(void)n;(void)x;(void)c;(void)s;(void)r;(void)d;(void)a;return ClosedMatchingDictionary(); }
- (BOOL)selectAlternateSetting:(NSUInteger)v error:(NSError **)e { (void)v;Unavailable(e);return NO; }
- (id)copyPipeWithAddress:(NSUInteger)a error:(NSError **)e { (void)a;Unavailable(e);return nil; }
- (BOOL)setIdleTimeout:(NSTimeInterval)t error:(NSError **)e { (void)t;Unavailable(e);return NO; }
- (NSTimeInterval)idleTimeout { return 0; }
- (const IOUSBConfigurationDescriptor *)configurationDescriptor { return NULL; }
- (const IOUSBInterfaceDescriptor *)interfaceDescriptor { return NULL; }
@end
@implementation IOUSBHostControllerInterface
- (instancetype)init { return nil; }
- (instancetype)initWithCapabilities:(NSData*)c queue:(dispatch_queue_t)q interruptRateHz:(NSUInteger)r error:(NSError**)e commandHandler:(IOUSBHostControllerInterfaceCommandHandler)h doorbellHandler:(IOUSBHostControllerInterfaceDoorbellHandler)d interestHandler:(VM27USBInterestCallback)i {
    int saved=errno;void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    if(!VM27AVPOfflineCallerV1(self,caller) || !q || !h || !d || !VM27AVPCapabilitiesV1(c)) {Unavailable(e);errno=saved;return nil;}
    if(!(self=[super init])) {Unavailable(e);errno=saved;return nil;}
    VM27OwnedAVPUSBOfflineStateV1 *state=[[VM27OwnedAVPUSBOfflineStateV1 alloc] initWithInterface:self data:c queue:q rate:r command:h doorbell:d interest:i];
    if(!state || !state->data || !state->identifier || state->data.length!=c.length) {Unavailable(e);errno=saved;return nil;}
    objc_setAssociatedObject(self,&VM27AVPOfflineStateKeyV1,state,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    if(e)*e=nil;
    dprintf(2,"[VM27OwnedAVPUSBOfflineV1] callerRVA=0x2449e8 ownedObjectReady=1 ownedQueueReady=1 capabilitiesBytes=%lu controllerState=off guestExternalUSBConnected=0 kernelUserClientCreated=0 physicalPassthroughUnavailable=1 generatedCommands=0 fabricatedResponses=0 standardGuestUSBInputUnchanged=1\n",(unsigned long)c.length);
    errno=saved;return self;
}
- (void)destroy { int saved=errno;VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);[s close];objc_setAssociatedObject(self,&VM27AVPOfflineStateKeyV1,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);errno=saved; }
- (BOOL)enqueueInterrupt:(const IOUSBHostCIMessage*)m error:(NSError**)e { (void)m;Unavailable(e);return NO; }
- (BOOL)enqueueInterrupt:(const IOUSBHostCIMessage*)m expedite:(BOOL)x error:(NSError**)e { (void)x;return [self enqueueInterrupt:m error:e]; }
- (BOOL)enqueueInterrupts:(const IOUSBHostCIMessage*)m count:(NSUInteger)c error:(NSError**)e { (void)m;(void)c;Unavailable(e);return NO; }
- (BOOL)enqueueInterrupts:(const IOUSBHostCIMessage*)m count:(NSUInteger)c expedite:(BOOL)x error:(NSError**)e { (void)x;return [self enqueueInterrupts:m count:c error:e]; }
- (id)getPortStateMachineForCommand:(const IOUSBHostCIMessage*)m error:(NSError**)e { (void)m;Unavailable(e);return nil; }
- (id)getPortStateMachineForPort:(NSUInteger)p error:(NSError**)e { (void)p;Unavailable(e);return nil; }
- (const IOUSBHostCIMessage*)capabilitiesForPort:(NSUInteger)p { VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);if(!s || s->closed)return NULL;const IOUSBHostCIMessage *m=s->data.bytes;for(NSUInteger n=0;n<s->data.length/16;n++)if((m[n].control&0x3f)==1 && ((m[n].control>>16)&0xff)==p)return &m[n];return NULL; }
- (NSString*)descriptionForMessage:(const IOUSBHostCIMessage*)m { (void)m;return @"Owned AVP external USB host mediation offline; no kernel user client"; }
- (dispatch_queue_t)queue { VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);return s?s->actualQueue:nil; }
- (NSUInteger)interruptRateHz { VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);return s?s->rate:0; }
- (void)setInterruptRateHz:(NSUInteger)r { VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);if(s && !s->closed)s->rate=r; }
- (id)controllerStateMachine { return VM27AVPStateV1(self); }
- (const IOUSBHostCIMessage*)capabilities { VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);if(!s || s->closed)return NULL;const IOUSBHostCIMessage *m=s->data.bytes;for(NSUInteger n=0;n<s->data.length/16;n++)if((m[n].control&0x3f)==0)return &m[n];return NULL; }
- (NSUUID*)uuid { VM27OwnedAVPUSBOfflineStateV1 *s=VM27AVPStateV1(self);return s?s->identifier:nil; }
@end
@implementation IOUSBHostCIDeviceStateMachine
- (instancetype)init { return nil; }
- (instancetype)initWithInterface:(IOUSBHostControllerInterface *)i command:(const IOUSBHostCIMessage *)c error:(NSError **)e { (void)i;(void)c;Unavailable(e);return nil; }
- (BOOL)inspectCommand:(const IOUSBHostCIMessage *)c error:(NSError **)e { (void)c;Unavailable(e);return NO; }
- (BOOL)respondToCommand:(const IOUSBHostCIMessage *)c status:(int)s error:(NSError **)e { (void)c;(void)s;Unavailable(e);return NO; }
- (BOOL)respondToCommand:(const IOUSBHostCIMessage *)c status:(int)s deviceAddress:(NSUInteger)a error:(NSError **)e { (void)a;return [self respondToCommand:c status:s error:e]; }
- (int)deviceState { return 0; }
- (NSUInteger)completeRoute { return 0; }
- (NSUInteger)deviceAddress { return 0; }
- (IOUSBHostControllerInterface *)controllerInterface { return nil; }
@end
@implementation IOUSBHostCIEndpointStateMachine
- (instancetype)init { return nil; }
- (instancetype)initWithInterface:(IOUSBHostControllerInterface *)i command:(const IOUSBHostCIMessage *)c error:(NSError **)e { (void)i;(void)c;Unavailable(e);return nil; }
- (BOOL)inspectCommand:(const IOUSBHostCIMessage *)c error:(NSError **)e { (void)c;Unavailable(e);return NO; }
- (BOOL)respondToCommand:(const IOUSBHostCIMessage *)c status:(int)s error:(NSError **)e { (void)c;(void)s;Unavailable(e);return NO; }
- (BOOL)processDoorbell:(IOUSBHostCIDoorbell)d error:(NSError **)e { (void)d;Unavailable(e);return NO; }
- (BOOL)enqueueTransferCompletionForMessage:(const IOUSBHostCIMessage *)m status:(int)s transferLength:(NSUInteger)l error:(NSError **)e { (void)m;(void)s;(void)l;Unavailable(e);return NO; }
- (int)endpointState { return 0; }
- (NSUInteger)deviceAddress { return 0; }
- (NSUInteger)endpointAddress { return 0; }
- (const IOUSBHostCIMessage *)currentTransferMessage { return NULL; }
- (IOUSBHostControllerInterface *)controllerInterface { return nil; }
@end
