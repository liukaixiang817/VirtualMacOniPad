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
- (instancetype)initWithCapabilities:(NSData *)c queue:(dispatch_queue_t)q interruptRateHz:(NSUInteger)r error:(NSError **)e commandHandler:(IOUSBHostControllerInterfaceCommandHandler)h doorbellHandler:(IOUSBHostControllerInterfaceDoorbellHandler)d interestHandler:(VM27USBInterestCallback)i { (void)c;(void)q;(void)r;(void)h;(void)d;(void)i;Unavailable(e);return nil; }
- (void)destroy { /* No IOKit connection or dispatch work was created. */ }
- (BOOL)enqueueInterrupt:(const IOUSBHostCIMessage *)m error:(NSError **)e { (void)m;Unavailable(e);return NO; }
- (BOOL)enqueueInterrupt:(const IOUSBHostCIMessage *)m expedite:(BOOL)x error:(NSError **)e { (void)x;return [self enqueueInterrupt:m error:e]; }
- (BOOL)enqueueInterrupts:(const IOUSBHostCIMessage *)m count:(NSUInteger)c error:(NSError **)e { (void)m;(void)c;Unavailable(e);return NO; }
- (BOOL)enqueueInterrupts:(const IOUSBHostCIMessage *)m count:(NSUInteger)c expedite:(BOOL)x error:(NSError **)e { (void)x;return [self enqueueInterrupts:m count:c error:e]; }
- (id)getPortStateMachineForCommand:(const IOUSBHostCIMessage *)c error:(NSError **)e { (void)c;Unavailable(e);return nil; }
- (id)getPortStateMachineForPort:(NSUInteger)p error:(NSError **)e { (void)p;Unavailable(e);return nil; }
- (const IOUSBHostCIMessage *)capabilitiesForPort:(NSUInteger)p { (void)p;return NULL; }
- (NSString *)descriptionForMessage:(const IOUSBHostCIMessage *)m { (void)m;return @"USB unavailable"; }
- (dispatch_queue_t)queue { return nil; }
- (NSUInteger)interruptRateHz { return 0; }
- (void)setInterruptRateHz:(NSUInteger)r { (void)r; }
- (id)controllerStateMachine { return nil; }
- (const IOUSBHostCIMessage *)capabilities { return NULL; }
- (NSUUID *)uuid { return nil; }
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
