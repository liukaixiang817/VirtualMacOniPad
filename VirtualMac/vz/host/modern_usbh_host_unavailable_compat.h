// App-private IOUSBHost compatibility surface. USB hardware is unavailable.
// ABI declarations checked against the local macOS27 SDK and native-abi.json.
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct __attribute__((packed)) IOUSBDescriptorHeader { uint8_t bLength,bDescriptorType; } IOUSBDescriptorHeader;
typedef struct __attribute__((packed)) IOUSBConfigurationDescriptor { uint8_t bLength,bDescriptorType;uint16_t wTotalLength;uint8_t bNumInterfaces,bConfigurationValue,iConfiguration,bmAttributes,MaxPower; } IOUSBConfigurationDescriptor;
typedef struct __attribute__((packed)) IOUSBInterfaceDescriptor { uint8_t bLength,bDescriptorType,bInterfaceNumber,bAlternateSetting,bNumEndpoints,bInterfaceClass,bInterfaceSubClass,bInterfaceProtocol,iInterface; } IOUSBInterfaceDescriptor;
typedef struct __attribute__((packed)) IOUSBEndpointDescriptor { uint8_t bLength,bDescriptorType,bEndpointAddress,bmAttributes;uint16_t wMaxPacketSize;uint8_t bInterval; } IOUSBEndpointDescriptor;
typedef struct __attribute__((packed)) IOUSBHostCIMessage { uint32_t control,data0;uint64_t data1; } IOUSBHostCIMessage;
typedef uint32_t IOUSBHostCIDoorbell;
const IOUSBDescriptorHeader *IOUSBGetNextDescriptor(const IOUSBConfigurationDescriptor *,const IOUSBDescriptorHeader *);
const IOUSBDescriptorHeader *IOUSBGetNextDescriptorWithType(const IOUSBConfigurationDescriptor *,const IOUSBDescriptorHeader *,uint8_t);
const IOUSBDescriptorHeader *IOUSBGetNextAssociatedDescriptorWithType(const IOUSBConfigurationDescriptor *,const IOUSBDescriptorHeader *,const IOUSBDescriptorHeader *,uint8_t);
const IOUSBInterfaceDescriptor *IOUSBGetNextInterfaceDescriptor(const IOUSBConfigurationDescriptor *,const IOUSBDescriptorHeader *);
const IOUSBEndpointDescriptor *IOUSBGetNextEndpointDescriptor(const IOUSBConfigurationDescriptor *,const IOUSBInterfaceDescriptor *,const IOUSBDescriptorHeader *);
uint8_t IOUSBGetEndpointDirection(const IOUSBEndpointDescriptor *);
uint8_t IOUSBGetEndpointType(const IOUSBEndpointDescriptor *);
#ifdef __cplusplus
}
#endif
#ifdef __OBJC__
#import <Foundation/Foundation.h>
@class IOUSBHostObject,IOUSBHostControllerInterface;
typedef void (^IOUSBHostInterestHandler)(IOUSBHostObject *,uint32_t,void *);
typedef void (^IOUSBHostControllerInterfaceCommandHandler)(IOUSBHostControllerInterface *,IOUSBHostCIMessage);
typedef void (^IOUSBHostControllerInterfaceDoorbellHandler)(IOUSBHostControllerInterface *,IOUSBHostCIDoorbell *,uint32_t);
// Actual IOKit callback is void (*)(void *,io_service_t,uint32_t,void *).
typedef void (*VM27USBInterestCallback)(void *,uint32_t,uint32_t,void *);
@interface IOUSBHostObject : NSObject { @private uint8_t _vm27UnavailableStorage[88]; }
- (instancetype)initWithIOService:(uint32_t)service options:(NSUInteger)options queue:(dispatch_queue_t)queue error:(NSError **)error interestHandler:(IOUSBHostInterestHandler)handler;
- (instancetype)initWithIOService:(uint32_t)service queue:(dispatch_queue_t)queue error:(NSError **)error interestHandler:(IOUSBHostInterestHandler)handler;
- (void)destroy;
- (void)destroyWithOptions:(NSUInteger)options;
@property(readonly) uint32_t ioService;
@property(readonly) dispatch_queue_t queue;
@end
@interface IOUSBHostDevice : IOUSBHostObject { @private uint8_t _vm27DeviceStorage[8]; }
+ (CFMutableDictionaryRef)createMatchingDictionaryWithVendorID:(NSNumber *)vendorID productID:(NSNumber *)productID bcdDevice:(NSNumber *)bcdDevice deviceClass:(NSNumber *)deviceClass deviceSubclass:(NSNumber *)deviceSubclass deviceProtocol:(NSNumber *)deviceProtocol speed:(NSNumber *)speed productIDArray:(NSArray *)array;
- (BOOL)configureWithValue:(NSUInteger)value matchInterfaces:(BOOL)match error:(NSError **)error;
- (BOOL)configureWithValue:(NSUInteger)value error:(NSError **)error;
- (BOOL)resetWithError:(NSError **)error;
@property(readonly) const IOUSBConfigurationDescriptor *configurationDescriptor;
@end
@interface IOUSBHostInterface : IOUSBHostObject { @private uint8_t _vm27InterfaceStorage[24]; }
+ (CFMutableDictionaryRef)createMatchingDictionaryWithVendorID:(NSNumber *)vendorID productID:(NSNumber *)productID bcdDevice:(NSNumber *)bcdDevice interfaceNumber:(NSNumber *)number configurationValue:(NSNumber *)value interfaceClass:(NSNumber *)cls interfaceSubclass:(NSNumber *)subcls interfaceProtocol:(NSNumber *)protocol speed:(NSNumber *)speed productIDArray:(NSArray *)array;
- (BOOL)selectAlternateSetting:(NSUInteger)value error:(NSError **)error;
- (id)copyPipeWithAddress:(NSUInteger)address error:(NSError **)error;
- (BOOL)setIdleTimeout:(NSTimeInterval)timeout error:(NSError **)error;
@property(readonly) NSTimeInterval idleTimeout;
@property(readonly) const IOUSBConfigurationDescriptor *configurationDescriptor;
@property(readonly) const IOUSBInterfaceDescriptor *interfaceDescriptor;
@end
@interface IOUSBHostControllerInterface : NSObject { @private uint8_t _vm27ControllerStorage[312]; }
- (instancetype)initWithCapabilities:(NSData *)capabilities queue:(dispatch_queue_t)queue interruptRateHz:(NSUInteger)rate error:(NSError **)error commandHandler:(IOUSBHostControllerInterfaceCommandHandler)command doorbellHandler:(IOUSBHostControllerInterfaceDoorbellHandler)doorbell interestHandler:(VM27USBInterestCallback)interest;
- (void)destroy;
- (BOOL)enqueueInterrupt:(const IOUSBHostCIMessage *)message error:(NSError **)error;
- (BOOL)enqueueInterrupt:(const IOUSBHostCIMessage *)message expedite:(BOOL)expedite error:(NSError **)error;
- (BOOL)enqueueInterrupts:(const IOUSBHostCIMessage *)messages count:(NSUInteger)count error:(NSError **)error;
- (BOOL)enqueueInterrupts:(const IOUSBHostCIMessage *)messages count:(NSUInteger)count expedite:(BOOL)expedite error:(NSError **)error;
- (id)getPortStateMachineForCommand:(const IOUSBHostCIMessage *)command error:(NSError **)error;
- (id)getPortStateMachineForPort:(NSUInteger)port error:(NSError **)error;
- (const IOUSBHostCIMessage *)capabilitiesForPort:(NSUInteger)port;
- (NSString *)descriptionForMessage:(const IOUSBHostCIMessage *)message;
@property(readonly) dispatch_queue_t queue;
@property(nonatomic) NSUInteger interruptRateHz;
@property(readonly) id controllerStateMachine;
@property(readonly) const IOUSBHostCIMessage *capabilities;
@property(readonly) NSUUID *uuid;
@end
@interface IOUSBHostCIDeviceStateMachine : NSObject { @private uint8_t _vm27DeviceStateStorage[32]; }
- (instancetype)initWithInterface:(IOUSBHostControllerInterface *)interface command:(const IOUSBHostCIMessage *)command error:(NSError **)error;
- (BOOL)inspectCommand:(const IOUSBHostCIMessage *)command error:(NSError **)error;
- (BOOL)respondToCommand:(const IOUSBHostCIMessage *)command status:(int)status error:(NSError **)error;
- (BOOL)respondToCommand:(const IOUSBHostCIMessage *)command status:(int)status deviceAddress:(NSUInteger)address error:(NSError **)error;
@property(readonly) int deviceState;
@property(readonly) NSUInteger completeRoute,deviceAddress;
@property(readonly) IOUSBHostControllerInterface *controllerInterface;
@end
@interface IOUSBHostCIEndpointStateMachine : NSObject { @private uint8_t _vm27EndpointStateStorage[40]; }
- (instancetype)initWithInterface:(IOUSBHostControllerInterface *)interface command:(const IOUSBHostCIMessage *)command error:(NSError **)error;
- (BOOL)inspectCommand:(const IOUSBHostCIMessage *)command error:(NSError **)error;
- (BOOL)respondToCommand:(const IOUSBHostCIMessage *)command status:(int)status error:(NSError **)error;
- (BOOL)processDoorbell:(IOUSBHostCIDoorbell)doorbell error:(NSError **)error;
- (BOOL)enqueueTransferCompletionForMessage:(const IOUSBHostCIMessage *)message status:(int)status transferLength:(NSUInteger)length error:(NSError **)error;
@property(readonly) int endpointState;
@property(readonly) NSUInteger deviceAddress,endpointAddress;
@property(readonly) const IOUSBHostCIMessage *currentTransferMessage;
@property(readonly) IOUSBHostControllerInterface *controllerInterface;
@end
#endif
