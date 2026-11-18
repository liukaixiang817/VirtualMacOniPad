#import "VM27ExclusiveBluetoothHOGPV1.h"
#import "../host/VM27SharedBluetoothGATTPeerV1.h"
#import <IOKit/hidsystem/IOHIDUserDevice.h>
#include <mach/mach_time.h>
#include <errno.h>

@class VM27ExclusiveBluetoothHOGPV1;
@interface VM27HOGPServiceV1 : NSObject {
@public IOHIDUserDeviceRef device;
}
@property(nonatomic,strong) NSDictionary *serviceDefinition;
@property(nonatomic,strong) NSData *reportMap;
@property(nonatomic,strong) NSMutableDictionary<NSString *,NSDictionary *> *reports;
@property(nonatomic,weak) VM27ExclusiveBluetoothHOGPV1 *owner;
- (void)invalidate;
@end
@interface VM27ExclusiveBluetoothHOGPV1 ()
@property(nonatomic,strong) NSUUID *identifier;
@property(nonatomic,strong) VM27SharedBluetoothGATTPeerV1 *peer;
@property(nonatomic,strong) NSMutableArray<VM27HOGPServiceV1 *> *services;
@property(nonatomic,strong) NSMutableArray<NSDictionary *> *tasks;
@property(nonatomic,strong) NSDictionary *pnp;
@property(nonatomic,copy) NSString *product;
@property(nonatomic,strong) dispatch_queue_t hidQueue;
@property(nonatomic,readwrite,getter=isClosed) BOOL closed;
@property(nonatomic) BOOL configured;
@property(nonatomic) NSUInteger pendingSubscriptions;
@property(nonatomic) unsigned long long reportsReceived;
@property(nonatomic) unsigned long long reportsDelivered;
- (void)emit:(NSString *)stage error:(NSInteger)error;
- (void)nextTask;
- (void)createDevices;
- (IOReturn)requestReportForService:(VM27HOGPServiceV1 *)service type:(IOHIDReportType)type reportID:(uint32_t)reportID bytes:(uint8_t *)bytes length:(CFIndex *)length write:(BOOL)write;
@end
@implementation VM27HOGPServiceV1
- (void)invalidate {if(device){IOHIDUserDeviceCancel(device);device=NULL;}}
- (void)dealloc {[self invalidate];}
@end

static BOOL uuidIs(NSDictionary *attribute,NSString *uuid){return [attribute[@"uuid"]caseInsensitiveCompare:uuid]==NSOrderedSame;}
static NSDictionary *attribute(NSArray *attributes,NSString *uuid){for(NSDictionary *item in attributes)if(uuidIs(item,uuid))return item;return nil;}
static NSString *reportKey(unsigned type,unsigned reportID){return [NSString stringWithFormat:@"%u:%u",type,reportID];}

@implementation VM27ExclusiveBluetoothHOGPV1
- (instancetype)initWithIdentifier:(NSUUID *)identifier {
    if(!identifier)return nil;
    if((self=[super init])){_identifier=identifier;_services=[NSMutableArray array];_tasks=[NSMutableArray array];_pnp=@{};_hidQueue=dispatch_queue_create("com.virtualmac.exclusive-hogp-reports",DISPATCH_QUEUE_SERIAL);}
    return self;
}
- (void)emit:(NSString *)stage error:(NSInteger)error {
    NSUInteger created=0;for(VM27HOGPServiceV1 *service in self.services)if(service->device)++created;
    if(self.statusHandler)self.statusHandler(@{@"stage":stage,@"error":@(error),@"nativeHIDDevices":@(created),
        @"inputReportsReceived":@(self.reportsReceived),@"inputReportsDelivered":@(self.reportsDelivered),@"nativeHIDOnly":@(self.nativeHIDOnly),@"firstPairingRequested":@NO});
}
- (void)start {
    NSAssert(NSThread.isMainThread,@"HOGP owner queue");if(self.closed||self.peer)return;
    self.peer=[[VM27SharedBluetoothGATTPeerV1 alloc]initWithIdentifier:self.identifier newPairingPermission:^BOOL{return NO;}];
    __weak typeof(self) weak=self;
    self.peer.notificationHandler=^(NSDictionary *event){
        typeof(self) owner=weak;if(!owner||owner.closed)return;
        if([event[@"event"]isEqual:@"disconnected"]){[owner emit:@"native-link-disconnected" error:[event[@"nativeError"]integerValue]];[owner invalidate];return;}
        if(![event[@"event"]isEqual:@"value"])return;
        NSString *key=event[@"attribute"];NSData *data=event[@"value"];if(![data isKindOfClass:NSData.class]||data.length>512)return;
        for(VM27HOGPServiceV1 *service in owner.services){NSDictionary *route=service.reports[key];
            if(!route||[route[@"type"]unsignedIntValue]!=1||!service->device)continue;
            uint8_t reportID=[route[@"reportID"]unsignedCharValue];NSMutableData *report=[NSMutableData data];
            if(reportID)[report appendBytes:&reportID length:1];[report appendData:data];++owner.reportsReceived;
            IOReturn result=IOHIDUserDeviceHandleReportWithTimeStamp(service->device,mach_absolute_time(),report.bytes,(CFIndex)report.length);
            if(result==kIOReturnSuccess)++owner.reportsDelivered;
            if(owner.reportsReceived<=3||result||owner.reportsReceived%100==0)[owner emit:@"native-hid-input" error:result];
        }
    };
    [self.peer connectBondedWithCompletion:^(NSDictionary *result){
        typeof(self) owner=weak;if(!owner||owner.closed)return;
        if(![result[@"ok"]boolValue]){[owner emit:@"bonded-gatt-connect-failed" error:[result[@"error"]integerValue]];[owner invalidate];return;}
        owner.product=[result[@"name"]isKindOfClass:NSString.class]?result[@"name"]:@"Bluetooth HID";
        if(owner.nativeHIDOnly){[owner emit:@"native-profile-connection-held" error:0];return;}
        NSArray *all=result[@"services"];
        for(NSDictionary *service in all){
            if(uuidIs(service,@"180A")){
                NSDictionary *pnp=attribute(service[@"characteristics"],@"2A50");
                if(pnp)[owner.tasks addObject:@{@"kind":@"pnp",@"attribute":pnp[@"id"]}];
            }
            if(!uuidIs(service,@"1812"))continue;
            if(owner.services.count>=8){[owner emit:@"too-many-hid-services" error:E2BIG];[owner invalidate];return;}
            VM27HOGPServiceV1 *hid=[VM27HOGPServiceV1 new];hid.serviceDefinition=service;hid.reports=[NSMutableDictionary dictionary];hid.owner=owner;
            NSDictionary *map=attribute(service[@"characteristics"],@"2A4B");
            if(!map){[owner emit:@"missing-report-map" error:EPROTO];[owner invalidate];return;}
            [owner.services addObject:hid];[owner.tasks addObject:@{@"kind":@"map",@"attribute":map[@"id"],@"service":hid}];
            for(NSDictionary *characteristic in service[@"characteristics"]){
                if(!uuidIs(characteristic,@"2A4D"))continue;
                NSDictionary *reference=attribute(characteristic[@"descriptors"],@"2908");
                if(!reference){[owner emit:@"missing-report-reference" error:EPROTO];[owner invalidate];return;}
                [owner.tasks addObject:@{@"kind":@"reference",@"attribute":reference[@"id"],@"report":characteristic,@"service":hid}];
            }
            NSDictionary *mode=attribute(service[@"characteristics"],@"2A4E");
            if(mode)[owner.tasks addObject:@{@"kind":@"mode",@"attribute":mode[@"id"],@"properties":mode[@"properties"]}];
        }
        if(!owner.services.count){[owner emit:@"no-hid-service" error:ENOTSUP];[owner invalidate];return;}
        [owner emit:@"reading-native-hid-description" error:0];[owner nextTask];
    }];
}
- (void)nextTask {
    if(self.closed)return;
    if(!self.tasks.count){[self createDevices];return;}
    NSDictionary *task=self.tasks.firstObject;[self.tasks removeObjectAtIndex:0];NSString *kind=task[@"kind"];
    NSMutableDictionary *operation=[@{@"operation":@"read",@"attribute":task[@"attribute"]}mutableCopy];
    if([kind isEqual:@"mode"]){uint8_t value=1;operation[@"operation"]=@"write";operation[@"value"]=[NSData dataWithBytes:&value length:1];operation[@"withResponse"]=@(([task[@"properties"]unsignedIntValue]&4)==0);}
    __weak typeof(self) weak=self;
    [self.peer performOperation:operation completion:^(NSDictionary *result){
        typeof(self) owner=weak;if(!owner||owner.closed)return;NSData *data=result[@"value"];
        if(![result[@"ok"]boolValue]){
            if([kind isEqual:@"pnp"]){[owner nextTask];return;}
            [owner emit:[@"native-hid-description-failed-"stringByAppendingString:kind] error:[result[@"nativeError"]integerValue]?:[result[@"error"]integerValue]];[owner invalidate];return;
        }
        VM27HOGPServiceV1 *service=task[@"service"];
        if([kind isEqual:@"pnp"]&&data.length==7){const uint8_t *b=data.bytes;owner.pnp=@{@"VendorID":@(b[1]|b[2]<<8),@"ProductID":@(b[3]|b[4]<<8),@"VersionNumber":@(b[5]|b[6]<<8)};}
        else if([kind isEqual:@"map"]){
            if(data.length<4||data.length>4096){[owner emit:@"invalid-report-map-size" error:EPROTO];[owner invalidate];return;}service.reportMap=data;
        }else if([kind isEqual:@"reference"]){
            if(data.length!=2||((const uint8_t *)data.bytes)[1]<1||((const uint8_t *)data.bytes)[1]>3){[owner emit:@"invalid-report-reference" error:EPROTO];[owner invalidate];return;}
            const uint8_t *b=data.bytes;NSDictionary *characteristic=task[@"report"];
            for(NSDictionary *existing in service.reports.allValues)if([existing[@"reportID"]unsignedIntValue]==b[0]&&[existing[@"type"]unsignedIntValue]==b[1]){[owner emit:@"duplicate-report-reference" error:EPROTO];[owner invalidate];return;}
            service.reports[characteristic[@"id"]]=@{@"reportID":@(b[0]),@"type":@(b[1]),@"properties":characteristic[@"properties"],@"attribute":characteristic[@"id"]};
        }
        [owner nextTask];
    }];
}
- (void)createDevices {
    if(self.closed||self.configured)return;self.configured=YES;__weak typeof(self) weak=self;
    for(VM27HOGPServiceV1 *service in self.services){
        NSMutableDictionary *properties=[self.pnp mutableCopy];properties[@kIOHIDReportDescriptorKey]=service.reportMap;
        properties[@kIOHIDProductKey]=self.product;properties[@kIOHIDTransportKey]=@"Bluetooth";
        properties[@kIOHIDUniqueIDKey]=[NSString stringWithFormat:@"VirtualMac-HOGP-%@-%@",self.identifier.UUIDString,service.serviceDefinition[@"id"]];
        properties[@"VirtualMacNativeHOGPV1"]=@YES;properties[@"HIDDefaultBehavior"]=@"";
        IOHIDUserDeviceRef device=IOHIDUserDeviceCreateWithProperties(kCFAllocatorDefault,(__bridge CFDictionaryRef)properties,IOHIDUserDeviceOptionsCreateOnActivate);
        if(!device){[self emit:@"native-hid-create-failed" error:EPERM];[self invalidate];return;}
        service->device=device;__weak VM27HOGPServiceV1 *weakService=service;
        IOHIDUserDeviceSetDispatchQueue(device,self.hidQueue);
        IOHIDUserDeviceSetCancelHandler(device,^{CFRelease(device);});
        IOHIDUserDeviceRegisterGetReportBlock(device,^IOReturn(IOHIDReportType type,uint32_t reportID,uint8_t *bytes,CFIndex *length){
            VM27HOGPServiceV1 *hid=weakService;typeof(self) owner=weak;
            if(!hid||!owner)return kIOReturnNotOpen;return [owner requestReportForService:hid type:type reportID:reportID bytes:bytes length:length write:NO];
        });
        IOHIDUserDeviceRegisterSetReportBlock(device,^IOReturn(IOHIDReportType type,uint32_t reportID,const uint8_t *bytes,CFIndex length){
            VM27HOGPServiceV1 *hid=weakService;typeof(self) owner=weak;
            if(!hid||!owner)return kIOReturnNotOpen;return [owner requestReportForService:hid type:type reportID:reportID bytes:(uint8_t *)bytes length:&length write:YES];
        });
        IOHIDUserDeviceActivate(device);
        for(NSDictionary *report in service.reports.allValues)if([report[@"type"]unsignedIntValue]==1){
            unsigned properties=[report[@"properties"]unsignedIntValue];if(!(properties&(16|32))){[self emit:@"input-report-cannot-notify" error:ENOTSUP];[self invalidate];return;}
            ++self.pendingSubscriptions;
            [self.peer performOperation:@{@"operation":@"notify",@"attribute":report[@"attribute"],@"enabled":@YES} completion:^(NSDictionary *result){
                typeof(self) owner=weak;if(!owner||owner.closed)return;
                if(![result[@"ok"]boolValue]){[owner emit:@"native-hid-subscription-failed" error:[result[@"nativeError"]integerValue]?:[result[@"error"]integerValue]];[owner invalidate];return;}
                if(owner.pendingSubscriptions)--owner.pendingSubscriptions;
                if(!owner.pendingSubscriptions)[owner emit:@"native-hid-ready" error:0];
            }];
        }
    }
    [self emit:@"native-hid-devices-created" error:0];
}
- (IOReturn)requestReportForService:(VM27HOGPServiceV1 *)service type:(IOHIDReportType)type reportID:(uint32_t)reportID bytes:(uint8_t *)bytes length:(CFIndex *)length write:(BOOL)write {
    // IOHID callbacks run on hidQueue. Native GATT stays on the main queue.
    // Only the IOKit callback waits, with a bounded timeout and copied data.
    if(!length||*length<0||*length>513||reportID>255||type>kIOHIDReportTypeFeature)return kIOReturnBadArgument;
    NSData *supplied=write?[NSData dataWithBytes:bytes length:(NSUInteger)*length]:nil;
    dispatch_semaphore_t ready=dispatch_semaphore_create(0);__block NSDictionary *reply=nil;
    dispatch_async(dispatch_get_main_queue(),^{
        if(self.closed){reply=@{@"ok":@NO};dispatch_semaphore_signal(ready);return;}
        NSDictionary *route=nil;NSString *key=reportKey((unsigned)type+1,reportID);
        for(NSDictionary *candidate in service.reports.allValues)if([reportKey([candidate[@"type"]unsignedIntValue],[candidate[@"reportID"]unsignedIntValue])isEqual:key]){route=candidate;break;}
        if(!route){reply=@{@"ok":@NO};dispatch_semaphore_signal(ready);return;}
        NSMutableDictionary *operation=[@{@"operation":write?@"write":@"read",@"attribute":route[@"attribute"]}mutableCopy];
        if(write){NSData *value=supplied;if(reportID&&value.length&&((const uint8_t *)value.bytes)[0]==reportID)value=[value subdataWithRange:NSMakeRange(1,value.length-1)];
            operation[@"value"]=value;operation[@"withResponse"]=@(([route[@"properties"]unsignedIntValue]&8)!=0);}
        [self.peer performOperation:operation completion:^(NSDictionary *result){reply=result;dispatch_semaphore_signal(ready);}];
    });
    if(dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)))return kIOReturnTimeout;
    if(![reply[@"ok"]boolValue])return kIOReturnError;
    if(!write){NSData *value=reply[@"value"];NSUInteger required=value.length+(reportID?1:0);
        if(![value isKindOfClass:NSData.class]||required>(NSUInteger)*length)return kIOReturnNoSpace;
        if(reportID)bytes[0]=(uint8_t)reportID;if(value.length)memcpy(bytes+(reportID?1:0),value.bytes,value.length);*length=(CFIndex)required;
    }
    return kIOReturnSuccess;
}
- (void)invalidate {
    if(self.closed)return;self.closed=YES;
    for(VM27HOGPServiceV1 *service in self.services)[service invalidate];
    self.peer.notificationHandler=nil;[self.peer invalidate];self.peer=nil;[self.tasks removeAllObjects];
}
- (void)dealloc {[self invalidate];}
@end
