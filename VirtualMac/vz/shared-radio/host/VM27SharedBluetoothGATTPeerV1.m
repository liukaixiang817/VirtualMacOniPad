#import "VM27SharedBluetoothGATTPeerV1.h"
#import <CoreBluetooth/CoreBluetooth.h>
#include <objc/message.h>
#include <errno.h>

static NSDictionary *failure(int code) {return @{@"ok":@NO,@"error":@(code)};}
static NSDictionary *nativeFailure(NSError *error) {
    if(!error)return @{@"ok":@YES};
    return @{@"ok":@NO,@"error":@(EIO),@"nativeError":@(error.code),
        @"ATTError":@([error.domain isEqual:CBATTErrorDomain])};
}
@interface VM27SharedBluetoothGATTPeerV1 () <CBCentralManagerDelegate,CBPeripheralDelegate> {
    NSUUID *_identifier;
    BOOL (^_permission)(void);
    CBCentralManager *_central;
    CBPeripheral *_peripheral;
    id _pairingAgent;
    BOOL _closed,_connecting,_ownsConnection,_requireExistingBond;
    uint64_t _generation,_nextAttribute;
    NSUInteger _discoveries;
    NSMutableDictionary<NSString *,id> *_attributes;
    NSMapTable<id,NSString *> *_attributeIDs;
    NSMutableDictionary<NSString *,NSMutableDictionary *> *_pending;
    void (^_connectCompletion)(NSDictionary *);
    void (^_pairCompletion)(NSDictionary *);
    NSString *_challengeID;
    NSInteger _challengeType;
}
- (void)beginConnect;
- (void)finishDiscovery;
- (BOOL)isPaired;
- (BOOL)hasExistingNativeBond;
- (void)completeKey:(NSString *)key result:(NSDictionary *)result;
- (void)finishPairing:(NSDictionary *)result;
@end

@implementation VM27SharedBluetoothGATTPeerV1
- (instancetype)initWithIdentifier:(NSUUID *)identifier newPairingPermission:(BOOL (^)(void))permission {
    if(!identifier||!permission)return nil;
    if((self=[super init])) {
        _identifier=identifier;_permission=[permission copy];
        _attributes=[NSMutableDictionary dictionary];_attributeIDs=[NSMapTable strongToStrongObjectsMapTable];
        _pending=[NSMutableDictionary dictionary];
    }
    return self;
}
- (void)connectWithCompletion:(void (^)(NSDictionary *))completion {
    NSAssert(NSThread.isMainThread,@"GATT owner queue");
    if(_closed||_central||!completion){if(completion)completion(failure(EALREADY));return;}
    _connectCompletion=[completion copy];_connecting=YES;
    uint64_t generation=++_generation;__weak typeof(self) weak=self;
    _central=[[CBCentralManager alloc]initWithDelegate:self queue:dispatch_get_main_queue()
        options:@{CBCentralManagerOptionShowPowerAlertKey:@NO}];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,30*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        typeof(self) owner=weak;if(owner&&!owner->_closed&&owner->_generation==generation&&owner->_connectCompletion) {
            void (^reply)(NSDictionary *)=owner->_connectCompletion;owner->_connectCompletion=nil;
            reply(failure(ETIMEDOUT));[owner invalidate];
        }
    });
}
- (void)connectBondedWithCompletion:(void (^)(NSDictionary *))completion {
    _requireExistingBond=YES;[self connectWithCompletion:completion];
}
- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    if(_closed||central!=_central)return;
    if(central.state==CBManagerStatePoweredOn)[self beginConnect];
    else if(central.state!=CBManagerStateUnknown&&central.state!=CBManagerStateResetting) {
        if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(failure(ENETDOWN));}
        [self invalidate];
    }
}
- (void)beginConnect {
    if(_closed||!_connecting||_peripheral)return;
    // Retrieve the actual peer observed by the scanning central, using this
    // connection's own central. No address or invented service is substituted.
    NSArray *peers=[_central retrievePeripheralsWithIdentifiers:@[_identifier]];
    for(CBPeripheral *peer in peers)if([peer.identifier isEqual:_identifier]){_peripheral=peer;break;}
    if(!_peripheral){if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(failure(ENOENT));}[self invalidate];return;}
    if(_requireExistingBond&&![self hasExistingNativeBond]) {
        if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(failure(EPERM));}
        [self invalidate];return;
    }
    _peripheral.delegate=self;_ownsConnection=YES;
    [_central connectPeripheral:_peripheral options:@{}];
}
- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral {
    if(_closed||central!=_central||peripheral!=_peripheral)return;
    _connecting=NO;[_peripheral discoverServices:nil];
}
- (void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
    if(central!=_central||peripheral!=_peripheral||_closed)return;
    if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(error?nativeFailure(error):failure(ENOTCONN));}
    [self invalidate];
}
- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
    if(central!=_central||peripheral!=_peripheral||_closed)return;
    if(self.notificationHandler)self.notificationHandler(@{@"event":@"disconnected",@"nativeError":@(error.code)});
    [self invalidate];
}
- (NSString *)registerAttribute:(id)attribute {
    NSString *identifier=[_attributeIDs objectForKey:attribute];
    if(!identifier&&_attributes.count<4096) {
        identifier=[NSString stringWithFormat:@"a%llu",(unsigned long long)++_nextAttribute];
        _attributes[identifier]=attribute;[_attributeIDs setObject:identifier forKey:attribute];
    }
    return identifier;
}
- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
    if(_closed||peripheral!=_peripheral)return;
    if(error||peripheral.services.count>128){if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(error?nativeFailure(error):failure(E2BIG));}[self invalidate];return;}
    for(CBService *service in peripheral.services) {
        [self registerAttribute:service];++_discoveries;[peripheral discoverCharacteristics:nil forService:service];
    }
    [self finishDiscovery];
}
- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(NSError *)error {
    if(_closed||peripheral!=_peripheral)return;
    if(error){if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(nativeFailure(error));}[self invalidate];return;}
    if(_discoveries)--_discoveries;
    for(CBCharacteristic *characteristic in service.characteristics) {
        if(![self registerAttribute:characteristic]){[self invalidate];return;}
        ++_discoveries;[peripheral discoverDescriptorsForCharacteristic:characteristic];
    }
    [self finishDiscovery];
}
- (void)peripheral:(CBPeripheral *)peripheral didDiscoverDescriptorsForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
    if(_closed||peripheral!=_peripheral)return;
    if(error){if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(nativeFailure(error));}[self invalidate];return;}
    if(_discoveries)--_discoveries;
    for(CBDescriptor *descriptor in characteristic.descriptors)if(![self registerAttribute:descriptor]){[self invalidate];return;}
    [self finishDiscovery];
}
- (id)pairingAgent {
    if(_pairingAgent)return _pairingAgent;
    SEL selector=NSSelectorFromString(@"sharedPairingAgent");
    if([_central respondsToSelector:selector])_pairingAgent=((id(*)(id,SEL))objc_msgSend)(_central,selector);
    return _pairingAgent;
}
- (BOOL)isPaired {
    id agent=[self pairingAgent];SEL selector=NSSelectorFromString(@"isPeerPaired:");
    return _peripheral&&[agent respondsToSelector:selector]&&((BOOL(*)(id,SEL,id))objc_msgSend)(agent,selector,_peripheral);
}
- (BOOL)hasExistingNativeBond {
    id agent=[self pairingAgent];SEL retrieve=NSSelectorFromString(@"retrievePairedPeers");
    if(![agent respondsToSelector:retrieve])return NO;
    id peers=((id(*)(id,SEL))objc_msgSend)(agent,retrieve);
    if(![peers isKindOfClass:NSArray.class])return NO;
    for(CBPeer *peer in peers)if([peer isKindOfClass:CBPeer.class]&&[peer.identifier isEqual:_identifier])return YES;
    return NO;
}
- (void)finishDiscovery {
    if(_closed||_discoveries||!_connectCompletion)return;
    NSMutableArray *services=[NSMutableArray array];
    for(CBService *service in _peripheral.services) {
        NSMutableArray *characteristics=[NSMutableArray array];
        for(CBCharacteristic *characteristic in service.characteristics) {
            NSMutableArray *descriptors=[NSMutableArray array];
            for(CBDescriptor *descriptor in characteristic.descriptors)
                [descriptors addObject:@{@"id":[_attributeIDs objectForKey:descriptor],@"uuid":descriptor.UUID.UUIDString}];
            [characteristics addObject:@{@"id":[_attributeIDs objectForKey:characteristic],@"uuid":characteristic.UUID.UUIDString,
                @"properties":@(characteristic.properties),@"descriptors":descriptors}];
        }
        [services addObject:@{@"id":[_attributeIDs objectForKey:service],@"uuid":service.UUID.UUIDString,
            @"primary":@(service.isPrimary),@"characteristics":characteristics}];
    }
    void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;
    reply(@{@"ok":@YES,@"services":services,@"paired":[NSNumber numberWithBool:[self isPaired]],@"name":_peripheral.name?:@""});
}
- (void)completeKey:(NSString *)key result:(NSDictionary *)result {
    NSMutableDictionary *item=_pending[key];if(!item)return;
    void (^reply)(NSDictionary *)=item[@"completion"];[_pending removeObjectForKey:key];reply(result);
}
- (void)performOperation:(NSDictionary *)operation completion:(void (^)(NSDictionary *))completion {
    NSAssert(NSThread.isMainThread,@"GATT owner queue");
    if(!completion)return;
    if(_closed||_peripheral.state!=CBPeripheralStateConnected){completion(failure(ENOTCONN));return;}
    NSString *kind=[operation[@"operation"]isKindOfClass:NSString.class]?operation[@"operation"]:nil;
    if([kind isEqual:@"respondPairing"]) {
        if(!_pairCompletion||!_challengeID||![operation[@"challenge"]isEqual:_challengeID]){completion(failure(ENOENT));return;}
        if(!_permission||!_permission()){[self finishPairing:failure(EPERM)];completion(failure(EPERM));return;}
        NSNumber *accept=operation[@"accept"],*passkey=operation[@"passkey"];
        if(![accept isKindOfClass:NSNumber.class]||(passkey&&(![passkey isKindOfClass:NSNumber.class]||
           passkey.longLongValue<0||passkey.longLongValue>999999||passkey.doubleValue!=(double)passkey.longLongValue))){completion(failure(EINVAL));return;}
        SEL respond=NSSelectorFromString(@"respondToPairingRequest:type:accept:data:");
        if(![_pairingAgent respondsToSelector:respond]){completion(failure(ENOTSUP));return;}
        // This key was audited in this iPad's own CBConnection response path.
        // The guest supplies the response; the host never guesses a code.
        NSDictionary *data=passkey?@{@"kCBMsgArgPairingPasskey":passkey}:@{};
        NSInteger type=_challengeType;_challengeID=nil;
        ((void(*)(id,SEL,id,NSInteger,BOOL,id))objc_msgSend)(_pairingAgent,respond,_peripheral,type,accept.boolValue,data);
        completion(@{@"ok":@YES});if(!accept.boolValue)[self finishPairing:failure(ECANCELED)];return;
    }
    if([kind isEqual:@"pair"]) {
        if([self isPaired]){completion(@{@"ok":@YES,@"paired":@YES,@"existingBond":@YES});return;}
        if(_pairCompletion){completion(failure(EBUSY));return;}
        if(!_permission||!_permission()){completion(failure(EPERM));return;}
        id agent=[self pairingAgent];SEL get=NSSelectorFromString(@"delegate"),set=NSSelectorFromString(@"setDelegate:"),pair=NSSelectorFromString(@"pairPeer:");
        if(![agent respondsToSelector:get]||![agent respondsToSelector:set]||![agent respondsToSelector:pair]){completion(failure(ENOTSUP));return;}
        id delegate=((id(*)(id,SEL))objc_msgSend)(agent,get);
        if(delegate&&delegate!=self){completion(failure(EBUSY));return;}
        _pairCompletion=[completion copy];((void(*)(id,SEL,id))objc_msgSend)(agent,set,self);
        uint64_t generation=_generation;__weak typeof(self) weak=self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,85*NSEC_PER_SEC),dispatch_get_main_queue(),^{
            typeof(self) owner=weak;if(owner&&!owner->_closed&&owner->_generation==generation&&owner->_pairCompletion)
                [owner finishPairing:failure(ETIMEDOUT)];
        });
        ((void(*)(id,SEL,id))objc_msgSend)(agent,pair,_peripheral);return;
    }
    NSString *key=[operation[@"attribute"]isKindOfClass:NSString.class]?operation[@"attribute"]:nil;
    id attribute=key?_attributes[key]:nil;
    if(!attribute||_pending.count>=64){completion(failure(attribute?ENOBUFS:ENOENT));return;}
    if(_pending[key]){completion(failure(EBUSY));return;}
    NSData *value=operation[@"value"];
    BOOL characteristic=[attribute isKindOfClass:CBCharacteristic.class],descriptor=[attribute isKindOfClass:CBDescriptor.class];
    if(([kind isEqual:@"read"]&&!(characteristic||descriptor))||
       ([kind isEqual:@"write"]&&(!characteristic||![value isKindOfClass:NSData.class]||value.length>512))||
       ([kind isEqual:@"notify"]&&!characteristic)||
       ![@[@"read",@"write",@"notify"]containsObject:kind?:@""]){completion(failure(EINVAL));return;}
    NSObject *token=[NSObject new];_pending[key]=[@{@"completion":[completion copy],@"token":token,@"operation":kind}mutableCopy];
    uint64_t generation=_generation;__weak typeof(self) weak=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        typeof(self) owner=weak;if(owner&&!owner->_closed&&owner->_generation==generation&&owner->_pending[key][@"token"]==token) {
            [owner completeKey:key result:failure(ETIMEDOUT)];[owner invalidate];
        }
    });
    if([kind isEqual:@"read"]) {
        if(characteristic)[_peripheral readValueForCharacteristic:attribute];else [_peripheral readValueForDescriptor:attribute];
    } else if([kind isEqual:@"write"]) {
        BOOL response=[operation[@"withResponse"]boolValue];
        if(value.length>[_peripheral maximumWriteValueLengthForType:response?CBCharacteristicWriteWithResponse:CBCharacteristicWriteWithoutResponse]){[self completeKey:key result:failure(EMSGSIZE)];return;}
        [_peripheral writeValue:value forCharacteristic:attribute type:response?CBCharacteristicWriteWithResponse:CBCharacteristicWriteWithoutResponse];
        if(!response)[self completeKey:key result:@{@"ok":@YES}];
    } else [_peripheral setNotifyValue:[operation[@"enabled"]boolValue] forCharacteristic:attribute];
}
- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
    if(_closed||peripheral!=_peripheral)return;NSString *key=[_attributeIDs objectForKey:characteristic];if(!key)return;
    if([_pending[key][@"operation"]isEqual:@"read"])[self completeKey:key result:error?nativeFailure(error):@{@"ok":@YES,@"value":characteristic.value?:[NSData data]}];
    if(characteristic.isNotifying&&self.notificationHandler)self.notificationHandler(error?@{@"event":@"notification-error",@"attribute":key,@"error":@(error.code)}:
        @{@"event":@"value",@"attribute":key,@"value":characteristic.value?:[NSData data]});
}
- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForDescriptor:(CBDescriptor *)descriptor error:(NSError *)error {
    if(_closed||peripheral!=_peripheral)return;NSString *key=[_attributeIDs objectForKey:descriptor];if(!key)return;
    if(error){[self completeKey:key result:nativeFailure(error)];return;}
    id value=descriptor.value;NSData *data=nil;
    if([value isKindOfClass:NSData.class])data=value;
    else if([value isKindOfClass:NSString.class])data=[value dataUsingEncoding:NSUTF8StringEncoding];
    else if([value isKindOfClass:NSNumber.class]){uint16_t number=[value unsignedShortValue];uint8_t bytes[]={(uint8_t)number,(uint8_t)(number>>8)};data=[NSData dataWithBytes:bytes length:2];}
    [self completeKey:key result:data?@{@"ok":@YES,@"value":data}:failure(EPROTONOSUPPORT)];
}
- (void)peripheral:(CBPeripheral *)peripheral didWriteValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
    if(!_closed&&peripheral==_peripheral){NSString *key=[_attributeIDs objectForKey:characteristic];if(key&&[_pending[key][@"operation"]isEqual:@"write"])[self completeKey:key result:nativeFailure(error)];}
}
- (void)peripheral:(CBPeripheral *)peripheral didUpdateNotificationStateForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
    if(!_closed&&peripheral==_peripheral){NSString *key=[_attributeIDs objectForKey:characteristic];if(key&&[_pending[key][@"operation"]isEqual:@"notify"])[self completeKey:key result:error?nativeFailure(error):@{@"ok":@YES,@"enabled":@(characteristic.isNotifying)}];}
}
- (void)finishPairing:(NSDictionary *)result {
    if(!_pairCompletion)return;
    void (^reply)(NSDictionary *)=_pairCompletion;_pairCompletion=nil;_challengeID=nil;
    SEL get=NSSelectorFromString(@"delegate"),set=NSSelectorFromString(@"setDelegate:");
    if([_pairingAgent respondsToSelector:get]&&((id(*)(id,SEL))objc_msgSend)(_pairingAgent,get)==self)
        ((void(*)(id,SEL,id))objc_msgSend)(_pairingAgent,set,nil);
    reply(result);
}
- (void)pairingAgent:(id)agent peerDidCompletePairing:(CBPeer *)peer {
    if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self pairingAgent:agent peerDidCompletePairing:peer];});return;}
    if(!_closed&&agent==_pairingAgent&&[peer.identifier isEqual:_identifier]&&_pairCompletion)
        [self finishPairing:[self isPaired]?@{@"ok":@YES,@"paired":@YES}:failure(EPROTO)];
}
- (void)pairingAgent:(id)agent peerDidFailToCompletePairing:(CBPeer *)peer error:(NSError *)error {
    if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self pairingAgent:agent peerDidFailToCompletePairing:peer error:error];});return;}
    if(!_closed&&agent==_pairingAgent&&[peer.identifier isEqual:_identifier]&&_pairCompletion)[self finishPairing:error?nativeFailure(error):failure(EACCES)];
}
- (void)pairingAgent:(id)agent peerDidRequestPairing:(CBPeer *)peer type:(NSInteger)type passkey:(id)passkey {
    if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self pairingAgent:agent peerDidRequestPairing:peer type:type passkey:passkey];});return;}
    if(_closed||agent!=_pairingAgent||![peer.identifier isEqual:_identifier]||!_pairCompletion)return;
    SEL respond=NSSelectorFromString(@"respondToPairingRequest:type:accept:data:");
    BOOL permitted=_permission&&_permission();
    if(type==0&&[agent respondsToSelector:respond]) {
        ((void(*)(id,SEL,id,NSInteger,BOOL,id))objc_msgSend)(agent,respond,peer,type,permitted,@{});
        if(!permitted)[self finishPairing:failure(EPERM)];return;
    }
    // Code/PIN challenges must reach the guest; never guess a PIN or approve
    // numeric comparison. The opaque value is transported in memory only.
    if(permitted&&self.pairingChallengeHandler) {
        _challengeID=NSUUID.UUID.UUIDString;_challengeType=type;
        NSMutableDictionary *challenge=[@{@"challenge":_challengeID,@"type":@(type)}mutableCopy];
        if([passkey isKindOfClass:NSNumber.class]||([passkey isKindOfClass:NSString.class]&&[passkey length]<=32))challenge[@"value"]=passkey;
        self.pairingChallengeHandler(challenge);
    } else [self finishPairing:failure(permitted?ENOTSUP:EPERM)];
}
- (void)invalidate {
    NSAssert(NSThread.isMainThread,@"GATT owner queue");
    if(_closed)return;_closed=YES;++_generation;
    if(_connectCompletion){void (^reply)(NSDictionary *)=_connectCompletion;_connectCompletion=nil;reply(failure(ECANCELED));}
    [self finishPairing:failure(ECANCELED)];
    for(NSString *key in [_pending.allKeys copy])[self completeKey:key result:failure(ECANCELED)];
    _peripheral.delegate=nil;
    if(_ownsConnection&&_peripheral){_ownsConnection=NO;[_central cancelPeripheralConnection:_peripheral];}
    _central.delegate=nil;_central=nil;_permission=nil;
    self.notificationHandler=nil;self.pairingChallengeHandler=nil;
    [_attributes removeAllObjects];[_attributeIDs removeAllObjects];
}
- (void)dealloc {[self invalidate];}
@end
