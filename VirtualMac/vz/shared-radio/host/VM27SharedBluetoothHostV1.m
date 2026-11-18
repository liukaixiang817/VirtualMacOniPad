// Apple BTVC WebSocket/binary-plist discovery bridge. Only actual CoreBluetooth
// discoveries produce advertisements. CoreBluetooth UUIDs map to virtual radio
// addresses; they are never presented as the physical device's private address.
#import "VM27SharedBluetoothHostV1.h"
#import "VM27SharedBluetoothGATTPeerV1.h"
#import "VM27SharedBluetoothPeerWorkerV1.h"
#import <CoreBluetooth/CoreBluetooth.h>
#include <objc/message.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "../common/vm27_shared_radio_paths_v1.h"

static const char *SocketPath = VM27_SHARED_RADIO_BLE_SOCKET_V1;
static int nonblocking(int fd) {
    int flags=fcntl(fd,F_GETFL),one=1;
    return flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK) ||
        fcntl(fd,F_SETFD,FD_CLOEXEC) || setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
}
static void element(NSMutableData *output, uint8_t type, NSData *data) {
    if (!data.length || data.length>254 || output.length+data.length+2>229) return;
    uint8_t header[2]={(uint8_t)(data.length+1),type};
    [output appendBytes:header length:2]; [output appendData:data];
}
static NSData *littleUUID(CBUUID *uuid) {
    NSData *data=uuid.data;
    NSMutableData *little=[NSMutableData dataWithLength:data.length];
    for(NSUInteger i=0;i<data.length;++i)((uint8_t *)little.mutableBytes)[i]=((const uint8_t *)data.bytes)[data.length-1-i];
    return little;
}
static NSData *proxyAddress(NSUUID *identifier) {
    uuid_t bytes;[identifier getUUIDBytes:bytes];
    uint8_t first[CC_SHA256_DIGEST_LENGTH];CC_SHA256(bytes,sizeof(bytes),first);first[5]|=0xc0;
    // Keep the schema-2 hash namespace deterministic across launches. The
    // wire address itself is big endian (the native HCI builder reverses it),
    // so random-static bits belong in its FIRST byte. Retain the former last
    // byte bits too to minimize identity changes when upgrading the format.
    // This matches the live cache-isolation experiment; it is an owned virtual
    // address, never the physical peripheral's private or public radio address.
    const char name[]="VirtualMacBLEProxyCacheIsolationV1";
    NSMutableData *seed=[NSMutableData dataWithBytes:name length:sizeof(name)-1];
    [seed appendBytes:first length:6];
    // BTVC's address is NSData(6), matching native filter-accept-list keys.
    // Padding it to a UInt64 still renders an HCI report, but NSData(8) cannot
    // match the native six-byte key, so Create Connection never reaches its
    // Bonjour connection endpoint. Keep the six existing identity bytes.
    uint8_t hash[CC_SHA256_DIGEST_LENGTH],address[6]={0};
    CC_SHA256(seed.bytes,(CC_LONG)seed.length,hash);memcpy(address,hash,6);address[0]|=0xc0;address[5]|=0xc0;
    return [NSData dataWithBytes:address length:sizeof(address)];
}
static NSData *advertisingData(NSDictionary *data) {
    NSMutableData *payload=[NSMutableData data];
    // GAP flags describe this LE-only virtual proxy's discoverability. They
    // are not copied or asserted as the physical device's original RF flags.
    // The proxy becomes discoverable only for an actually connectable device.
    uint8_t flags=[data[CBAdvertisementDataIsConnectable]boolValue]?0x06:0x04;
    element(payload,1,[NSData dataWithBytes:&flags length:1]);
    NSString *name=data[CBAdvertisementDataLocalNameKey];
    if([name isKindOfClass:NSString.class]) {
        NSData *bytes=[name dataUsingEncoding:NSUTF8StringEncoding];
        if(bytes.length<=100)element(payload,9,bytes);
    }
    NSData *manufacturer=data[CBAdvertisementDataManufacturerDataKey];
    if([manufacturer isKindOfClass:NSData.class])element(payload,0xff,manufacturer);
    NSArray *services=data[CBAdvertisementDataServiceUUIDsKey];
    // A complete service list is one AD structure per UUID width. Emitting
    // multiple "complete" 16-bit lists can make a receiver replace HID with
    // the last service (for example Battery), hiding a real BLE mouse.
    for(NSNumber *width in @[@2,@4,@16]) {
        NSMutableData *list=[NSMutableData data];
        if([services isKindOfClass:NSArray.class])for(CBUUID *uuid in services)
            if([uuid isKindOfClass:CBUUID.class]&&uuid.data.length==width.unsignedIntegerValue)
                [list appendData:littleUUID(uuid)];
        element(payload,width.unsignedIntegerValue==2?3:width.unsignedIntegerValue==4?5:7,list);
    }
    NSDictionary *serviceData=data[CBAdvertisementDataServiceDataKey];
    if([serviceData isKindOfClass:NSDictionary.class])for(CBUUID *uuid in serviceData) {
        NSData *value=serviceData[uuid];
        if(![uuid isKindOfClass:CBUUID.class]||![value isKindOfClass:NSData.class])continue;
        uint8_t type=uuid.data.length==2?0x16:uuid.data.length==4?0x20:uuid.data.length==16?0x21:0;
        if(type) {NSMutableData *item=[littleUUID(uuid) mutableCopy];[item appendData:value];element(payload,type,item);}
    }
    return payload;
}
static NSArray<NSData *> *legacyAdvertisingPayloads(NSDictionary *data) {
    NSData *combined=advertisingData(data);
    const uint8_t *bytes=combined.bytes;
    NSMutableArray<NSData *> *elements=[NSMutableArray array];
    for(NSUInteger at=0;at<combined.length;) {
        NSUInteger length=(NSUInteger)bytes[at]+1;
        if(length<2||length>combined.length-at)break;
        [elements addObject:[combined subdataWithRange:NSMakeRange(at,length)]];at+=length;
    }
    NSMutableData *advert=[NSMutableData data],*response=[NSMutableData data];
    BOOL connectable=[data[CBAdvertisementDataIsConnectable]boolValue];
    // CoreBluetooth merges ADV and SCAN_RSP. Its combined dictionary can exceed
    // 31 bytes even for an ordinary legacy mouse (the actual target was 32).
    // The guest's virtual HCI does not advertise extended-advertising support.
    // Reconstruct a legacy proxy, prioritizing discoverability and service UUIDs,
    // and put remaining whole AD structures in its scan response. Never emit a
    // >31-byte legacy report or silently switch to an unsupported extended one.
    for(unsigned priority=0;priority<3;++priority)for(NSData *item in elements) {
        const uint8_t *part=item.bytes;uint8_t type=part[1];
        unsigned rank=type==1?0:(type>=2&&type<=7)?1:2;
        if(rank!=priority)continue;
        NSMutableData *destination=advert.length+item.length<=31?advert:
            connectable&&response.length+item.length<=31?response:nil;
        if(destination){[destination appendData:item];continue;}
        if(type==9) {
            destination=connectable&&response.length<advert.length?response:advert;
            NSUInteger available=31-destination.length;
            if(available>2) {
                NSUInteger count=MIN(item.length-2,available-2);
                NSData *name=nil;
                while(count) {
                    name=[NSData dataWithBytes:part+2 length:count];
                    if([[NSString alloc]initWithData:name encoding:NSUTF8StringEncoding])break;
                    --count;
                }
                if(count)element(destination,8,name); // Honest shortened name.
            }
        }
        // Oversized manufacturer/service-data structures cannot be represented
        // by this legacy proxy. Do not fragment an AD structure into invalid AD.
    }
    return response.length?@[advert,response]:@[advert];
}

// A newly created physical bond needs an explicit native guest pairing
// operation. Discovery, ordinary Connect and a diagnostic URL do not issue
// this ticket. The eventual connection/SMP adapter must supply its validated
// guest Pairing Request and current connection generation here.
@interface VM27GuestPairingIntentV1 : NSObject {
    NSUUID *_peer;
    uint64_t _generation;
    double _deadline;
}
- (instancetype)initWithPeer:(NSUUID *)peer generation:(uint64_t)generation
    nativePairingRequest:(NSData *)request now:(double)now;
- (BOOL)permitsPeer:(NSUUID *)peer generation:(uint64_t)generation now:(double)now;
@end
@implementation VM27GuestPairingIntentV1
- (instancetype)initWithPeer:(NSUUID *)peer generation:(uint64_t)generation
    nativePairingRequest:(NSData *)request now:(double)now {
    // SMP Pairing Request (not peripheral Security Request or Pairing Response).
    if(!peer||!generation||request.length!=7||!isfinite(now)||now<0)return nil;
    const uint8_t *p=request.bytes;
    if(p[0]!=1||p[1]>4||p[2]>1||(p[3]&0xc0)||(p[3]&3)>1||p[4]<7||p[4]>16||
       (p[5]&0xf0)||(p[6]&0xf0))return nil;
    if((self=[super init])){_peer=peer;_generation=generation;_deadline=now+90;}
    return self;
}
- (BOOL)permitsPeer:(NSUUID *)peer generation:(uint64_t)generation now:(double)now {
    return generation&&generation==_generation&&[_peer isEqual:peer]&&isfinite(now)&&
        now>=_deadline-90&&now<_deadline;
}
@end

@interface VM27SharedBluetoothHostV1 () <CBCentralManagerDelegate,CBPeripheralDelegate> {
    int _listener, _client;
    dispatch_source_t _acceptSource, _readSource, _writeSource;
    NSMutableData *_input, *_output;
    CBCentralManager *_central;
    NSUUID *_serverID;
    NSMutableDictionary<NSUUID *,NSDictionary *> *_lastAdvertisement;
    NSMutableOrderedSet<NSUUID *> *_recentDevices;
    NSMutableData *_fragment;
    BOOL _started, _invalidated, _upgraded, _exclusiveLifecycleOnly;
    BOOL _acceptanceMouseSeen;
    CBPeripheral *_acceptanceMousePeripheral,*_gattProbePeripheral;
    double _acceptanceMouseLastSeen;
    void (^_gattProbeCompletion)(NSDictionary *);
    NSMutableDictionary *_gattProbeResult;
    BOOL _gattProbeUsed,_gattProbeOwnReference;
    BOOL _gattProbePairingAttempted;
    BOOL _gattProbePairingPromptAnswered;
    id _gattProbePairingAgent;
    CBCharacteristic *_gattProbeReportMap;
    uint64_t _gattProbeGeneration;
    VM27GuestPairingIntentV1 *_guestPairingIntent;
    __weak VM27SharedBluetoothHostV1 *_parent,*_guestPairingClient;
    NSMutableSet<VM27SharedBluetoothHostV1 *> *_children;
    NSMutableDictionary<NSUUID *,CBPeripheral *> *_observedPeripherals;
    CBPeripheral *_selectedPeripheral;
    VM27SharedBluetoothGATTPeerV1 *_gattPeer;
    VM27SharedBluetoothPeerWorkerV1 *_peerWorker;
    VM27GuestPairingIntentV1 *_connectionPairingIntent;
    NSString *_peerSession;
    NSMutableArray<NSDictionary *> *_queuedPackets;
    BOOL _peerReady;
    NSData *_remoteAddress,*_localAddress;
    __weak VM27SharedBluetoothHostV1 *_dataClient;
    BOOL _connectionOnly;
    unsigned _closeReports, _messageReports;
    unsigned _connectionPacketReports;
    uint64_t _generation, _published, _publishedHID;
    ino_t _socketInode;
}
- (void)acceptClients;
- (void)adoptClient:(int)fd;
- (BOOL)hasDiscoveryClient;
- (void)broadcastDiscovery:(NSData *)data;
- (void)observeMessage:(NSData *)message fromClient:(VM27SharedBluetoothHostV1 *)client;
- (void)readClient;
- (void)flushClient;
- (void)closeClient;
- (void)closeClientWithReason:(const char *)reason;
- (void)observeMessage:(NSData *)message;
- (void)scanIfReady;
- (void)sendOpcode:(uint8_t)opcode data:(NSData *)data;
- (void)finishGATTProbe:(NSString *)stage error:(NSError *)error;
- (BOOL)startGATTProbePairing;
- (void)requestNativeGATTProbePairing;
- (void)openGenericPeer:(NSDictionary *)parameters client:(VM27SharedBluetoothHostV1 *)client;
- (void)handleWorkerMessage:(NSDictionary *)message;
- (void)forwardPacket:(NSDictionary *)packet client:(VM27SharedBluetoothHostV1 *)client;
@end
@implementation VM27SharedBluetoothHostV1
- (instancetype)init {if((self=[super init])){_listener=-1;_client=-1;_serverID=NSUUID.UUID;}return self;}
- (NSDictionary *)startExclusiveControllerLifecycle {
    if(_started&&!_exclusiveLifecycleOnly)return @{@"ok":@NO};
    _exclusiveLifecycleOnly=YES;return [self start];
}
- (NSDictionary *)start {
    NSAssert(NSThread.isMainThread,@"Bluetooth bridge requires the owner queue");
    if(_invalidated)return @{ @"ok":@NO };
    if(!_started) {
        struct stat existing;
        if(!VM27SharedRadioPrepareHostDirectoryV1())return @{ @"ok":@NO };
        if(!lstat(SocketPath,&existing)) {
            if(!S_ISSOCK(existing.st_mode)||existing.st_uid!=geteuid()||existing.st_nlink!=1||
                (existing.st_mode&0777)!=0600)return @{ @"ok":@NO };
            if(unlink(SocketPath))return @{ @"ok":@NO };
        } else if(errno!=ENOENT)return @{ @"ok":@NO };
        int fd=socket(AF_UNIX,SOCK_STREAM,0);
        if(fd<0)return @{ @"ok":@NO };
        struct sockaddr_un address={0};address.sun_family=AF_UNIX;address.sun_len=sizeof(address);
        strlcpy(address.sun_path,SocketPath,sizeof(address.sun_path));
        if(nonblocking(fd)||bind(fd,(void *)&address,sizeof(address))||chmod(SocketPath,0600)||listen(fd,2)||lstat(SocketPath,&existing)) {
            close(fd);return @{ @"ok":@NO };
        }
        _listener=fd;_socketInode=existing.st_ino;_started=YES;
        __weak typeof(self) weak=self;
        _acceptSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)fd,0,dispatch_get_main_queue());
        dispatch_source_set_event_handler(_acceptSource,^{[weak acceptClients];});dispatch_resume(_acceptSource);
        if(!_exclusiveLifecycleOnly){
        _central=[[CBCentralManager alloc]initWithDelegate:self queue:dispatch_get_main_queue()
            options:@{CBCentralManagerOptionShowPowerAlertKey:@NO}];
        _peerWorker=[VM27SharedBluetoothPeerWorkerV1 new];
        _peerWorker.messageHandler=^(NSDictionary *message){[weak handleWorkerMessage:message];};
        _peerWorker.disconnectionHandler=^{typeof(self) owner=weak;if(!owner)return;
            if(owner->_peerSession)[owner closeClientWithReason:"peer-worker-lost"];
            for(VM27SharedBluetoothHostV1 *child in [owner->_children copy])if(child->_peerSession)[child closeClientWithReason:"peer-worker-lost"];
        };
        if(![_peerWorker start])fprintf(stderr,"[SharedBluetooth] generic peer worker endpoint unavailable\n");
        }
        fprintf(stderr,"[SharedBluetooth] private BTVC listener ready lifecycleOnly=%d\n",_exclusiveLifecycleOnly);
    }
    return @{ @"ok":@YES,@"protocol":@1,@"guestAddress":@"10.0.2.4",@"guestPort":@39028,
        @"serverUUID":_serverID.UUIDString,@"virtualAddressSchema":@3,@"physicalAddressesExposed":@NO,@"nativePairingImplemented":@NO };
}
- (void)acceptClients {
    if(_invalidated||_listener<0)return;
    for(unsigned i=0;i<8;++i) {
        int fd=accept(_listener,NULL,NULL);if(fd<0)return;
        uid_t uid;gid_t gid;
        if(getpeereid(fd,&uid,&gid)||uid!=geteuid()||nonblocking(fd)||(_client>=0&&_children.count>=16)){close(fd);continue;}
        if(_client<0)[self adoptClient:fd];
        else {
            VM27SharedBluetoothHostV1 *child=[VM27SharedBluetoothHostV1 new];
            child->_parent=self;child->_serverID=_serverID;
            if(!_children)_children=[NSMutableSet set];[_children addObject:child];
            [child adoptClient:fd];
        }
    }
}
- (void)adoptNativePeerFD:(int)fd closed:(void (^)(void))closed {
    NSAssert(NSThread.isMainThread,@"Bluetooth bridge owner queue");
    if(_invalidated||!_peerWorker){if(fd>=0)close(fd);if(closed)closed();return;}
    [_peerWorker adoptOwnedFD:fd closed:closed];
}
- (void)adoptClient:(int)fd {
    _client=fd;_upgraded=NO;_connectionOnly=NO;++_generation;
    _input=[NSMutableData data];_output=[NSMutableData data];
    uint64_t generation=_generation;__weak typeof(self) weak=self;
    _readSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)fd,0,dispatch_get_main_queue());
    dispatch_source_set_event_handler(_readSource,^{typeof(self) strong=weak;if(strong&&strong->_generation==generation)[strong readClient];});
    dispatch_resume(_readSource);
}
- (BOOL)hasDiscoveryClient {
    if(_client>=0&&_upgraded&&!_connectionOnly)return YES;
    for(VM27SharedBluetoothHostV1 *child in _children)if(child->_client>=0&&child->_upgraded&&!child->_connectionOnly)return YES;
    return NO;
}
- (void)broadcastDiscovery:(NSData *)data {
    if(_client>=0&&_upgraded&&!_connectionOnly)[self sendOpcode:2 data:data];
    for(VM27SharedBluetoothHostV1 *child in [_children copy])
        if(child->_client>=0&&child->_upgraded&&!child->_connectionOnly)[child sendOpcode:2 data:data];
}
- (void)closeClient {
    VM27SharedBluetoothHostV1 *owner=_parent?:self;
    NSMutableArray *connections=[owner->_children.allObjects mutableCopy]?:[NSMutableArray array];[connections addObject:owner];
    for(VM27SharedBluetoothHostV1 *connection in connections)if(connection!=self&&connection->_dataClient==self) {
        connection->_dataClient=nil;[connection closeClientWithReason:"native-data-channel-lost"];
    }
    if(_peerSession)[owner->_peerWorker sendMessage:@{@"kind":@"close",@"session":_peerSession}];
    _peerSession=nil;_peerReady=NO;_queuedPackets=nil;_connectionPairingIntent=nil;_dataClient=nil;_remoteAddress=_localAddress=nil;
    [_gattPeer invalidate];_gattPeer=nil;
    ++_generation;
    if(owner->_guestPairingClient==self||(!owner->_guestPairingClient&&owner==self)) {
        owner->_guestPairingIntent=nil;owner->_guestPairingClient=nil;
        if(owner->_gattProbePairingAttempted)[owner finishGATTProbe:@"guest-pairing-request-canceled" error:nil];
    }
    _upgraded=NO;_selectedPeripheral=nil;
    if(_readSource){dispatch_source_cancel(_readSource);_readSource=nil;}
    if(_writeSource){dispatch_source_cancel(_writeSource);_writeSource=nil;}
    int fd=_client;_client=-1;if(fd>=0)close(fd);
    _input=nil;_output=nil;_fragment=nil;
    if(_parent)[_parent->_children removeObject:self];
    [owner scanIfReady];
}
- (void)closeClientWithReason:(const char *)reason {
    if(_closeReports++<24)fprintf(stderr,"[SharedBluetooth] BTVC closed reason=%s pendingBytes=%lu\n",
        reason,(unsigned long)_input.length);
    [self closeClient];
}
- (void)observeMessage:(NSData *)message {
    [(_parent?:self) observeMessage:message fromClient:self];
}
- (void)observeMessage:(NSData *)message fromClient:(VM27SharedBluetoothHostV1 *)client {
    if(_invalidated||client->_client<0||!client->_upgraded||
       (client!=self&&(client->_parent!=self||![_children containsObject:client])))return;
    // Only the native protocol's fixed message names and value shape are
    // diagnosed. Never log peer addresses, advertisement bytes or parameters.
    id decoded=[NSPropertyListSerialization propertyListWithData:message options:NSPropertyListImmutable format:NULL error:NULL];
    NSString *kind=[decoded isKindOfClass:NSDictionary.class]?decoded[@"BTVCBonjourServiceMessageType"]:nil;
    unsigned type=0;
    if([kind isKindOfClass:NSString.class]) {
        NSArray *known=@[@"BTVCBonjourServiceMessageTypeStartAdvertiseData",@"BTVCBonjourServiceMessageTypeStopAdvertiseData",
            @"BTVCBonjourServiceMessageTypeConnect",@"BTVCBonjourServiceMessageTypeDisconnect",@"BTVCBonjourServiceMessageTypeDataPacket"];
        NSUInteger index=[known indexOfObject:kind];if(index!=NSNotFound)type=(unsigned)index+1;
    }
    id value=[decoded isKindOfClass:NSDictionary.class]?decoded[@"BTVCBonjourServiceMessageValue"]:nil;
    unsigned shape=[value isKindOfClass:NSDictionary.class]?1:[value isKindOfClass:NSArray.class]?2:
        [value isKindOfClass:NSData.class]?3:0;
    if(_messageReports++<24)fprintf(stderr,"[SharedBluetooth] BTVC incoming type=%u shape=%u bytes=%lu\n",
        type,shape,(unsigned long)message.length);
    if(type==3) {
        // This is a connection request, not permission to create a new bond.
        client->_connectionOnly=YES;
        NSData *address=shape==1?value[@"peerA"]:nil;
        if(_connectionPacketReports++<32)fprintf(stderr,"[SharedBluetooth] guest Connect addressBytes=%lu addressType=%u\n",
            (unsigned long)([address isKindOfClass:NSData.class]?address.length:0),
            [address isKindOfClass:NSData.class]&&address.length==7?((const uint8_t *)address.bytes)[6]:255u);
        if(![address isKindOfClass:NSData.class]||address.length!=7||((const uint8_t *)address.bytes)[6]!=1)return;
        for(NSUUID *identifier in _observedPeripherals) {
            NSData *proxy=proxyAddress(identifier);
            if(!memcmp(address.bytes,proxy.bytes,6)) {client->_selectedPeripheral=_observedPeripherals[identifier];break;}
        }
        fprintf(stderr,"[SharedBluetooth] guest connection selected knownPeer=%d newPairingAuthorized=0\n",client->_selectedPeripheral!=nil);
        NSData *local=shape==1?value[@"initA"]:nil;
        if(client->_selectedPeripheral&&[local isKindOfClass:NSData.class]&&local.length==7&&((const uint8_t *)local.bytes)[6]<=1) {
            client->_remoteAddress=[address copy];client->_localAddress=[local copy];
        }
        if(client->_selectedPeripheral&&_peerWorker.connected)[self openGenericPeer:value client:client];
        [self scanIfReady];
    } else if(type==4) {
        [client closeClientWithReason:"guest-disconnect"];
    } else if(type==5) {
        id packet=value;
        if([packet isKindOfClass:NSData.class])packet=[NSPropertyListSerialization propertyListWithData:packet options:0 format:NULL error:NULL];
        if(![packet isKindOfClass:NSDictionary.class])return;
        // Native Bonjour uses connectionType 2 for Connect and type 4 for data.
        // Bind the separate data socket to the live logical connection using
        // both seven-byte virtual addresses. Never infer a target from a scan
        // or grant pairing permission to a socket that lacks this association.
        VM27SharedBluetoothHostV1 *incoming=client;
        if(!client->_selectedPeripheral) {
            NSData *remote=packet[@"peerA"],*local=packet[@"initA"];
            if(![remote isKindOfClass:NSData.class]||remote.length!=7||![local isKindOfClass:NSData.class]||local.length!=7)return;
            NSMutableArray *connections=[_children.allObjects mutableCopy]?:[NSMutableArray array];[connections addObject:self];
            VM27SharedBluetoothHostV1 *selected=nil;
            for(VM27SharedBluetoothHostV1 *candidate in connections)if(candidate->_selectedPeripheral&&candidate->_client>=0&&
                [candidate->_remoteAddress isEqual:remote]&&[candidate->_localAddress isEqual:local]) {
                if(selected)return;selected=candidate; // Ambiguous/stale routes are never guessed.
            }
            if(!selected)return;client=selected;incoming->_connectionOnly=YES;client->_dataClient=incoming;
        }
        NSNumber *header=packet[@"header"];NSData *payload=packet[@"payload"];
        if(_connectionPacketReports++<32&&[header isKindOfClass:NSNumber.class]&&[payload isKindOfClass:NSData.class]) {
            unsigned channel=0,opcode=255;BOOL encrypted=packet[@"MIC"]!=nil;
            const uint8_t *p=payload.bytes;
            if(!encrypted&&header.unsignedIntValue==3&&payload.length)opcode=p[0];
            if(!encrypted&&header.unsignedIntValue==2&&payload.length>=4)channel=p[2]|((unsigned)p[3]<<8);
            fprintf(stderr,"[SharedBluetooth] guest data header=%u bytes=%lu channel=%u controlOpcode=%u encrypted=%d\n",
                header.unsignedIntValue,(unsigned long)payload.length,channel,opcode,encrypted);
        }
        if(!client->_selectedPeripheral||![header isKindOfClass:NSNumber.class]||![payload isKindOfClass:NSData.class])return;
        if(!packet[@"MIC"]&&header.unsignedIntValue==2&&payload.length==11) {
            const uint8_t *p=payload.bytes;
            if(p[0]==7&&p[1]==0&&p[2]==6&&p[3]==0) {
                VM27GuestPairingIntentV1 *intent=[[VM27GuestPairingIntentV1 alloc]initWithPeer:client->_selectedPeripheral.identifier
                    generation:client->_generation nativePairingRequest:[payload subdataWithRange:NSMakeRange(4,7)] now:NSProcessInfo.processInfo.systemUptime];
                if(intent) {
                    _guestPairingIntent=intent;_guestPairingClient=client;client->_connectionPairingIntent=intent;
                    fprintf(stderr,"[SharedBluetooth] explicit native guest pairing request received\n");
                }
            }
        }
        if(client->_peerSession)[self forwardPacket:packet client:client];
    }
}
- (void)openGenericPeer:(NSDictionary *)parameters client:(VM27SharedBluetoothHostV1 *)client {
    NSData *remote=parameters[@"peerA"],*local=parameters[@"initA"];
    if(client->_peerSession||![remote isKindOfClass:NSData.class]||remote.length!=7||
       ![local isKindOfClass:NSData.class]||local.length!=7||((const uint8_t *)local.bytes)[6]>1)return;
    client->_peerSession=NSUUID.UUID.UUIDString;client->_queuedPackets=[NSMutableArray array];
    uint64_t generation=client->_generation;__weak typeof(self) weakOwner=self;__weak typeof(client) weakClient=client;
    VM27SharedBluetoothGATTPeerV1 *gatt=[[VM27SharedBluetoothGATTPeerV1 alloc]initWithIdentifier:client->_selectedPeripheral.identifier newPairingPermission:^BOOL{
        VM27SharedBluetoothHostV1 *selected=weakClient;
        return selected&&selected->_generation==generation&&selected->_client>=0&&
            [selected->_connectionPairingIntent permitsPeer:selected->_selectedPeripheral.identifier generation:generation now:NSProcessInfo.processInfo.systemUptime];
    }];client->_gattPeer=gatt;
    gatt.notificationHandler=^(NSDictionary *event){VM27SharedBluetoothHostV1 *owner=weakOwner,*selected=weakClient;
        if(!owner||!selected||selected->_generation!=generation||!selected->_peerSession)return;
        if([event[@"event"]isEqual:@"disconnected"]){[selected closeClientWithReason:"actual-peer-disconnected"];return;}
        [owner->_peerWorker sendMessage:@{@"kind":@"notification",@"session":selected->_peerSession,@"event":event}];
    };
    gatt.pairingChallengeHandler=^(NSDictionary *challenge){VM27SharedBluetoothHostV1 *owner=weakOwner,*selected=weakClient;
        if(owner&&selected&&selected->_generation==generation&&selected->_peerSession)
            [owner->_peerWorker sendMessage:@{@"kind":@"pairingChallenge",@"session":selected->_peerSession,@"challenge":challenge}];
    };
    [gatt connectWithCompletion:^(NSDictionary *result){VM27SharedBluetoothHostV1 *owner=weakOwner,*selected=weakClient;
        if(!owner||!selected||selected->_generation!=generation||!selected->_peerSession)return;
        if(![result[@"ok"]boolValue]){[selected closeClientWithReason:"actual-gatt-open-failed"];return;}
        if(![owner->_peerWorker sendMessage:@{@"kind":@"open",@"session":selected->_peerSession,
            @"peripheral":remote,@"central":local,@"metadata":result}])[selected closeClientWithReason:"peer-worker-unavailable"];
        else fprintf(stderr,"[SharedBluetooth] generic actual GATT discovered services=%lu existingBond=%d\n",(unsigned long)[result[@"services"]count],[result[@"paired"]boolValue]);
    }];
}
- (void)forwardPacket:(NSDictionary *)packet client:(VM27SharedBluetoothHostV1 *)client {
    NSNumber *header=packet[@"header"];NSData *payload=packet[@"payload"],*mic=packet[@"MIC"];
    if(![header isKindOfClass:NSNumber.class]||header.unsignedIntegerValue<1||header.unsignedIntegerValue>3||
       ![payload isKindOfClass:NSData.class]||payload.length>251||(mic&&(![mic isKindOfClass:NSData.class]||mic.length!=4))) {
        [client closeClientWithReason:"peer-packet-invalid"];return;
    }
    NSMutableDictionary *data=[@{@"header":header,@"payload":payload}mutableCopy];if(mic)data[@"MIC"]=mic;
    if(!client->_peerReady) {
        if(client->_queuedPackets.count>=32){[client closeClientWithReason:"peer-start-queue-limit"];return;}
        [client->_queuedPackets addObject:data];return;
    }
    if(![_peerWorker sendMessage:@{@"kind":@"packet",@"session":client->_peerSession,@"packet":data}])
        [client closeClientWithReason:"peer-worker-unavailable"];
}
- (void)handleWorkerMessage:(NSDictionary *)message {
    NSString *session=message[@"session"],*kind=message[@"kind"];
    if(![session isKindOfClass:NSString.class]||session.length!=36||![kind isKindOfClass:NSString.class])return;
    VM27SharedBluetoothHostV1 *client=[_peerSession isEqual:session]?self:nil;
    for(VM27SharedBluetoothHostV1 *child in _children)if([child->_peerSession isEqual:session]){client=child;break;}
    if(!client||client->_client<0||!client->_upgraded)return;
    if([kind isEqual:@"opened"]) {
        client->_peerReady=YES;NSArray *packets=[client->_queuedPackets copy];[client->_queuedPackets removeAllObjects];
        for(NSDictionary *packet in packets)if(client->_peerSession)[self forwardPacket:packet client:client];
    } else if([kind isEqual:@"close"]) {
        [client closeClientWithReason:"generic-peer-closed"];
    } else if([kind isEqual:@"packet"]) {
        NSDictionary *packet=message[@"packet"];if(![packet isKindOfClass:NSDictionary.class])return;
        NSNumber *header=packet[@"header"];NSData *payload=packet[@"payload"],*mic=packet[@"MIC"];
        if(![header isKindOfClass:NSNumber.class]||header.unsignedIntegerValue<1||header.unsignedIntegerValue>3||
           ![payload isKindOfClass:NSData.class]||payload.length>251||(mic&&(![mic isKindOfClass:NSData.class]||mic.length!=4))){[client closeClientWithReason:"worker-packet-invalid"];return;}
        NSData *data=[NSPropertyListSerialization dataWithPropertyList:@{@"BTVCBonjourServiceMessageType":@"BTVCBonjourServiceMessageTypeDataPacket",
            @"BTVCBonjourServiceMessageValue":packet}format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
        if(data)[(client->_dataClient?:client) sendOpcode:2 data:data];
    } else if([kind isEqual:@"operation"]) {
        NSNumber *identifier=message[@"request"];NSDictionary *operation=message[@"operation"];
        if(![identifier isKindOfClass:NSNumber.class]||!identifier.unsignedLongLongValue||![operation isKindOfClass:NSDictionary.class])return;
        uint64_t generation=client->_generation;__weak typeof(self) weakOwner=self;__weak typeof(client) weakClient=client;
        [client->_gattPeer performOperation:operation completion:^(NSDictionary *result){VM27SharedBluetoothHostV1 *owner=weakOwner,*selected=weakClient;
            if(owner&&selected&&selected->_generation==generation&&[selected->_peerSession isEqual:session])
                [owner->_peerWorker sendMessage:@{@"kind":@"result",@"session":session,@"request":identifier,@"result":result}];
        }];
    }
}
- (void)flushClient {
    if(_client<0)return;
    while(_output.length) {
        ssize_t count=send(_client,_output.bytes,_output.length,MSG_DONTWAIT);
        if(count<0&&errno==EINTR)continue;
        if(count<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(count<=0){[self closeClientWithReason:"send-failed"];return;}
        [_output replaceBytesInRange:NSMakeRange(0,(NSUInteger)count) withBytes:NULL length:0];
    }
    if(!_output.length&&_writeSource){dispatch_source_cancel(_writeSource);_writeSource=nil;}
    else if(_output.length&&!_writeSource) {
        uint64_t generation=_generation;__weak typeof(self) weak=self;
        _writeSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,(uintptr_t)_client,0,dispatch_get_main_queue());
        dispatch_source_set_event_handler(_writeSource,^{typeof(self) strong=weak;if(strong&&strong->_generation==generation)[strong flushClient];});
        dispatch_resume(_writeSource);
    }
}
- (void)sendOpcode:(uint8_t)opcode data:(NSData *)data {
    if(_client<0||!_upgraded||data.length>65535||_output.length+data.length+4>262144)return;
    uint8_t header[4]={0x80|opcode,(uint8_t)data.length,0,0};size_t n=2;
    if(data.length>=126){header[1]=126;header[2]=(uint8_t)(data.length>>8);header[3]=(uint8_t)data.length;n=4;}
    [_output appendBytes:header length:n];[_output appendData:data];[self flushClient];
}
- (void)readClient {
    if(_client<0)return;
    for(unsigned batch=0;batch<8;++batch) {
        uint8_t bytes[8192];ssize_t count=recv(_client,bytes,sizeof(bytes),MSG_DONTWAIT);
        if(count<0&&errno==EINTR)continue;
        if(count<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(count<=0){[self closeClientWithReason:count==0?"peer-eof":"receive-failed"];return;}
        if(_input.length+(NSUInteger)count>131072){[self closeClientWithReason:"input-limit"];return;}
        [_input appendBytes:bytes length:(NSUInteger)count];
    }
    if(!_upgraded) {
        NSData *terminator=[@"\r\n\r\n" dataUsingEncoding:NSASCIIStringEncoding];
        NSRange end=[_input rangeOfData:terminator options:0 range:NSMakeRange(0,_input.length)];
        if(end.location==NSNotFound){if(_input.length>16384)[self closeClientWithReason:"upgrade-header-limit"];return;}
        NSString *request=[[NSString alloc]initWithData:[_input subdataWithRange:NSMakeRange(0,end.location)] encoding:NSASCIIStringEncoding];
        NSArray *lines=[request componentsSeparatedByString:@"\r\n"];NSMutableDictionary *headers=[NSMutableDictionary dictionary];
        for(NSString *line in lines) {NSRange colon=[line rangeOfString:@":"];if(colon.location==NSNotFound)continue;
            headers[[[line substringToIndex:colon.location]lowercaseString]]=[[line substringFromIndex:colon.location+1]stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];}
        NSString *key=headers[@"sec-websocket-key"];
        NSString *peer=headers[@"btvcbonjourendpointclientuuidheader"];
        if(![lines.firstObject hasPrefix:@"GET "]||![[headers[@"upgrade"]lowercaseString]isEqual:@"websocket"]||
            [[[NSData alloc]initWithBase64EncodedString:key?:@"" options:0]length]!=16||
            peer.length!=36||![[NSUUID alloc]initWithUUIDString:peer]){[self closeClientWithReason:"upgrade-invalid"];return;}
        NSData *challenge=[[key stringByAppendingString:@"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"]dataUsingEncoding:NSASCIIStringEncoding];
        unsigned char hash[CC_SHA1_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CC_SHA1(challenge.bytes,(CC_LONG)challenge.length,hash);
#pragma clang diagnostic pop
        NSString *accept=[[NSData dataWithBytes:hash length:sizeof(hash)]base64EncodedStringWithOptions:0];
        NSString *response=[NSString stringWithFormat:@"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %@\r\nBTVCBonjourEndpointServerUUIDHeader: %@\r\n\r\n",accept,_serverID.UUIDString];
        [_output appendData:[response dataUsingEncoding:NSASCIIStringEncoding]];
        [_input replaceBytesInRange:NSMakeRange(0,end.location+4)withBytes:NULL length:0];_upgraded=YES;
        [self flushClient];[self scanIfReady];fprintf(stderr,"[SharedBluetooth] native BTVC client upgraded\n");
    }
    for(unsigned frames=0;frames<32&&_input.length>=2;++frames) {
        const uint8_t *raw=_input.bytes;uint8_t opcode=raw[0]&15;BOOL final=(raw[0]&0x80)!=0;
        NSUInteger header=2,length=raw[1]&127;
        if((raw[0]&0x70)||!(raw[1]&0x80)||length==127){[self closeClientWithReason:"frame-header-invalid"];return;}
        if(length==126){if(_input.length<4)return;length=(raw[2]<<8)|raw[3];header=4;}
        if(_input.length<header+4+length)return;
        if(opcode>=8&&(!final||length>125)){[self closeClientWithReason:"control-frame-invalid"];return;}
        if(opcode==8){[self closeClientWithReason:"peer-close-frame"];return;}
        NSMutableData *payload=[NSMutableData dataWithLength:length];
        for(NSUInteger i=0;i<length;++i)((uint8_t *)payload.mutableBytes)[i]=raw[header+4+i]^raw[header+(i&3)];
        if(opcode==9) {
            [self sendOpcode:10 data:payload];
        } else if(opcode==2) {
            if(_fragment){[self closeClientWithReason:"fragment-overlap"];return;}
            if(final)[self observeMessage:payload];else _fragment=payload;
        } else if(opcode==0) {
            if(!_fragment||_fragment.length+payload.length>65535){[self closeClientWithReason:"fragment-invalid"];return;}
            [_fragment appendData:payload];
            if(final){[self observeMessage:_fragment];_fragment=nil;}
        } else if(opcode!=10){[self closeClientWithReason:"opcode-unsupported"];return;}
        if(_client<0)return;
        [_input replaceBytesInRange:NSMakeRange(0,header+4+length)withBytes:NULL length:0];
    }
    // A coalesced socket read may contain more than one bounded batch. Drain
    // buffered complete frames even if no further socket readiness arrives.
    if(_input.length>=2) {
        uint64_t generation=_generation;__weak typeof(self) weak=self;
        dispatch_async(dispatch_get_main_queue(),^{typeof(self) strong=weak;
            if(strong&&strong->_generation==generation)[strong readClient];});
    }
}
- (void)scanIfReady {
    if(_exclusiveLifecycleOnly)return;
    if(_parent){[_parent scanIfReady];return;}
    if(_invalidated){[_central stopScan];return;}
    if([self hasDiscoveryClient]&&_central.state==CBManagerStatePoweredOn)
        // Native guests expect a live stream of RF observations, including
        // stable HID advertisements. CoreBluetooth's default coalescing sends
        // an unchanged device only once, which can precede the guest scanner.
        // Coalesce actual callbacks below; never replay a stale cached device.
        [_central scanForPeripheralsWithServices:nil options:@{CBCentralManagerScanOptionAllowDuplicatesKey:@YES}];
    else [_central stopScan];
}
- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    if(central.state!=CBManagerStatePoweredOn&&_gattProbeCompletion)
        [self finishGATTProbe:@"host-Bluetooth-unavailable" error:nil];
    if(central.state!=CBManagerStatePoweredOn)[central stopScan];else[self scanIfReady];
}
- (void)centralManager:(CBCentralManager *)central didDiscoverPeripheral:(CBPeripheral *)peripheral
    advertisementData:(NSDictionary<NSString *,id> *)data RSSI:(NSNumber *)rssi {
    (void)central;
    if(![self hasDiscoveryClient])return;
    NSMutableDictionary *actual=[data mutableCopy];
    if(![actual[CBAdvertisementDataLocalNameKey]length]&&peripheral.name.length)
        actual[CBAdvertisementDataLocalNameKey]=peripheral.name;
    NSData *contents=advertisingData(actual);
    if(!_lastAdvertisement)_lastAdvertisement=[NSMutableDictionary dictionary];
    if(!_recentDevices)_recentDevices=[NSMutableOrderedSet orderedSet];
    if(!_observedPeripherals)_observedPeripherals=[NSMutableDictionary dictionary];
    double now=NSProcessInfo.processInfo.systemUptime;
    NSDictionary *previous=_lastAdvertisement[peripheral.identifier];
    // A scan response may add a name or HID service just after the first
    // callback. Only suppress an unchanged payload; forward new AD content
    // immediately even inside the one-second duplicate interval.
    if(previous&&now-[previous[@"time"]doubleValue]<1.0&&[previous[@"payload"]isEqual:contents])return;
    // Bounded recency bookkeeping evicts an old entry, never the newly arrived
    // device. A full cache must not prevent a late mouse from being discovered.
    if(!previous&&_recentDevices.count>=256) {
        [_observedPeripherals removeObjectForKey:_recentDevices.firstObject];
        [_lastAdvertisement removeObjectForKey:_recentDevices.firstObject];
        [_recentDevices removeObjectAtIndex:0];
    }
    [_recentDevices removeObject:peripheral.identifier];[_recentDevices addObject:peripheral.identifier];
    _lastAdvertisement[peripheral.identifier]=@{@"time":@(now),@"payload":contents};
    _observedPeripherals[peripheral.identifier]=peripheral;
    NSArray<NSData *> *payloads=legacyAdvertisingPayloads(actual);
    if(![payloads.firstObject length])return;
    NSData *address=proxyAddress(peripheral.identifier);
    BOOL connectable=[data[CBAdvertisementDataIsConnectable]boolValue];
    NSNumber *power=data[CBAdvertisementDataTxPowerLevelKey];if(![power isKindOfClass:NSNumber.class])power=@127;
    NSMutableArray *reports=[NSMutableArray array];
    for(NSUInteger index=0;index<payloads.count;++index) {
        NSData *payload=payloads[index];
        unsigned event=index?0x1bu:(connectable?0x13u:0x10u);
        [reports addObject:@{@"et":@(event),@"at":@1,@"pa":address,
            @"pPHY":@1,@"sPHY":@0,@"aSID":@255,@"tp":power,@"rssi":rssi?:@127,
            @"pai":@0,@"dat":@0,@"da":@0,@"dtl":@(payload.length),@"data":payload}];
    }
    // BTVCLinkScanner's public type 2 (LE) maps to Bonjour link type 1;
    // type 2 here is a different namespace and is silently filtered out.
    NSDictionary *advert=@{@"BTVCBonjourLinkType":@1,@"BTVCBonjourPayloadKey":reports};
    NSDictionary *message=@{@"BTVCBonjourServiceMessageType":@"BTVCBonjourServiceMessageTypeStartAdvertiseData",
        @"BTVCBonjourServiceMessageValue":@[advert]};
    NSData *encoded=[NSPropertyListSerialization dataWithPropertyList:message format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    BOOL hid=NO;for(CBUUID *uuid in data[CBAdvertisementDataServiceUUIDsKey])
        if([uuid isKindOfClass:CBUUID.class]&&[uuid isEqual:[CBUUID UUIDWithString:@"1812"]])hid=YES;
    if(encoded){[self broadcastDiscovery:encoded];++_published;
        if(_published<=4||!(_published%16))fprintf(stderr,"[SharedBluetooth] actual BLE advertisements forwarded=%llu\n",(unsigned long long)_published);
        if(hid){++_publishedHID;if(_publishedHID<=4||!(_publishedHID%16))
            fprintf(stderr,"[SharedBluetooth] actual HID advertisements forwarded=%llu\n",(unsigned long long)_publishedHID);}}
    NSString *name=data[CBAdvertisementDataLocalNameKey]?:peripheral.name;
    if(hid&&connectable&&[name isKindOfClass:NSString.class]&&[name caseInsensitiveCompare:@"UGREEN BLE Mouse"]==NSOrderedSame) {
        _acceptanceMousePeripheral=peripheral;_acceptanceMouseLastSeen=now;
    }
    if(!_acceptanceMouseSeen&&[name isKindOfClass:NSString.class]&&[name caseInsensitiveCompare:@"UGREEN BLE Mouse"]==NSOrderedSame) {
        _acceptanceMouseSeen=YES;
        fprintf(stderr,"[SharedBluetooth] acceptance mouse observed connectable=%d HIDServiceAdvertised=%d eventType=%u bytes=%lu scanResponseBytes=%lu\n",
            connectable,hid,connectable?0x13u:0x10u,(unsigned long)[payloads.firstObject length],
            (unsigned long)(payloads.count>1?[payloads[1]length]:0));
    }
}
- (void)probeAcceptanceMouseGATTWithCompletion:(void (^)(NSDictionary *))completion {
    NSAssert(NSThread.isMainThread,@"GATT probe requires the owner queue");
    if(_invalidated||_gattProbeUsed||_central.state!=CBManagerStatePoweredOn||!_acceptanceMousePeripheral||
       (NSProcessInfo.processInfo.systemUptime-_acceptanceMouseLastSeen>15&&_acceptanceMousePeripheral.state!=CBPeripheralStateConnected)) {
        completion(@{@"ok":@NO,@"stage":@"fresh-actual-target-required",@"pairingVerified":@NO});return;
    }
    _gattProbeUsed=YES;_gattProbeCompletion=[completion copy];_gattProbePeripheral=_acceptanceMousePeripheral;
    _gattProbePeripheral.delegate=self;_gattProbeOwnReference=YES;
    _gattProbeResult=[@{@"ok":@NO,@"actualTargetPreviouslyDiscovered":@YES,
        @"physicalLEConnectionEstablished":@NO,@"HIDServiceFound":@NO,@"reportMapFound":@NO,
        @"pairingVerified":@NO,@"guestPairingImplemented":@NO,@"inputNotificationsEnabled":@NO,
        @"identifiersRecorded":@NO,@"GATTValuesRecorded":@NO}mutableCopy];
    uint64_t generation=++_gattProbeGeneration;__weak typeof(self) weak=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,90*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        typeof(self) owner=weak;if(owner&&owner->_gattProbeCompletion&&owner->_gattProbeGeneration==generation)
            [owner finishGATTProbe:@"timeout" error:nil];
    });
    fprintf(stderr,"[SharedBluetoothGATTProbe] actual target connection requested; no input subscription\n");
    [_central connectPeripheral:_gattProbePeripheral options:nil];
}
- (void)finishGATTProbe:(NSString *)stage error:(NSError *)error {
    if(!_gattProbeCompletion)return;++_gattProbeGeneration;
    _gattProbeResult[@"stage"]=stage;_gattProbeResult[@"nativeErrorCode"]=@(error.code);
    _gattProbeResult[@"nativeErrorDomain"]=error.domain?:@"";
    _gattProbeResult[@"ok"]=@(!error&&[stage isEqual:@"report-map-read"]);
    NSDictionary *result=[_gattProbeResult copy];void (^reply)(NSDictionary *)=_gattProbeCompletion;
    _gattProbeCompletion=nil;_gattProbeResult=nil;CBPeripheral *peripheral=_gattProbePeripheral;
    _gattProbePeripheral=nil;peripheral.delegate=nil;_guestPairingIntent=nil;_guestPairingClient=nil;
    _gattProbeReportMap=nil;
    if(_gattProbePairingAgent) {
        SEL get=NSSelectorFromString(@"delegate"),set=NSSelectorFromString(@"setDelegate:");
        if([_gattProbePairingAgent respondsToSelector:get]&&[_gattProbePairingAgent respondsToSelector:set]&&
           ((id(*)(id,SEL))objc_msgSend)(_gattProbePairingAgent,get)==self)
            ((void(*)(id,SEL,id))objc_msgSend)(_gattProbePairingAgent,set,nil);
        _gattProbePairingAgent=nil;
    }
    if(_gattProbeOwnReference){_gattProbeOwnReference=NO;if(_central.state==CBManagerStatePoweredOn)[_central cancelPeripheralConnection:peripheral];}
    reply(result);
}
- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral {
    (void)central;if(peripheral!=_gattProbePeripheral||!_gattProbeCompletion)return;
    _gattProbeResult[@"physicalLEConnectionEstablished"]=@YES;
    fprintf(stderr,"[SharedBluetoothGATTProbe] physical LE connection established; discovering services\n");
    [peripheral discoverServices:nil];
}
- (void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
    (void)central;if(peripheral==_gattProbePeripheral)[self finishGATTProbe:@"native-connection-failed" error:error];
}
- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error {
    (void)central;if(peripheral==_gattProbePeripheral)[self finishGATTProbe:@"native-disconnected" error:error];
}
- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
    if(peripheral!=_gattProbePeripheral||!_gattProbeCompletion)return;
    if(error){[self finishGATTProbe:@"native-service-discovery-failed" error:error];return;}
    _gattProbeResult[@"serviceCount"]=@(peripheral.services.count);
    for(CBService *service in peripheral.services)if([service.UUID isEqual:[CBUUID UUIDWithString:@"1812"]]) {
        _gattProbeResult[@"HIDServiceFound"]=@YES;[peripheral discoverCharacteristics:nil forService:service];return;
    }
    [self finishGATTProbe:@"HID-service-unavailable" error:nil];
}
- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(NSError *)error {
    if(peripheral!=_gattProbePeripheral||!_gattProbeCompletion)return;
    if(error){[self finishGATTProbe:@"native-characteristic-discovery-failed" error:error];return;}
    _gattProbeResult[@"HIDCharacteristicCount"]=@(service.characteristics.count);
    for(CBCharacteristic *characteristic in service.characteristics)
        if([characteristic.UUID isEqual:[CBUUID UUIDWithString:@"2A4B"]]) {
            _gattProbeResult[@"reportMapFound"]=@YES;_gattProbeReportMap=characteristic;
            [peripheral readValueForCharacteristic:characteristic];return;
        }
    [self finishGATTProbe:@"report-map-unavailable" error:nil];
}
- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error {
    if(peripheral!=_gattProbePeripheral||!_gattProbeCompletion||![characteristic.UUID isEqual:[CBUUID UUIDWithString:@"2A4B"]])return;
    if([error.domain isEqual:CBATTErrorDomain]&&
       (error.code==CBATTErrorInsufficientEncryption||error.code==CBATTErrorInsufficientAuthentication)&&
       [self startGATTProbePairing])return;
    _gattProbeResult[@"reportMapBytes"]=@(characteristic.value.length);
    if(!error&&_gattProbePairingAgent&&[_gattProbePairingAgent respondsToSelector:NSSelectorFromString(@"isPeerPaired:")])
        _gattProbeResult[@"physicalBondVerified"]=@(((BOOL(*)(id,SEL,id))objc_msgSend)(
            _gattProbePairingAgent,NSSelectorFromString(@"isPeerPaired:"),peripheral));
    [self finishGATTProbe:error?@"native-report-map-read-failed":@"report-map-read" error:error];
}
- (BOOL)startGATTProbePairing {
    // Runtime metadata was read from this iPad. Use its own central manager's
    // pairing agent, with the actual discovered peer; never pair by a supplied
    // address or infer a bond from successful connection/service discovery.
    if(_gattProbePairingAttempted||!_gattProbeCompletion||!_gattProbeReportMap)return NO;
    uint64_t pairingGeneration=_guestPairingClient?_guestPairingClient->_generation:_generation;
    if(![_guestPairingIntent permitsPeer:_gattProbePeripheral.identifier generation:pairingGeneration
        now:NSProcessInfo.processInfo.systemUptime]) {
        _gattProbeResult[@"guestExplicitPairingRequired"]=@YES;return NO;
    }
    SEL shared=NSSelectorFromString(@"sharedPairingAgent"),get=NSSelectorFromString(@"delegate"),
        set=NSSelectorFromString(@"setDelegate:"),pair=NSSelectorFromString(@"pairPeer:");
    if(![_central respondsToSelector:shared])return NO;
    id agent=((id(*)(id,SEL))objc_msgSend)(_central,shared);
    if(![agent respondsToSelector:get]||![agent respondsToSelector:set]||![agent respondsToSelector:pair])return NO;
    id delegate=((id(*)(id,SEL))objc_msgSend)(agent,get);
    if(delegate&&delegate!=self)return NO;
    _gattProbePairingAttempted=YES;_gattProbePairingAgent=agent;
    ((void(*)(id,SEL,id))objc_msgSend)(agent,set,self);
    [self requestNativeGATTProbePairing];
    return YES;
}
- (void)requestNativeGATTProbePairing {
    if(!_gattProbeCompletion||!_gattProbePairingAgent||!_gattProbePeripheral)return;
    _gattProbeResult[@"physicalPairingRequested"]=@YES;
    // The scoped request already carries the user's authorization. Pairing
    // consent belongs to the guest action; no extra iPadOS prompt is introduced.
    uint64_t generation=++_gattProbeGeneration;__weak typeof(self) weak=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,90*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        typeof(self) owner=weak;if(owner&&owner->_gattProbeCompletion&&owner->_gattProbeGeneration==generation)
            [owner finishGATTProbe:@"native-physical-pairing-timeout" error:nil];
    });
    fprintf(stderr,"[SharedBluetoothGATTProbe] actual target native pairing requested\n");
    ((void(*)(id,SEL,id))objc_msgSend)(_gattProbePairingAgent,NSSelectorFromString(@"pairPeer:"),_gattProbePeripheral);
}
- (void)pairingAgent:(id)agent peerDidCompletePairing:(CBPeer *)peer {
    if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self pairingAgent:agent peerDidCompletePairing:peer];});return;}
    if(!_gattProbeCompletion||agent!=_gattProbePairingAgent||![peer.identifier isEqual:_gattProbePeripheral.identifier])return;
    _gattProbeResult[@"nativePhysicalPairingCompleted"]=@YES;
    fprintf(stderr,"[SharedBluetoothGATTProbe] native physical pairing completed; retrying protected read\n");
    [_gattProbePeripheral readValueForCharacteristic:_gattProbeReportMap];
}
- (void)pairingAgent:(id)agent peerDidFailToCompletePairing:(CBPeer *)peer error:(NSError *)error {
    if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self pairingAgent:agent peerDidFailToCompletePairing:peer error:error];});return;}
    if(_gattProbeCompletion&&agent==_gattProbePairingAgent&&[peer.identifier isEqual:_gattProbePeripheral.identifier])
        [self finishGATTProbe:@"native-physical-pairing-failed" error:error];
}
- (void)pairingAgent:(id)agent peerDidRequestPairing:(CBPeer *)peer type:(NSInteger)type passkey:(id)passkey {
    if(!NSThread.isMainThread){dispatch_async(dispatch_get_main_queue(),^{[self pairingAgent:agent peerDidRequestPairing:peer type:type passkey:passkey];});return;}
    if(!_gattProbeCompletion||agent!=_gattProbePairingAgent||![peer.identifier isEqual:_gattProbePeripheral.identifier])return;
    uint64_t pairingGeneration=_guestPairingClient?_guestPairingClient->_generation:_generation;
    if(![_guestPairingIntent permitsPeer:peer.identifier generation:pairingGeneration now:NSProcessInfo.processInfo.systemUptime]) {
        [self finishGATTProbe:@"guest-pairing-request-expired" error:nil];return;
    }
    _gattProbeResult[@"nativePhysicalPairingPromptReceived"]=@YES;
    fprintf(stderr,"[SharedBluetoothGATTProbe] native physical pairing confirmation required type=%ld\n",(long)type);
    // The actual iPad's CBConnection implementation treats native type 0 as a
    // consent request even when the callback carries a numeric placeholder.
    // Match its response (type 0, accept YES, empty options dictionary).
    // Only this explicitly armed, actual acceptance peer reaches this path;
    // discovery does not grant pairing consent to nearby devices.
    SEL respond=NSSelectorFromString(@"respondToPairingRequest:type:accept:data:");
    BOOL noPasskey=!passkey||([passkey isKindOfClass:NSString.class]&&![passkey length]);
    if(!_gattProbePairingPromptAnswered&&type==0&&[agent respondsToSelector:respond]) {
        _gattProbePairingPromptAnswered=YES;_gattProbeResult[@"nativePhysicalPairingPromptAccepted"]=@YES;
        fprintf(stderr,"[SharedBluetoothGATTProbe] authorized native consent response submitted\n");
        ((void(*)(id,SEL,id,NSInteger,BOOL,id))objc_msgSend)(agent,respond,peer,type,YES,@{});return;
    }
    _gattProbeResult[@"nativePairingType"]=@(type);
    _gattProbeResult[@"nativePairingPasskeyPresent"]=@(!noPasskey);
    [self finishGATTProbe:@"guest-pairing-interaction-required" error:nil];
}
- (void)invalidate {
    NSAssert(NSThread.isMainThread,@"Bluetooth bridge requires the owner queue");
    if(_invalidated)return;_invalidated=YES;
    for(VM27SharedBluetoothHostV1 *child in [_children copy])[child invalidate];_children=nil;
    [_peerWorker invalidate];_peerWorker=nil;
    [self finishGATTProbe:@"VM-radio-session-closed" error:nil];_acceptanceMousePeripheral=nil;
    [self closeClient];_central.delegate=nil;_central=nil;
    if(_acceptSource){dispatch_source_cancel(_acceptSource);_acceptSource=nil;}
    int fd=_listener;_listener=-1;if(fd>=0)close(fd);
    struct stat metadata;if(_socketInode&&!lstat(SocketPath,&metadata)&&metadata.st_ino==_socketInode&&S_ISSOCK(metadata.st_mode)&&metadata.st_uid==geteuid())unlink(SocketPath);
}
@end
