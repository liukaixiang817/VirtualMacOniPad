#import "VM27SharedRadioHostV1.h"
#import "VM27SharedBluetoothHostV1.h"
#import "VM27SharedBluetoothClassicHostV1.h"
#import "VM27OwnedWiFiHostV1.h"
#include "../../host/vm27_native_network_v1.h"
#import <CoreBluetooth/CoreBluetooth.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

typedef CFTypeRef (*ManagerCreate)(CFAllocatorRef, int);
typedef CFArrayRef (*CopyDevices)(CFTypeRef);
typedef void (*Schedule)(CFTypeRef, CFRunLoopRef, CFStringRef);
typedef CFStringRef (*InterfaceName)(CFTypeRef);
typedef CFTypeRef (*CopyNetwork)(CFTypeRef);
typedef CFTypeRef (*NetworkProperty)(CFTypeRef, CFStringRef);
typedef CFStringRef (*NetworkSSID)(CFTypeRef);
typedef int (*GetPower)(CFTypeRef);
typedef CFTypeRef (*DeviceProperty)(CFTypeRef, CFStringRef);
typedef void (*ScanCallback)(CFTypeRef, CFArrayRef, void *, void *);
// Actual iPadOS16.1.1 implementation saves x2/x3 as callback/context and
// returns the native operation status in w0 (see the recorded disassembly).
typedef int (*ScanAsync)(CFTypeRef, CFDictionaryRef, ScanCallback, void *);
typedef void (*ScanCancel)(CFTypeRef);

static NSDictionary *Failure(int code, NSString *message) {
    return @{@"ok":@NO, @"error":@{@"code":@(code), @"message":message}};
}
static id JSONProperty(CFTypeRef value) {
    if (!value) return NSNull.null;
    id object = (__bridge id)value;
    if ([object isKindOfClass:NSString.class] || [object isKindOfClass:NSNumber.class]) return object;
    if ([object isKindOfClass:NSData.class]) return @{ @"base64":[object base64EncodedStringWithOptions:0] };
    return NSNull.null;
}

@interface VM27SharedRadioHostV1 () <CBCentralManagerDelegate> {
    void *_library;
    CFTypeRef _manager, _device;
    CopyNetwork _copyNetwork;
    NetworkProperty _networkProperty;
    NetworkSSID _networkSSID;
    GetPower _getPower;
    DeviceProperty _deviceProperty;
    Schedule _unschedule;
    ScanAsync _scan;
    ScanCancel _scanCancel;
    void *_scanToken;
    void (^_scanReply)(NSDictionary *);
    BOOL _scanOutstanding, _invalidated, _attached, _usesOwnedWiFiController;
    uint64_t _scanSequence;
    CBCentralManager *_bluetooth;
    NSMutableDictionary<NSUUID *, NSDictionary *> *_bleDevices;
    void (^_bleReply)(NSDictionary *);
    uint64_t _bleSequence;
    VM27SharedBluetoothHostV1 *_nativeBluetooth;
    VM27SharedBluetoothClassicHostV1 *_classicBluetooth;
    VM27NativeNetworkV1 *_wifiNetwork;
    int _wifiDescriptor;
    NSString *_attachedSSID;
    VM27OwnedWiFiHostV1 *_ownedWiFi;
}
- (NSDictionary *)networkRow:(CFTypeRef)network;
- (NSDictionary *)wifiState;
- (void)releaseNativeWiFiReader;
- (void)scanFinished:(CFArrayRef)results error:(void *)error device:(CFTypeRef)device sequence:(uint64_t)sequence;
@end

@interface VM27SharedRadioScanContextV1 : NSObject
@property(weak) VM27SharedRadioHostV1 *owner;
@property uint64_t sequence;
@end
@implementation VM27SharedRadioScanContextV1 @end

static void ScanDone(CFTypeRef device, CFArrayRef results, void *error, void *token) {
    VM27SharedRadioScanContextV1 *context = CFBridgingRelease(token);
    [context.owner scanFinished:results error:error device:device sequence:context.sequence];
}

@implementation VM27SharedRadioHostV1
- (void)adoptBluetoothPeerFD:(int)fd closed:(void (^)(void))closed {
    NSAssert(NSThread.isMainThread,@"radio owner queue");
    if(_invalidated){if(fd>=0)close(fd);if(closed)closed();return;}
    if(!_nativeBluetooth)_nativeBluetooth=[VM27SharedBluetoothHostV1 new];
    [_nativeBluetooth start];[_nativeBluetooth adoptNativePeerFD:fd closed:closed];
}
- (instancetype)init {
    if (!(self = [super init])) return nil;
    _wifiDescriptor = -1;
    _usesOwnedWiFiController = [VM27OwnedWiFiHostV1 endpointPresent];
    if (_usesOwnedWiFiController) {
        fprintf(stderr,"[SharedRadio] owned Wi-Fi controller selected nativeAppWiFiReaderCreated=0\n");
        return self;
    }
    _library = dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi", RTLD_NOW | RTLD_LOCAL);
    if (!_library) return self;
    ManagerCreate create = (ManagerCreate)dlsym(_library, "WiFiManagerClientCreate");
    CopyDevices devices = (CopyDevices)dlsym(_library, "WiFiManagerClientCopyDevices");
    InterfaceName name = (InterfaceName)dlsym(_library, "WiFiDeviceClientGetInterfaceName");
    Schedule schedule = (Schedule)dlsym(_library, "WiFiManagerClientScheduleWithRunLoop");
    _unschedule = (Schedule)dlsym(_library, "WiFiManagerClientUnscheduleFromRunLoop");
    _copyNetwork = (CopyNetwork)dlsym(_library, "WiFiDeviceClientCopyCurrentNetwork");
    _networkProperty = (NetworkProperty)dlsym(_library, "WiFiNetworkGetProperty");
    _networkSSID = (NetworkSSID)dlsym(_library, "WiFiNetworkGetSSID");
    _getPower = (GetPower)dlsym(_library, "WiFiDeviceClientGetPower");
    _deviceProperty = (DeviceProperty)dlsym(_library, "WiFiDeviceClientCopyProperty");
    _scan = (ScanAsync)dlsym(_library, "WiFiDeviceClientScanAsync");
    _scanCancel = (ScanCancel)dlsym(_library, "WiFiDeviceClientScanCancel");
    if (!create || !devices || !name || !schedule || !_unschedule || !_copyNetwork ||
        !_networkProperty || !_networkSSID || !_getPower || !_deviceProperty) return self;
    _manager = create(kCFAllocatorDefault, 0);
    if (!_manager) return self;
    schedule(_manager, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    CFArrayRef list = devices(_manager);
    if (list && CFGetTypeID(list) == CFArrayGetTypeID()) {
        for (CFIndex i = 0; i < CFArrayGetCount(list); ++i) {
            CFTypeRef device = CFArrayGetValueAtIndex(list, i);
            CFStringRef interface = name(device);
            if (interface && CFEqual(interface, CFSTR("en0"))) { _device = CFRetain(device); break; }
        }
    }
    if (list) CFRelease(list);
    return self;
}
- (void)dealloc {
    if (_wifiDescriptor >= 0) close(_wifiDescriptor);
    VM27NativeNetworkStopV1(_wifiNetwork);
    [self releaseNativeWiFiReader];
    // The process owns the loaded framework; callbacks must never target an unloaded image.
}
- (void)releaseNativeWiFiReader {
    if (_scanToken && _scanCancel && _device) {
        _scanCancel(_device); CFRelease(_scanToken); _scanToken = NULL;
    }
    _scanOutstanding = NO;
    if (_manager && _unschedule) _unschedule(_manager, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    if (_device) { CFRelease(_device); _device = NULL; }
    if (_manager) { CFRelease(_manager); _manager = NULL; }
}
- (NSDictionary *)networkRow:(CFTypeRef)network {
    NSMutableDictionary *row = [NSMutableDictionary dictionary];
    CFStringRef ssid = _networkSSID(network);
    if (ssid && CFGetTypeID(ssid) == CFStringGetTypeID()) {
        NSData *data = [(__bridge NSString *)ssid dataUsingEncoding:NSUTF8StringEncoding];
        if (data.length > 0 && data.length <= 32) {
            row[@"ssid"] = (__bridge NSString *)ssid;
            row[@"ssidBase64"] = [data base64EncodedStringWithOptions:0];
        }
    }
    // Explicit radio fields only; never copy a network record or its password.
    for (NSString *key in @[@"BSSID", @"CHANNEL", @"CHANNEL_FLAGS", @"RSSI", @"IE", @"CAPABILITIES"])
        row[key] = JSONProperty(_networkProperty(network, (__bridge CFStringRef)key));
    return row;
}
- (NSDictionary *)wifiState {
    if (!_device) return Failure(ENODEV, @"Native en0 query client unavailable");
    CFTypeRef current = _copyNetwork(_device);
    NSDictionary *network = current ? [self networkRow:current] : nil;
    if (current) CFRelease(current);
    BOOL powered = _getPower(_device) != 0;
    return @{@"ok":@YES, @"wifi":@{@"interface":@"en0", @"hostPowered":@(powered),
        @"hostAssociated":@(powered && network != nil), @"network":network ?: (id)NSNull.null,
        @"guestAttached":@(_attached), @"mode":@"shared-host-association",
        @"dataPathConfigured":@(_attached && _wifiDescriptor >= 0 &&
            [_attachedSSID isEqualToString:network[@"ssidBase64"]]),
        @"nativeGuestDataPathValidated":@NO}};
}
- (void)scanFinished:(CFArrayRef)results error:(void *)error device:(CFTypeRef)device sequence:(uint64_t)sequence {
    if (_invalidated || sequence != _scanSequence || device != _device || !_scanOutstanding) return;
    // Native ScanCancel clears the saved callback/context (two stores); it
    // does not power down, disassociate, or cancel another client's scan.
    _scanCancel(_device); _scanToken = NULL; // callback owns/releases its token
    _scanOutstanding = NO;
    void (^reply)(NSDictionary *) = _scanReply; _scanReply = nil;
    if (!reply) return;
    if (error) { reply(Failure(EIO, @"Native scan returned an error")); return; }
    if (!results || CFGetTypeID(results) != CFArrayGetTypeID()) {
        reply(Failure(EPROTO, @"Native scan returned no result array")); return;
    }
    NSMutableArray *networks = [NSMutableArray array];
    CFIndex count = MIN(CFArrayGetCount(results), 256);
    for (CFIndex i = 0; i < count; ++i)
        [networks addObject:[self networkRow:CFArrayGetValueAtIndex(results, i)]];
    reply(@{@"ok":@YES, @"source":@"native-wifid-scan", @"networks":networks});
}
- (void)request:(NSDictionary *)request completion:(void (^)(NSDictionary *))completion {
    NSAssert(NSThread.isMainThread, @"Radio operations require the main run loop");
    if (_invalidated) { completion(Failure(ECANCELED, @"VM radio session closed")); return; }
    NSString *method = request[@"method"];
    if (![method isKindOfClass:NSString.class]) { completion(Failure(EINVAL, @"Missing method")); return; }
    if([method hasPrefix:@"wifi."]&&(_usesOwnedWiFiController||_ownedWiFi||[VM27OwnedWiFiHostV1 endpointPresent])){
        if(!_usesOwnedWiFiController){
            _usesOwnedWiFiController=YES; ++_scanSequence;
            void (^scanReply)(NSDictionary *)=_scanReply; _scanReply=nil;
            [self releaseNativeWiFiReader];
            if(scanReply)scanReply(Failure(ECANCELED,@"Independent Wi-Fi controller selected"));
        }
        if(!_ownedWiFi)_ownedWiFi=[VM27OwnedWiFiHostV1 new];
        [_ownedWiFi request:request completion:completion];return;
    }
    if ([method isEqualToString:@"capabilities"]) {
        BOOL owned=_usesOwnedWiFiController||_ownedWiFi||[VM27OwnedWiFiHostV1 endpointPresent];
        completion(@{@"ok":@YES, @"protocol":@1, @"wifiState":@(owned||_device != NULL),
            @"wifiScan":@(owned||(_device && _scan && _scanCancel)), @"sharedCurrentAssociation":@(!owned&&_device != NULL),
            @"hostRadioPowerControl":@NO, @"nativeGuestDriverValidated":@NO,
            @"rawHCITransport":@NO, @"ethernetTransport":@NO}); return;
    }
    if ([method isEqualToString:@"wifi.state"]) { completion([self wifiState]); return; }
    if ([method isEqualToString:@"bluetooth.nativeEndpoint"]) {
        if(!access("/var/run/VirtualMacRadioOwned-v1/exclusive-bluetooth.sock",W_OK)){
            if(!_nativeBluetooth)_nativeBluetooth=[VM27SharedBluetoothHostV1 new];
            completion([_nativeBluetooth startExclusiveControllerLifecycle]);return;
        }
        if (!_nativeBluetooth) _nativeBluetooth=[VM27SharedBluetoothHostV1 new];
        if (!_classicBluetooth) _classicBluetooth=[VM27SharedBluetoothClassicHostV1 new];
        if(![_classicBluetooth start])fprintf(stderr,"[SharedBluetoothClassic] endpoint unavailable\n");
        completion([_nativeBluetooth start]); return;
    }
    if ([method isEqualToString:@"bluetooth.acceptanceMouseGATTProbe"]) {
        if(!_nativeBluetooth){completion(Failure(ENETDOWN,@"Native Bluetooth endpoint is not running"));return;}
        [_nativeBluetooth probeAcceptanceMouseGATTWithCompletion:completion];return;
    }
    if ([method isEqualToString:@"wifi.detachShared"]) {
        _attached = NO; _attachedSSID=nil;
        if (_wifiDescriptor >= 0) {close(_wifiDescriptor); _wifiDescriptor=-1;}
        VM27NativeNetworkStopV1(_wifiNetwork); _wifiNetwork=NULL;
        completion([self wifiState]); return;
    }
    if ([method isEqualToString:@"wifi.attachShared"]) {
        NSDictionary *state = [self wifiState];
        NSDictionary *wifi = state[@"wifi"];
        NSString *wanted = request[@"ssidBase64"];
        if (![wanted isKindOfClass:NSString.class] || ![wifi[@"hostAssociated"] boolValue] ||
            ![wanted isEqualToString:wifi[@"network"][@"ssidBase64"]]) {
            completion(Failure(ENETUNREACH, @"Shared attachment requires the iPad's current associated SSID")); return;
        }
        if (_wifiDescriptor < 0) {
            int error=VM27NativeNetworkStartSharedWiFiV1(&_wifiNetwork,&_wifiDescriptor);
            if(error){completion(Failure(error,@"Shared Wi-Fi packet transport unavailable"));return;}
        }
        _attachedSSID=[wanted copy];_attached=YES;
        completion([self wifiState]);return;
    }
    if ([method isEqualToString:@"wifi.data"]) {
        NSDictionary *state=[self wifiState];
        if(![state[@"wifi"][@"hostAssociated"]boolValue]||
            ![state[@"wifi"][@"dataPathConfigured"]boolValue]) {
            completion(Failure(ENETDOWN,@"The shared host Wi-Fi association changed"));return;
        }
        NSArray *frames=request[@"frames"];
        if(![frames isKindOfClass:NSArray.class]||frames.count>24) {
            completion(Failure(EINVAL,@"Invalid shared Wi-Fi frame batch"));return;
        }
        NSMutableArray<NSData *> *decoded=[NSMutableArray arrayWithCapacity:frames.count];
        for(id value in frames) {
            NSData *frame=[value isKindOfClass:NSString.class]?
                [[NSData alloc]initWithBase64EncodedString:value options:0]:nil;
            if(frame.length<14||frame.length>1518) {
                completion(Failure(EINVAL,@"Invalid Ethernet frame size"));return;
            }
            [decoded addObject:frame];
        }
        unsigned sent=0,dropped=0;
        for(NSData *frame in decoded) {
            ssize_t count=send(_wifiDescriptor,frame.bytes,frame.length,MSG_DONTWAIT);
            if(count==(ssize_t)frame.length)++sent;else ++dropped;
        }
        NSMutableArray *received=[NSMutableArray array];
        for(unsigned i=0;i<24;++i) {
            uint8_t packet[2048];ssize_t count=recv(_wifiDescriptor,packet,sizeof(packet),MSG_DONTWAIT);
            if(count<0&&errno==EINTR){--i;continue;}
            if(count<0)break;
            if(count>=14&&count<=1518)
                [received addObject:[[NSData dataWithBytes:packet length:(NSUInteger)count]base64EncodedStringWithOptions:0]];
            else ++dropped;
        }
        completion(@{@"ok":@YES,@"frames":received,@"sent":@(sent),@"dropped":@(dropped)});return;
    }
    if ([method isEqualToString:@"wifi.scan"]) {
        if (!_device || !_scan || !_scanCancel) { completion(Failure(ENODEV, @"Native scan API unavailable")); return; }
        if (_scanOutstanding) {
            completion(Failure(EBUSY, @"A native radio scan is already outstanding")); return;
        }
        _scanOutstanding = YES; _scanReply = [completion copy];
        uint64_t sequence = ++_scanSequence;
        VM27SharedRadioScanContextV1 *context = [VM27SharedRadioScanContextV1 new];
        context.owner = self; context.sequence = sequence;
        void *token = (void *)CFBridgingRetain(context);
        _scanToken = token;
        int nativeStatus = _scan(_device, (__bridge CFDictionaryRef)@{}, ScanDone, token);
        if (nativeStatus) {
            _scanCancel(_device); _scanToken = NULL; CFRelease(token);
            // These exact native preflight failures precede callback/context
            // storage, so no callback can consume their retained token.
            if (nativeStatus == -3930 || nativeStatus == -3900) {
                _scanOutstanding = NO;
            }
            void (^reply)(NSDictionary *) = _scanReply; _scanReply = nil;
            reply(@{@"ok":@NO, @"error":@{@"code":@(EIO),
                @"nativeStatus":@(nativeStatus), @"message":@"Native scan start failed"}});
            return;
        }
        __weak VM27SharedRadioHostV1 *weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 12 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            VM27SharedRadioHostV1 *owner = weakSelf;
            if (!owner || owner->_invalidated || sequence != owner->_scanSequence || !owner->_scanReply) return;
            owner->_scanCancel(owner->_device);
            if (owner->_scanToken) CFRelease(owner->_scanToken);
            owner->_scanToken = NULL;
            // Keep scan admission closed until this client is recreated: a
            // cancelled callback does not prove the underlying scan ended.
            void (^reply)(NSDictionary *) = owner->_scanReply; owner->_scanReply = nil;
            reply(Failure(ETIMEDOUT, @"Native scan callback deadline exceeded"));
        });
        return;
    }
    if ([method hasPrefix:@"bluetooth."]) {
        if (!_bluetooth) _bluetooth = [[CBCentralManager alloc] initWithDelegate:self
            queue:dispatch_get_main_queue() options:@{CBCentralManagerOptionShowPowerAlertKey:@NO}];
        if ([method isEqualToString:@"bluetooth.state"]) {
            completion(@{@"ok":@YES, @"state":@(_bluetooth.state),
                @"transport":@"host-CoreBluetooth", @"rawHCITransport":@NO}); return;
        }
        if ([method isEqualToString:@"bluetooth.scan"]) {
            if (_bluetooth.state != CBManagerStatePoweredOn) {
                completion(Failure(EAGAIN, @"Host Bluetooth is not ready or permission is unavailable")); return;
            }
            if (_bleReply) { completion(Failure(EBUSY, @"Bluetooth scan already outstanding")); return; }
            _bleDevices = [NSMutableDictionary dictionary]; _bleReply = [completion copy];
            uint64_t sequence = ++_bleSequence;
            [_bluetooth scanForPeripheralsWithServices:nil options:@{CBCentralManagerScanOptionAllowDuplicatesKey:@NO}];
            __weak VM27SharedRadioHostV1 *weakSelf = self;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                VM27SharedRadioHostV1 *owner = weakSelf;
                if (!owner || owner->_invalidated || owner->_bleSequence != sequence || !owner->_bleReply) return;
                [owner->_bluetooth stopScan];
                void (^reply)(NSDictionary *) = owner->_bleReply; owner->_bleReply = nil;
                reply(@{@"ok":@YES, @"source":@"native-CoreBluetooth-LE-scan",
                    @"devices":owner->_bleDevices.allValues});
                owner->_bleDevices = nil;
            }); return;
        }
    }
    completion(Failure(ENOTSUP, @"Unsupported shared radio operation"));
}
- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
    if (central.state != CBManagerStatePoweredOn && _bleReply) {
        [central stopScan]; void (^reply)(NSDictionary *) = _bleReply; _bleReply = nil;
        reply(Failure(ENETDOWN, @"Host Bluetooth became unavailable"));
    }
}
- (void)centralManager:(CBCentralManager *)central didDiscoverPeripheral:(CBPeripheral *)peripheral
    advertisementData:(NSDictionary<NSString *,id> *)data RSSI:(NSNumber *)RSSI {
    (void)central;
    if (_invalidated || !_bleReply || (_bleDevices.count >= 128 && !_bleDevices[peripheral.identifier])) return;
    NSMutableArray *services = [NSMutableArray array];
    for (CBUUID *uuid in data[CBAdvertisementDataServiceUUIDsKey]) [services addObject:uuid.UUIDString];
    _bleDevices[peripheral.identifier] = @{@"identifier":peripheral.identifier.UUIDString,
        @"name":data[CBAdvertisementDataLocalNameKey] ?: peripheral.name ?: @"",
        @"rssi":RSSI, @"services":services, @"connectable":data[CBAdvertisementDataIsConnectable] ?: @NO};
}
- (void)invalidate {
    if (_invalidated) return;
    _invalidated = YES; _attached = NO; ++_scanSequence; ++_bleSequence;
    [_ownedWiFi invalidate];_ownedWiFi=nil;
    _attachedSSID=nil;
    if(_wifiDescriptor>=0){close(_wifiDescriptor);_wifiDescriptor=-1;}
    VM27NativeNetworkStopV1(_wifiNetwork);_wifiNetwork=NULL;
    [_nativeBluetooth invalidate]; _nativeBluetooth=nil;
    [_classicBluetooth invalidate]; _classicBluetooth=nil;
    [self releaseNativeWiFiReader];
    [_bluetooth stopScan]; _bluetooth.delegate = nil;
    void (^scanReply)(NSDictionary *) = _scanReply; _scanReply = nil;
    void (^bleReply)(NSDictionary *) = _bleReply; _bleReply = nil;
    if (scanReply) scanReply(Failure(ECANCELED, @"VM radio session closed"));
    if (bleReply) bleReply(Failure(ECANCELED, @"VM radio session closed"));
}
@end
