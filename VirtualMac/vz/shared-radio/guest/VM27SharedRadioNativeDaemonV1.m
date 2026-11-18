// Real host scan -> bounded native IO80211 driver messages. No network or
// device identifiers, advertising bytes, credentials or keys enter the log.
#define VM27_SHARED_RADIO_CLIENT_LIBRARY 1
#import "VM27SharedRadioGuestLinkV1.m"
#import <IOKit/IOKitLib.h>
#import <IOKit/pwr_mgt/IOPMLib.h>
#include "VM27IndependentWiFiDevelopmentV1.inc"
#import "VM27SharedBluetoothBonjourGuestV1.h"
#include "../common/vm27_shared_radio_native_v1.h"
#include "VM27SharedWiFiNetworkSetupV1.inc"

static volatile sig_atomic_t stopping;
static BOOL networkPriorityPrepared;
static void releaseHostActivity(IOPMAssertionID *assertion){
    if(*assertion!=kIOPMNullAssertionID){IOPMAssertionRelease(*assertion);*assertion=kIOPMNullAssertionID;}
}
static void stopNow(int value) { (void)value; stopping = 1; }
static NSData *bytes(id value) {
    if ([value isKindOfClass:NSDictionary.class] && [value[@"base64"] isKindOfClass:NSString.class])
        return [[NSData alloc] initWithBase64EncodedString:value[@"base64"] options:0];
    return nil;
}
static BOOL address(id value, uint8_t output[6]) {
    NSData *data = bytes(value);
    if (data.length == 6) memcpy(output, data.bytes, 6);
    else if ([value isKindOfClass:NSString.class]) {
        NSArray *parts = [value componentsSeparatedByString:@":"];
        if (parts.count != 6) return NO;
        for (unsigned i = 0; i < 6; ++i) {
            NSString *part = parts[i]; unsigned number;
            NSScanner *scanner = [NSScanner scannerWithString:part];
            if (!part.length || part.length > 2 || ![scanner scanHexInt:&number] || !scanner.isAtEnd || number > 255) return NO;
            output[i] = (uint8_t)number;
        }
    } else return NO;
    unsigned nonzero = 0; for (unsigned i = 0; i < 6; ++i) nonzero |= output[i];
    return nonzero && !(output[0] & 1);
}
static BOOL number(id value, long minimum, long maximum, long *output) {
    if (![value isKindOfClass:NSNumber.class]) return NO;
    long result = [value longValue];
    if (result < minimum || result > maximum) return NO;
    *output = result; return YES;
}
static BOOL convertRow(NSDictionary *row, VM27NativeRadioBSSV1 *out) {
    if (![row isKindOfClass:NSDictionary.class]) return NO;
    bzero(out, sizeof(*out));
    if (!address(row[@"BSSID"], out->bssid)) return NO;
    NSData *ssid = [row[@"ssidBase64"] isKindOfClass:NSString.class]
        ? [[NSData alloc] initWithBase64EncodedString:row[@"ssidBase64"] options:0]
        : (row[@"ssidBase64"] ? nil : [NSData data]);
    if (!ssid || ssid.length > 32) return NO;
    out->ssidLength = (uint8_t)ssid.length; memcpy(out->ssid, ssid.bytes, ssid.length);
    long value;
    if (!number(row[@"CHANNEL"], 1, 196, &value)) return NO;
    out->channel = (uint16_t)value;
    out->rssi = number(row[@"RSSI"], -127, 0, &value) ? (int8_t)value : -127;
    if (number(row[@"CAPABILITIES"], 0, 65535, &value)) out->capability = (uint16_t)value;
    if (number(row[@"BEACON_INTERVAL"], 0, 65535, &value)) out->beaconInterval = (uint16_t)value;
    if (number(row[@"ageMS"], 0, UINT32_MAX, &value)) out->ageMS=(uint32_t)value;
    NSData *ie = bytes(row[@"IE"]);
    BOOL haveSSID = NO;
    if (ie) {
        const uint8_t *raw = ie.bytes; size_t offset = 0, stored = 0;
        while (offset < ie.length) {
            if (ie.length - offset < 2 || raw[offset + 1] > ie.length - offset - 2) return NO;
            size_t length = 2 + raw[offset + 1];
            if (stored + length <= VM27_NATIVE_RADIO_MAX_IE) {
                memcpy(out->ies + stored, raw + offset, length); stored += length;
                haveSSID |= raw[offset] == 0;
            }
            offset += length;
        }
        out->ieLength = (uint16_t)stored;
    }
    // Construct only the SSID element from the host's actual bytes when the
    // host API omitted it. Security and capability elements are never invented.
    if (!haveSSID && out->ieLength + 2 + ssid.length <= VM27_NATIVE_RADIO_MAX_IE) {
        memmove(out->ies + 2 + ssid.length, out->ies, out->ieLength);
        out->ies[0] = 0; out->ies[1] = (uint8_t)ssid.length;
        memcpy(out->ies + 2, ssid.bytes, ssid.length); out->ieLength += 2 + ssid.length;
    }
    return YES;
}
static int makeListener(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_vm address = {0};
    address.svm_len = sizeof(address); address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_ANY; address.svm_port = VM27_RADIO_VSOCK_PORT;
    if (bind(fd, (void *)&address, sizeof(address)) || listen(fd, 1)) { close(fd); return -1; }
    return fd;
}
static VM27GuestRadioClientV1 *acceptHost(int listener) {
    static unsigned reports;
    while (!stopping) {
        struct pollfd item = {listener, POLLIN, 0};
        int ready = poll(&item, 1, 1000);
        if (ready < 0) { if (errno == EINTR) continue; return nil; }
        if (!ready) continue;
        struct sockaddr_vm peer = {0}; socklen_t size = sizeof(peer);
        int fd = accept(listener, (void *)&peer, &size);
        if (fd < 0) return nil;
        int flags = fcntl(fd, F_GETFL), one = 1;
        if (size != sizeof(peer) || peer.svm_family != AF_VSOCK || peer.svm_cid != VMADDR_CID_HOST ||
            flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) || setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) {
            close(fd); continue;
        }
        if (reports < 8) fprintf(stderr, "Native radio host accepted; handshake beginning\n");
        VM27GuestRadioClientV1 *client = [[VM27GuestRadioClientV1 alloc] initWithOwnedFD:fd];
        int error = 0;
        NSDictionary *hello = [client call:@{@"client":@"macOS-native-shared-radio", @"protocol":@1} hello:YES error:&error];
        if (hello && [hello[@"ok"] boolValue] && !error) return client;
        if (reports++ < 8) fprintf(stderr, "Native radio handshake failed error=%d replyPresent=%d\n", error, hello != nil);
    }
    return nil;
}
static BOOL ExplicitAssociationSupported, IndependentAssociationSupported;
static io_connect_t openDriver(void) {
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("VM27SharedRadioBackendV1"));
    io_connect_t connection = IO_OBJECT_NULL;
    if (service) {
        CFTypeRef feature=IORegistryEntryCreateCFProperty(service,CFSTR("NativeExplicitAssociationAvailable"),kCFAllocatorDefault,0);
        ExplicitAssociationSupported=feature&&CFEqual(feature,kCFBooleanTrue);if(feature)CFRelease(feature);
        feature=IORegistryEntryCreateCFProperty(service,CFSTR("NativeIndependentAssociationAvailable"),kCFAllocatorDefault,0);
        IndependentAssociationSupported=feature&&CFEqual(feature,kCFBooleanTrue);if(feature)CFRelease(feature);
        kern_return_t result = IOServiceOpen(service, mach_task_self(), VM27_NATIVE_RADIO_CLIENT_TYPE, &connection);
        IOObjectRelease(service);
        if (result) { fprintf(stderr, "Native radio driver open failed status=0x%x\n", result); return IO_OBJECT_NULL; }
    }
    return connection;
}
static void hostState(VM27NativeRadioSnapshotV1 *snapshot, NSDictionary *state) {
    NSDictionary *wifi = [state[@"wifi"] isKindOfClass:NSDictionary.class] ? state[@"wifi"] : nil;
    snapshot->hostPowered = [wifi[@"hostPowered"] boolValue];
    snapshot->hostAssociated = [wifi[@"hostAssociated"] boolValue];
    snapshot->dataPathConfigured = [wifi[@"dataPathConfigured"] boolValue];
    snapshot->reserved[0] = ExplicitAssociationSupported&&[wifi[@"mode"]isEqual:@"independent-native-auxiliary-station"]?VM27_NATIVE_STATE_EXPLICIT_ASSOCIATION:0;
    if(IndependentAssociationSupported&&[wifi[@"mode"]isEqual:@"independent-native-managed-station"])
        snapshot->reserved[0]=VM27_NATIVE_STATE_MANAGED_ASSOCIATION;
    snapshot->recordCount=0;
    if(snapshot->hostAssociated&&convertRow(wifi[@"network"],&snapshot->records[0])) {
        snapshot->records[0].flags=VM27_NATIVE_BSS_CURRENT_HOST;snapshot->recordCount=1;
    }
}
static NSDictionary *associationState(VM27NativeRadioSnapshotV1 *snapshot,
                                      NSDictionary *reply, NSDictionary *knownState) {
    BOOL metadata=[reply[@"wifi"]isKindOfClass:NSDictionary.class];
    if(!metadata&&!snapshot->status)snapshot->status=EPROTO;
    BOOL succeeded=!snapshot->status&&[reply[@"ok"]boolValue]&&metadata;
    NSDictionary *next=metadata?reply:knownState;
    if(!succeeded){
        // An association error is not a host power/capability observation.
        // Preserve verified metadata while reporting this guest link down.
        NSMutableDictionary *copy=[next mutableCopy]?:[NSMutableDictionary new];
        NSMutableDictionary *wifi=[next[@"wifi"]isKindOfClass:NSDictionary.class]?[next[@"wifi"]mutableCopy]:[NSMutableDictionary new];
        wifi[@"hostAssociated"]=@NO;wifi[@"dataPathConfigured"]=@NO;
        [wifi removeObjectForKey:@"network"];copy[@"wifi"]=wifi;next=copy;
    }
    hostState(snapshot,next);
    return next;
}
static void collect(VM27NativeRadioSnapshotV1 *snapshot, NSDictionary *scan, NSMutableDictionary *summary) {
    VM27NativeRadioBSSV1 current={0};BOOL haveCurrent=snapshot->recordCount!=0;
    if(haveCurrent)current=snapshot->records[0];snapshot->recordCount=0;
    NSArray *rows = [scan[@"networks"] isKindOfClass:NSArray.class] ? scan[@"networks"] : @[];
    unsigned invalid = 0, withIE = 0, privateBSS = 0;
    NSMutableDictionary *rejected = [NSMutableDictionary dictionary];
    NSMutableDictionary *kinds = [NSMutableDictionary dictionary];
    for (NSDictionary *row in rows) {
        if (![row isKindOfClass:NSDictionary.class]) { ++invalid; continue; }
        for (NSString *key in @[@"BSSID",@"CHANNEL",@"RSSI",@"IE",@"CAPABILITIES"])
            if (!kinds[key]) kinds[key] = row[key] ? NSStringFromClass([row[key] class]) : @"absent";
        VM27NativeRadioBSSV1 record;
        if (!convertRow(row, &record)) {
            ++invalid; NSString *reason = @"informationElements"; uint8_t mac[6]; long channel;
            NSData *ssid = [row[@"ssidBase64"] isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:row[@"ssidBase64"] options:0] : nil;
            if (!address(row[@"BSSID"], mac)) reason = @"address";
            else if (!ssid || ssid.length > 32) reason = @"SSID";
            else if (!number(row[@"CHANNEL"], 1, 196, &channel)) reason = @"channel";
            rejected[reason] = @([rejected[reason] unsignedIntValue]+1); continue;
        }
        withIE += bytes(row[@"IE"]).length != 0; privateBSS += !!(record.capability & 0x10);
        if (snapshot->recordCount < VM27_NATIVE_RADIO_MAX_BSS) snapshot->records[snapshot->recordCount++] = record;
    }
    summary[@"hostRows"] = @(rows.count); summary[@"nativeRows"] = @(snapshot->recordCount);
    summary[@"invalidRows"] = @(invalid); summary[@"rejectedFieldCounts"] = rejected; summary[@"rowsWithHostIE"] = @(withIE);
    summary[@"rowsWithPrivacyBit"] = @(privateBSS); summary[@"fieldTypes"] = kinds;
    if(haveCurrent) {
        BOOL found=NO;
        for(uint32_t i=0;i<snapshot->recordCount;++i)if(!memcmp(snapshot->records[i].bssid,current.bssid,6)) {
            snapshot->records[i].flags|=VM27_NATIVE_BSS_CURRENT_HOST;found=YES;break;
        }
        if(!found&&snapshot->recordCount<VM27_NATIVE_RADIO_MAX_BSS)snapshot->records[snapshot->recordCount++]=current;
    }
    summary[@"nativeRows"]=@(snapshot->recordCount);
}
static IOReturn publish(io_connect_t connection, VM27NativeRadioSnapshotV1 *snapshot) {
    snapshot->version = VM27_NATIVE_RADIO_PROTOCOL;
    snapshot->byteSize = offsetof(VM27NativeRadioSnapshotV1, records) + snapshot->recordCount * sizeof(VM27NativeRadioBSSV1);
    return IOConnectCallStructMethod(connection, VM27_NATIVE_METHOD_PUBLISH, snapshot, snapshot->byteSize, NULL, NULL);
}
static IOReturn exchangePackets(io_connect_t connection,VM27GuestRadioClientV1 *client,int *error) {
    NSMutableArray *frames=[NSMutableArray array];
    for(unsigned i=0;i<24;++i) {
        VM27NativeRadioPacketV1 packet={0};size_t size=sizeof(packet);
        IOReturn result=IOConnectCallStructMethod(connection,VM27_NATIVE_METHOD_TX_PULL,NULL,0,&packet,&size);
        if(result)return result;
        if(size!=sizeof(packet)||packet.version!=VM27_NATIVE_RADIO_PROTOCOL||packet.byteSize!=sizeof(packet)||packet.reserved||packet.length>sizeof(packet.bytes))return kIOReturnBadArgument;
        if(!packet.length)break;
        if(packet.length<14)return kIOReturnBadArgument;
        [frames addObject:[[NSData dataWithBytes:packet.bytes length:packet.length]base64EncodedStringWithOptions:0]];
    }
    NSDictionary *reply=wifiCall(client,@{@"method":@"wifi.data",@"frames":frames},error);
    if(*error)return kIOReturnError;
    if(![reply[@"ok"]boolValue])return kIOReturnNotReady;
    NSArray *received=reply[@"frames"];
    if(![received isKindOfClass:NSArray.class]||received.count>24)return kIOReturnBadArgument;
    for(id value in received) {
        NSData *data=[value isKindOfClass:NSString.class]?[[NSData alloc]initWithBase64EncodedString:value options:0]:nil;
        if(data.length<14||data.length>1518)return kIOReturnBadArgument;
        VM27NativeRadioPacketV1 packet={0};packet.version=VM27_NATIVE_RADIO_PROTOCOL;packet.byteSize=sizeof(packet);
        packet.length=(uint32_t)data.length;memcpy(packet.bytes,data.bytes,data.length);
        IOReturn result=IOConnectCallStructMethod(connection,VM27_NATIVE_METHOD_RX_PUSH,&packet,sizeof(packet),NULL,NULL);
        if(result)return result;
    }
    return kIOReturnSuccess;
}
static NSDictionary *associateManaged(io_connect_t connection,VM27GuestRadioClientV1 *client,const VM27NativeRadioRequestV1 *request,int *error) {
    VM27NativeRadioJoinDetailsV1 details={0};size_t size=sizeof(details);uint32_t sequence=request->sequence;
    IOReturn result=IOConnectCallStructMethod(connection,VM27_NATIVE_METHOD_JOIN_DETAILS,&sequence,sizeof(sequence),&details,&size);
    BOOL valid=!result&&size==sizeof(details)&&vm27_native_join_details_match_v1(&details,request);
    NSDictionary *reply=nil;
    if(valid){@autoreleasepool{
        // This request traverses only the already authenticated VM radio link.
        // PMK bytes and encoded request never enter a log or persistent file.
        NSMutableDictionary *body=[@{@"method":@"wifi.associate",@"ssidBase64":[[NSData dataWithBytes:details.ssid length:details.ssidLength]base64EncodedStringWithOptions:0],
            @"bssidBase64":[[NSData dataWithBytes:details.bssid length:6]base64EncodedStringWithOptions:0],
            @"macBase64":[[NSData dataWithBytes:details.mac length:6]base64EncodedStringWithOptions:0],
            @"channel":@(details.channel),@"keyType":@(details.keyType)}mutableCopy];
        if(details.keyType==VM27_NATIVE_JOIN_PMK)body[@"pmkBase64"]=[[NSData dataWithBytes:details.pmk length:32]base64EncodedStringWithOptions:0];
        reply=wifiCall(client,body,error);[body removeAllObjects];
    }}else *error=EPROTO;
    volatile uint8_t *erase=(volatile uint8_t *)&details;for(size_t i=0;i<sizeof(details);i++)erase[i]=0;
    return reply;
}
int main(int argc, char **argv) { @autoreleasepool {
    BOOL inspect = argc == 2 && !strcmp(argv[1], "--inspect-host-scan");
    BOOL diagnose = argc == 2 && !strcmp(argv[1], "--diagnose-once");
    if (!inspect && !diagnose && (argc != 2 || strcmp(argv[1], "--run"))) return 64;
    if (!inspect && geteuid()) return EPERM;
    int independentError=initializeIndependentWiFi();if(independentError)return independentError;
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, stopNow); signal(SIGINT, stopNow);
    if (diagnose) { signal(SIGALRM, stopNow); alarm(90); }
    int listener = makeListener(); if (listener < 0) return errno;
    fprintf(stderr, "Native radio listener ready port=%u\n", VM27_RADIO_VSOCK_PORT);
    VM27NativeRadioSnapshotV1 *snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) { close(listener); return ENOMEM; }
    int status = 0;
    while (!stopping) { @autoreleasepool {
        VM27GuestRadioClientV1 *client = acceptHost(listener);
        if (!client) { status = stopping ? 0 : EIO; break; }
        int error = 0;
        NSDictionary *state = wifiCall(client,@{@"method":@"wifi.state"},&error);
        if (!state || error) {
            static unsigned failures;
            if (failures++ < 8) fprintf(stderr, "Native radio host state failed error=%d replyPresent=%d\n", error, state != nil);
            continue;
        }
        if (inspect) {
            bzero(snapshot, sizeof(*snapshot)); hostState(snapshot, state);
            NSDictionary *scan = wifiCall(client,@{@"method":@"wifi.scan"},&error);
            NSMutableDictionary *report = [@{@"schema":@1,@"radioIdentifiersRedacted":@YES,
                @"transport":@"native-AF_VSOCK",@"hostPowered":@(snapshot->hostPowered),
                @"scanOK":@([scan[@"ok"] boolValue]),@"error":@(error)} mutableCopy];
            collect(snapshot, scan, report);
            NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:NULL];
            if (data) { fwrite(data.bytes, 1, data.length, stdout); fputc('\n', stdout); }
            status = error ?: ([scan[@"ok"] boolValue] ? 0 : EIO); break;
        }
        // A running guest transport must survive the VM image's one-minute
        // automatic system-sleep default. Scope this assertion to the actual
        // host session; it neither changes saved power settings nor prevents
        // a user explicitly putting the guest to sleep.
        IOPMAssertionID hostActivity __attribute__((cleanup(releaseHostActivity)))=kIOPMNullAssertionID;
        IOReturn powerStatus=IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep,
            kIOPMAssertionLevelOn,CFSTR("VirtualMac active guest radio transport"),&hostActivity);
        fprintf(stderr,"Native host-session idle-sleep assertion status=0x%x active=%d\n",powerStatus,hostActivity!=kIOPMNullAssertionID);
        VM27SharedBluetoothBonjourGuestV1 *bluetooth=[VM27SharedBluetoothBonjourGuestV1 new];
        NSDictionary *endpoint=[client call:@{@"method":@"bluetooth.nativeEndpoint"} hello:NO error:&error];
        if(endpoint&&[endpoint[@"ok"]boolValue])[bluetooth startWithEndpoint:endpoint];
        else fprintf(stderr,"Native Bluetooth endpoint unavailable error=%d\n",error);
        if(error)continue;
        fprintf(stderr, "Native radio driver open beginning\n"); fflush(stderr);
        io_connect_t connection = openDriver();
        // A fresh guest can start the built-in Bluetooth transport before its
        // Wi-Fi kext has been installed/approved. Keep its real Bonjour endpoint
        // and host session alive while waiting; otherwise Bluetooth disappears
        // every time the optional Wi-Fi driver cannot yet be opened.
        unsigned waiting = 0;
        while (!connection && !stopping && !error) { @autoreleasepool {
            if (!waiting) fprintf(stderr,"Native Wi-Fi driver pending; Bluetooth relay remains active\n");
            if (!(waiting++ % 10)) {
                NSDictionary *alive = [client call:@{@"method":@"bluetooth.state"} hello:NO error:&error];
                if (!alive || error) break;
            }
            sleep(waiting < 20 ? 1 : 5);
            if (!stopping && !error) connection = openDriver();
        } }
        if (!connection) { [bluetooth invalidate]; continue; }
        fprintf(stderr, "Native radio driver opened; state publish beginning\n"); fflush(stderr);
        if(!networkPriorityPrepared)networkPriorityPrepared=VM27PrepareNativeWiFiNetworkV1();
        bzero(snapshot, sizeof(*snapshot)); snapshot->kind = VM27_NATIVE_REQUEST_STATE; hostState(snapshot, state);
        IOReturn result = publish(connection, snapshot);
        fprintf(stderr, "Native radio initial state published driver=0x%x\n", result); fflush(stderr);
        unsigned ticks = 0;BOOL dataActive=NO;
        while (!stopping && !error && result == kIOReturnSuccess) { @autoreleasepool {
            VM27NativeRadioRequestV1 request = {0}; size_t size = sizeof(request);
            result = IOConnectCallStructMethod(connection, VM27_NATIVE_METHOD_POLL, NULL, 0, &request, &size);
            if (result || size != sizeof(request) || request.version != VM27_NATIVE_RADIO_PROTOCOL ||
                request.byteSize != sizeof(request) || request.reserved) {
                fprintf(stderr,"Native poll rejected status=0x%x size=%zu version=%u declared=%u reserved=%llu\n",result,size,request.version,request.byteSize,(unsigned long long)request.reserved);
                break;
            }
            if (request.kind == VM27_NATIVE_REQUEST_SCAN) {
                bzero(snapshot, sizeof(*snapshot)); snapshot->kind = VM27_NATIVE_REQUEST_SCAN; snapshot->sequence = request.sequence;
                hostState(snapshot, state);
                NSDictionary *scan = wifiCall(client,@{@"method":@"wifi.scan"},&error);
                snapshot->status = error ?: ([scan[@"ok"] boolValue] ? 0 : EIO);
                NSMutableDictionary *summary = [NSMutableDictionary dictionary]; collect(snapshot, scan, summary);
                result = publish(connection, snapshot);
                fprintf(stderr, "Native scan completed hostRows=%u nativeRows=%u error=%d driver=0x%x\n",
                    [summary[@"hostRows"] unsignedIntValue], snapshot->recordCount, snapshot->status, result);
                fflush(stderr);
                if (diagnose) stopping = 1;
            } else if(request.kind==VM27_NATIVE_REQUEST_JOIN||request.kind==VM27_NATIVE_REQUEST_DETACH) {
                if(request.ssidLength>32){result=kIOReturnBadArgument;break;}
                BOOL join=request.kind==VM27_NATIVE_REQUEST_JOIN;
                NSString *ssid=[[NSData dataWithBytes:request.ssid length:request.ssidLength]base64EncodedStringWithOptions:0];
                NSString *mac=[[NSData dataWithBytes:request.mac length:6]base64EncodedStringWithOptions:0];
                BOOL managed=join&&IndependentAssociationSupported&&[state[@"wifi"][@"mode"]isEqual:@"independent-native-managed-station"];
                uint64_t associationStarted=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
                NSDictionary *associationReply=managed?associateManaged(connection,client,&request,&error):wifiCall(client,join?@{@"method":@"wifi.attachShared",@"ssidBase64":ssid,@"macBase64":mac}:@{@"method":@"wifi.detachShared"},&error);
                bzero(snapshot,sizeof(*snapshot));snapshot->kind=request.kind;snapshot->sequence=request.sequence;
                NSInteger hostError=[associationReply[@"error"][@"code"]integerValue];
                snapshot->status=error?:([associationReply[@"ok"]boolValue]?0:(hostError>0&&hostError<256?(int)hostError:EIO));
                state=associationState(snapshot,associationReply,state);
                result=publish(connection,snapshot);
                dataActive=join&&!snapshot->status&&snapshot->dataPathConfigured&&result==kIOReturnSuccess;
                fprintf(stderr,"Native shared association kind=%u status=%d configured=%u driver=0x%x elapsedMS=%llu\n",request.kind,snapshot->status,snapshot->dataPathConfigured,result,(unsigned long long)((clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)-associationStarted)/NSEC_PER_MSEC));
                // WCL can cancel a join while the physical firmware is still
                // answering it. The backend rejects that old sequence; keep
                // the transport alive to receive the pending detach/new join.
                if(result==kIOReturnNotReady&&!error){
                    fprintf(stderr,"Native association completion superseded; session retained\n");
                    result=kIOReturnSuccess;
                }
            } else if (request.kind != VM27_NATIVE_REQUEST_NONE) { result = kIOReturnBadArgument; break; }
            else dataActive=request.ssidLength>0;
            if(!stopping&&dataActive&&!error&&!result) {
                IOReturn packets=exchangePackets(connection,client,&error);
                if(packets==kIOReturnNotReady)dataActive=NO;
                else if(packets)result=packets;
            }
            if ((++ticks % 100) == 0) {
                if(!networkPriorityPrepared){
                    networkPriorityPrepared=VM27PrepareNativeWiFiNetworkV1();
                    if(networkPriorityPrepared)fprintf(stderr,"Native Wi-Fi first-install network priority prepared\n");
                }
                state = wifiCall(client,@{@"method":@"wifi.state"},&error);
                if (!state || ![state[@"ok"] boolValue] || error) {
                    fprintf(stderr,"Native periodic Wi-Fi state failed transport=%d hostStatus=%ld\n",error,(long)[state[@"error"][@"code"]integerValue]);
                    break;
                }
                bzero(snapshot, sizeof(*snapshot)); snapshot->kind = VM27_NATIVE_REQUEST_STATE; hostState(snapshot, state);
                result = publish(connection, snapshot);
            }
            usleep(dataActive?10000:100000);
        } }
        IOServiceClose(connection);
        [bluetooth invalidate];
        fprintf(stderr, "Native radio session closed error=%d driver=0x%x\n", error, result);
    } }
    free(snapshot); close(listener); return status;
} }
