#import <Foundation/Foundation.h>
#include "../common/vm27_shared_radio_wire_v1.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#ifndef VM27_SHARED_RADIO_CLIENT_NO_VSOCK
#include <sys/vsock.h>
#endif
#include <unistd.h>

static int transfer(int fd, void *data, size_t length, BOOL sending, unsigned seconds) {
    uint8_t *bytes = data;
    size_t done = 0;
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + (uint64_t)seconds * NSEC_PER_SEC;
    while (done < length) {
        uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
        if (now >= deadline) return ETIMEDOUT;
        struct pollfd p = {fd, sending ? POLLOUT : POLLIN, 0};
        int result = poll(&p, 1, (int)((deadline - now) / NSEC_PER_MSEC + 1));
        if (result < 0) { if (errno == EINTR) continue; return errno; }
        if (!result) continue;
        if (p.revents & POLLNVAL) return EBADF;
        ssize_t count = sending ? send(fd, bytes + done, length - done, 0) : recv(fd, bytes + done, length - done, 0);
        if (count > 0) { done += (size_t)count; continue; }
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return count ? errno : EPIPE;
    }
    return 0;
}

@interface VM27GuestRadioClientV1 : NSObject {
    int _fd;
    uint64_t _sequence, _generation;
}
- (instancetype)initWithOwnedFD:(int)fd;
- (NSDictionary *)call:(NSDictionary *)request hello:(BOOL)hello error:(int *)error;
@end
@implementation VM27GuestRadioClientV1
- (instancetype)initWithOwnedFD:(int)fd { if ((self = [super init])) _fd = fd; return self; }
- (void)dealloc { close(_fd); }
- (NSDictionary *)call:(NSDictionary *)request hello:(BOOL)hello error:(int *)error {
    NSString *method=request[@"method"];
    unsigned seconds=[method isEqual:@"wifi.associate"]?30:[method isEqual:@"wifi.scan"]?23:18;
    NSData *data = [NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
    if (!data || data.length > VM27_RADIO_WIRE_MAX_PAYLOAD || _sequence == UINT64_MAX) { *error = EINVAL; return nil; }
    struct vm27_radio_frame_v1 frame = {hello ? VM27_RADIO_HELLO : VM27_RADIO_REQUEST,
        (uint32_t)data.length, ++_sequence, _generation};
    uint8_t header[32];
    *error = vm27_radio_header_encode_v1(header, &frame);
    if (!*error) *error = transfer(_fd, header, 32, YES, seconds);
    if (!*error) *error = transfer(_fd, (void *)data.bytes, data.length, YES, seconds);
    if (!*error) *error = transfer(_fd, header, 32, NO, seconds);
    struct vm27_radio_frame_v1 response;
    if (!*error) *error = vm27_radio_header_decode_v1(header, 32, &response);
    if (*error) return nil;
    if (response.request_id != _sequence || response.type != (hello ? VM27_RADIO_HELLO_REPLY : VM27_RADIO_REPLY) ||
        (!hello && response.generation != _generation)) { *error = EPROTO; return nil; }
    if (hello) _generation = response.generation;
    NSMutableData *payload = [NSMutableData dataWithLength:response.payload_bytes];
    *error = transfer(_fd, payload.mutableBytes, payload.length, NO, seconds);
    if (*error) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:payload options:0 error:NULL];
    if (![object isKindOfClass:NSDictionary.class]) { *error = EPROTO; return nil; }
    return object;
}
@end

#ifndef VM27_SHARED_RADIO_CLIENT_LIBRARY
int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 3 || (strcmp(argv[1], "--probe") && strcmp(argv[1], "--probe-bluetooth"))) return 64;
    BOOL bluetooth = !strcmp(argv[1], "--probe-bluetooth");
    signal(SIGPIPE, SIG_IGN);
    int listener = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (listener < 0) return errno;
    struct sockaddr_vm address = {0};
    address.svm_len = sizeof(address); address.svm_family = AF_VSOCK;
    address.svm_cid = VMADDR_CID_ANY; address.svm_port = VM27_RADIO_VSOCK_PORT;
    if (bind(listener, (void *)&address, sizeof(address)) || listen(listener, 1)) { int error = errno; close(listener); return error; }
    fprintf(stderr, "VM27_GUEST_RADIO_LISTEN port=%u\n", VM27_RADIO_VSOCK_PORT);
    struct pollfd p = {listener, POLLIN, 0};
    if (poll(&p, 1, 60000) <= 0) { close(listener); return ETIMEDOUT; }
    struct sockaddr_vm peer = {0}; socklen_t size = sizeof(peer);
    int fd = accept(listener, (void *)&peer, &size); close(listener);
    if (fd < 0) return errno;
    if (size != sizeof(peer) || peer.svm_family != AF_VSOCK || peer.svm_cid != VMADDR_CID_HOST) { close(fd); return EPERM; }
    int one = 1;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) ||
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) {
        int error = errno; close(fd); return error;
    }
    VM27GuestRadioClientV1 *client = [[VM27GuestRadioClientV1 alloc] initWithOwnedFD:fd];
    NSMutableDictionary *report = [@{@"schema":@1, @"transport":@"native-AF_VSOCK",
        @"peerCID":@(peer.svm_cid), @"nativeWiFiInterfaceCreated":@NO,
        @"radioIdentifiersRedacted":@YES} mutableCopy];
    int error = 0;
    NSDictionary *hello = [client call:@{@"client":@"macOS-guest-radio-link", @"protocol":@1} hello:YES error:&error];
    if (!hello || ![hello[@"ok"] boolValue]) return error ?: EPROTO;
    report[@"capabilities"] = [client call:@{@"method":@"capabilities"} hello:NO error:&error];
    NSDictionary *before = [client call:@{@"method":@"wifi.state"} hello:NO error:&error];
    if (!before || ![before[@"ok"] boolValue]) return error ?: EIO;
    NSDictionary *wifi = before[@"wifi"];
    report[@"hostAssociated"] = wifi[@"hostAssociated"];
    if ([wifi[@"hostAssociated"] boolValue] && wifi[@"network"][@"ssidBase64"]) {
        NSString *ssid = wifi[@"network"][@"ssidBase64"];
        NSDictionary *attached = [client call:@{@"method":@"wifi.attachShared", @"ssidBase64":ssid} hello:NO error:&error];
        report[@"sameSSIDControlAttachment"] = @([attached[@"wifi"][@"guestAttached"] boolValue]);
        NSDictionary *detached = [client call:@{@"method":@"wifi.detachShared"} hello:NO error:&error];
        report[@"hostAssociationPreservedAfterDetach"] = @([detached[@"wifi"][@"hostAssociated"] boolValue] &&
            [detached[@"wifi"][@"network"][@"ssidBase64"] isEqualToString:ssid]);
    }
    NSDictionary *scan = [client call:@{@"method":@"wifi.scan"} hello:NO error:&error];
    if (!scan) return error ?: EIO;
    report[@"wifiScan"] = @{@"ok":scan[@"ok"] ?: @NO,
        @"source":scan[@"source"] ?: (id)NSNull.null,
        @"networkCount":@([scan[@"networks"] count]), @"error":scan[@"error"] ?: (id)NSNull.null};
    if (bluetooth) {
        NSDictionary *state = nil;
        for (unsigned i = 0; i < 10; ++i) {
            state = [client call:@{@"method":@"bluetooth.state"} hello:NO error:&error];
            if (!state || ![state[@"ok"] boolValue] || [state[@"state"] integerValue] != 0) break;
            usleep(100000);
        }
        report[@"bluetoothState"] = state ?: (id)NSNull.null;
        if (state && [state[@"ok"] boolValue] && [state[@"state"] integerValue] == 5) {
            NSDictionary *devices = [client call:@{@"method":@"bluetooth.scan"} hello:NO error:&error];
            report[@"bluetoothScan"] = @{@"ok":devices[@"ok"] ?: @NO,
                @"deviceCount":@([devices[@"devices"] count]),
                @"source":devices[@"source"] ?: (id)NSNull.null,
                @"error":devices[@"error"] ?: (id)NSNull.null};
        }
        report[@"nativeGuestBluetoothHCICreated"] = @NO;
    }
    report[@"transportChecksPassed"] = @(error == 0);
    NSData *output = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (!output || ![output writeToFile:@(argv[2]) options:NSDataWritingAtomic error:NULL]) return EIO;
    fprintf(stderr, "VM27_GUEST_RADIO_PROBE_DONE errno=%d\n", error);
    return error;
} }
#endif
