#import "VM27SharedRadioStreamV1.h"
#include "../common/vm27_shared_radio_wire_v1.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

static int Transfer(int fd, void *buffer, size_t length, BOOL writeMode, int seconds, int cancellation) {
    uint8_t *bytes = buffer;
    size_t done = 0;
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + (uint64_t)seconds * NSEC_PER_SEC;
    while (done < length) {
        uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
        if (now >= deadline) return ETIMEDOUT;
        int timeout = (int)MIN((deadline - now + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC, INT_MAX);
        struct pollfd p[2] = {{fd, writeMode ? POLLOUT : POLLIN, 0}, {cancellation, POLLIN, 0}};
        int n = poll(p, 2, timeout);
        if (n < 0) { if (errno == EINTR) continue; return errno; }
        if (!n) continue;
        if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) return ECANCELED;
        if ((p[0].revents | p[1].revents) & POLLNVAL) return EBADF;
        ssize_t count = writeMode ? write(fd, bytes + done, length - done) : read(fd, bytes + done, length - done);
        if (count > 0) { done += (size_t)count; continue; }
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return count ? errno : EPIPE;
    }
    return 0;
}
static int Reply(int output, int cancellation, struct vm27_radio_frame_v1 request,
                 uint16_t type, uint64_t generation, NSDictionary *reply) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:reply options:NSJSONWritingSortedKeys error:NULL];
    if (!data || data.length > VM27_RADIO_WIRE_MAX_PAYLOAD) {
        data = [NSJSONSerialization dataWithJSONObject:@{@"ok":@NO,
            @"error":@{@"code":@(EMSGSIZE), @"message":@"Radio reply exceeds negotiated size"}}
            options:0 error:NULL];
    }
    struct vm27_radio_frame_v1 frame = {type, (uint32_t)data.length, request.request_id, generation};
    uint8_t header[32]; int error = vm27_radio_header_encode_v1(header, &frame);
    if (!error) error = Transfer(output, header, sizeof(header), YES, 5, cancellation);
    if (!error) error = Transfer(output, (void *)data.bytes, data.length, YES, 5, cancellation);
    return error;
}
int VM27SharedRadioServeStreamV1(int input, int output, int cancellation, VM27SharedRadioHostV1 *host) {
    if (NSThread.isMainThread || input < 0 || output < 0 || !host) return EINVAL;
    for (unsigned i = 0; i < 2; ++i) {
        int fd = i ? output : input;
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return errno;
    }
    int finalStatus = 0;
        uint64_t generation = 0, sequence = 0;
        arc4random_buf(&generation,sizeof(generation));if(!generation)generation=1;
        BOOL helloPending=YES;
        // Our clients start with HELLO request 1. Send its acknowledgement
        // immediately so neither endpoint depends on receiving guest data
        // before making the first host-to-guest write.
        struct vm27_radio_frame_v1 greeting={VM27_RADIO_HELLO,0,1,0};
        int greetingError=Reply(output,cancellation,greeting,VM27_RADIO_HELLO_REPLY,generation,
            @{@"ok":@YES,@"protocol":@1,@"maxPayload":@(VM27_RADIO_WIRE_MAX_PAYLOAD),
              @"mode":@"shared-host-association",@"nativeGuestDriverValidated":@NO});
        if(greetingError)return greetingError;
        for (;;) { @autoreleasepool {
            uint8_t header[32];
            int error = Transfer(input, header, sizeof(header), NO, 60, cancellation);
            if (error) { if (error != EPIPE) finalStatus = error; break; }
            struct vm27_radio_frame_v1 frame = {0};
            error = vm27_radio_header_decode_v1(header, sizeof(header), &frame);
            // A native VSOCK stream can lose the guest's initial write before
            // its first host write completes. Request 2 carrying this stream's
            // fresh generation proves the client received HELLO_REPLY 1. It
            // therefore also acknowledges our greeting if HELLO 1 was lost.
            BOOL greetingAcknowledged = !error && helloPending &&
                frame.type == VM27_RADIO_REQUEST && frame.request_id == 2 &&
                frame.generation == generation;
            if (error || frame.request_id <= sequence ||
                (helloPending && !greetingAcknowledged &&
                    (frame.type != VM27_RADIO_HELLO || frame.request_id != 1 || frame.generation)) ||
                (!helloPending && (frame.type != VM27_RADIO_REQUEST || frame.generation != generation))) {
                // Framing metadata only: never emit payload, identifiers or keys.
                static unsigned failures;
                if (__atomic_fetch_add(&failures, 1, __ATOMIC_RELAXED) < 8)
                    fprintf(stderr, "[SharedRadio] frame rejected decode=%d helloExpected=%d type=%u sequenceAdvanced=%d generationMatches=%d\n",
                        error, helloPending, frame.type, frame.request_id > sequence, frame.generation == generation);
                finalStatus = EPROTO; break;
            }
            NSMutableData *data = [NSMutableData dataWithLength:frame.payload_bytes];
            error = Transfer(input, data.mutableBytes, data.length, NO, 5, cancellation);
            if (error) { finalStatus = error; break; }
            id request = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            if (![request isKindOfClass:NSDictionary.class]) { finalStatus = EPROTO; break; }
            sequence = frame.request_id;
            if (helloPending && !greetingAcknowledged) {
                if(![request[@"protocol"]isEqual:@1]){finalStatus=EPROTO;break;}
                helloPending=NO; // Already acknowledged; never enqueue a second reply.
            } else {
                helloPending=NO;
                dispatch_semaphore_t ready = dispatch_semaphore_create(0);
                __block NSDictionary *response = nil;
                dispatch_async(dispatch_get_main_queue(), ^{
                    [host request:request completion:^(NSDictionary *reply) {
                        response = reply; dispatch_semaphore_signal(ready);
                    }];
                });
                NSString *method=request[@"method"];
                unsigned seconds=[method isEqual:@"wifi.associate"]?27:[method isEqual:@"wifi.scan"]?20:15;
                if (dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, (uint64_t)seconds * NSEC_PER_SEC))) {
                    finalStatus = ETIMEDOUT; break;
                }
                error = Reply(output, cancellation, frame, VM27_RADIO_REPLY, generation, response);
            }
            if (error) { finalStatus = error; break; }
        }}
    return finalStatus;
}
#ifndef VM27_SHARED_RADIO_LIBRARY
int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 2 || strcmp(argv[1], "--stdio")) return 64;
    signal(SIGPIPE, SIG_IGN);
    VM27SharedRadioHostV1 *host = [VM27SharedRadioHostV1 new];
    __block int finalStatus = 0;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        finalStatus = VM27SharedRadioServeStreamV1(STDIN_FILENO, STDOUT_FILENO, -1, host);
        dispatch_async(dispatch_get_main_queue(), ^{
            [host invalidate]; CFRunLoopStop(CFRunLoopGetMain());
        });
    });
    CFRunLoopRun();
    fprintf(stderr, "VM27_SHARED_RADIO_HOST_STOP errno=%d\n", finalStatus);
    return finalStatus ? 1 : 0;
} }
#endif
