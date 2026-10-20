#import "vm27_own_uikit_ingress_endpoint_v1.h"
#include <unistd.h>
#if !__has_feature(objc_arc)
#error Own UIKit input endpoint requires ARC.
#endif
@implementation VM27OwnUIKitIngressEndpointV1 {
    id<VM27ProvenOwnInputExecutorV1> _executor;
    VM27OwnUIKitIngressProfileV1 *_profile;
    pid_t _pid;
    BOOL _started, _profileClosed, _joined;
    VM27InputResult _closeResult;
}
- (instancetype)initWithPointingDevice:(id)pointing keyboard:(id)keyboard
    executor:(id<VM27ProvenOwnInputExecutorV1>)executor epoch:(uint64_t)epoch
    coordinates:(uint64_t)coordinates viewport:(VM27InputViewportV1)viewport {
    if (!executor || [executor independent27InputExecutorAvailabilityReason]) return nil;
    NSThread *thread=[executor independent27InputConsumerThread];
    VM27OwnUIKitIngressProfileV1 *profile=[[VM27OwnUIKitIngressProfileV1 alloc]
        initWithPointingDevice:pointing keyboard:keyboard consumerThread:thread
        epoch:epoch coordinates:coordinates viewport:viewport];
    if (!profile) return nil;
    self=[super init];
    if (self) { _profile=profile;_executor=executor;_pid=getpid(); }
    return self;
}
- (NSString *)independent27InputAvailabilityReason {
    if (_pid!=getpid() || _joined || _profileClosed)
        return @"Independent27 input endpoint ownership changed or closed.";
    return [_executor independent27InputExecutorAvailabilityReason];
}
- (BOOL)startIndependent27CopiedInputConsumer:(VM27UIKitInputSessionV2 *)session {
    if (!session || _started || [self independent27InputAvailabilityReason]) return NO;
    /* The actual executor may already have begun before it reports failure.
     * Keep ownership and require the same stop/join contract in either case. */
    _started=YES;
    return [_executor startIndependent27CopiedSession:session];
}
- (VM27InputResult)consumeCopiedInputPacket:(const VM27InputPacket *)packet {
    if (_pid!=getpid()) return VM27InputStaleEpoch;
    if (!_started || _profileClosed || _joined) return VM27InputClosed;
    return [_profile consumeCopiedInputPacket:packet];
}
- (VM27InputResult)stopAndJoinIndependent27CopiedInputConsumer {
    if (_pid!=getpid()) return VM27InputStaleEpoch;
    if (_joined) return _closeResult;
    if (!_profileClosed) {
        /* C queue admission was closed by the coordinator first. Backend
         * serialization, rather than a main-thread mutation, closes profile. */
        VM27InputResult closed=[_executor performIndependent27InputOwnerBlock:^{
            VM27InputResult result=[_profile closeOnConsumerThread];
            /* Only the genuine owner may set this state. An executor error
             * which never invoked the block must not mark the profile closed. */
            _profileClosed=[_profile hasClosedAdmissionOnConsumerThread];
            _closeResult=result;
            return result;
        }];
        if (!_profileClosed) return closed==VM27InputOK?VM27InputUnavailable:closed;
    }
    VM27InputResult joined=[_executor stopAndJoinIndependent27InputExecutor];
    if (joined!=VM27InputOK) return joined;
    _joined=YES;
    return _closeResult;
}
@end
