#import "modern_independent_input_coordinator_v2.h"
#import "vm27_own_uikit_ingress_profile_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Implemented by the actual independent27 VM owner. Its original sender
 * affinity must be proved, rather than inferred from an NSThread object.
 * The executor retains its actual VM, drains session.consumeNextCopiedPacket
 * on that thread and never waits for UIKit while the coordinator closes.
 * This protocol does not supply an executor or grant backend availability. */
@protocol VM27ProvenOwnInputExecutorV1 <NSObject>
- (nullable NSString *)independent27InputExecutorAvailabilityReason;
- (NSThread *)independent27InputConsumerThread;
- (BOOL)startIndependent27CopiedSession:(VM27UIKitInputSessionV2 *)session;
/* Serializes this block after all admitted deliveries, on the exact consumer
 * thread, before returning. It must propagate the block's result. */
- (VM27InputResult)performIndependent27InputOwnerBlock:(VM27InputResult (NS_NOESCAPE ^)(void))block;
/* A successful result means actual thread termination/join, not a request. */
- (VM27InputResult)stopAndJoinIndependent27InputExecutor;
@end
@interface VM27OwnUIKitIngressEndpointV1 : NSObject <VM27IndependentInputEndpointV2>
- (nullable instancetype)initWithPointingDevice:(id)pointing keyboard:(id)keyboard
    executor:(id<VM27ProvenOwnInputExecutorV1>)executor epoch:(uint64_t)epoch
    coordinates:(uint64_t)coordinates viewport:(VM27InputViewportV1)viewport;
- (instancetype)init NS_UNAVAILABLE;
@end
NS_ASSUME_NONNULL_END
