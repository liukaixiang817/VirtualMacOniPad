#import "modern_processed_scroll_sink_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* This endpoint belongs to the independent27 source backend. Its consuming
 * thread owns the session, drains copied packets atomically and stops/joins
 * without waiting for UIKit. A native event passed to its receiver is borrowed;
 * it must retain before returning if it stores the event. No implementation for
 * the original UHK generic consumer is claimed by this source contract. */
@protocol VM27IndependentInputEndpointV1 <VM27NativeProcessedScrollReceiverV1>
- (nullable NSString *)independent27InputAvailabilityReason;
- (BOOL)startIndependent27CopiedInputConsumer:(VM27UIKitInputSessionV2 *)session;
- (void)stopAndJoinIndependent27CopiedInputConsumer;
@end
@interface VM27IndependentInputCoordinatorV1 : NSObject
- (nullable instancetype)initWithWindow:(VM27UIKitInputWindowV2 *)window
    surface:(VM27UIKitInputSurfaceV2 *)surface;
/* Main thread only. Existing backend availability/load/run checks are required,
 * and the source's actual UIKit timestamp/runtime validation gate stays closed. */
- (BOOL)attachValidatedEndpoint:(id<VM27IndependentInputEndpointV1>)endpoint
    epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates error:(NSError **)error;
- (VM27InputResult)close;
- (instancetype)init NS_UNAVAILABLE;
@end
FOUNDATION_EXPORT NSString *VM27IndependentInputPlatformAvailabilityReasonV1(void);
NS_ASSUME_NONNULL_END
