#import "modern_uikit_input_adapter_v2.h"

NS_ASSUME_NONNULL_BEGIN
/* A source port's own packet sink, never an NSEvent or original UHK conformance.
 * Unsupported capabilities must be reported as VM27InputUnsupported. The sink
 * runs synchronously on its caller's consuming thread under queue admission;
 * it must not reenter the session or synchronously wait for the UIKit thread. */
@protocol VM27CopiedInputSinkV2 <NSObject>
- (VM27InputResult)consumeCopiedInputPacket:(const VM27InputPacket *)packet;
@end

API_AVAILABLE(ios(15.0))
@interface VM27UIKitInputSessionV2 : NSObject
/* Backend consumer thread: exactly one acquired lease is delivered and drained.
 * This uses atomic delivery admission, never isCurrent followed by a call. */
- (VM27InputResult)consumeNextCopiedPacket;
/* Receiving main thread. Closed/Busy packets can no longer enter the sink. */
- (VM27InputResult)close;
- (instancetype)init NS_UNAVAILABLE;
@end

@class VM27UIKitInputSurfaceV2;
/* Use as the app's own window at launch. It passes real UIEvents synchronously
 * to the one associated own surface. No event routing hook or swizzle occurs. */
API_AVAILABLE(ios(15.0))
@interface VM27UIKitInputWindowV2 : UIWindow
@property(nonatomic, weak, nullable) VM27UIKitInputSurfaceV2 *inputSurface;
@end

/* Standalone input view for the independently selected 27 source route. It has
 * no legacy VZ handler and provides no software-keyboard/repeat/smart-magnify,
 * raw CGEvent, sender ID, pressure or relative hardware pointer synthesis. */
API_AVAILABLE(ios(15.0))
@interface VM27UIKitInputSurfaceV2 : UIView <UIGestureRecognizerDelegate>
- (instancetype)initWithFrame:(CGRect)frame;
- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithCoder:(NSCoder *)coder NS_UNAVAILABLE;
/* Main thread, after attachment to its own window. Call only after the host
 * has exclusively selected its validated 27 route and disabled legacy input.
 * Caller owns a nonzero session epoch and coordinate generation. */
- (nullable VM27UIKitInputSessionV2 *)activateWithSink:(id<VM27CopiedInputSinkV2>)sink
    epoch:(uint64_t)epoch coordinateGeneration:(uint64_t)generation capacity:(size_t)capacity;
- (VM27InputResult)close;
@property(nonatomic, readonly) VM27InputResult lastInputResult;
@end
NS_ASSUME_NONNULL_END
