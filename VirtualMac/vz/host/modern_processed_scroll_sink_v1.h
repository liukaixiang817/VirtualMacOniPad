#import "modern_uikit_input_surface_v2.h"
#import "modern_processed_scroll_native_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Backend's own delivery entry. Event is a borrowed real +0 native type6 object
 * for this synchronous call; retain it explicitly if the backend queues it.
 * No global input dispatch or original UHK protocol conformance is supplied. */
@protocol VM27NativeProcessedScrollReceiverV1 <NSObject>
- (VM27InputResult)consumeNativeProcessedScroll:(CFTypeRef)event
    epoch:(uint64_t)epoch sequence:(uint64_t)sequence coordinates:(uint64_t)coordinates;
@end
@interface VM27NativeProcessedScrollSinkV1 : NSObject <VM27CopiedInputSinkV2>
- (instancetype)initWithReceiver:(id<VM27NativeProcessedScrollReceiverV1>)receiver;
- (instancetype)init NS_UNAVAILABLE;
@end
NS_ASSUME_NONNULL_END
