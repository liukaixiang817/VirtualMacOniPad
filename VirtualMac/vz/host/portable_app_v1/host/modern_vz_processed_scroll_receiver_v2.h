#import "modern_vz_processed_scroll_receiver_v1.h"
NS_ASSUME_NONNULL_BEGIN
@interface VM27VZGenuineProcessedScrollReceiverV1 (CopiedUIKitPanV2)
/* Values copied from a real UIKit scroll recognizer. Delivery remains on the
 * genuine VM input queue; no intermediate HIDEvent or global dispatch. */
- (VM27InputResult)consumeCopiedPan:(const VM27InputPacket *)packet
    speed:(double)speed commit:(void (NS_NOESCAPE ^ _Nullable)(void))commit;
@end
NS_ASSUME_NONNULL_END
