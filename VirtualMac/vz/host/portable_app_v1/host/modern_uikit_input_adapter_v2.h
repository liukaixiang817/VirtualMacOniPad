#import <UIKit/UIKit.h>
#import "modern_input_packet_v2.h"
#import "modern_input_packet_lease_v2.h"

NS_ASSUME_NONNULL_BEGIN
@class VM27UIKitInputAdapterV2;
API_AVAILABLE(ios(15.0))
@interface VM27UIKitInputAdapterV2 : NSObject
/* Create after the receiving view is in its real window. Coordinates are UIKit
 * view points. Bounds/window changes require close and a new generation; no
 * screen/guest conversion or iPad coordinate calibration is implied.
 */
- (nullable instancetype)initWithView:(UIView *)view epoch:(uint64_t)epoch
                  coordinateGeneration:(uint64_t)generation capacity:(size_t)capacity;
- (instancetype)init NS_UNAVAILABLE;

/* Receiving main thread only. The timestamp must come from the receiving
 * UIEvent/UITouch/UIPress monotonic seconds; no timestamp is invented here.
 * Gesture deltas advance only after successful publication. UIPan supplies
 * processed point scroll only, with no native sender/raw/accelerated/momentum.
 */
- (VM27InputResult)snapshotPan:(UIPanGestureRecognizer *)recognizer timestamp:(double)seconds;
- (VM27InputResult)snapshotHover:(UIHoverGestureRecognizer *)recognizer timestamp:(double)seconds;
- (VM27InputResult)snapshotPinch:(UIPinchGestureRecognizer *)recognizer timestamp:(double)seconds;
- (VM27InputResult)snapshotRotation:(UIRotationGestureRecognizer *)recognizer timestamp:(double)seconds;
- (VM27InputResult)snapshotKeyPress:(UIPress *)press;
- (VM27InputResult)snapshotTouchesInEvent:(UIEvent *)event;

/* A consumer may acquire on its own thread. Use the lease delivery method
 * for atomic sink admission. isCurrent is an observation only. The original
 * UHK getters, class metadata and event factories are not invoked.
 */
- (nullable VM27InputPacketLeaseV2 *)copyNextLease:(VM27InputResult *)result;
/* Main thread. Busy means closed with outstanding leases; they retain this
 * adapter until they drain. Close before releasing the session's own reference.
 */
- (VM27InputResult)close;
/* Own lifetime teardown only: closes admission without touching UIKit or
 * mutable receiving-thread gesture state. Safe for final-owner cleanup. */
- (VM27InputResult)invalidateOwnAdmission;
@end
NS_ASSUME_NONNULL_END
