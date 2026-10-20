#import <GameController/GameController.h>
#import "vm27_scoped_pointer_lifecycle_v1.h"

NS_ASSUME_NONNULL_BEGIN

/* These are real raw GameController deltas, not absolute UIKit coordinates.
 * The caller supplies the actual backend input sink for its registered view.
 * All methods and callbacks use the construction process's main thread.
 */
typedef void (^VM27RelativeMotionV2)(GCMouseInput *input, float deltaX, float deltaY);

API_AVAILABLE(ios(16.1))
@interface VM27ScopedPointerInputV2 : NSObject
- (nullable instancetype)initWithController:(VM27ScopedPointerControllerV1 *)controller
                                      owner:(uint64_t)ownerIdentifier
                                 generation:(uint64_t)generation;
- (instancetype)init NS_UNAVAILABLE;

/* Call before requesting pointer lock. Requires an unlocked registered scene
 * and the mouse's existing main handler queue. Never changes that queue.
 * Confirmed means the real handler is installed, not that capture is active.
 * The old motion handler is borrowed through a copy and used while unlocked.
 */
- (VM27PointerResultV1)bindCurrentMouseWithMotion:(VM27RelativeMotionV2)motion;

/* Use this gate for future original pre-grab admission. It combines actual
 * lock/window readback with ownership of this exact mouse/profile/handler.
 * Recheck on the main thread immediately before the original grab call.
 */
- (BOOL)originalGrabReady;

/* First release pointer lock through the controller. Detach refuses while
 * release is pending or restoration is unknown. Only restores the old handler
 * if this module still owns the installed one; never overwrites another owner.
 * Failure closes motion admission but does not claim restored ownership.
 */
- (VM27PointerResultV1)detach;
@end

NS_ASSUME_NONNULL_END
