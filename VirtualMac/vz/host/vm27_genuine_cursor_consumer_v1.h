#import <UIKit/UIKit.h>
#import "vm27_genuine_display_observer_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Immutable copied genuine27 cursor, delivered on main. A nil image with
 * changed=YES means the guest explicitly removed its hardware cursor. */
typedef void (^VM27GenuineCursorConsumerV1)(UIImage * _Nullable image, BOOL changed,
    CGPoint guestPosition, CGPoint hotspot);
@interface VM27GenuineDisplayObserverV1 (VM27CursorConsumerV1)
- (void)setGenuineCursorConsumerV1:(VM27GenuineCursorConsumerV1)consumer;
@end
NS_ASSUME_NONNULL_END
