#import <Foundation/Foundation.h>
#import "vm27_native_trackpad_swipe_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Native iPad HID monitoring, limited to Apple AID touchpad usage13/12 with
 * usage13/5 capability. No key reports, event writes or retained HID events. */
@interface VM27OwnedNativeTrackpadV1 : NSObject
- (instancetype)initWithAction:(void (^)(unsigned,VM27TrackpadDirectionV1))action;
- (BOOL)start;
- (void)stop;
@property(nonatomic,readonly) BOOL admitted;
@end
NS_ASSUME_NONNULL_END
