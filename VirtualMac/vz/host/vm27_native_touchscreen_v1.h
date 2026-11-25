#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString *const VM27NativeTouchScreenSettingV1;
BOOL VM27NativeTouchScreenGuestSupportedV1(NSDictionary *options);
BOOL VM27ConfigureNativeTouchScreenV1(id configuration, id display,
    NSString *bundlePath, NSDictionary *options, NSError **error);

// The VM and its original UIKit surface both execute on the main serial queue.
// Only direct finger contacts use this device; mouse, keyboard and Pencil keep
// their existing owners. No guest helper or synthetic mouse gesture is used.
@interface VM27NativeTouchScreenV1 : NSObject
+ (nullable instancetype)screenForVirtualMachine:(id)vm view:(UIView *)view;
- (BOOL)ownsDirectFingers;
- (void)receiveEvent:(UIEvent *)event dispatchStamp:(uint64_t)stamp;
- (void)willDispatchWindowEvent:(UIEvent *)event;
- (void)cancelAll;
@end

@protocol VM27NativeTouchScreenSurfaceV1 <NSObject>
- (void)vm27_setNativeTouchScreenV1:(nullable VM27NativeTouchScreenV1 *)screen;
@end

NS_ASSUME_NONNULL_END
