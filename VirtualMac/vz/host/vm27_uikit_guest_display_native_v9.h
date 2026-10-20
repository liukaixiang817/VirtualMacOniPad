#import "vm27_uikit_guest_display_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* One optional live comparison mode. Default display remains the CPU bitmap.
 * YES admits a mode change, not a rendered frame or physical visibility.
 * Busy returns NO without changing the mode; no polling or guest operation. */
@interface VM27UIKitGuestDisplayV1 (VM27NativeIOSurfaceLayerV9)
- (BOOL)vm27_tryEnableNativeIOSurfaceLayerV9ForVirtualMachine:(id)vm
    error:(NSError * _Nullable * _Nullable)error;
@end
NS_ASSUME_NONNULL_END
