#import <UIKit/UIKit.h>
#import "vm27_genuine_display_observer_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* The copied app calls this on main after its independently loaded backend has
 * passed admission. It uses the original initWithConfiguration:queue: API. */
FOUNDATION_EXPORT id _Nullable VM27UIKitCreateActualVirtualMachineV1(
    id configuration,NSError * _Nullable * _Nullable error) NS_RETURNS_RETAINED;
@interface VM27UIKitGuestDisplayV1 : NSObject
- (nullable instancetype)initWithVirtualMachine:(id)vm container:(UIView *)container
    failureHandler:(void (^)(NSError *error))failure
    error:(NSError * _Nullable * _Nullable)error;
@property(nonatomic,readonly) UIView *view;
/* Drain display callbacks and actual Metal command completions before the VM
 * owner releases its actual VM. This does not claim the VM is stopped. */
- (void)closeWithCompletion:(void (^)(NSError * _Nullable error))completion;
- (instancetype)init NS_UNAVAILABLE;
@end
NS_ASSUME_NONNULL_END
