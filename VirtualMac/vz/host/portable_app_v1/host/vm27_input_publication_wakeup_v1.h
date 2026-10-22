#import "modern_uikit_input_adapter_v2.h"
NS_ASSUME_NONNULL_BEGIN
/* Own copied-packet notification only. It schedules the actual VM queue after
 * publication; it must not consume synchronously or retain an input event. */
@protocol VM27PublicationWakeupV1 <NSObject>
- (VM27InputResult)vm27_setPublicationWakeupV1:(void (^ _Nullable)(void))wakeup;
@end
@interface VM27UIKitInputAdapterV2 (VM27PublicationWakeupV1) <VM27PublicationWakeupV1>
@end
NS_ASSUME_NONNULL_END
