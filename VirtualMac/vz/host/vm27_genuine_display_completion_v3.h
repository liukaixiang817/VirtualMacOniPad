#import "vm27_genuine_display_observer_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* The exact registered observer acknowledges only a successfully consumed
 * original update. Empty updates use a separate sequence namespace and never
 * count as completed IOSurface bitmap frames. Calls require main. */
@interface VM27GenuineDisplayObserverV1 (VM27FrameCompletionV3)
- (void)markConsumedSequence:(uint64_t)sequence;
- (void)markEmptyConsumedSequence:(uint64_t)sequence;
- (void)setEmptyFrameConsumer:(void (^)(uint64_t sequence))consumer;
@end
NS_ASSUME_NONNULL_END
