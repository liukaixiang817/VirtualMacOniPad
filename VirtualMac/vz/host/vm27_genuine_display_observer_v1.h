#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
NS_ASSUME_NONNULL_BEGIN
/* Attach to the actual independently loaded VZ27 VM on its main control queue.
 * This object retains that VM until the real accessor and presenter queues have
 * completed their detach operations. CPU execution remains in original VMM. */
@interface VM27GenuineDisplayObserverV1 : NSObject
- (nullable instancetype)initWithVirtualMachine:(id)vm
    graphicsDisplay:(id)display
    frameConsumer:(void (^)(IOSurfaceRef surface, uint64_t sequence))consumer
    failureHandler:(void (^)(NSError *error))failure
    error:(NSError * _Nullable * _Nullable)error;
- (void)closeWithCompletion:(void (^)(NSError * _Nullable error))completion;
- (instancetype)init NS_UNAVAILABLE;
@end
/* Does not load a framework or bypass backend admission. It validates the
 * actual loaded image, selectors, original class/ivar ABI and current bytes. */
FOUNDATION_EXPORT BOOL VM27GenuineDisplayProfileAvailableV1(id vm,
    NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT BOOL VM27GenuineDisplayClassProfileAvailableV1(
    NSError * _Nullable * _Nullable error);
NS_ASSUME_NONNULL_END
