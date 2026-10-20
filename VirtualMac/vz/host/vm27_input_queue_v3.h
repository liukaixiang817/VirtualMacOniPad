#import "modern_uikit_input_surface_v2.h"
NS_ASSUME_NONNULL_BEGIN
/* A source UIKit input owner for the genuine VZ27 VM's main serial queue.
 * It retains the actual VM and original devices until close has closed packet
 * admission and completed delivery cleanup. CPU execution stays independent. */
@interface VM27InputQueueV3 : NSObject
/* Main VM control queue only, after original start completion. This verifies
 * actual VM.state before opening delivery; no boolean replaces that state. */
- (BOOL)startAdmission:(NSError * _Nullable * _Nullable)error;
/* Main control queue. Failed native release keeps VM/session/queue identity
 * retained. OK/Closed is required before releasing this owner or its VM. */
- (VM27InputResult)close;
/* Completion follows actual source cancellation/drain on the main queue.
 * This supports VM teardown without synchronously waiting on its own queue. */
- (void)closeWithCompletion:(void (^)(VM27InputResult result))completion;
@property(nonatomic,readonly) VM27InputResult lastDeliveryResult;
- (instancetype)init NS_UNAVAILABLE;
@end
/* Main only. actualSurface must already belong to an own input window.
 * Construct before start; delivery admission opens only with startAdmission. */
FOUNDATION_EXPORT VM27InputQueueV3 * _Nullable VM27ConnectGenuineInputQueueV3(
    id actualVM,id pointing,id keyboard,VM27UIKitInputSurfaceV2 *actualSurface,
    uint64_t epoch,uint64_t coordinates,NSError * _Nullable * _Nullable error);
NS_ASSUME_NONNULL_END
