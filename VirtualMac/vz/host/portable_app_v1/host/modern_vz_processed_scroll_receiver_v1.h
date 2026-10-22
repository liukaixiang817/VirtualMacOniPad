#import <Foundation/Foundation.h>
#import "modern_processed_scroll_sink_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Actual original27 object receiver, compiled but not validated or admitted by
 * the app gate. The backend supplies its genuine pointing object and a thread
 * it has independently proved owns that object's serialized input context.
 * This receiver neither starts a VM nor invents an executor/thread-affinity
 * contract. Its caller must stop/join before releasing that backend context.
 */
@interface VM27VZGenuineProcessedScrollReceiverV1 : NSObject <VM27NativeProcessedScrollReceiverV1>
- (nullable instancetype)initWithPointingDevice:(id)pointingDevice
    consumerThread:(NSThread *)consumerThread epoch:(uint64_t)epoch
    coordinates:(uint64_t)coordinates;
- (instancetype)init NS_UNAVAILABLE;
/* Class sizes, genuine UUID, exact original IMP RVAs and type encodings.
 * This is a runtime identity predicate, not a successful VZ call or VM proof. */
+ (BOOL)genuine27ScrollProfileMatchesPointingDevice:(id)pointingDevice;
@end
NS_ASSUME_NONNULL_END
