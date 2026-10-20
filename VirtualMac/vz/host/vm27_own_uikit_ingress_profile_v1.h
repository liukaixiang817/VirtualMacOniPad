#import "modern_vz_processed_scroll_receiver_v1.h"
#include "vm27_own_uikit_ingress_values_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Own UIKit surface sink. The backend supplies genuine devices from its own27
 * VM and the thread it has actually proved owns serialized input. This object
 * creates no executor, VM, Mac view, CG event or NSEvent. The application must
 * close queue admission first, call closeOnConsumerThread on that proven
 * thread, then stop/join before releasing the VM. Existing app/runtime gates
 * remain prerequisites; an identity predicate is not execution validation. */
@interface VM27OwnUIKitIngressProfileV1 : NSObject <VM27CopiedInputSinkV2>
- (nullable instancetype)initWithPointingDevice:(id)pointing keyboard:(id)keyboard
    consumerThread:(NSThread *)thread epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates
    viewport:(VM27InputViewportV1)viewport;
+ (BOOL)genuine27PointingAndKeyboardProfileMatches:(id)pointing keyboard:(id)keyboard;
- (VM27InputResult)closeOnConsumerThread;
/* Admission state only; a true result does not prove native releases succeeded. */
- (BOOL)hasClosedAdmissionOnConsumerThread;
- (instancetype)init NS_UNAVAILABLE;
@end
NS_ASSUME_NONNULL_END
