#import "vm27_independent_app_runtime_v1.h"
/* Called on the actual main VM queue after normal stop and input/display/SSH
 * drains, before the App releases its VM. Never detaches a running VM. */
FOUNDATION_EXPORT BOOL VM27IndependentAppRuntimeUnbindStoppedGuestV1(
    id actualVM, dispatch_queue_t actualQueue, NSError **error);
