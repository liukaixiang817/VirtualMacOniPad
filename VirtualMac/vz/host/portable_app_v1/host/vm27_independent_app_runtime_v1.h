#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
#ifdef __cplusplus
extern "C" {
#endif
/* Implemented by the independently finalized runtime graph provider. These
 * are strong interfaces: the App never substitutes a flag or a stub. The
 * root is the exact selected App/runtime root, never the Ventura fallback.
 * Preflight verifies the product signatures, frozen file pins, dependencies,
 * and required process entry contracts without loading native CPU state.
 * Load admits and loads that exact frontend graph, connects the actual child
 * VMM entry installer, and retains acquired handles if partial loading cannot
 * be rolled back. Production native operations are installed by the child
 * VMM's actual VM setup pthread, never by the frontend control queue.
 * GuestStarted runs only after the original VZ start completion succeeds. */
FOUNDATION_EXPORT BOOL VM27IndependentAppRuntimePreflightV1(
    NSString *actualRuntimeRoot,NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT BOOL VM27IndependentAppRuntimeLoadV1(
    NSString *actualRuntimeRoot,NSError * _Nullable * _Nullable error);
/* Called on the original VM's own queue after actual init and before start.
 * The runtime retains that real VM; GuestStarted reads its original state. */
FOUNDATION_EXPORT BOOL VM27IndependentAppRuntimeBindGuestV1(
    id actualVM,dispatch_queue_t actualQueue,NSError * _Nullable * _Nullable error);
FOUNDATION_EXPORT BOOL VM27IndependentAppRuntimeGuestStartedV1(
    NSError * _Nullable * _Nullable error);
#ifdef __cplusplus
}
#endif
NS_ASSUME_NONNULL_END
