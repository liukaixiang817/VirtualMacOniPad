#import "VZGuestTools_owned_active_ssh_v5.h"
NS_ASSUME_NONNULL_BEGIN
/* New service owns exactly this already attached actual VM. Completion on main.
 * Wait at most120s for genuine guest-info/idle; every guest operation has the
 * original45s real socket lease. Start success means a captured own launchd job,
 * not bridge HELLO/authenticated SSH or current physical guest visibility.
 * One active/pending service; conflict and uncertain cleanup retain the owner.
 * Close the genuine22223 bridge first, Stop with this sameVM while505050 is live,
 * then Reset/normalVM release only after Stop success. No arbitrary paths/args.
 */
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) void VZGuestToolsStartOwnedSSHServiceV2(id actualVM,void (^completion)(BOOL success,NSData *output));
__attribute__((visibility("default"))) void VZGuestToolsStopOwnedSSHServiceV2(id actualVM,void (^completion)(BOOL success,NSData *output));
/* Unexpected guestDidStop/error: native state must actually be Stopped(0) on
 * the original actual main VM.queue. Invalidates only the ended guest service
 * lease: jobBootoutVerified=false, capturedPIDExitVerified=false. No Root bool
 * substitutes state; Paused/unknown/anotherVM refuses and retains the owner.
 * Private QGA native cleanup remains honest and sticky if it is unresolved. */
__attribute__((visibility("default"))) void VZGuestToolsInvalidateOwnedSSHServiceAfterActualVMStopV2(id actualVM,void (^completion)(BOOL success,NSData *output));
#ifdef __cplusplus
}
#endif
NS_ASSUME_NONNULL_END
