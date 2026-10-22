#import "VZGuestTools.h"
NS_ASSUME_NONNULL_BEGIN
/* Fixed signed helper diagnostic only, exclusive real SDK QGA socket lifetime.
 * Completion is on main after private operation cleanup. Launch request/HELLO
 * never prove authenticated SSH. 300s watcher has no persistent handoff yet. */
__attribute__((visibility("default"))) void VZGuestToolsInstallOwnedActiveSSHHelperV1(void (^completion)(BOOL success,NSData *output));
NS_ASSUME_NONNULL_END
