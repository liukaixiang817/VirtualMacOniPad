#import "VZGuestTools_owned_active_ssh_v7.h"
NS_ASSUME_NONNULL_BEGIN
/* Fixed read-only desktop diagnostic through the existing exclusive QGA lease.
 * No desktop-user requirement, arbitrary command/path, guest file writes or SSH.
 * The unchanged owner enforces its real 45-second bound and socket identity.
 * Returns NO immediately when the existing QGA owner is busy/unavailable,
 * without sending a request or invoking completion. YES admits a fixed attempt;
 * completion reports actual guest-exec/poll result, with at most 16384 bytes;
 * it does not prove successful GUI startup or physical display visibility. */
__attribute__((visibility("default"))) BOOL VZGuestToolsReadDesktopDiagnosticV10(void (^completion)(BOOL success, NSData *output));
NS_ASSUME_NONNULL_END
