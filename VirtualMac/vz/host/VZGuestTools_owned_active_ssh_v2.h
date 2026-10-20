#import "VZGuestTools.h"
NS_ASSUME_NONNULL_BEGIN
/* Fixed signed resource only. Launch-request completion never proves HELLO or SSH.
 * Caller owns the normal VM lifecycle. Its control close ends the actual helper;
 * a 300s watcher also signals only its exact UID/PPID/path/start captured child.
 * This first diagnostic entry does not provide persistent SSH; the persistent
 * helper and lease handoff remain a required integration step. */
__attribute__((visibility("default"))) void VZGuestToolsInstallOwnedActiveSSHHelperV1(void (^completion)(BOOL success, NSData *output));
NS_ASSUME_NONNULL_END
