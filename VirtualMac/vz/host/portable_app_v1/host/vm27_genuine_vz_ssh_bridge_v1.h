#ifndef VM27_GENUINE_VZ_SSH_BRIDGE_V1_H
#define VM27_GENUINE_VZ_SSH_BRIDGE_V1_H
#import <Foundation/Foundation.h>
#include "vm27_host_vsock_ssh_owner_v1.h"
NS_ASSUME_NONNULL_BEGIN
@interface VM27GenuineVZSSHBridgeV1 : NSObject
- (int)copySnapshot:(struct vm27_host_ssh_snapshot_v1 *)snapshot;
/* Invoke on actualVM.queue. Completion also runs there, after admission stops,
 * listener removal, worker joins and genuine connection.close calls. A cleanup
 * exception retains VM/connection leases and reports an error, never false closed.
 */
- (void)closeWithCompletion:(void (^)(NSError * _Nullable error))completion;
@end
/* Must be called on actualVM.queue after the genuine VM is created/bound and
 * before starting it. expectedVZImagePath is the actual verified Runtime manifest
 * image path (current product: <root>/parent-flat/VZ27.dylib), not an untrusted
 * discovery result. Does not create or start a VM, nor install a guest helper.
 * The caller must exclusively own socket listener port22223 for this VM.
 */
/* outOwner can be nonnil even when registration fails: retain it and finish
 * closeWithCompletion before releasing the VM. Failure never discards leases. */
FOUNDATION_EXPORT BOOL
VM27CreateGenuineVZSSHBridgeV1(id actualVM, NSString *expectedVZImagePath,
                             uint32_t idleMilliseconds,
                             VM27GenuineVZSSHBridgeV1 * _Nullable * _Nonnull outOwner, NSError **error);
NS_ASSUME_NONNULL_END
#endif
