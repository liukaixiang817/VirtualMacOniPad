#import <UIKit/UIKit.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(uint32_t, VM27PointerResultV1) {
    VM27PointerPendingV1 = 1,
    VM27PointerConfirmedV1,
    VM27PointerWrongOwnerV1,
    VM27PointerWrongThreadV1,
    VM27PointerInvalidArgumentV1,
    VM27PointerUnavailableV1,
    VM27PointerBusyV1,
    VM27PointerTimedOutV1,
    VM27PointerLockLostV1,
    VM27PointerRestoreUnconfirmedV1
};

typedef struct {
    uint64_t ownerIdentifier;
    uint64_t generation;
    uint32_t ownerPID;
    BOOL registered;
    BOOL requestActive;
    BOOL actualLockKnown;
    BOOL actualLocked;
    BOOL originalGrabReady;
    BOOL restorationConfirmed;
} VM27PointerSnapshotV1;

typedef void (^VM27PointerCompletionV1)(VM27PointerResultV1 result);
typedef void (^VM27PointerLossV1)(uint64_t generation);

/* Application-private UIKit controller, not an SL/CG provider. Build this file
 * with ARC. All methods, lifecycle integration and completions use the main
 * thread in the process that constructed it. Live UIKit objects are required;
 * no arbitrary-invalid-object safety is claimed. The callback may run inline.
 *
 * The window must actually contain this controller as its root, and its own
 * view must be installed. No method replaces a root controller or mounts a
 * caller view. Only the main screen is supported. Generations are nonzero and
 * strictly increase on each registration, including after detach.
 *
 * Acquire is a bounded request, never proof of effect. ONLY genuine system
 * pointerLockState.locked readback plus live ownership opens the pre-grab gate.
 * The caller must wire a separate verified relative-input path, suspend its
 * absolute hover path while captured, and release original grab on loss.
 * Explicitly detach before discarding the controller. There are no SL exports,
 * hide-count emulation, pointer warp, guest cursor, CPU/VM/GPU or global edits.
 */
API_AVAILABLE(ios(16.1))
@interface VM27ScopedPointerControllerV1 : UIViewController

- (nullable instancetype)initWithOwnerIdentifier:(uint64_t)ownerIdentifier;
- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithNibName:(nullable NSString *)name
                         bundle:(nullable NSBundle *)bundle NS_UNAVAILABLE;
- (instancetype)initWithCoder:(NSCoder *)coder NS_UNAVAILABLE;

- (VM27PointerResultV1)registerOwnedWindow:(UIWindow *)window
                                   owner:(uint64_t)ownerIdentifier
                              generation:(uint64_t)generation
                                 onLoss:(VM27PointerLossV1)onLoss;
- (VM27PointerResultV1)acquireForOwner:(uint64_t)ownerIdentifier
                          generation:(uint64_t)generation
                 timeoutMilliseconds:(uint32_t)timeoutMilliseconds
                          completion:(VM27PointerCompletionV1)completion;
- (BOOL)originalGrabReadyForOwner:(uint64_t)ownerIdentifier
                       generation:(uint64_t)generation;
- (VM27PointerResultV1)releaseForOwner:(uint64_t)ownerIdentifier
                          generation:(uint64_t)generation
                 timeoutMilliseconds:(uint32_t)timeoutMilliseconds
                          completion:(VM27PointerCompletionV1)completion;
- (VM27PointerResultV1)detachForOwner:(uint64_t)ownerIdentifier
                         generation:(uint64_t)generation
                timeoutMilliseconds:(uint32_t)timeoutMilliseconds
                         completion:(VM27PointerCompletionV1)completion;
/* On failure the output is untouched. Snapshot is an instantaneous readback,
 * not a guarantee that the lock remains held across a later asynchronous call. */
- (VM27PointerResultV1)copySnapshot:(VM27PointerSnapshotV1 *)snapshot
                            owner:(uint64_t)ownerIdentifier
                       generation:(uint64_t)generation;
@end

NS_ASSUME_NONNULL_END
