#import "vm27_scoped_pointer_input_v2.h"
#include <math.h>
#include <pthread.h>
#include <unistd.h>

#if !__has_feature(objc_arc)
#error VM27 scoped pointer input v2 requires ARC.
#endif

@implementation VM27ScopedPointerInputV2 {
    VM27ScopedPointerControllerV1 *_controller;
    uint64_t _ownerIdentifier, _generation, _ticket;
    pid_t _ownerPID;
    pthread_t _ownerThread;
    BOOL _bound;
    GCMouse *_mouse;
    GCMouseInput *_input;
    GCMouseMoved _previousHandler, _installedHandler;
    VM27RelativeMotionV2 _motion;
}

- (instancetype)initWithController:(VM27ScopedPointerControllerV1 *)controller
    owner:(uint64_t)owner generation:(uint64_t)generation
{
    if (!pthread_main_np() || !controller || !owner || !generation) return nil;
    VM27PointerSnapshotV1 snapshot;
    if ([controller copySnapshot:&snapshot owner:owner generation:generation] !=
        VM27PointerConfirmedV1 || !snapshot.registered) return nil;
    self = [super init];
    if (self) {
        _controller = controller;
        _ownerIdentifier = owner;
        _generation = generation;
        _ownerPID = getpid();
        _ownerThread = pthread_self();
    }
    return self;
}

- (VM27PointerResultV1)checkOwner
{
    if (getpid() != _ownerPID) return VM27PointerWrongOwnerV1;
    if (!pthread_main_np() || !pthread_equal(pthread_self(), _ownerThread))
        return VM27PointerWrongThreadV1;
    return VM27PointerConfirmedV1;
}

- (BOOL)ownsHandler
{
    return _bound && _mouse && _input && _installedHandler &&
        _mouse.mouseInput == _input &&
        _mouse.handlerQueue == dispatch_get_main_queue() &&
        _input.mouseMovedHandler == _installedHandler;
}

- (BOOL)hasCurrentMouse
{
    return _mouse == GCMouse.current && [GCMouse.mice containsObject:_mouse];
}

- (BOOL)originalGrabReady
{
    return [self checkOwner] == VM27PointerConfirmedV1 &&
        [self ownsHandler] && [self hasCurrentMouse] &&
        [_controller originalGrabReadyForOwner:_ownerIdentifier generation:_generation];
}

- (void)deliverInput:(GCMouseInput *)input deltaX:(float)x deltaY:(float)y
    ticket:(uint64_t)ticket
{
    /* No state/property reads on a foreign queue. A handler-queue change is
     * an ownership loss, not permission to touch UIKit from that queue. */
    if ([self checkOwner] != VM27PointerConfirmedV1) return;
    if (ticket != _ticket || input != _input || ![self ownsHandler] ||
        ![self hasCurrentMouse] || !isfinite(x) || !isfinite(y)) return;
    if ([self originalGrabReady]) {
        VM27RelativeMotionV2 motion = _motion;
        if (motion) motion(input, x, y);
        return;
    }
    VM27PointerSnapshotV1 snapshot;
    if ([_controller copySnapshot:&snapshot owner:_ownerIdentifier generation:_generation] !=
        VM27PointerConfirmedV1) return;
    /* Keep the old ordinary path only when the same real scene is known
     * unlocked. During acquisition, loss or unknown restoration, drop motion
     * rather than accidentally delivering captured deltas to an absolute path.
     */
    if (snapshot.restorationConfirmed && !snapshot.requestActive) {
        GCMouseMoved previous = _previousHandler;
        if (previous) previous(input, x, y);
    }
}

- (VM27PointerResultV1)bindCurrentMouseWithMotion:(VM27RelativeMotionV2)motion
{
    VM27PointerResultV1 result = [self checkOwner];
    if (result != VM27PointerConfirmedV1) return result;
    if (!motion) return VM27PointerInvalidArgumentV1;
    if (_bound || _ticket == UINT64_MAX) return VM27PointerBusyV1;
    VM27PointerSnapshotV1 snapshot;
    result = [_controller copySnapshot:&snapshot owner:_ownerIdentifier generation:_generation];
    if (result != VM27PointerConfirmedV1) return result;
    if (!snapshot.restorationConfirmed || snapshot.requestActive)
        return VM27PointerRestoreUnconfirmedV1;
    GCMouse *mouse = GCMouse.current;
    GCMouseInput *input = mouse.mouseInput;
    if (!mouse || !input || ![GCMouse.mice containsObject:mouse] ||
        mouse.handlerQueue != dispatch_get_main_queue()) return VM27PointerUnavailableV1;

    _mouse = mouse;
    _input = input;
    _previousHandler = input.mouseMovedHandler;
    _motion = motion;
    uint64_t ticket = ++_ticket;
    __weak VM27ScopedPointerInputV2 *weakSelf = self;
    _installedHandler = ^(GCMouseInput *value, float x, float y) {
        [weakSelf deliverInput:value deltaX:x deltaY:y ticket:ticket];
    };
    _bound = YES;
    input.mouseMovedHandler = _installedHandler;
    if (![self ownsHandler]) {
        /* Retain the installation record for an explicit cleanup attempt.
         * Readiness remains closed; never silently rebind over this hook. */
        return VM27PointerUnavailableV1;
    }
    return VM27PointerConfirmedV1;
}

- (VM27PointerResultV1)detach
{
    VM27PointerResultV1 result = [self checkOwner];
    if (result != VM27PointerConfirmedV1) return result;
    if (!_bound) return VM27PointerInvalidArgumentV1;
    VM27PointerSnapshotV1 snapshot;
    result = [_controller copySnapshot:&snapshot owner:_ownerIdentifier generation:_generation];
    if (result != VM27PointerConfirmedV1) return result;
    if (!snapshot.restorationConfirmed || snapshot.requestActive)
        return VM27PointerRestoreUnconfirmedV1;
    BOOL owned = [self ownsHandler];
    _bound = NO; // Close forwarding before calling a property setter.
    if (!owned) return VM27PointerBusyV1;
    _input.mouseMovedHandler = _previousHandler;
    if (_input.mouseMovedHandler != _previousHandler) return VM27PointerRestoreUnconfirmedV1;
    _installedHandler = nil;
    _previousHandler = nil;
    _motion = nil;
    _input = nil;
    _mouse = nil;
    return VM27PointerConfirmedV1;
}

- (void)dealloc
{
    /* Normal lifecycle explicitly releases lock and detaches. Do not restore
     * from a foreign queue or overwrite another handler during teardown. */
    if (getpid() == _ownerPID && pthread_main_np() &&
        pthread_equal(pthread_self(), _ownerThread) && [self ownsHandler]) {
        VM27PointerSnapshotV1 snapshot;
        if ([_controller copySnapshot:&snapshot owner:_ownerIdentifier generation:_generation] ==
            VM27PointerConfirmedV1 && snapshot.restorationConfirmed && !snapshot.requestActive)
            _input.mouseMovedHandler = _previousHandler;
    }
}
@end
