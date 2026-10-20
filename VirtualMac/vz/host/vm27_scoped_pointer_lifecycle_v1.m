#import "vm27_scoped_pointer_lifecycle_v1.h"
#import <GameController/GameController.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#if !__has_feature(objc_arc)
#error VM27 scoped pointer lifecycle v1 requires ARC.
#endif

_Static_assert(sizeof(VM27PointerResultV1) == 4, "Result is a uint32_t enum.");
_Static_assert(sizeof(VM27PointerSnapshotV1) == 32, "Snapshot has a fixed 32-byte ABI.");
_Static_assert(__builtin_offsetof(VM27PointerSnapshotV1, ownerPID) == 16,
               "Snapshot PID offset is 16.");
_Static_assert(__builtin_offsetof(VM27PointerSnapshotV1, originalGrabReady) == 24,
               "Snapshot pre-grab field offset is 24.");

typedef NS_ENUM(uint32_t, VM27PointerPhaseV1) {
    VM27PointerIdlePhaseV1,
    VM27PointerAcquiringPhaseV1,
    VM27PointerReadyPhaseV1,
    VM27PointerRestoringPhaseV1,
    VM27PointerUnknownRestorePhaseV1
};

@class VM27PointerRootViewV1;
@interface VM27ScopedPointerControllerV1 () {
    pid_t _ownerPID;
    pthread_t _ownerThread;
    uint64_t _ownerIdentifier, _generation, _highestGeneration, _ticket;
    uint64_t _deadline;
    BOOL _registered, _requestActive, _detaching, _closing, _updatingPreference;
    VM27PointerPhaseV1 _phase;
    __weak UIWindow *_ownedWindow;
    __weak UIWindowScene *_ownedScene;
    __weak UIView *_ownedView;
    UIPointerLockState *_ownedLockState;
    GCMouse *_ownedMouse;
    NSMutableArray<id> *_observers;
    dispatch_source_t _timer;
    VM27PointerCompletionV1 _completion;
    VM27PointerLossV1 _loss;
}
- (void)ownedViewMoved;
- (void)revokeCapture;
- (void)refreshOperation;
@end

@interface VM27PointerRootViewV1 : UIView
@property (nonatomic, weak) VM27ScopedPointerControllerV1 *pointerController;
@end
@implementation VM27PointerRootViewV1
- (void)didMoveToWindow
{
    [super didMoveToWindow];
    [self.pointerController ownedViewMoved];
}
@end

static BOOL VM27PointerMonotonicNanosecondsV1(uint64_t *out)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0 ||
        value.tv_nsec < 0 || value.tv_nsec >= 1000000000L ||
        (uint64_t)value.tv_sec > (UINT64_MAX - 999999999ULL) / 1000000000ULL)
        return NO;
    *out = (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
    return YES;
}

@implementation VM27ScopedPointerControllerV1
- (instancetype)initWithOwnerIdentifier:(uint64_t)ownerIdentifier
{
    if (!ownerIdentifier || !pthread_main_np()) return nil;
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _ownerPID = getpid();
        _ownerThread = pthread_self();
        _ownerIdentifier = ownerIdentifier;
        _observers = [NSMutableArray array];
    }
    return self;
}

- (VM27PointerResultV1)checkOwner:(uint64_t)owner generation:(uint64_t)generation
{
    if (getpid() != _ownerPID || owner != _ownerIdentifier)
        return VM27PointerWrongOwnerV1;
    if (!pthread_main_np() || !pthread_equal(pthread_self(), _ownerThread))
        return VM27PointerWrongThreadV1;
    if (!_registered || !generation || generation != _generation)
        return VM27PointerInvalidArgumentV1;
    return VM27PointerConfirmedV1;
}

- (BOOL)isOwnerThread
{
    return getpid() == _ownerPID && pthread_main_np() &&
           pthread_equal(pthread_self(), _ownerThread);
}

- (void)loadView
{
    VM27PointerRootViewV1 *view = [[VM27PointerRootViewV1 alloc] init];
    view.pointerController = self;
    self.view = view;
}

- (BOOL)hasLiveOwnedWindow
{
    UIWindow *window = _ownedWindow;
    UIWindowScene *scene = _ownedScene;
    return _registered && window && scene && _ownedView &&
        window.rootViewController == self && self.viewIfLoaded == _ownedView &&
        ((VM27PointerRootViewV1 *)_ownedView).pointerController == self &&
        _ownedView.window == window && window.windowScene == scene &&
        scene.screen == UIScreen.mainScreen && window.screen == scene.screen &&
        !window.hidden && window.isKeyWindow && !_ownedView.hidden &&
        self.presentedViewController == nil &&
        scene.activationState == UISceneActivationStateForegroundActive &&
        UIApplication.sharedApplication.applicationState == UIApplicationStateActive;
}

- (BOOL)readActualLock:(BOOL *)locked
{
    UIWindowScene *scene = _ownedScene;
    if (!scene || !_ownedLockState || scene.pointerLockState != _ownedLockState)
        return NO;
    *locked = _ownedLockState.isLocked;
    return YES;
}

- (BOOL)hasOwnedMouse
{
    return _ownedMouse && _ownedMouse.mouseInput &&
           GCMouse.current == _ownedMouse && [GCMouse.mice containsObject:_ownedMouse];
}

- (BOOL)prefersPointerLocked
{
    return [self isOwnerThread] && _requestActive &&
        (_phase == VM27PointerAcquiringPhaseV1 || _phase == VM27PointerReadyPhaseV1) &&
        [self hasLiveOwnedWindow] && [self hasOwnedMouse];
}

- (void)addObserver:(NSNotificationName)name object:(nullable id)object
               loss:(BOOL)loss
{
    __weak VM27ScopedPointerControllerV1 *weakSelf = self;
    id token = [NSNotificationCenter.defaultCenter addObserverForName:name object:object
        queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
        (void)note;
        VM27ScopedPointerControllerV1 *controller = weakSelf;
        if (![controller isOwnerThread] || controller->_updatingPreference) return;
        if (loss) [controller revokeCapture];
        else [controller refreshOperation];
    }];
    [_observers addObject:token];
}

- (void)removeObservers
{
    for (id token in _observers)
        [NSNotificationCenter.defaultCenter removeObserver:token];
    [_observers removeAllObjects];
}

- (VM27PointerResultV1)registerOwnedWindow:(UIWindow *)window owner:(uint64_t)owner
    generation:(uint64_t)generation onLoss:(VM27PointerLossV1)onLoss
{
    if (getpid() != _ownerPID || owner != _ownerIdentifier) return VM27PointerWrongOwnerV1;
    if (![self isOwnerThread]) return VM27PointerWrongThreadV1;
    if (_closing || _updatingPreference) return VM27PointerBusyV1;
    if (!generation || generation <= _highestGeneration || !onLoss)
        return VM27PointerInvalidArgumentV1;
    if (_registered || _completion || _requestActive) return VM27PointerBusyV1;
    if (_phase == VM27PointerUnknownRestorePhaseV1) {
        BOOL locked;
        if (![self readActualLock:&locked] || locked) return VM27PointerRestoreUnconfirmedV1;
    }
    if (!window || window.rootViewController != self || !self.isViewLoaded ||
        ![self.view isKindOfClass:VM27PointerRootViewV1.class] ||
        ((VM27PointerRootViewV1 *)self.view).pointerController != self || self.view.window != window ||
        !window.windowScene || window.screen != UIScreen.mainScreen ||
        window.windowScene.screen != window.screen || !window.windowScene.pointerLockState)
        return VM27PointerUnavailableV1;
    /* Never adopt an already locked scene as proof that this module acquired it. */
    if (window.windowScene.pointerLockState.isLocked) return VM27PointerBusyV1;
    _ownedWindow = window;
    _ownedScene = window.windowScene;
    _ownedView = self.view;
    _ownedLockState = window.windowScene.pointerLockState;
    _generation = _highestGeneration = generation;
    _registered = YES;
    _phase = VM27PointerIdlePhaseV1;
    _loss = onLoss;
    /* Always re-read the registered scene. Do not trust a notification's
     * asserted state or depend on its object field for correctness. */
    [self addObserver:UIPointerLockStateDidChangeNotification object:nil loss:NO];
    for (NSNotificationName name in @[UISceneWillDeactivateNotification,
        UISceneDidEnterBackgroundNotification, UISceneDidDisconnectNotification])
        [self addObserver:name object:_ownedScene loss:YES];
    [self addObserver:UIWindowDidResignKeyNotification object:window loss:YES];
    [self addObserver:UIApplicationWillResignActiveNotification object:nil loss:YES];
    [self addObserver:GCMouseDidDisconnectNotification object:nil loss:NO];
    [self addObserver:GCMouseDidBecomeCurrentNotification object:nil loss:NO];
    [self addObserver:GCMouseDidStopBeingCurrentNotification object:nil loss:NO];
    return VM27PointerConfirmedV1; // Registration only; originalGrabReady remains NO.
}

- (void)cancelTimer
{
    if (_timer) { dispatch_source_cancel(_timer); _timer = nil; }
}

- (void)finishOperation:(VM27PointerResultV1)result
{
    [self cancelTimer];
    VM27PointerCompletionV1 completion = _completion;
    _completion = nil;
    if (_detaching) {
        _detaching = NO;
        _registered = NO;
        [self removeObservers];
        _ownedMouse = nil;
        _ownedWindow = nil;
        _ownedView = nil;
        _loss = nil;
        /* Preserve scene/readback on unknown restore; never silently rebind. */
        if (_phase != VM27PointerUnknownRestorePhaseV1) {
            _ownedScene = nil;
            _ownedLockState = nil;
        }
    }
    if (completion) completion(result);
}

- (void)updatePreference
{
    /* UIKit may deliver a notification while evaluating the new preference.
     * Public mutations and our observers cannot reenter that transition. */
    BOOL wasUpdatingPreference = _updatingPreference;
    _updatingPreference = YES;
    [self setNeedsUpdateOfPrefersPointerLocked];
    _updatingPreference = wasUpdatingPreference;
}

- (void)dropPreference
{
    _requestActive = NO;
    [self updatePreference];
}

- (VM27PointerResultV1)beginTimerWithMilliseconds:(uint32_t)milliseconds
    completion:(VM27PointerCompletionV1)completion
{
    uint64_t now;
    if (milliseconds < 10 || milliseconds > 2000 || !completion || _ticket == UINT64_MAX ||
        !VM27PointerMonotonicNanosecondsV1(&now) ||
        now > UINT64_MAX - (uint64_t)milliseconds * 1000000ULL)
        return VM27PointerInvalidArgumentV1;
    _deadline = now + (uint64_t)milliseconds * 1000000ULL;
    uint64_t ticket = ++_ticket, generation = _generation;
    _completion = completion;
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    if (!_timer) { _completion = nil; return VM27PointerUnavailableV1; }
    __weak VM27ScopedPointerControllerV1 *weakSelf = self;
    dispatch_source_set_event_handler(_timer, ^{
        VM27ScopedPointerControllerV1 *controller = weakSelf;
        if ([controller isOwnerThread] && controller->_ticket == ticket &&
            controller->_generation == generation) [controller refreshOperation];
    });
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, 0),
        10 * NSEC_PER_MSEC, NSEC_PER_MSEC);
    dispatch_resume(_timer);
    return VM27PointerPendingV1;
}

- (VM27PointerResultV1)acquireForOwner:(uint64_t)owner generation:(uint64_t)generation
    timeoutMilliseconds:(uint32_t)milliseconds completion:(VM27PointerCompletionV1)completion
{
    VM27PointerResultV1 result = [self checkOwner:owner generation:generation];
    if (result != VM27PointerConfirmedV1) return result;
    if (_closing || _updatingPreference || _completion || _phase != VM27PointerIdlePhaseV1)
        return VM27PointerBusyV1;
    BOOL locked;
    _ownedMouse = GCMouse.current;
    if (![self hasLiveOwnedWindow] || ![self hasOwnedMouse] ||
        ![self readActualLock:&locked]) return VM27PointerUnavailableV1;
    if (locked) return VM27PointerBusyV1;
    result = [self beginTimerWithMilliseconds:milliseconds completion:completion];
    if (result != VM27PointerPendingV1) return result;
    _phase = VM27PointerAcquiringPhaseV1;
    _requestActive = YES;
    [self updatePreference];
    [self refreshOperation];
    return VM27PointerPendingV1;
}

- (BOOL)originalGrabReadyForOwner:(uint64_t)owner generation:(uint64_t)generation
{
    if ([self checkOwner:owner generation:generation] != VM27PointerConfirmedV1) return NO;
    BOOL locked;
    return _phase == VM27PointerReadyPhaseV1 && _requestActive &&
        [self hasLiveOwnedWindow] && [self hasOwnedMouse] &&
        [self readActualLock:&locked] && locked;
}

- (void)refreshOperation
{
    if (![self isOwnerThread] || !_registered) return;
    BOOL locked = NO;
    BOOL known = [self readActualLock:&locked];
    if (_phase == VM27PointerReadyPhaseV1 &&
        (!known || !locked || ![self hasLiveOwnedWindow] || ![self hasOwnedMouse])) {
        [self revokeCapture];
        return;
    }
    if (!_completion) return;
    uint64_t now;
    if (!VM27PointerMonotonicNanosecondsV1(&now) || now >= _deadline) {
        [self dropPreference];
        /* A deadline never invents a successful release. */
        known = [self readActualLock:&locked];
        _phase = known && !locked ? VM27PointerIdlePhaseV1 : VM27PointerUnknownRestorePhaseV1;
        [self finishOperation:VM27PointerTimedOutV1];
    } else if (_phase == VM27PointerAcquiringPhaseV1) {
        if (![self hasLiveOwnedWindow] || ![self hasOwnedMouse] || !known) {
            [self dropPreference];
            _phase = known && !locked ? VM27PointerIdlePhaseV1 : VM27PointerUnknownRestorePhaseV1;
            [self finishOperation:VM27PointerUnavailableV1];
        } else if (locked) {
            _phase = VM27PointerReadyPhaseV1;
            [self finishOperation:VM27PointerConfirmedV1];
        }
    } else if (_phase == VM27PointerRestoringPhaseV1 && known && !locked) {
        _phase = VM27PointerIdlePhaseV1;
        [self finishOperation:VM27PointerConfirmedV1];
    }
}

- (void)revokeCapture
{
    if (![self isOwnerThread] || !_registered) return;
    BOOL wasReady = _phase == VM27PointerReadyPhaseV1;
    uint64_t capturedGeneration = _generation;
    VM27PointerLossV1 capturedLoss = _loss;
    /* Close the gate before a UIKit update or client callback can reenter.
     * Later completions may create another registration; they must not change
     * the identity of the capture whose loss is being reported here. */
    _phase = VM27PointerUnknownRestorePhaseV1;
    [self dropPreference];
    BOOL locked;
    _phase = [self readActualLock:&locked] && !locked ? VM27PointerIdlePhaseV1
                                                   : VM27PointerUnknownRestorePhaseV1;
    if (_completion) [self finishOperation:VM27PointerLockLostV1];
    if (wasReady && capturedLoss) capturedLoss(capturedGeneration);
}

- (VM27PointerResultV1)releaseForOwner:(uint64_t)owner generation:(uint64_t)generation
    timeoutMilliseconds:(uint32_t)milliseconds completion:(VM27PointerCompletionV1)completion
{
    VM27PointerResultV1 result = [self checkOwner:owner generation:generation];
    if (result != VM27PointerConfirmedV1) return result;
    if (milliseconds < 10 || milliseconds > 2000 || !completion)
        return VM27PointerInvalidArgumentV1;
    if (_closing || _updatingPreference) return VM27PointerBusyV1;
    if (_completion && _phase == VM27PointerAcquiringPhaseV1) {
        /* A canceled acquisition callback cannot reacquire in the middle of
         * this release transaction. No callback executes under a mutex. */
        _closing = YES;
        [self revokeCapture];
        _closing = NO;
    }
    if (_completion) return VM27PointerBusyV1;
    result = [self beginTimerWithMilliseconds:milliseconds completion:completion];
    if (result != VM27PointerPendingV1) return result;
    _phase = VM27PointerRestoringPhaseV1;
    [self dropPreference];
    [self refreshOperation];
    return VM27PointerPendingV1;
}

- (VM27PointerResultV1)detachForOwner:(uint64_t)owner generation:(uint64_t)generation
    timeoutMilliseconds:(uint32_t)milliseconds completion:(VM27PointerCompletionV1)completion
{
    VM27PointerResultV1 result = [self checkOwner:owner generation:generation];
    if (result != VM27PointerConfirmedV1) return result;
    if (milliseconds < 10 || milliseconds > 2000 || !completion)
        return VM27PointerInvalidArgumentV1;
    if (_closing || _updatingPreference) return VM27PointerBusyV1;
    if (_completion && _phase == VM27PointerAcquiringPhaseV1) {
        _closing = YES;
        [self revokeCapture];
        _closing = NO;
    }
    if (_completion || _detaching) return VM27PointerBusyV1;
    result = [self beginTimerWithMilliseconds:milliseconds completion:completion];
    if (result != VM27PointerPendingV1) return result;
    _detaching = YES;
    _phase = VM27PointerRestoringPhaseV1;
    [self dropPreference];
    [self refreshOperation];
    return VM27PointerPendingV1;
}

- (VM27PointerResultV1)copySnapshot:(VM27PointerSnapshotV1 *)snapshot
    owner:(uint64_t)owner generation:(uint64_t)generation
{
    VM27PointerResultV1 result = [self checkOwner:owner generation:generation];
    if (result != VM27PointerConfirmedV1) return result;
    if (!snapshot) return VM27PointerInvalidArgumentV1;
    BOOL locked = NO, known = [self readActualLock:&locked];
    BOOL ready = _phase == VM27PointerReadyPhaseV1 && _requestActive &&
        known && locked && [self hasLiveOwnedWindow] && [self hasOwnedMouse];
    VM27PointerSnapshotV1 value = {
        .ownerIdentifier = _ownerIdentifier, .generation = _generation,
        .ownerPID = (uint32_t)_ownerPID, .registered = _registered,
        .requestActive = _requestActive, .actualLockKnown = known,
        .actualLocked = known && locked,
        .originalGrabReady = ready,
        .restorationConfirmed = !_requestActive && known && !locked
    };
    *snapshot = value;
    return VM27PointerConfirmedV1; // Snapshot copied, not lock acquired.
}

- (void)ownedViewMoved
{
    if ([self isOwnerThread] && _registered && _ownedView.window != _ownedWindow)
        [self revokeCapture];
}

- (void)viewWillDisappear:(BOOL)animated
{
    [self revokeCapture];
    [super viewWillDisappear:animated];
}

- (void)dealloc
{
    /* Normal lifecycle relinquishes preference before teardown; dealloc does
     * not fabricate restoration evidence or call UIKit on a foreign thread. */
    [self cancelTimer];
    [self removeObservers];
}
@end
