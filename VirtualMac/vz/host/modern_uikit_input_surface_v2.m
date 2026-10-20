#import "modern_uikit_input_surface_v2.h"
#include <math.h>
#include <pthread.h>
#include <unistd.h>

#if !__has_feature(objc_arc)
#error Own UIKit input surface requires ARC.
#endif

@interface VM27UIKitInputSessionV2 ()
- (instancetype)initWithAdapter:(VM27UIKitInputAdapterV2 *)adapter sink:(id<VM27CopiedInputSinkV2>)sink;
- (VM27UIKitInputAdapterV2 *)adapter;
- (VM27InputResult)invalidateOwnAdmission;
@end
static VM27InputResult own_sink(const VM27InputPacket *packet, void *opaque)
{
    id<VM27CopiedInputSinkV2> sink = (__bridge id)opaque;
    return [sink consumeCopiedInputPacket:packet];
}
@implementation VM27UIKitInputSessionV2 {
    VM27UIKitInputAdapterV2 *_adapter;
    id<VM27CopiedInputSinkV2> _sink;
    pid_t _ownerPID;
}
- (instancetype)initWithAdapter:(VM27UIKitInputAdapterV2 *)adapter sink:(id<VM27CopiedInputSinkV2>)sink
{
    self = [super init];
    if (self) { _adapter = adapter; _sink = sink; _ownerPID = getpid(); }
    return self;
}
- (VM27UIKitInputAdapterV2 *)adapter { return _adapter; }
- (VM27InputResult)consumeNextCopiedPacket
{
    if (_ownerPID != getpid()) return VM27InputStaleEpoch;
    @autoreleasepool {
        VM27InputResult result;
        VM27InputPacketLeaseV2 *lease = [_adapter copyNextLease:&result];
        if (!lease) return result;
        id<VM27CopiedInputSinkV2> sink = _sink;
        /* Local strong ownership survives a concurrent close. Only the queue's
         * admission decides whether this copied packet may enter the sink. */
        return [lease deliverToSink:own_sink context:(__bridge void *)sink];
    }
}
- (VM27InputResult)close
{
    if (_ownerPID != getpid()) return VM27InputStaleEpoch;
    return [_adapter close];
}
- (VM27InputResult)invalidateOwnAdmission { return [_adapter invalidateOwnAdmission]; }
@end

@interface VM27UIKitInputSurfaceV2 ()
- (void)dispatchEvent:(UIEvent *)event action:(void (NS_NOESCAPE ^)(void))action;
- (uint64_t)dispatchStampForEvent:(UIEvent *)event;
@end
@protocol VM27ObservedGestureV2 <NSObject>
@property(nonatomic) uint64_t ownDispatchStamp;
@end

/* Gesture callbacks may be deferred by UIKit. A target accepts a timestamp
 * only if its recognizer actually received this exact UIEvent during this
 * window's current dispatch. Pointer hover without such a public callback is
 * explicitly unavailable; no clock value is manufactured for it. */
#define VM27_OBSERVED_GESTURE(CLASS, BASE) \
@interface CLASS : BASE <VM27ObservedGestureV2> \
@property(nonatomic) uint64_t ownDispatchStamp; \
@end \
@implementation CLASS \
- (void)observeOwnEvent:(UIEvent *)event { \
    UIView *view = self.view; \
    self.ownDispatchStamp = [view isKindOfClass:VM27UIKitInputSurfaceV2.class] \
        ? [(VM27UIKitInputSurfaceV2 *)view dispatchStampForEvent:event] : 0; \
} \
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { \
    [self observeOwnEvent:event]; [super touchesBegan:touches withEvent:event]; } \
- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { \
    [self observeOwnEvent:event]; [super touchesMoved:touches withEvent:event]; } \
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { \
    [self observeOwnEvent:event]; [super touchesEnded:touches withEvent:event]; } \
- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { \
    [self observeOwnEvent:event]; [super touchesCancelled:touches withEvent:event]; } \
@end

VM27_OBSERVED_GESTURE(VM27OwnPanRecognizerV2, UIPanGestureRecognizer)
VM27_OBSERVED_GESTURE(VM27OwnPinchRecognizerV2, UIPinchGestureRecognizer)
VM27_OBSERVED_GESTURE(VM27OwnRotationRecognizerV2, UIRotationGestureRecognizer)
VM27_OBSERVED_GESTURE(VM27OwnHoverRecognizerV2, UIHoverGestureRecognizer)

@implementation VM27UIKitInputWindowV2
- (void)sendEvent:(UIEvent *)event
{
    VM27UIKitInputSurfaceV2 *surface = self.inputSurface;
    if (surface && surface.window == self)
        [surface dispatchEvent:event action:^{ [super sendEvent:event]; }];
    else [super sendEvent:event];
}
@end

@implementation VM27UIKitInputSurfaceV2 {
    VM27UIKitInputSessionV2 *_session;
    __weak VM27UIKitInputWindowV2 *_activeWindow;
    CGRect _activeBounds;
    UIEvent *_dispatchEvent;
    VM27UIKitInputSessionV2 *_dispatchSession;
    uint64_t _dispatchStamp, _lastStamp;
    pid_t _ownerPID;
    VM27InputResult _lastInputResult;
}
- (instancetype)initWithFrame:(CGRect)frame
{
    self = [super initWithFrame:frame];
    if (!self) return nil;
    _ownerPID = getpid(); _lastInputResult = VM27InputUnavailable;
    self.multipleTouchEnabled = YES;
    VM27OwnPanRecognizerV2 *pan = [[VM27OwnPanRecognizerV2 alloc] initWithTarget:self action:@selector(receivePan:)];
    pan.minimumNumberOfTouches = 2; pan.maximumNumberOfTouches = 2;
    pan.allowedTouchTypes = @[@(UITouchTypeDirect)];
    pan.cancelsTouchesInView = NO;
    [self addGestureRecognizer:pan];
    VM27OwnPinchRecognizerV2 *pinch = [[VM27OwnPinchRecognizerV2 alloc] initWithTarget:self action:@selector(receivePinch:)];
    VM27OwnRotationRecognizerV2 *rotation = [[VM27OwnRotationRecognizerV2 alloc] initWithTarget:self action:@selector(receiveRotation:)];
    VM27OwnHoverRecognizerV2 *hover = [[VM27OwnHoverRecognizerV2 alloc] initWithTarget:self action:@selector(receiveHover:)];
    for (UIGestureRecognizer *recognizer in @[pan, pinch, rotation, hover]) {
        recognizer.delegate = self; recognizer.cancelsTouchesInView = NO;
    }
    [self addGestureRecognizer:pinch]; [self addGestureRecognizer:rotation]; [self addGestureRecognizer:hover];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(resignActive:)
        name:UIApplicationWillResignActiveNotification object:nil];
    return self;
}
- (BOOL)canBecomeFirstResponder { return YES; }
- (VM27InputResult)lastInputResult { return _lastInputResult; }
- (VM27UIKitInputSessionV2 *)activateWithSink:(id<VM27CopiedInputSinkV2>)sink
    epoch:(uint64_t)epoch coordinateGeneration:(uint64_t)generation capacity:(size_t)capacity
{
    if (_ownerPID != getpid() || !pthread_main_np() || _session || !sink ||
        ![self.window isKindOfClass:VM27UIKitInputWindowV2.class]) return nil;
    VM27UIKitInputWindowV2 *window = (id)self.window;
    if (window.inputSurface && window.inputSurface != self) return nil;
    VM27UIKitInputAdapterV2 *adapter = [[VM27UIKitInputAdapterV2 alloc] initWithView:self
        epoch:epoch coordinateGeneration:generation capacity:capacity];
    if (!adapter) return nil;
    VM27UIKitInputSessionV2 *session = [[VM27UIKitInputSessionV2 alloc] initWithAdapter:adapter sink:sink];
    if (!session) { [adapter close]; return nil; }
    _session = session; _activeWindow = window; _activeBounds = self.bounds;
    window.inputSurface = self; _lastInputResult = VM27InputOK;
    return session;
}
- (VM27InputResult)close
{
    if (_ownerPID != getpid()) return VM27InputStaleEpoch;
    if (!pthread_main_np()) return VM27InputWrongThread;
    VM27UIKitInputSessionV2 *session = _session;
    if (!session) return VM27InputClosed;
    VM27InputResult result = [session close];
    if (result == VM27InputOK || result == VM27InputBusy || result == VM27InputClosed) {
        if (_activeWindow.inputSurface == self) _activeWindow.inputSurface = nil;
        _session = nil; _activeWindow = nil;
    }
    _lastInputResult = result;
    return result;
}
- (void)resignActive:(NSNotification *)notification { (void)notification; [self close]; }
- (void)didMoveToWindow
{
    [super didMoveToWindow];
    if (_session && self.window != _activeWindow) [self close];
}
- (void)willMoveToWindow:(UIWindow *)window
{
    if (_session && window != _activeWindow) [self close];
    [super willMoveToWindow:window];
}
- (void)setBounds:(CGRect)bounds
{
    if (_session && !CGRectEqualToRect(self.bounds, bounds)) [self close];
    [super setBounds:bounds];
}
- (void)setFrame:(CGRect)frame
{
    if (_session && !CGRectEqualToRect(self.frame, frame)) [self close];
    [super setFrame:frame];
}
- (void)setTransform:(CGAffineTransform)transform
{
    if (_session && !CGAffineTransformEqualToTransform(self.transform, transform)) [self close];
    [super setTransform:transform];
}
- (void)setHidden:(BOOL)hidden
{
    if (_session && hidden) [self close];
    [super setHidden:hidden];
}
- (void)layoutSubviews
{
    [super layoutSubviews];
    if (_session && !CGRectEqualToRect(self.bounds, _activeBounds)) [self close];
}
- (void)dispatchEvent:(UIEvent *)event action:(void (NS_NOESCAPE ^)(void))action
{
    if (_ownerPID != getpid() || !pthread_main_np() || !_session || !event ||
        !isfinite(event.timestamp) || event.timestamp < 0 || _lastStamp == UINT64_MAX) {
        action(); return;
    }
    UIEvent *previous = _dispatchEvent;
    VM27UIKitInputSessionV2 *previousSession = _dispatchSession;
    uint64_t stamp = _dispatchStamp;
    _dispatchEvent = event; _dispatchSession = _session; _dispatchStamp = ++_lastStamp;
    @try { action(); }
    @finally { _dispatchEvent = previous; _dispatchSession = previousSession; _dispatchStamp = stamp; }
}
- (uint64_t)dispatchStampForEvent:(UIEvent *)event
{
    if (_ownerPID != getpid() || !pthread_main_np() || !_session ||
        _session != _dispatchSession || event != _dispatchEvent) return 0;
    return _dispatchStamp;
}
- (VM27UIKitInputAdapterV2 *)adapterForGesture:(UIGestureRecognizer<VM27ObservedGestureV2> *)recognizer
{
    if (_ownerPID != getpid() || !pthread_main_np() || !_session || _session != _dispatchSession || !_dispatchEvent ||
        !recognizer.ownDispatchStamp || recognizer.ownDispatchStamp != _dispatchStamp ||
        recognizer.view != self) { _lastInputResult = VM27InputUnavailable; return nil; }
    return [_session adapter];
}
- (void)receivePan:(VM27OwnPanRecognizerV2 *)recognizer
{
    VM27UIKitInputAdapterV2 *adapter = [self adapterForGesture:recognizer];
    if (adapter) _lastInputResult = [adapter snapshotPan:recognizer timestamp:_dispatchEvent.timestamp];
}
- (void)receivePinch:(VM27OwnPinchRecognizerV2 *)recognizer
{
    VM27UIKitInputAdapterV2 *adapter = [self adapterForGesture:recognizer];
    if (adapter) _lastInputResult = [adapter snapshotPinch:recognizer timestamp:_dispatchEvent.timestamp];
}
- (void)receiveRotation:(VM27OwnRotationRecognizerV2 *)recognizer
{
    VM27UIKitInputAdapterV2 *adapter = [self adapterForGesture:recognizer];
    if (adapter) _lastInputResult = [adapter snapshotRotation:recognizer timestamp:_dispatchEvent.timestamp];
}
- (void)receiveHover:(VM27OwnHoverRecognizerV2 *)recognizer
{
    VM27UIKitInputAdapterV2 *adapter = [self adapterForGesture:recognizer];
    if (adapter) _lastInputResult = [adapter snapshotHover:recognizer timestamp:_dispatchEvent.timestamp];
}
- (void)receiveTouches:(UIEvent *)event
{
    if (![self dispatchStampForEvent:event]) { _lastInputResult = VM27InputUnavailable; return; }
    _lastInputResult = [[_session adapter] snapshotTouchesInEvent:event];
}
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)receivePresses:(NSSet<UIPress *> *)presses event:(UIPressesEvent *)event
{
    if (![self dispatchStampForEvent:event]) { _lastInputResult = VM27InputUnavailable; return; }
    for (UIPress *press in presses) _lastInputResult = [[_session adapter] snapshotKeyPress:press];
}
- (void)pressesBegan:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event { [self receivePresses:presses event:event]; }
- (void)pressesEnded:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event { [self receivePresses:presses event:event]; }
- (void)pressesCancelled:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event { [self receivePresses:presses event:event]; }
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)first shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)second
{
    return first.view == self && second.view == self;
}
- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
    /* Failsafe closes only our C admission. Explicit main-thread close remains
     * the application lifecycle entry; no UIKit mutation occurs in dealloc. */
    [_session invalidateOwnAdmission];
}
@end
