#import <QuartzCore/CADisplayLink.h>
#import "modern_uikit_input_surface_v3.h"
#import "vm27_finite_scroll_diagnostic_v1.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#import "VZAppSettings.h"
#include "vm27_trackpad_three_finger_swipe_v1.h"
#include "vm27_trackpad_transform_swipe_v1.h"
#import <objc/runtime.h>
#import <objc/message.h>

@interface UIEvent (VM27ActualTrackpadContactV13)
- (NSInteger)_trackpadFingerDownCount;
@end

#if !__has_feature(objc_arc)
#error Own UIKit input surface requires ARC.
#endif

/* These are the existing own adapter's checked publication methods, not an
 * Apple private event API. Software callbacks share its epoch/sequence/lease
 * queue with real touches/presses; they never construct UIPress or UIEvent. */
@interface VM27UIKitInputAdapterV2 (VM27SoftwareKeyPublicationV3)
- (VM27InputResult)checkReceivingView:(UIView * _Nullable * _Nullable)output;
- (VM27InputResult)publish:(VM27InputPacket *)packet;
- (VM27InputResult)vm27_setFiniteDiagnosticPanCoalescingV1:(BOOL)enabled;
@end

static BOOL software_ascii_key_v3(unichar character, uint32_t *usage, BOOL *shift)
{
    *shift = NO;
    if (character >= 'a' && character <= 'z') { *usage = 4 + character - 'a'; return YES; }
    if (character >= 'A' && character <= 'Z') { *usage = 4 + character - 'A'; *shift = YES; return YES; }
    if (character >= '1' && character <= '9') { *usage = 0x1e + character - '1'; return YES; }
    if (character == '0') { *usage = 0x27; return YES; }
    if (character == '\n' || character == '\r') { *usage = 0x28; return YES; }
    static const char plain[] = " \t-=[]\\;'`,./";
    static const uint8_t plainUsage[] = {0x2c,0x2b,0x2d,0x2e,0x2f,0x30,0x31,0x33,0x34,0x35,0x36,0x37,0x38};
    static const char shifted[] = "!@#$%^&*()_+{}|:\"~<>?";
    static const uint8_t shiftedUsage[] = {0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x2d,0x2e,0x2f,0x30,0x31,0x33,0x34,0x35,0x36,0x37,0x38};
    for (size_t i = 0; i < sizeof(plain)-1; ++i) if (character == (unsigned char)plain[i]) { *usage = plainUsage[i]; return YES; }
    for (size_t i = 0; i < sizeof(shifted)-1; ++i) if (character == (unsigned char)shifted[i]) { *usage = shiftedUsage[i]; *shift = YES; return YES; }
    return NO;
}

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

@interface VM27UIKitInputSurfaceV2 () <UIPointerInteractionDelegate>
- (void)dispatchEvent:(UIEvent *)event action:(void (NS_NOESCAPE ^)(void))action;
- (uint64_t)dispatchStampForEvent:(UIEvent *)event;
- (void)receiveTrackpadTransformEventV14:(UIEvent *)event;
- (void)sendThreeFingerDirectionV13:(UISwipeGestureRecognizerDirection)direction;
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
    BOOL _hardwareKeysDown[256];
    NSHashTable<UITouch *> *_directContactsV6;
    UIPointerInteraction *_pointerInteractionV6;
    unsigned _softwareKeyboardRejectionLogs;
    UIPanGestureRecognizer *_trackpadScrollV7;
    unsigned _scrollReceiptLogsV7;
    UIPanGestureRecognizer *_directScrollV8;
    __weak UIPanGestureRecognizer *_activeScrollV8;
    unsigned _threeFingerLogsV8;
    BOOL _softwareKeyboardRequestedV9;
    UIView *_hiddenSoftwareKeyboardV9;
    BOOL _viewAdmissionInvalidatedV11;
    BOOL _recoveryNoticePendingV11;
    unsigned _physicalReceiptLogsV12, _keyReceiptLogsV12;
    VM27TrackpadSwipeV1 _trackpadSwipeV13;
    unsigned _trackpadContactLogsV13;
    VM27TrackpadTransformV1 _trackpadTransformV14;
    unsigned _trackpadTransformLogsV14;
    CADisplayLink *_finiteScrollLinkV15;
    __weak VM27UIKitInputSessionV2 *_finiteScrollSessionV15;
    unsigned _finiteScrollRunsV15,_finiteScrollPacketsV15,_finiteScrollTicksV15;
    BOOL _finiteScrollBaselineV15;
    double _finiteScrollStartV15,_finiteScrollLastTickV15,_finiteScrollMaxGapV15,_finiteScrollTargetV15;
}
- (instancetype)initWithFrame:(CGRect)frame
{
    self = [super initWithFrame:frame];
    if (!self) return nil;
    _ownerPID = getpid(); _lastInputResult = VM27InputUnavailable;
    // The independent27 basic input profile exposes one real pointer and keyboard.
    self.multipleTouchEnabled = YES;
    _directContactsV6=[NSHashTable weakObjectsHashTable];
    _pointerInteractionV6=[[UIPointerInteraction alloc] initWithDelegate:self];
    [self addInteraction:_pointerInteractionV6];
    /* Hardware scroll has no UITouch. Preserve the existing direct touch and
     * button paths by rejecting every touch type on this recognizer. */
    VM27OwnPanRecognizerV2 *pan = [[VM27OwnPanRecognizerV2 alloc] initWithTarget:self action:@selector(receivePan:)];
    pan.allowedTouchTypes=@[];
    pan.allowedScrollTypesMask=UIScrollTypeMaskAll;
    pan.cancelsTouchesInView=NO;
    _trackpadScrollV7=pan;
    [self addGestureRecognizer:pan];
    VM27OwnPanRecognizerV2 *directPan=[[VM27OwnPanRecognizerV2 alloc] initWithTarget:self action:@selector(receivePan:)];
    directPan.minimumNumberOfTouches=2;directPan.maximumNumberOfTouches=2;
    directPan.allowedTouchTypes=@[@(UITouchTypeDirect)];
    directPan.delegate=self;directPan.cancelsTouchesInView=NO;
    _directScrollV8=directPan;[self addGestureRecognizer:directPan];
    for(NSNumber *direction in @[@(UISwipeGestureRecognizerDirectionUp),@(UISwipeGestureRecognizerDirectionDown),
                                  @(UISwipeGestureRecognizerDirectionLeft),@(UISwipeGestureRecognizerDirectionRight)]) {
        UISwipeGestureRecognizer *swipe=[[UISwipeGestureRecognizer alloc] initWithTarget:self action:@selector(receiveThreeFingerSwipe:)];
        swipe.direction=direction.unsignedIntegerValue;swipe.numberOfTouchesRequired=3;
        swipe.allowedTouchTypes=@[@(UITouchTypeDirect)];
        swipe.delegate=self;swipe.cancelsTouchesInView=NO;[self addGestureRecognizer:swipe];
    }
    VM27OwnPinchRecognizerV2 *pinch = [[VM27OwnPinchRecognizerV2 alloc] initWithTarget:self action:@selector(receivePinch:)];
    VM27OwnRotationRecognizerV2 *rotation = [[VM27OwnRotationRecognizerV2 alloc] initWithTarget:self action:@selector(receiveRotation:)];
    VM27OwnHoverRecognizerV2 *hover = [[VM27OwnHoverRecognizerV2 alloc] initWithTarget:self action:@selector(receiveHover:)];
    for (UIGestureRecognizer *recognizer in @[pan, pinch, rotation, hover]) {
        recognizer.delegate = self; recognizer.cancelsTouchesInView = NO;
    }
    pinch.enabled = NO; rotation.enabled = NO;
    [self addGestureRecognizer:pinch]; [self addGestureRecognizer:rotation]; [self addGestureRecognizer:hover];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(resignActive:)
        name:UIApplicationWillResignActiveNotification object:nil];
    return self;
}
- (UIPointerRegion *)pointerInteraction:(UIPointerInteraction *)interaction
    regionForRequest:(UIPointerRegionRequest *)request defaultRegion:(UIPointerRegion *)region {
    (void)request;
    return interaction==_pointerInteractionV6 && _session && !self.hidden ? region:nil;
}
- (UIPointerStyle *)pointerInteraction:(UIPointerInteraction *)interaction styleForRegion:(UIPointerRegion *)region {
    (void)region;
    if(interaction!=_pointerInteractionV6 || !_session || self.hidden ||
       UIApplication.sharedApplication.applicationState!=UIApplicationStateActive)return nil;
    return [UIPointerStyle hiddenPointerStyle];
}
- (BOOL)canBecomeFirstResponder { return YES; }
/* Hiding the software keyboard must retain this actual input owner. Resigning
 * focus here would also remove hardware key delivery from the independent VM. */
- (UIView *)inputView {
    if (_softwareKeyboardRequestedV9) return nil;
    if (!_hiddenSoftwareKeyboardV9)
        _hiddenSoftwareKeyboardV9 = [[UIView alloc] initWithFrame:CGRectZero];
    return _hiddenSoftwareKeyboardV9;
}
- (void)setSoftwareKeyboardRequestedV9:(BOOL)requested {
    if (_ownerPID != getpid() || !pthread_main_np()) return;
    if (_softwareKeyboardRequestedV9 == requested) return;
    _softwareKeyboardRequestedV9 = requested;
    if (self.isFirstResponder) [self reloadInputViews];
}
/* UIKeyInput callbacks have no UIEvent timestamp. The timestamp below is the
 * real callback receipt uptime, explicitly not a hardware event time. All
 * publication and the actual VM consumer execute on the main serial queue. */
- (BOOL)hasText { return YES; }
- (UIKeyboardType)keyboardType { return UIKeyboardTypeASCIICapable; }
- (UITextAutocapitalizationType)autocapitalizationType { return UITextAutocapitalizationTypeNone; }
- (UITextAutocorrectionType)autocorrectionType { return UITextAutocorrectionTypeNo; }
- (UITextSpellCheckingType)spellCheckingType { return UITextSpellCheckingTypeNo; }
- (UITextSmartQuotesType)smartQuotesType { return UITextSmartQuotesTypeNo; }
- (UITextSmartDashesType)smartDashesType { return UITextSmartDashesTypeNo; }
- (UITextSmartInsertDeleteType)smartInsertDeleteType { return UITextSmartInsertDeleteTypeNo; }
- (void)softwareKeyboardRejected:(VM27InputResult)result character:(uint32_t)character
{
    _lastInputResult = result;
    if (_softwareKeyboardRejectionLogs < 8) {
        ++_softwareKeyboardRejectionLogs;
        fprintf(stderr, "[Independent27] software-keyboard rejected status=%u character=U+%04X\n", (unsigned)result, character);
    }
}
- (VM27InputResult)publishSoftwareUsage:(uint32_t)usage pressed:(BOOL)pressed timestamp:(double)seconds
    modifiers:(uint32_t)modifiers adapter:(VM27UIKitInputAdapterV2 *)adapter
{
    VM27InputPacket packet = {.source = VM27InputKey, .monotonic_timestamp_seconds = seconds,
        .present = VM27InputHasPhase | VM27InputHasHIDUsage | VM27InputHasModifiers,
        .phase = pressed ? VM27InputBegan : VM27InputEnded, .hid_usage_page = 7,
        .hid_usage = usage, .named_modifiers = modifiers, .pressed = pressed};
    return [adapter publish:&packet];
}
- (void)receiveSoftwareText:(NSString *)text backspace:(BOOL)backspace
{
    if (_ownerPID != getpid() || !pthread_main_np()) return;
    if (!_session || !_activeWindow || self.window != _activeWindow ||
        _activeWindow.inputSurface != self || self.hidden || !self.isFirstResponder ||
        UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
        [self softwareKeyboardRejected:VM27InputUnavailable character:0]; return;
    }
    /* A software release must never release a physically held key/modifier. */
    for (unsigned i = 0; i < 256; ++i) if (_hardwareKeysDown[i]) {
        [self softwareKeyboardRejected:VM27InputBusy character:0]; return;
    }
    if (!backspace && (!text || text.length > 32)) {
        [self softwareKeyboardRejected:VM27InputUnsupported character:0]; return;
    }
    /* Reject the whole callback before publishing if any character is unknown. */
    for (NSUInteger i = 0; !backspace && i < text.length; ++i) {
        uint32_t usage; BOOL shifted;
        unichar character = [text characterAtIndex:i];
        if (!software_ascii_key_v3(character, &usage, &shifted)) {
            [self softwareKeyboardRejected:VM27InputUnsupported character:character]; return;
        }
    }
    VM27UIKitInputAdapterV2 *adapter = [_session adapter];
    UIView *receiving = nil;
    VM27InputResult result = [adapter checkReceivingView:&receiving];
    if (result != VM27InputOK || receiving != self) {
        [self softwareKeyboardRejected:result == VM27InputOK ? VM27InputUnavailable : result character:0]; return;
    }
    const double seconds = NSProcessInfo.processInfo.systemUptime;
    for (NSUInteger i = 0; i < (backspace ? 1 : text.length); ++i) {
        uint32_t usage = 0x2a; BOOL shifted = NO;
        if (!backspace) software_ascii_key_v3([text characterAtIndex:i], &usage, &shifted);
        uint32_t usages[4] = {shifted ? 0xe1 : usage, usage, usage, 0xe1};
        BOOL pressed[4] = {YES, shifted ? YES : NO, NO, NO};
        unsigned count = shifted ? 4 : 2;
        for (unsigned k = 0; k < count; ++k) {
            uint32_t modifiers = shifted && k != 3 ? VM27InputShift : 0;
            result = [self publishSoftwareUsage:usages[k] pressed:pressed[k] timestamp:seconds modifiers:modifiers adapter:adapter];
            if (result != VM27InputOK) {
                /* No consumer can interleave this main-thread callback. Close
                 * drops its pending prefix; original owner cleanup releases any
                 * previously admitted hardware state. Never retry a partial key. */
                [self close]; [self softwareKeyboardRejected:result character:0]; return;
            }
        }
    }
    _lastInputResult = VM27InputOK;
}
- (void)insertText:(NSString *)text { [self receiveSoftwareText:text backspace:NO]; }
- (void)deleteBackward { [self receiveSoftwareText:nil backspace:YES]; }

- (BOOL)needsViewAdmissionRecoveryV11
{
    return _ownerPID == getpid() && pthread_main_np() &&
        _viewAdmissionInvalidatedV11 && !_session;
}
- (void)requestViewAdmissionRecoveryV11
{
    if (!_viewAdmissionInvalidatedV11 || _recoveryNoticePendingV11) return;
    _recoveryNoticePendingV11 = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_recoveryNoticePendingV11 = NO;
        if (![self needsViewAdmissionRecoveryV11] || self.hidden ||
            ![self.window isKindOfClass:VM27UIKitInputWindowV2.class] ||
            CGRectIsEmpty(self.bounds) ||
            UIApplication.sharedApplication.applicationState != UIApplicationStateActive) return;
        [NSNotificationCenter.defaultCenter postNotificationName:
            @"VM27InputSurfaceViewInvalidatedV11" object:self];
    });
}
- (void)invalidateViewAdmissionV11
{
    if (_session) {
        _viewAdmissionInvalidatedV11 = YES;
        [self close];
    }
}
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
    memset(_hardwareKeysDown, 0, sizeof(_hardwareKeysDown));
    VM27TrackpadSwipeResetV1(&_trackpadSwipeV13);
    VM27TrackpadTransformResetV1(&_trackpadTransformV14);
    _session = session; _activeWindow = window; _activeBounds = self.bounds;
    _viewAdmissionInvalidatedV11 = NO;
    window.inputSurface = self; _lastInputResult = VM27InputOK;
    [_pointerInteractionV6 invalidate];
    return session;
}
- (VM27InputResult)close
{
    if (_ownerPID != getpid()) return VM27InputStaleEpoch;
    if (!pthread_main_np()) return VM27InputWrongThread;
    [self vm27_cancelFiniteScrollDiagnosticV1];
    VM27UIKitInputSessionV2 *session = _session;
    if (!session) return VM27InputClosed;
    VM27InputResult result = [session close];
    [_directContactsV6 removeAllObjects];
    _activeScrollV8 = nil;
    VM27TrackpadSwipeResetV1(&_trackpadSwipeV13);
    VM27TrackpadTransformResetV1(&_trackpadTransformV14);
    if (result == VM27InputOK || result == VM27InputBusy || result == VM27InputClosed) {
        if (_activeWindow.inputSurface == self) _activeWindow.inputSurface = nil;
        _session = nil; _activeWindow = nil;
        [self requestViewAdmissionRecoveryV11];
    }
    [_pointerInteractionV6 invalidate];
    _lastInputResult = result;
    return result;
}
- (void)resignActive:(NSNotification *)notification { (void)notification; [self close]; }
- (void)didMoveToWindow
{
    [super didMoveToWindow];
    [self requestViewAdmissionRecoveryV11];
    if (_session && self.window != _activeWindow) [self invalidateViewAdmissionV11];
}
- (void)willMoveToWindow:(UIWindow *)window
{
    if (_session && window != _activeWindow) [self invalidateViewAdmissionV11];
    [super willMoveToWindow:window];
    [self requestViewAdmissionRecoveryV11];
}
- (void)setBounds:(CGRect)bounds
{
    if (_session && !CGRectEqualToRect(self.bounds, bounds)) [self invalidateViewAdmissionV11];
    [super setBounds:bounds];
    [self requestViewAdmissionRecoveryV11];
}
- (void)setFrame:(CGRect)frame
{
    if (_session && !CGRectEqualToRect(self.frame, frame)) [self invalidateViewAdmissionV11];
    [super setFrame:frame];
    [self requestViewAdmissionRecoveryV11];
}
- (void)setTransform:(CGAffineTransform)transform
{
    if (_session && !CGAffineTransformEqualToTransform(self.transform, transform)) [self invalidateViewAdmissionV11];
    [super setTransform:transform];
    [self requestViewAdmissionRecoveryV11];
}
- (void)setHidden:(BOOL)hidden
{
    if (_session && hidden) [self invalidateViewAdmissionV11];
    [super setHidden:hidden];
    [self requestViewAdmissionRecoveryV11];
}
- (void)layoutSubviews
{
    [super layoutSubviews];
    if (_session && !CGRectEqualToRect(self.bounds, _activeBounds)) [self invalidateViewAdmissionV11];
    [self requestViewAdmissionRecoveryV11];
}
- (void)dispatchEvent:(UIEvent *)event action:(void (NS_NOESCAPE ^)(void))action
{
    if(_finiteScrollLinkV15)[self vm27_cancelFiniteScrollDiagnosticV1];
    if (_ownerPID != getpid() || !pthread_main_np() || !_session || !event ||
        !isfinite(event.timestamp) || event.timestamp < 0 || _lastStamp == UINT64_MAX) {
        action(); return;
    }
    /* UIHoverEvent reports physical trackpad contacts independently of the
     * zero-touch scroll recognizer. Inspect only an actual event received by
     * this active window; do not monitor global HID or retain event objects. */
    Class hoverClass=NSClassFromString(@"UIHoverEvent");
    if (hoverClass && [event isKindOfClass:hoverClass] &&
        [event respondsToSelector:@selector(_trackpadFingerDownCount)] &&
        self.window==_activeWindow && _activeWindow.inputSurface==self &&
        !self.hidden && UIApplication.sharedApplication.applicationState==UIApplicationStateActive) {
        NSInteger count=[event _trackpadFingerDownCount];
        if (count>=0 && count<=16) {
            BOOL changed=!_trackpadSwipeV13.haveContact || _trackpadSwipeV13.contacts!=(unsigned)count;
            VM27TrackpadSwipeContactV1(&_trackpadSwipeV13,(unsigned)count,NSProcessInfo.processInfo.systemUptime);
            VM27TrackpadTransformContactV1(&_trackpadTransformV14,(unsigned)count,NSProcessInfo.processInfo.systemUptime);
            if(changed && _trackpadContactLogsV13++<24)
                fprintf(stderr,"[Independent27TrackpadContactV13] fingers=%ld actualWindowEvent=1\n",(long)count);
        } else {
            VM27TrackpadSwipeResetV1(&_trackpadSwipeV13);
            VM27TrackpadTransformResetV1(&_trackpadTransformV14);
        }
    }
    UIEvent *previous = _dispatchEvent;
    VM27UIKitInputSessionV2 *previousSession = _dispatchSession;
    uint64_t stamp = _dispatchStamp;
    _dispatchEvent = event; _dispatchSession = _session; _dispatchStamp = ++_lastStamp;
    @try { [self receiveTrackpadTransformEventV14:event]; action(); }
    @finally { _dispatchEvent = previous; _dispatchSession = previousSession; _dispatchStamp = stamp; }
}
- (void)receiveTrackpadTransformEventV14:(UIEvent *)event {
    if (!_session || _session!=_dispatchSession || event!=_dispatchEvent ||
        self.window!=_activeWindow || _activeWindow.inputSurface!=self || self.hidden ||
        UIApplication.sharedApplication.applicationState!=UIApplicationStateActive) return;
    Class cls=NSClassFromString(@"UITransformEvent");
    if (!cls || ![event isKindOfClass:cls]) return;
    Method translationMethod=class_getInstanceMethod(cls,sel_registerName("translation"));
    Method phaseMethod=class_getInstanceMethod(cls,sel_registerName("phase"));
    if(!translationMethod || !phaseMethod ||
        strcmp(method_getTypeEncoding(translationMethod),"{CGPoint=dd}16@0:8") ||
        strcmp(method_getTypeEncoding(phaseMethod),"Q16@0:8")) return;
    CGPoint translation=((CGPoint(*)(id,SEL))objc_msgSend)(event,sel_registerName("translation"));
    NSUInteger phase=((NSUInteger(*)(id,SEL))objc_msgSend)(event,sel_registerName("phase"));
    double received=NSProcessInfo.processInfo.systemUptime;
    VM27TrackpadDirectionV1 direction=VM27TrackpadTransformMoveV1(&_trackpadTransformV14,
        translation.x,translation.y,received);
    if (_trackpadTransformLogsV14++<24)
        fprintf(stderr,"[Independent27TrackpadTransformV14] phase=%lu translation=%.3f,%.3f contacts=%u fresh=%d direction=%u actualWindowEvent=1\n",
            (unsigned long)phase,translation.x,translation.y,_trackpadTransformV14.contacts,
            received>=_trackpadTransformV14.contactTime && received-_trackpadTransformV14.contactTime<=0.35,(unsigned)direction);
    if(direction) {
        UISwipeGestureRecognizerDirection action=direction==VM27TrackpadSwipeUp?UISwipeGestureRecognizerDirectionUp:
            direction==VM27TrackpadSwipeDown?UISwipeGestureRecognizerDirectionDown:
            direction==VM27TrackpadSwipeLeft?UISwipeGestureRecognizerDirectionLeft:UISwipeGestureRecognizerDirectionRight;
        [self sendThreeFingerDirectionV13:action];
        fprintf(stderr,"[Independent27TrackpadSwipeV14] direction=%u result=%u actualThreeContactTransform=1\n",(unsigned)direction,(unsigned)_lastInputResult);
    }
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
    if(_ownerPID!=getpid() || !pthread_main_np() || !_session ||
       !_activeWindow || self.window!=_activeWindow || _activeWindow.inputSurface!=self ||
       (recognizer!=_trackpadScrollV7 && recognizer!=_directScrollV8) || recognizer.view!=self || self.hidden ||
       UIApplication.sharedApplication.applicationState!=UIApplicationStateActive) {
        _lastInputResult=VM27InputUnavailable;return;
    }
    if(recognizer.state==UIGestureRecognizerStateBegan) {
        if(_activeScrollV8 && _activeScrollV8!=recognizer)return;
        _activeScrollV8=recognizer;
    } else if(_activeScrollV8!=recognizer)return;
    const double received=NSProcessInfo.processInfo.systemUptime;
    if(recognizer==_trackpadScrollV7) {
        CGPoint translation=[recognizer translationInView:self];
        VM27TrackpadSwipeResultV1 swipe=VM27TrackpadSwipePanV1(&_trackpadSwipeV13,
            (unsigned)recognizer.state,translation.x,translation.y,received);
        if(swipe.consumed) {
            if(swipe.direction) {
                UISwipeGestureRecognizerDirection direction=swipe.direction==VM27TrackpadSwipeUp?UISwipeGestureRecognizerDirectionUp:
                    swipe.direction==VM27TrackpadSwipeDown?UISwipeGestureRecognizerDirectionDown:
                    swipe.direction==VM27TrackpadSwipeLeft?UISwipeGestureRecognizerDirectionLeft:UISwipeGestureRecognizerDirectionRight;
                [self sendThreeFingerDirectionV13:direction];
                if(_threeFingerLogsV8++<16)fprintf(stderr,"[Independent27TrackpadSwipeV13] direction=%lu result=%u actualThreeContactHint=1\n",
                    (unsigned long)direction,(unsigned)_lastInputResult);
            }
            if(recognizer.state>=UIGestureRecognizerStateEnded)_activeScrollV8=nil;
            return; /* Never also scroll the guest for this three-finger sequence. */
        }
    }
    _lastInputResult=[[_session adapter] snapshotPan:recognizer timestamp:received];
    if(recognizer.state==UIGestureRecognizerStateEnded || recognizer.state==UIGestureRecognizerStateCancelled)
        _activeScrollV8=nil;
    if(_scrollReceiptLogsV7<64) {
        ++_scrollReceiptLogsV7;
        CGPoint translation=[recognizer translationInView:self];
        fprintf(stderr,"[Independent27ScrollReceiptV2] state=%ld touches=%lu translation=%.3f,%.3f received=%.6f result=%u callbackReceiptClock=1\n",
            (long)recognizer.state,(unsigned long)recognizer.numberOfTouches,
            translation.x,translation.y,received,(unsigned)_lastInputResult);
    }
}
/* Three real contacts map to the guest's standard Control-arrow shortcuts.
 * Hardware trackpads may reserve this stream before UIKit; bounded receipt
 * logs distinguish delivered gestures from unimplemented platform routing. */
- (void)receiveThreeFingerSwipe:(UISwipeGestureRecognizer *)recognizer {
    if(_ownerPID!=getpid() || !pthread_main_np() || !_session || !_activeWindow ||
       self.window!=_activeWindow || _activeWindow.inputSurface!=self || recognizer.view!=self ||
       self.hidden || UIApplication.sharedApplication.applicationState!=UIApplicationStateActive ||
       recognizer.state!=UIGestureRecognizerStateRecognized)return;
    [self sendThreeFingerDirectionV13:recognizer.direction];
    if(_threeFingerLogsV8++<16)fprintf(stderr,"[Independent27ThreeFingerV1] direction=%lu result=%u copiedActualRecognizer=1\n",
        (unsigned long)recognizer.direction,(unsigned)_lastInputResult);
}
- (void)sendThreeFingerDirectionV13:(UISwipeGestureRecognizerDirection)direction {
    for(unsigned i=0;i<256;++i)if(_hardwareKeysDown[i])return;
    uint32_t usage;
    switch(direction) {
        case UISwipeGestureRecognizerDirectionUp:usage=0x52;break;
        case UISwipeGestureRecognizerDirectionDown:usage=0x51;break;
        case UISwipeGestureRecognizerDirectionLeft:usage=0x50;break;
        case UISwipeGestureRecognizerDirectionRight:usage=0x4f;break;
        default:return;
    }
    VM27UIKitInputAdapterV2 *adapter=[_session adapter];
    if([adapter checkReceivingView:NULL]!=VM27InputOK)return;
    const double received=NSProcessInfo.processInfo.systemUptime;
    const uint32_t usages[4]={0xe0,usage,usage,0xe0};
    for(unsigned i=0;i<4;++i) {
        _lastInputResult=[self publishSoftwareUsage:usages[i] pressed:i<2 timestamp:received
            modifiers:i<3?VM27InputControl:0 adapter:adapter];
        if(_lastInputResult!=VM27InputOK){[self close];break;}
    }
}
- (BOOL)gestureRecognizerShouldBegin:(UIGestureRecognizer *)recognizer {
    if(recognizer==_directScrollV8 && ![VZAppSettings.sharedSettings boolForKey:VZTouchTwoFingerScrollingKey])return NO;
    return _session!=nil;
}
- (UIEditingInteractionConfiguration)editingInteractionConfiguration {
    return _session && [VZAppSettings.sharedSettings boolForKey:VZMultitaskingGestureSuppressionKey]
        ? UIEditingInteractionConfigurationNone : UIEditingInteractionConfigurationDefault;
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
    /* Hover targets can run after UIWindow.sendEvent returns. They carry
     * a real UIKit location/state but no public UIEvent argument. Use actual
     * callback receipt uptime, as with software keys, and the live session's
     * own queue/epoch. Never require an unrelated touch dispatch stamp. */
    if(_ownerPID!=getpid() || !pthread_main_np() || !_session ||
       !_activeWindow || self.window!=_activeWindow || _activeWindow.inputSurface!=self ||
       recognizer.view!=self || self.hidden ||
       UIApplication.sharedApplication.applicationState!=UIApplicationStateActive) {
        _lastInputResult=VM27InputUnavailable;return;
    }
    if(recognizer.state==UIGestureRecognizerStateEnded || recognizer.state==UIGestureRecognizerStateCancelled)return;
    // A physical hover may move its own held indirect-pointer button. It
    // must not steer a simultaneously active finger or Pencil contact.
    // A cancellation may leave its UITouch retained by UIKit after the view
    // callback was interrupted. The real terminal phase remains authoritative.
    for (UITouch *contact in _directContactsV6.allObjects)
        if (contact.phase == UITouchPhaseEnded || contact.phase == UITouchPhaseCancelled ||
            contact.view.window != _activeWindow)
            [_directContactsV6 removeObject:contact];
    if(_directContactsV6.count){_lastInputResult=VM27InputUnsupported;return;}
    if (!self.isFirstResponder) [self becomeFirstResponder];
    double received=NSProcessInfo.processInfo.systemUptime;
    _lastInputResult=[[_session adapter] snapshotHover:recognizer timestamp:received];
    if (_physicalReceiptLogsV12++ < 16)
        fprintf(stderr,"[Independent27PhysicalReceiptV12] hoverState=%ld result=%u actualFirstResponder=%d liveSession=1\n",
            (long)recognizer.state,(unsigned)_lastInputResult,self.isFirstResponder);
}
- (void)receiveTouches:(UIEvent *)event
{
    if (![self dispatchStampForEvent:event]) { _lastInputResult = VM27InputUnavailable; return; }
    if (!self.isFirstResponder) [self becomeFirstResponder];
    for(UITouch *touch in event.allTouches) {
        UIView *view=touch.view;
        if(touch.type==UITouchTypeIndirectPointer || !view ||
           (view!=self && ![view isDescendantOfView:self]))continue;
        if(touch.phase==UITouchPhaseEnded || touch.phase==UITouchPhaseCancelled)
            [_directContactsV6 removeObject:touch];
        else [_directContactsV6 addObject:touch];
    }
    _lastInputResult = [[_session adapter] snapshotTouchesInEvent:event];
}
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event { (void)touches; [self receiveTouches:event]; }
- (void)receivePresses:(NSSet<UIPress *> *)presses event:(UIPressesEvent *)event
{
    if (![self dispatchStampForEvent:event]) {
        _lastInputResult = VM27InputUnavailable;
        if (_keyReceiptLogsV12++ < 16)
            fprintf(stderr,"[Independent27KeyReceiptV12] dispatchAdmitted=0 actualFirstResponder=%d liveSession=%d noKeyPayload=1\n",
                self.isFirstResponder,_session!=nil);
        return;
    }
    for (UIPress *press in presses) {
        _lastInputResult = [[_session adapter] snapshotKeyPress:press];
        if (_keyReceiptLogsV12++ < 16)
            fprintf(stderr,"[Independent27KeyReceiptV12] dispatchAdmitted=1 result=%u actualFirstResponder=%d sameWindow=%d noKeyPayload=1\n",
                (unsigned)_lastInputResult,self.isFirstResponder,press.window==_activeWindow);
        if (_lastInputResult == VM27InputOK && press.key && press.key.keyCode > 0 && press.key.keyCode < 256)
            _hardwareKeysDown[press.key.keyCode] = press.phase == UIPressPhaseBegan;
    }
}
- (void)pressesBegan:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event { [self receivePresses:presses event:event]; }
- (void)pressesEnded:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event { [self receivePresses:presses event:event]; }
- (void)pressesCancelled:(NSSet<UIPress *> *)presses withEvent:(UIPressesEvent *)event { [self receivePresses:presses event:event]; }
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)first shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)second
{
    return first.view == self && second.view == self;
}
- (BOOL)vm27_scrollDiagnosticIdentityV15
{
    if(_ownerPID!=getpid() || !pthread_main_np() || !_session ||
       !_activeWindow || self.window!=_activeWindow || _activeWindow.inputSurface!=self ||
       self.hidden || UIApplication.sharedApplication.applicationState!=UIApplicationStateActive)return NO;
    UIView *view=nil;
    return [[_session adapter] checkReceivingView:&view]==VM27InputOK && view==self;
}
- (VM27InputResult)vm27_publishDiagnosticScrollV15:(VM27InputPhase)phase delta:(double)delta
{
    BOOL terminal=phase==VM27InputEnded || phase==VM27InputCancelled;
    if(_ownerPID!=getpid() || !pthread_main_np() || !_session ||
       _session!=_finiteScrollSessionV15)return VM27InputUnavailable;
    if(!terminal && ![self vm27_scrollDiagnosticIdentityV15])return VM27InputUnavailable;
    /* A terminal cleanup must remain possible after the App becomes inactive.
     * It uses the same live adapter/epoch and never starts new input there. */
    if(terminal && [[_session adapter] checkReceivingView:NULL]!=VM27InputOK)return VM27InputUnavailable;
    VM27InputPacket packet={.source=VM27InputPan,
        .monotonic_timestamp_seconds=NSProcessInfo.processInfo.systemUptime,
        .present=VM27InputHasPhase|VM27InputHasPosition|VM27InputHasProcessedScroll,
        .phase=phase,.view_x_points=CGRectGetMidX(self.bounds),.view_y_points=CGRectGetMidY(self.bounds),
        .processed_scroll_y_points=delta};
    VM27InputResult result=[[_session adapter] publish:&packet];
    if(result==VM27InputOK)++_finiteScrollPacketsV15;
    return result;
}
- (void)vm27_finishFiniteScrollV15:(BOOL)cancelled
{
    if(!_finiteScrollLinkV15)return;
    [_finiteScrollLinkV15 invalidate];_finiteScrollLinkV15=nil;
    VM27InputResult terminal=[self vm27_publishDiagnosticScrollV15:
        cancelled?VM27InputCancelled:VM27InputEnded delta:0];
    VM27InputResult restored=[[_finiteScrollSessionV15 adapter] vm27_setFiniteDiagnosticPanCoalescingV1:YES];
    fprintf(stderr,"[VM27FiniteScrollV1] end run=%u baseline=%u cancelled=%u published=%u ticks=%u elapsed=%.3f maxTickGapMs=%.3f rawDistance=%.3f terminal=%u restore=%u hardwareEventClaimed=0\n",
        _finiteScrollRunsV15,_finiteScrollBaselineV15,cancelled,_finiteScrollPacketsV15,
        _finiteScrollTicksV15,NSProcessInfo.processInfo.systemUptime-_finiteScrollStartV15,
        _finiteScrollMaxGapV15*1000,_finiteScrollTargetV15,(unsigned)terminal,(unsigned)restored);
    _finiteScrollSessionV15=nil;
}
- (void)vm27_cancelFiniteScrollDiagnosticV1 { [self vm27_finishFiniteScrollV15:YES]; }
- (void)vm27_finiteScrollTickV15:(CADisplayLink *)link
{
    if(link!=_finiteScrollLinkV15 || ![self vm27_scrollDiagnosticIdentityV15] ||
       _session!=_finiteScrollSessionV15 || _finiteScrollTicksV15>=1800) {
        [self vm27_finishFiniteScrollV15:YES];return;
    }
    double now=NSProcessInfo.processInfo.systemUptime;
    double elapsed=now-_finiteScrollStartV15;
    if(elapsed>10.0) {[self vm27_finishFiniteScrollV15:YES];return;}
    _finiteScrollMaxGapV15=fmax(_finiteScrollMaxGapV15,now-_finiteScrollLastTickV15);
    _finiteScrollLastTickV15=now;++_finiteScrollTicksV15;
    double target=6000.0;
    if(elapsed<7.5) {
        unsigned leg=(unsigned)(elapsed/1.5);
        double fraction=(elapsed-leg*1.5)/1.5;
        target=6000.0*((leg&1)?1.0-fraction:fraction);
    }
    VM27InputResult result=[self vm27_publishDiagnosticScrollV15:VM27InputChanged
        delta:target-_finiteScrollTargetV15];
    if(result!=VM27InputOK) {[self vm27_finishFiniteScrollV15:YES];return;}
    _finiteScrollTargetV15=target;
    if(elapsed>=7.5)[self vm27_finishFiniteScrollV15:NO];
}
- (BOOL)vm27_beginFiniteScrollDiagnosticV1:(BOOL)legacyUncoalesced
{
    if(![self vm27_scrollDiagnosticIdentityV15] || _finiteScrollLinkV15 ||
       _finiteScrollRunsV15>=3 || _activeScrollV8 || _directContactsV6.count)return NO;
    for(unsigned i=0;i<256;++i)if(_hardwareKeysDown[i])return NO;
    VM27UIKitInputAdapterV2 *adapter=[_session adapter];
    if([adapter vm27_setFiniteDiagnosticPanCoalescingV1:!legacyUncoalesced]!=VM27InputOK)return NO;
    _finiteScrollSessionV15=_session;_finiteScrollBaselineV15=legacyUncoalesced;
    _finiteScrollPacketsV15=_finiteScrollTicksV15=0;_finiteScrollTargetV15=0;_finiteScrollMaxGapV15=0;
    _finiteScrollStartV15=_finiteScrollLastTickV15=NSProcessInfo.processInfo.systemUptime;
    if([self vm27_publishDiagnosticScrollV15:VM27InputBegan delta:0]!=VM27InputOK) {
        [adapter vm27_setFiniteDiagnosticPanCoalescingV1:YES];_finiteScrollSessionV15=nil;return NO;
    }
    ++_finiteScrollRunsV15;
    _finiteScrollLinkV15=[CADisplayLink displayLinkWithTarget:self selector:@selector(vm27_finiteScrollTickV15:)];
    _finiteScrollLinkV15.preferredFramesPerSecond=120;
    [_finiteScrollLinkV15 addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
    unsigned run=_finiteScrollRunsV15;__weak VM27UIKitInputSurfaceV2 *weakSelf=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        VM27UIKitInputSurfaceV2 *owner=weakSelf;
        if(owner && owner->_finiteScrollRunsV15==run)[owner vm27_finishFiniteScrollV15:YES];
    });
    fprintf(stderr,"[VM27FiniteScrollV1] begin run=%u baseline=%u durationSeconds=7.5 maxRuns=3 ownCopiedPanPackets=1 hardwareEventClaimed=0\n",run,legacyUncoalesced);
    return YES;
}

- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
    /* Failsafe closes only our C admission. Explicit main-thread close remains
     * the application lifecycle entry; no UIKit mutation occurs in dealloc. */
    [_session invalidateOwnAdmission];
}
@end
