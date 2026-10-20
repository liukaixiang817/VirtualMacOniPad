#import "modern_uikit_input_adapter_v2.h"
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#import "modern_input_packet_lease_private_v2.h"

#if !__has_feature(objc_arc)
#error Own UIKit input adapter requires ARC.
#endif

static VM27InputResult gesture_phase(UIGestureRecognizerState state, uint32_t *output)
{
    uint32_t phase;
    switch (state) {
    case UIGestureRecognizerStateBegan: phase = VM27InputBegan; break;
    case UIGestureRecognizerStateChanged: phase = VM27InputChanged; break;
    case UIGestureRecognizerStateEnded: phase = VM27InputEnded; break;
    case UIGestureRecognizerStateCancelled: phase = VM27InputCancelled; break;
    default: return VM27InputUnsupported;
    }
    *output = phase;
    return VM27InputOK;
}

@implementation VM27UIKitInputAdapterV2 {
    __weak UIView *_view;
    __weak UIWindow *_window;
    CGRect _bounds;
    pid_t _pid;
    pthread_t _thread;
    uint64_t _epoch, _generation, _sequence, _contactGeneration;
    VM27InputQueue *_queue;
    NSMapTable<UITouch *, NSNumber *> *_contactIDs;
    __weak UIPanGestureRecognizer *_pan;
    __weak UIPinchGestureRecognizer *_pinch;
    __weak UIRotationGestureRecognizer *_rotation;
    CGPoint _panTranslation;
    double _pinchScale, _rotationRadians;
    BOOL _panActive, _pinchActive, _rotationActive;
}

- (instancetype)initWithView:(UIView *)view epoch:(uint64_t)epoch
                  coordinateGeneration:(uint64_t)generation capacity:(size_t)capacity
{
    if (!pthread_main_np() || !view || !view.window) return nil;
    CGRect bounds = view.bounds;
    if (!isfinite(bounds.origin.x) || !isfinite(bounds.origin.y) ||
        !isfinite(bounds.size.width) || !isfinite(bounds.size.height) ||
        bounds.size.width <= 0 || bounds.size.height <= 0) return nil;
    VM27InputQueue *queue = NULL;
    if (vm27_input_queue_create(epoch, generation, capacity, &queue) != VM27InputOK) return nil;
    self = [super init];
    if (!self) {
        vm27_input_queue_close(queue, epoch); vm27_input_queue_destroy(&queue);
        return nil;
    }
    _view = view; _window = view.window; _bounds = bounds;
    _pid = getpid(); _thread = pthread_self();
    _epoch = epoch; _generation = generation; _queue = queue;
    /* Weak UIKit keys, copied monotonically allocated own IDs. No UIKit object
     * is retained in a packet or through a consumer's autorelease boundary. */
    _contactIDs = [NSMapTable weakToStrongObjectsMapTable];
    if (!_contactIDs) return nil;
    return self;
}

- (VM27InputResult)checkReceivingView:(UIView * _Nullable * _Nullable)output
{
    if (_pid != getpid()) return VM27InputStaleEpoch;
    if (!pthread_main_np() || !pthread_equal(_thread, pthread_self())) return VM27InputWrongThread;
    UIView *view = _view;
    UIWindow *window = _window;
    if (!view || !window || view.window != window) return VM27InputUnavailable;
    if (!CGRectEqualToRect(_bounds, view.bounds)) return VM27InputWrongCoordinates;
    if (output) *output = view;
    return VM27InputOK;
}

- (VM27InputResult)publish:(VM27InputPacket *)packet
{
    if (_sequence == UINT64_MAX) return VM27InputInvalid;
    packet->version = 1; packet->owner_epoch = _epoch;
    packet->coordinate_generation = _generation; packet->event_sequence = _sequence + 1;
    VM27InputResult result = vm27_input_queue_publish(_queue, packet);
    if (result == VM27InputOK) _sequence++;
    return result;
}

- (VM27InputResult)prepareGesture:(UIGestureRecognizer *)recognizer source:(uint32_t)source
                       timestamp:(double)seconds packet:(VM27InputPacket *)packet
{
    UIView *view = nil;
    VM27InputResult result = [self checkReceivingView:&view];
    if (result != VM27InputOK) return result;
    if (!recognizer || recognizer.view != view) return VM27InputWrongCoordinates;
    uint32_t phase;
    result = gesture_phase(recognizer.state, &phase);
    if (result != VM27InputOK) return result;
    CGPoint position = [recognizer locationInView:view];
    *packet = (VM27InputPacket){.source = source, .monotonic_timestamp_seconds = seconds,
        .present = VM27InputHasPhase | VM27InputHasPosition, .phase = phase,
        .view_x_points = position.x, .view_y_points = position.y};
    return VM27InputOK;
}

- (VM27InputResult)snapshotPan:(UIPanGestureRecognizer *)recognizer timestamp:(double)seconds
{
    VM27InputPacket packet;
    VM27InputResult result = [self prepareGesture:recognizer source:VM27InputPan timestamp:seconds packet:&packet];
    if (result != VM27InputOK) return result;
    BOOL began = packet.phase == VM27InputBegan;
    if (began ? _panActive : (!_panActive || _pan != recognizer)) return VM27InputInvalid;
    CGPoint translation = [recognizer translationInView:_view];
    CGPoint previous = began ? CGPointZero : _panTranslation;
    packet.present |= VM27InputHasProcessedScroll;
    packet.processed_scroll_x_points = translation.x - previous.x;
    packet.processed_scroll_y_points = translation.y - previous.y;
    result = [self publish:&packet];
    if (result == VM27InputOK) {
        _pan = recognizer; _panTranslation = translation;
        _panActive = packet.phase == VM27InputBegan || packet.phase == VM27InputChanged;
    }
    return result;
}

- (VM27InputResult)snapshotHover:(UIHoverGestureRecognizer *)recognizer timestamp:(double)seconds
{
    VM27InputPacket packet;
    VM27InputResult result = [self prepareGesture:recognizer source:VM27InputHover timestamp:seconds packet:&packet];
    return result == VM27InputOK ? [self publish:&packet] : result;
}

- (VM27InputResult)snapshotPinch:(UIPinchGestureRecognizer *)recognizer timestamp:(double)seconds
{
    VM27InputPacket packet;
    VM27InputResult result = [self prepareGesture:recognizer source:VM27InputPinch timestamp:seconds packet:&packet];
    if (result != VM27InputOK) return result;
    BOOL began = packet.phase == VM27InputBegan;
    if (began ? _pinchActive : (!_pinchActive || _pinch != recognizer)) return VM27InputInvalid;
    double scale = recognizer.scale;
    if (!isfinite(scale) || scale <= 0) return VM27InputInvalid;
    packet.present |= VM27InputHasScaleDelta;
    packet.additive_scale_delta = scale - (began ? 1.0 : _pinchScale);
    result = [self publish:&packet];
    if (result == VM27InputOK) {
        _pinch = recognizer; _pinchScale = scale;
        _pinchActive = packet.phase == VM27InputBegan || packet.phase == VM27InputChanged;
    }
    return result;
}

- (VM27InputResult)snapshotRotation:(UIRotationGestureRecognizer *)recognizer timestamp:(double)seconds
{
    VM27InputPacket packet;
    VM27InputResult result = [self prepareGesture:recognizer source:VM27InputRotation timestamp:seconds packet:&packet];
    if (result != VM27InputOK) return result;
    BOOL began = packet.phase == VM27InputBegan;
    if (began ? _rotationActive : (!_rotationActive || _rotation != recognizer)) return VM27InputInvalid;
    double radians = recognizer.rotation;
    if (!isfinite(radians)) return VM27InputInvalid;
    packet.present |= VM27InputHasRotationRadians;
    packet.rotation_delta_radians = radians - (began ? 0.0 : _rotationRadians);
    result = [self publish:&packet];
    if (result == VM27InputOK) {
        _rotation = recognizer; _rotationRadians = radians;
        _rotationActive = packet.phase == VM27InputBegan || packet.phase == VM27InputChanged;
    }
    return result;
}

- (VM27InputResult)snapshotKeyPress:(UIPress *)press
{
    VM27InputResult result = [self checkReceivingView:NULL];
    if (result != VM27InputOK) return result;
    if (!press || !press.key) return VM27InputUnsupported;
    if (press.window != _window) return VM27InputWrongCoordinates;
    uint32_t phase;
    switch (press.phase) {
    case UIPressPhaseBegan: phase = VM27InputBegan; break;
    case UIPressPhaseEnded: phase = VM27InputEnded; break;
    case UIPressPhaseCancelled: phase = VM27InputCancelled; break;
    default: return VM27InputUnsupported;
    }
    UIKey *key = press.key;
    NSInteger usage = key.keyCode;
    if (usage <= 0 || usage > UINT16_MAX) return VM27InputUnsupported;
    UIKeyModifierFlags flags = key.modifierFlags;
    const UIKeyModifierFlags known = UIKeyModifierAlphaShift | UIKeyModifierShift | UIKeyModifierControl |
        UIKeyModifierAlternate | UIKeyModifierCommand | UIKeyModifierNumericPad;
    if (flags & ~known) return VM27InputUnsupported;
    uint32_t modifiers = 0;
    if (flags & UIKeyModifierAlphaShift) modifiers |= VM27InputCapsLock;
    if (flags & UIKeyModifierShift) modifiers |= VM27InputShift;
    if (flags & UIKeyModifierControl) modifiers |= VM27InputControl;
    if (flags & UIKeyModifierAlternate) modifiers |= VM27InputAlternate;
    if (flags & UIKeyModifierCommand) modifiers |= VM27InputCommand;
    if (flags & UIKeyModifierNumericPad) modifiers |= VM27InputNumericPad;
    VM27InputPacket packet = {.source = VM27InputKey, .monotonic_timestamp_seconds = press.timestamp,
        .present = VM27InputHasPhase | VM27InputHasHIDUsage | VM27InputHasModifiers,
        .phase = phase, .hid_usage_page = 7, .hid_usage = (uint32_t)usage,
        .named_modifiers = modifiers, .pressed = phase == VM27InputBegan};
    return [self publish:&packet];
}

- (VM27InputResult)snapshotTouchesInEvent:(UIEvent *)event
{
    UIView *view = nil;
    VM27InputResult result = [self checkReceivingView:&view];
    if (result != VM27InputOK) return result;
    if (!event || event.type != UIEventTypeTouches) return VM27InputUnsupported;
    VM27InputContact contacts[32];
    size_t count = 0;
    for (UITouch *touch in event.allTouches) {
        UIView *receiving = touch.view;
        if (!receiving || receiving.window != _window ||
            (receiving != view && ![receiving isDescendantOfView:view])) continue;
        if (count == 32) return VM27InputUnsupported;
        uint32_t phase;
        switch (touch.phase) {
        case UITouchPhaseBegan: phase = VM27InputBegan; break;
        case UITouchPhaseMoved: phase = VM27InputChanged; break;
        case UITouchPhaseStationary: phase = VM27InputStationary; break;
        case UITouchPhaseEnded: phase = VM27InputEnded; break;
        case UITouchPhaseCancelled: phase = VM27InputCancelled; break;
        default: return VM27InputUnsupported;
        }
        NSNumber *identifier = [_contactIDs objectForKey:touch];
        if (!identifier) {
            if (_contactGeneration == UINT64_MAX) return VM27InputInvalid;
            identifier = @(++_contactGeneration);
            [_contactIDs setObject:identifier forKey:touch];
        }
        CGPoint position = [touch locationInView:view];
        contacts[count++] = (VM27InputContact){.owner_epoch = _epoch,
            .contact_generation = identifier.unsignedLongLongValue,
            .view_x_points = position.x, .view_y_points = position.y, .phase = phase};
    }
    if (!count) return VM27InputUnavailable;
    VM27InputPacket packet = {.source = VM27InputTouch, .monotonic_timestamp_seconds = event.timestamp,
        .present = VM27InputHasPhase | VM27InputHasContacts, .phase = VM27InputContactSnapshot,
        .contact_count = count, .contacts = contacts};
    return [self publish:&packet];
}

- (VM27InputPacketLeaseV2 *)copyNextLease:(VM27InputResult *)result
{
    if (!result) return nil;
    if (_pid != getpid()) { *result = VM27InputStaleEpoch; return nil; }
    VM27InputLease *lease = NULL;
    *result = vm27_input_queue_acquire(_queue, &lease);
    if (*result != VM27InputOK) return nil;
    VM27InputPacketLeaseV2 *wrapper = vm27_input_objc_lease_take_v2(self, &lease);
    if (!wrapper) {
        vm27_input_lease_release(&lease);
        *result = VM27InputNoMemory;
    }
    return wrapper;
}

- (VM27InputResult)close
{
    if (_pid != getpid()) return VM27InputStaleEpoch;
    if (!pthread_main_np() || !pthread_equal(_thread, pthread_self())) return VM27InputWrongThread;
    VM27InputResult result = [self invalidateOwnAdmission];
    _panActive = NO; _pinchActive = NO; _rotationActive = NO;
    [_contactIDs removeAllObjects];
    return result;
}

- (VM27InputResult)invalidateOwnAdmission
{
    if (_pid != getpid()) return VM27InputStaleEpoch;
    return vm27_input_queue_close(_queue, _epoch);
}

- (void)dealloc
{
    /* Each outstanding wrapper retains this adapter. This cannot run before
     * its leases drain; cleanup never accesses or changes UIKit here. */
    if (_queue) {
        vm27_input_queue_close(_queue, _epoch);
        vm27_input_queue_destroy(&_queue);
    }
}
@end
