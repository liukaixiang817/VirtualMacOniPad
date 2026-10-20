#import "vm27_own_uikit_ingress_profile_v1.h"
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <math.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <string.h>
#include <unistd.h>
#if !__has_feature(objc_arc)
#error Own UIKit ingress profile requires ARC.
#endif

@protocol VM27OriginalKeyValueV1 <NSObject>
- (instancetype)initWithType:(int64_t)type keyCode:(uint16_t)key;
- (int64_t)type;
- (uint16_t)keyCode;
@end
@protocol VM27OriginalPointerValueV1 <NSObject>
- (instancetype)initWithLocation:(CGPoint)location pressedButtons:(int64_t)buttons;
- (CGPoint)location;
- (int64_t)pressedButtons;
@end
@protocol VM27OriginalOwnInputSenderV1 <NSObject>
- (void)sendKeyEvents:(NSArray *)events;
- (void)sendPointerEvents:(NSArray *)events;
@end

static const uint8_t uuid[16] = {0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,
    0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
static BOOL original_image(const void *address, uintptr_t *base) {
    Dl_info info = {0};
    if (!address || !dladdr(address, &info) || !info.dli_fbase) return NO;
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > 128*1024) return NO;
    const uint8_t *at = (const uint8_t *)(header+1), *end = at+header->sizeofcmds;
    unsigned found = 0;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end-at) < 8) return NO;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize > (size_t)(end-at)) return NO;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) ||
                memcmp(((const struct uuid_command *)at)->uuid, uuid, 16)) return NO;
            ++found;
        }
        at += command->cmdsize;
    }
    if (at != end || found != 1) return NO;
    if (base) *base = (uintptr_t)header;
    return YES;
}
static BOOL method_at(Class cls, const char *name, const char *type, uintptr_t rva) {
    Method method = class_getInstanceMethod(cls, sel_registerName(name));
    if (!method || strcmp(method_getTypeEncoding(method), type)) return NO;
    const void *imp = ptrauth_strip((void *)method_getImplementation(method), ptrauth_key_function_pointer);
    uintptr_t base = 0;
    return original_image(imp, &base) && (uintptr_t)imp >= base && (uintptr_t)imp-base == rva;
}
static BOOL class_shape(const char *name, size_t bytes, Class *output) {
    Class cls = objc_getClass(name);
    if (!cls || class_getInstanceSize(cls) != bytes || !original_image((__bridge const void *)cls, NULL)) return NO;
    *output = cls; return YES;
}

@implementation VM27OwnUIKitIngressProfileV1 {
    id<VM27OriginalOwnInputSenderV1> _pointing, _keyboard;
    VM27NativeProcessedScrollSinkV1 *_scroll;
    NSThread *_thread;
    pid_t _pid;
    uint64_t _epoch, _coordinates, _lastSequence;
    VM27InputViewportV1 _viewport;
    VM27OwnPointerStateV1 _pointer;
    BOOL _keyPressed[256], _closed, _panActive, _deliveryUncertain;
    unsigned _codeHolds[128];
    VM27InputPacket _lastPan;
}
+ (BOOL)genuine27PointingAndKeyboardProfileMatches:(id)pointing keyboard:(id)keyboard {
    Class key, pointer, baseKeyboard, usbKeyboard, screenPointing;
    if (!pointing || !keyboard ||
        !class_shape("_VZKeyEvent", 24, &key) ||
        !class_shape("_VZScreenCoordinatePointerEvent", 32, &pointer) ||
        !class_shape("_VZKeyboard", 40, &baseKeyboard) ||
        !class_shape("_VZUSBKeyboard", 48, &usbKeyboard) ||
        !class_shape("_VZScreenCoordinatePointingDevice", 36, &screenPointing) ||
        object_getClass(keyboard) != usbKeyboard || object_getClass(pointing) != screenPointing ||
        class_getSuperclass(usbKeyboard) != baseKeyboard) return NO;
    return method_at(key, "initWithType:keyCode:", "@28@0:8q16S24", 0x5a28c) &&
        method_at(key, "type", "q16@0:8", 0x5a454) &&
        method_at(key, "keyCode", "S16@0:8", 0x5a45c) &&
        method_at(usbKeyboard, "sendKeyEvents:", "v24@0:8@16", 0x58aa8) &&
        method_at(pointer, "initWithLocation:pressedButtons:", "@40@0:8{CGPoint=dd}16q32", 0x64394) &&
        method_at(pointer, "location", "{CGPoint=dd}16@0:8", 0x645c8) &&
        method_at(pointer, "pressedButtons", "q16@0:8", 0x64604) &&
        method_at(screenPointing, "sendPointerEvents:", "v24@0:8@16", 0x6460c) &&
        [VM27VZGenuineProcessedScrollReceiverV1 genuine27ScrollProfileMatchesPointingDevice:pointing];
}
- (instancetype)initWithPointingDevice:(id)pointing keyboard:(id)keyboard
    consumerThread:(NSThread *)thread epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates
    viewport:(VM27InputViewportV1)viewport {
    if (!thread || !epoch || !coordinates || !isfinite(viewport.x) || !isfinite(viewport.y) ||
        !isfinite(viewport.width) || !isfinite(viewport.height) || viewport.width <= 0 || viewport.height <= 0 ||
        ![[self class] genuine27PointingAndKeyboardProfileMatches:pointing keyboard:keyboard]) return nil;
    VM27VZGenuineProcessedScrollReceiverV1 *receiver = [[VM27VZGenuineProcessedScrollReceiverV1 alloc]
        initWithPointingDevice:pointing consumerThread:thread epoch:epoch coordinates:coordinates];
    if (!receiver) return nil;
    self = [super init];
    if (self) {
        _pointing = pointing; _keyboard = keyboard; _thread = thread; _pid = getpid();
        _epoch = epoch; _coordinates = coordinates; _viewport = viewport;
        _scroll = [[VM27NativeProcessedScrollSinkV1 alloc] initWithReceiver:receiver];
    }
    return self;
}
- (VM27InputResult)ownerResult {
    if (getpid() != _pid) return VM27InputStaleEpoch;
    if ([NSThread currentThread] != _thread) return VM27InputWrongThread;
    if (_closed) return VM27InputClosed;
    if (_deliveryUncertain) return VM27InputUnavailable;
    if (![[self class] genuine27PointingAndKeyboardProfileMatches:_pointing keyboard:_keyboard])
        return VM27InputUnavailable;
    return VM27InputOK;
}
- (VM27InputResult)sendKeyType:(int64_t)type code:(uint16_t)code commit:(void (NS_NOESCAPE ^)(void))commit {
    Class cls = objc_getClass("_VZKeyEvent");
    id<VM27OriginalKeyValueV1> event = [(id<VM27OriginalKeyValueV1>)[cls alloc] initWithType:type keyCode:code];
    if (!event) return VM27InputNoMemory;
    if (object_getClass(event) != cls || [event type] != type || [event keyCode] != code) return VM27InputUnavailable;
    NSArray *ownedEvents = @[event];
    if (commit) commit();
    [_keyboard sendKeyEvents:ownedEvents];
    return VM27InputOK;
}
- (VM27InputResult)sendPointerArguments:(VM27OwnPointerArgumentsV1)args commit:(void (NS_NOESCAPE ^)(void))commit {
    Class cls = objc_getClass("_VZScreenCoordinatePointerEvent");
    CGPoint location = CGPointMake(args.x, args.y);
    id<VM27OriginalPointerValueV1> event = [(id<VM27OriginalPointerValueV1>)[cls alloc]
        initWithLocation:location pressedButtons:args.buttons];
    if (!event) return VM27InputNoMemory;
    CGPoint readback = [event location];
    if (object_getClass(event) != cls || readback.x != args.x || readback.y != args.y || [event pressedButtons] != args.buttons)
        return VM27InputUnavailable;
    NSArray *ownedEvents = @[event];
    if (commit) commit();
    [_pointing sendPointerEvents:ownedEvents];
    return VM27InputOK;
}
- (VM27InputResult)consumeCopiedInputPacket:(const VM27InputPacket *)packet {
    VM27InputResult result = [self ownerResult]; if (result != VM27InputOK) return result;
    if (!packet || packet->owner_epoch != _epoch) return VM27InputStaleEpoch;
    if (packet->coordinate_generation != _coordinates) return VM27InputWrongCoordinates;
    if (!packet->event_sequence || packet->event_sequence <= _lastSequence) return VM27InputStaleSequence;
    if (packet->version != 1) return VM27InputInvalid;
    @try {
        if (packet->source == VM27InputKey) {
            int64_t type; uint16_t code;
            result = vm27_own_key_arguments_v1(packet, &type, &code); if (result != VM27InputOK) return result;
            if (packet->hid_usage >= 256) return VM27InputUnsupported;
            if (_keyPressed[packet->hid_usage] == packet->pressed) return VM27InputEmpty;
            if (code >= 128 || (!packet->pressed && !_codeHolds[code])) return VM27InputInvalid;
            /* Several distinct HID usages share the same genuine virtual key.
             * One alias must not release another admitted alias's held key. */
            if ((packet->pressed && _codeHolds[code]) || (!packet->pressed && _codeHolds[code] > 1)) {
                _lastSequence = packet->event_sequence;
                _keyPressed[packet->hid_usage] = packet->pressed;
                if (packet->pressed) ++_codeHolds[code]; else --_codeHolds[code];
                return VM27InputOK;
            }
            /* Burn the sequence before delivery. An original sender exception
             * cannot prove whether the genuine VM consumed the key. */
            return [self sendKeyType:type code:code commit:^{
                _lastSequence = packet->event_sequence; _keyPressed[packet->hid_usage] = packet->pressed;
                if (packet->pressed) ++_codeHolds[code]; else --_codeHolds[code];
            }];
        }
        if (packet->source == VM27InputTouch || packet->source == VM27InputHover) {
            VM27OwnPointerArgumentsV1 args; VM27OwnPointerStateV1 next;
            result = vm27_own_pointer_arguments_v1(packet, _viewport, &_pointer, &args, &next);
            if (result != VM27InputOK) return result;
            return [self sendPointerArguments:args commit:^{
                _lastSequence = packet->event_sequence; _pointer = next;
            }];
        }
        if (packet->source == VM27InputPan) {
            _lastSequence = packet->event_sequence;
            result = [_scroll consumeCopiedInputPacket:packet];
            if (result == VM27InputOK) {
                _panActive = packet->phase == VM27InputBegan || packet->phase == VM27InputChanged;
                _lastPan = *packet; _lastPan.contacts = NULL; _lastPan.contact_count = 0;
            }
            return result;
        }
        return VM27InputUnsupported;
    } @catch (NSException *exception) {
        (void)exception; _deliveryUncertain = YES; return VM27InputInvalid;
    }
}
- (VM27InputResult)closeOnConsumerThread {
    /* A failed sender has unknown consumption, but close must still attempt to
     * release the inputs this profile had admitted before that failure. */
    if (getpid() != _pid) return VM27InputStaleEpoch;
    if ([NSThread currentThread] != _thread) return VM27InputWrongThread;
    if (_closed) return VM27InputClosed;
    if (![[self class] genuine27PointingAndKeyboardProfileMatches:_pointing keyboard:_keyboard])
        return VM27InputUnavailable;
    VM27InputResult result = VM27InputOK;
    _closed = YES;
    VM27InputResult firstError = _deliveryUncertain ? VM27InputUnavailable : VM27InputOK;
    for (unsigned usage = 0; usage < 256; ++usage) if (_keyPressed[usage]) {
        _keyPressed[usage] = NO;
        VM27InputPacket release = {.version=1, .source=VM27InputKey,
            .present=VM27InputHasHIDUsage|VM27InputHasPhase, .hid_usage_page=7,
            .hid_usage=usage, .phase=VM27InputCancelled, .pressed=false};
        int64_t type; uint16_t code;
        result = vm27_own_key_arguments_v1(&release, &type, &code);
        if (result == VM27InputOK && code < 128 && _codeHolds[code] > 1) {
            --_codeHolds[code]; continue;
        }
        @try { if (result == VM27InputOK) result = [self sendKeyType:type code:code commit:nil]; }
        @catch (NSException *exception) { (void)exception; result = VM27InputInvalid; }
        if (firstError == VM27InputOK && result != VM27InputOK) firstError = result;
        if (result == VM27InputOK && code < 128) _codeHolds[code] = 0;
    }
    if (_pointer.pressed) {
        _pointer.pressed = false; _pointer.primaryContact = 0;
        @try { result = [self sendPointerArguments:(VM27OwnPointerArgumentsV1){_pointer.normalizedX, _pointer.normalizedY, 0} commit:nil]; }
        @catch (NSException *exception) { (void)exception; result = VM27InputInvalid; }
        if (firstError == VM27InputOK && result != VM27InputOK) firstError = result;
    }
    if (_panActive) {
        _panActive = NO;
        if (_lastSequence == UINT64_MAX) result = VM27InputInvalid;
        else {
            VM27InputPacket cancel = _lastPan;
            cancel.event_sequence = ++_lastSequence; cancel.phase = VM27InputCancelled;
            cancel.processed_scroll_x_points = cancel.processed_scroll_y_points = 0;
            @try { result = [_scroll consumeCopiedInputPacket:&cancel]; }
            @catch (NSException *exception) { (void)exception; result = VM27InputInvalid; }
        }
        if (firstError == VM27InputOK && result != VM27InputOK) firstError = result;
    }
    return firstError;
}
- (BOOL)hasClosedAdmissionOnConsumerThread {
    return getpid()==_pid && [NSThread currentThread]==_thread && _closed;
}
@end
