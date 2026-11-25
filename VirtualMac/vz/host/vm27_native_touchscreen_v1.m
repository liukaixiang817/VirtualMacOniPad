#import "vm27_native_touchscreen_v1.h"
#import "VZAppSettings.h"
#import <CommonCrypto/CommonDigest.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <math.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

NSString *const VM27NativeTouchScreenSettingV1 = @"NativeTouchScreenEnabled27";
// The initializer's 64-value index domain is wider than the guest's routed
// transducers. Keep a bounded pool in the verified low range, ample for the
// physical iPad's simultaneous finger contacts plus delayed retirement.
enum { VM27NativeTouchSlotCountV1 = 16 };

static NSError *TouchError(NSString *message)
{
    return [NSError errorWithDomain:@"VirtualMac.NativeTouchScreenV1" code:1
        userInfo:@{NSLocalizedDescriptionKey:message}];
}

BOOL VM27NativeTouchScreenGuestSupportedV1(NSDictionary *options)
{
    NSNumber *explicit = options[VM27NativeTouchScreenSettingV1];
    if ([explicit isKindOfClass:NSNumber.class]) return explicit.boolValue;
    NSString *build = options[@"VMGuestOSBuildV1"] ?: options[@"AppleAccountGuestBuildV1"];
    if (![build isKindOfClass:NSString.class]) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:build];
    NSInteger darwin = 0;
    if (![scanner scanInteger:&darwin]) return NO;
    // macOS 27.2 introduced the shipping touchscreen Mac. Older guests retain
    // the established pointer/trackpad path even on the macOS 27 host backend.
    return darwin > 26 || (darwin == 26 && scanner.scanLocation < build.length &&
        [build characterAtIndex:scanner.scanLocation] >= 'B' &&
        [build characterAtIndex:scanner.scanLocation] <= 'Z');
}

static BOOL OriginalTouchAPI(void)
{
    Class touch = objc_getClass("_VZTouch");
    Method init = class_getInstanceMethod(touch,
        sel_registerName("initWithView:index:phase:location:swipeAim:timestamp:"));
    const char *image = touch ? class_getImageName(touch) : NULL;
    return init && image && strstr(image, "/parent-flat/VZ27.dylib") &&
        !strcmp(method_getTypeEncoding(init), "@68@0:8@16C24q28{CGPoint=dd}36q52d60");
}

BOOL VM27ConfigureNativeTouchScreenV1(id configuration, id display,
    NSString *bundlePath, NSDictionary *options, NSError **error)
{
    if (!VM27NativeTouchScreenGuestSupportedV1(options) ||
        [VZAppSettings.sharedSettings.dictionaryRepresentation[VM27NativeTouchScreenSettingV1] isEqual:@NO])
        return YES;
    @try {
        Class cls = objc_getClass("_VZAppleTouchScreenConfiguration");
        if (!OriginalTouchAPI() || !cls ||
            ![configuration respondsToSelector:sel_registerName("_setMultiTouchDevices:")] ||
            ![display respondsToSelector:sel_registerName("_setDisplayIdentifier:")]) {
            if (error) *error = TouchError(@"The native macOS 27 touchscreen interface is unavailable.");
            return NO;
        }
        NSData *machine = [NSData dataWithContentsOfFile:
            [bundlePath stringByAppendingPathComponent:@"MachineIdentifier"]];
        if (!machine.length) {
            if (error) *error = TouchError(@"The virtual Mac has no saved machine identifier.");
            return NO;
        }
        NSMutableData *seed = [[@"VirtualMac native touch display v1" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        [seed appendData:machine];
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(seed.bytes, (CC_LONG)seed.length, hash);
        hash[6] = (hash[6] & 0x0f) | 0x50;
        hash[8] = (hash[8] & 0x3f) | 0x80;
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:hash];
        id screen = [[cls alloc] init];
        if (!screen || ![screen respondsToSelector:sel_registerName("_setRegistryProperties:")]) {
            if (error) *error = TouchError(@"The native touchscreen device could not be created.");
            return NO;
        }
        // Match the digitizer and PVG display before the guest HID service is
        // published. A touchscreen descriptor alone does not enable AppKit's
        // direct-touch routing. See Henge PR #32's display-association findings.
        ((void (*)(id, SEL, id))objc_msgSend)(display,
            sel_registerName("_setDisplayIdentifier:"), uuid.UUIDString);
        ((void (*)(id, SEL, id))objc_msgSend)(screen,
            sel_registerName("_setRegistryProperties:"),
            @{ @"displayUUID":uuid.UUIDString, @"DisplayIntegrated":@YES });
        ((void (*)(id, SEL, id))objc_msgSend)(configuration,
            sel_registerName("_setMultiTouchDevices:"), @[screen]);
        fprintf(stderr, "[NativeTouchScreenV1] configured originalAppleDevice=1 displayAssociated=1\n");
        return YES;
    } @catch (NSException *exception) {
        if (error) *error = TouchError(exception.reason ?: @"Native touchscreen configuration failed.");
        return NO;
    }
}

@interface VM27NativeTouchScreenV1 ()
@property(nonatomic, weak) id vm;
@property(nonatomic, weak) UIView *view;
@property(nonatomic, strong) id device;
@end

@protocol VM27OriginalTouchInitializerV1 <NSObject>
- (instancetype)initWithView:(nullable id)view index:(unsigned char)index
    phase:(NSInteger)phase location:(CGPoint)point swipeAim:(NSInteger)aim timestamp:(double)time;
@end
@protocol VM27OriginalTouchFrameInitializerV1 <NSObject>
- (instancetype)initWithTouches:(NSSet *)touches;
@end

@implementation VM27NativeTouchScreenV1 {
    NSMapTable<UITouch *, NSNumber *> *_contacts;
    NSMutableDictionary<NSNumber *, NSValue *> *_positions;
    double _retiredUntil[VM27NativeTouchSlotCountV1];
    uint64_t _occupied, _lastStamp;
    unsigned _nextIndex, _logs;
    pid_t _pid;
    BOOL _failed;
}

+ (instancetype)screenForVirtualMachine:(id)vm view:(UIView *)view
{
    if (!pthread_main_np() || !OriginalTouchAPI() ||
        ![vm respondsToSelector:sel_registerName("_multiTouchDevices")]) return nil;
    NSArray *devices = ((id (*)(id, SEL))objc_msgSend)(vm, sel_registerName("_multiTouchDevices"));
    id device = devices.firstObject;
    if (!device || ![device respondsToSelector:sel_registerName("sendMultiTouchEvents:")]) return nil;
    VM27NativeTouchScreenV1 *owner = [self new];
    owner.vm = vm; owner.view = view; owner.device = device; owner->_pid = getpid();
    owner->_contacts = [NSMapTable strongToStrongObjectsMapTable];
    owner->_positions = [NSMutableDictionary dictionary];
    fprintf(stderr, "[NativeTouchScreenV1] bound originalDevice=1 mainQueue=1\n");
    return owner;
}

- (BOOL)ownsDirectFingers { return self.device != nil; }

- (BOOL)canSend
{
    id vm = self.vm;
    if (_pid != getpid() || !pthread_main_np() || !vm || !self.device) return NO;
    if (((dispatch_queue_t (*)(id, SEL))objc_msgSend)(vm, sel_registerName("queue")) != dispatch_get_main_queue() ||
        ((NSInteger (*)(id, SEL))objc_msgSend)(vm, sel_registerName("state")) != 1) return NO;
    NSArray *devices = ((id (*)(id, SEL))objc_msgSend)(vm, sel_registerName("_multiTouchDevices"));
    return [devices indexOfObjectIdenticalTo:self.device] != NSNotFound;
}

static id MakeTouch(unsigned index, NSInteger phase, CGPoint point, double time)
{
    // This original initializer accepts normalized, top-left coordinates and
    // phases 0..4 (began/moved/stationary/ended/cancelled). A nil VZ view selects
    // its nonrotated path; UIKit geometry is normalized by this owner instead.
    id<VM27OriginalTouchInitializerV1> allocated = [objc_getClass("_VZTouch") alloc];
    return [allocated initWithView:nil index:(unsigned char)index phase:phase
        location:point swipeAim:0 timestamp:time];
}

- (void)send:(NSSet *)touches
{
    if (!touches.count || ![self canSend]) return;
    id<VM27OriginalTouchFrameInitializerV1> allocated = [objc_getClass("_VZMultiTouchEvent") alloc];
    id frame = [allocated initWithTouches:touches];
    ((void (*)(id, SEL, id))objc_msgSend)(self.device,
        sel_registerName("sendMultiTouchEvents:"), @[frame]);
    if (_logs++ < 12)
        fprintf(stderr, "[NativeTouchScreenV1] frame contacts=%lu originalSender=1\n", (unsigned long)touches.count);
}

- (void)retire:(NSNumber *)slot now:(double)now
{
    unsigned index = slot.unsignedIntValue;
    _occupied &= ~(UINT64_C(1) << index);
    _retiredUntil[index] = now + .07;
    [_positions removeObjectForKey:slot];
}

- (void)receiveEvent:(UIEvent *)event dispatchStamp:(uint64_t)stamp
{
    UIView *view = self.view;
    if (!stamp || stamp == _lastStamp || ![self canSend] || _failed ||
        !view.window || view.hidden || event.type != UIEventTypeTouches) return;
    _lastStamp = stamp;
    CGRect bounds = view.bounds;
    if (!(bounds.size.width > 0 && bounds.size.height > 0)) { [self cancelAll]; return; }
    double now = NSProcessInfo.processInfo.systemUptime;
    NSMutableSet *frame = [NSMutableSet set];
    NSMutableArray<UITouch *> *finished = [NSMutableArray array];
    @try {
        for (UITouch *touch in _contacts.keyEnumerator.allObjects) {
            if ([event.allTouches containsObject:touch]) continue;
            NSNumber *slot = [_contacts objectForKey:touch];
            [frame addObject:MakeTouch(slot.unsignedIntValue, 4, _positions[slot].CGPointValue, now)];
            [finished addObject:touch];
        }
        for (UITouch *touch in event.allTouches) {
            if (touch.type != UITouchTypeDirect ||
                !(touch.view == view || [touch.view isDescendantOfView:view]) ||
                touch.phase < UITouchPhaseBegan || touch.phase > UITouchPhaseCancelled) continue;
            NSNumber *slot = [_contacts objectForKey:touch];
            // Do not cycle through every value accepted by VZTouch: higher
            // transducer indices were silently dropped in device testing.
            if (!slot && touch.phase == UITouchPhaseBegan && _contacts.count < VM27NativeTouchSlotCountV1) {
                for (unsigned attempt = 0; attempt < VM27NativeTouchSlotCountV1; ++attempt) {
                    unsigned index = (_nextIndex + attempt) % VM27NativeTouchSlotCountV1;
                    if (!(_occupied & (UINT64_C(1) << index)) && now >= _retiredUntil[index]) {
                        slot = @(index); _nextIndex = (index + 1) % VM27NativeTouchSlotCountV1;
                        _occupied |= UINT64_C(1) << index;
                        [_contacts setObject:slot forKey:touch]; break;
                    }
                }
            }
            if (!slot) continue; // A mid-stroke reconnect must wait for a new finger-down.
            CGPoint p = [touch locationInView:view];
            if (!isfinite(p.x) || !isfinite(p.y) || !isfinite(touch.timestamp)) { [self cancelAll]; return; }
            p = CGPointMake(fmin(1, fmax(0, (p.x - bounds.origin.x) / bounds.size.width)),
                            fmin(1, fmax(0, (p.y - bounds.origin.y) / bounds.size.height)));
            _positions[slot] = [NSValue valueWithCGPoint:p];
            [frame addObject:MakeTouch(slot.unsignedIntValue, touch.phase, p, touch.timestamp)];
            if (touch.phase == UITouchPhaseEnded || touch.phase == UITouchPhaseCancelled)
                [finished addObject:touch];
        }
        [self send:frame];
        for (UITouch *touch in finished) {
            NSNumber *slot = [_contacts objectForKey:touch];
            if (slot) [self retire:slot now:now];
            [_contacts removeObjectForKey:touch];
        }
    } @catch (NSException *exception) {
        fprintf(stderr, "[NativeTouchScreenV1] sender failed: %s\n", exception.name.UTF8String);
        [self cancelAll]; _failed = YES;
    }
}

- (void)willDispatchWindowEvent:(UIEvent *)event
{
    if (!_contacts.count || !pthread_main_np()) return;
    UIView *view = self.view;
    for (UITouch *touch in event.allTouches)
        if (touch.type == UITouchTypeDirect && touch.phase == UITouchPhaseBegan &&
            touch.view != view && ![touch.view isDescendantOfView:view]) {
            [self cancelAll]; break; // Host controls, panels and software keyboard.
        }
}

- (void)cancelAll
{
    if (_pid != getpid() || !pthread_main_np()) return;
    double now = NSProcessInfo.processInfo.systemUptime;
    @try {
        NSMutableSet *frame = [NSMutableSet set];
        for (NSNumber *slot in _positions)
            [frame addObject:MakeTouch(slot.unsignedIntValue, 4, _positions[slot].CGPointValue, now)];
        [self send:frame];
    } @catch (NSException *exception) { (void)exception; }
    for (NSNumber *slot in _positions.allKeys) [self retire:slot now:now];
    [_contacts removeAllObjects]; _occupied = 0; _lastStamp = 0;
}
@end
