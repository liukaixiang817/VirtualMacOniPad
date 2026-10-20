#import "modern_vz_processed_scroll_receiver_v2.h"
#import "modern_vz_scroll_normalization_v1.h"
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

extern uint32_t IOHIDEventGetType(CFTypeRef);
extern uint32_t IOHIDEventGetPhase(CFTypeRef);
extern double IOHIDEventGetFloatValue(CFTypeRef, uint32_t);

/* Own compile-time declarations for messages to already loaded, identity-
 * checked genuine classes. No Apple class or method is defined/replaced. */
@protocol VM27ActualScrollConstructorV1 <NSObject>
- (instancetype)initWithScrollingDeltaX:(double)x scrollingDeltaY:(double)y
    acceleratedScrollingDeltaX:(double)normalizedX acceleratedScrollingDeltaY:(double)normalizedY
    scrollPhase:(uint64_t)phase momentumPhase:(uint64_t)momentum;
- (double)scrollingDeltaX;
- (double)scrollingDeltaY;
- (double)acceleratedScrollingDeltaX;
- (double)acceleratedScrollingDeltaY;
- (uint64_t)scrollPhase;
- (uint64_t)momentumPhase;
@end
@protocol VM27ActualPointingSenderV1 <NSObject>
- (void)sendScrollWheelEvents:(NSArray *)events;
@end

static const uint8_t original27_uuid[16] = {0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,
    0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};

static BOOL genuine_image(const void *pointer, uintptr_t *base) {
    Dl_info image = {0};
    if (!pointer || !dladdr(pointer, &image) || !image.dli_fbase) return NO;
    const struct mach_header_64 *header = image.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > 128*1024) return NO;
    const uint8_t *at = (const uint8_t *)(header+1), *end = at+header->sizeofcmds;
    unsigned matched = 0;
    for (uint32_t i=0; i<header->ncmds; ++i) {
        if ((size_t)(end-at) < 8) return NO;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize > (size_t)(end-at)) return NO;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) ||
                memcmp(((const struct uuid_command *)at)->uuid, original27_uuid,16)) return NO;
            ++matched;
        }
        at += command->cmdsize;
    }
    if (at != end || matched != 1) return NO;
    if (base) *base = (uintptr_t)header;
    return YES;
}

static BOOL genuine_method(Class cls, const char *selector, const char *encoding, uintptr_t rva) {
    Method method = class_getInstanceMethod(cls, sel_registerName(selector));
    if (!method || strcmp(method_getTypeEncoding(method), encoding)) return NO;
    const void *imp = ptrauth_strip((void *)method_getImplementation(method), ptrauth_key_function_pointer);
    uintptr_t base = 0;
    return genuine_image(imp,&base) && (uintptr_t)imp >= base && (uintptr_t)imp-base == rva;
}

@implementation VM27VZGenuineProcessedScrollReceiverV1 {
    id<VM27ActualPointingSenderV1> _pointingDevice;
    NSThread *_consumerThread;
    uint64_t _epoch, _coordinates, _lastSequence;
    pid_t _ownerPID;
}
+ (BOOL)genuine27ScrollProfileMatchesPointingDevice:(id)pointingDevice {
    Class event = objc_getClass("_VZScrollWheelEvent");
    Class pointing = objc_getClass("_VZPointingDevice");
    if (!event || !pointing || !pointingDevice || class_getInstanceSize(event)!=56 ||
        class_getInstanceSize(pointing)!=32 || !genuine_image((__bridge const void *)event,NULL) ||
        !genuine_image((__bridge const void *)pointing,NULL)) return NO;
    Class concrete = object_getClass(pointingDevice), ancestor = concrete;
    while (ancestor && ancestor != pointing) ancestor = class_getSuperclass(ancestor);
    if (ancestor != pointing || !genuine_image((__bridge const void *)concrete,NULL)) return NO;
    return genuine_method(event,"initWithScrollingDeltaX:scrollingDeltaY:acceleratedScrollingDeltaX:acceleratedScrollingDeltaY:scrollPhase:momentumPhase:","@64@0:8d16d24d32d40Q48Q56",0x6494c) &&
        genuine_method(event,"scrollingDeltaX","d16@0:8",0x64e04) &&
        genuine_method(event,"scrollingDeltaY","d16@0:8",0x64e0c) &&
        genuine_method(event,"acceleratedScrollingDeltaX","d16@0:8",0x64e14) &&
        genuine_method(event,"acceleratedScrollingDeltaY","d16@0:8",0x64e1c) &&
        genuine_method(event,"scrollPhase","Q16@0:8",0x64e24) &&
        genuine_method(event,"momentumPhase","Q16@0:8",0x64e2c) &&
        genuine_method(concrete,"sendScrollWheelEvents:","v24@0:8@16",0x5c770);
}
- (instancetype)initWithPointingDevice:(id)pointingDevice consumerThread:(NSThread *)consumerThread
    epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates {
    if (!consumerThread || !epoch || !coordinates ||
        ![[self class] genuine27ScrollProfileMatchesPointingDevice:pointingDevice]) return nil;
    self = [super init];
    if (self) { _pointingDevice = pointingDevice; _consumerThread = consumerThread;
        _epoch = epoch; _coordinates = coordinates; _ownerPID=getpid(); }
    return self;
}
- (VM27InputResult)consumeNativeProcessedScroll:(CFTypeRef)nativeEvent epoch:(uint64_t)epoch
    sequence:(uint64_t)sequence coordinates:(uint64_t)coordinates {
    if ([NSThread currentThread] != _consumerThread) return VM27InputWrongThread;
    if (epoch != _epoch) return VM27InputStaleEpoch;
    if (coordinates != _coordinates) return VM27InputWrongCoordinates;
    if (!sequence || sequence <= _lastSequence) return VM27InputStaleSequence;
    if (!nativeEvent || !vm27_processed_scroll_native_profile_matches() ||
        object_getClass((__bridge id)nativeEvent) != objc_getClass("HIDEvent") ||
        IOHIDEventGetType(nativeEvent) != 6 ||
        ![[self class] genuine27ScrollProfileMatchesPointingDevice:_pointingDevice])
        return VM27InputUnavailable;
    VM27VZProcessedScrollArgumentsV1 args;
    VM27InputResult result = vm27_vz_processed_scroll_arguments_v1(
        IOHIDEventGetFloatValue(nativeEvent,0x60000), IOHIDEventGetFloatValue(nativeEvent,0x60001),
        IOHIDEventGetFloatValue(nativeEvent,0x60002), IOHIDEventGetPhase(nativeEvent), &args);
    if (result != VM27InputOK) return result;
    return [self sendArguments:args sequence:sequence commit:nil];
}
- (VM27InputResult)consumeCopiedPan:(const VM27InputPacket *)packet
    speed:(double)speed commit:(void (NS_NOESCAPE ^)(void))commit {
    if (_ownerPID!=getpid()) return VM27InputStaleEpoch;
    if ([NSThread currentThread]!=_consumerThread) return VM27InputWrongThread;
    if (!packet || packet->version!=1 || packet->source!=VM27InputPan ||
        (packet->present & (VM27InputHasPhase|VM27InputHasProcessedScroll))!=
            (VM27InputHasPhase|VM27InputHasProcessedScroll) ||
        !isfinite(speed) || speed<0.01 || speed>1.0) return VM27InputInvalid;
    if (packet->owner_epoch!=_epoch) return VM27InputStaleEpoch;
    if (packet->coordinate_generation!=_coordinates) return VM27InputWrongCoordinates;
    if (!packet->event_sequence || packet->event_sequence<=_lastSequence) return VM27InputStaleSequence;
    if (![[self class] genuine27ScrollProfileMatchesPointingDevice:_pointingDevice]) return VM27InputUnavailable;
    uint32_t phase;
    switch(packet->phase) {
        case VM27InputBegan:phase=1;break;
        case VM27InputChanged:phase=2;break;
        case VM27InputEnded:phase=4;break;
        case VM27InputCancelled:phase=8;break;
        default:return VM27InputUnsupported;
    }
    VM27VZProcessedScrollArgumentsV1 args;
    VM27InputResult result=vm27_vz_processed_scroll_arguments_v1(
        packet->processed_scroll_x_points,packet->processed_scroll_y_points,0,phase,&args);
    if(result!=VM27InputOK)return result;
    args.normalized_x=args.scrolling_x*speed;
    args.normalized_y=args.scrolling_y*speed;
    return [self sendArguments:args sequence:packet->event_sequence commit:commit];
}
- (VM27InputResult)sendArguments:(VM27VZProcessedScrollArgumentsV1)args
    sequence:(uint64_t)sequence commit:(void (NS_NOESCAPE ^)(void))commit {
    @try {
        Class eventClass = objc_getClass("_VZScrollWheelEvent");
        id<VM27ActualScrollConstructorV1> event = [(id<VM27ActualScrollConstructorV1>)[eventClass alloc]
            initWithScrollingDeltaX:args.scrolling_x scrollingDeltaY:args.scrolling_y
            acceleratedScrollingDeltaX:args.normalized_x acceleratedScrollingDeltaY:args.normalized_y
            scrollPhase:args.scroll_phase momentumPhase:args.momentum_phase];
        if (!event) return VM27InputNoMemory;
        if (object_getClass(event) != eventClass || [event scrollingDeltaX] != args.scrolling_x ||
            [event scrollingDeltaY] != args.scrolling_y ||
            [event acceleratedScrollingDeltaX] != args.normalized_x ||
            [event acceleratedScrollingDeltaY] != args.normalized_y ||
            [event scrollPhase] != args.scroll_phase || [event momentumPhase] != 0)
            return VM27InputUnavailable;
        /* Commit immediately before original delivery. Once the genuine sender
         * is entered, an exception cannot establish whether its context consumed
         * the packet; sequence must never be retried as a duplicate. */
        _lastSequence = sequence;
        if(commit)commit();
        [_pointingDevice sendScrollWheelEvents:@[event]];
        return VM27InputOK;
    } @catch (NSException *exception) {
        (void)exception; return VM27InputInvalid;
    }
}
@end
