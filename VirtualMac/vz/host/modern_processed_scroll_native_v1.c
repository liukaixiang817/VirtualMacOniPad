#include "modern_processed_scroll_native_v1.h"
#include <dlfcn.h>
#include <mach/mach_time.h>
#include <mach-o/loader.h>
#include <math.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <string.h>

extern CFTypeRef IOHIDEventCreateScrollEvent(CFAllocatorRef, uint64_t, double, double, double, uint32_t);
extern uint32_t IOHIDEventGetType(CFTypeRef);
extern uint64_t IOHIDEventGetTimeStamp(CFTypeRef);
extern double IOHIDEventGetFloatValue(CFTypeRef, uint32_t);
extern void IOHIDEventSetPhase(CFTypeRef, uint32_t);
extern uint32_t IOHIDEventGetPhase(CFTypeRef);
extern void objc_release(id);

#ifdef VM27_SCROLL_MAC_COMPARISON_PROFILE
static const uint8_t native_uuid[16] = {0x0e,0x4c,0xf3,0xe4,0xb0,0xc2,0x31,0x2a,
    0xb1,0x47,0x0b,0xd4,0x97,0x8e,0xf0,0xb7};
enum { native_instance_size = 104 };
#else
static const uint8_t native_uuid[16] = {0x87,0xae,0x25,0xce,0x3b,0xef,0x39,0xd9,
    0xba,0xa9,0x0d,0x8c,0xc1,0x5a,0x34,0xa0};
enum { native_instance_size = 112 };
#endif

static int genuine_uuid(const void *address) {
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase) return 0;
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > 128 * 1024) return 0;
    const uint8_t *at = (const uint8_t *)(header + 1), *end = at + header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(end-at) < sizeof(struct load_command)) return 0;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize > (size_t)(end-at)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) ||
                memcmp(((const struct uuid_command *)at)->uuid, native_uuid, 16)) return 0;
            ++matches;
        }
        at += command->cmdsize;
    }
    return at == end && matches == 1;
}

#define REAL_IOKIT(function) genuine_uuid(ptrauth_strip((void *)&function, ptrauth_key_function_pointer))
int vm27_processed_scroll_native_profile_matches(void) {
    Class cls = objc_getClass("HIDEvent");
    return cls && class_getInstanceSize(cls) == native_instance_size && genuine_uuid(cls) &&
        REAL_IOKIT(IOHIDEventCreateScrollEvent) && REAL_IOKIT(IOHIDEventGetType) &&
        REAL_IOKIT(IOHIDEventGetTimeStamp) && REAL_IOKIT(IOHIDEventGetFloatValue) &&
        REAL_IOKIT(IOHIDEventSetPhase) && REAL_IOKIT(IOHIDEventGetPhase);
}

VM27InputResult vm27_processed_scroll_mach_ticks(double seconds, uint32_t numer,
                                                uint32_t denom, uint64_t *output) {
    if (!output || !numer || !denom || !isfinite(seconds) || seconds < 0) return VM27InputInvalid;
    /* Original genuine UHK scales seconds by 1e9, then HIDTime multiplies by
     * denom, divides by numer and FRINTA. Compile with fp-contract=off. The own
     * port rejects overflow rather than using original saturating invalid data. */
    double nanoseconds = seconds * 1000000000.0;
    double ticks = round((nanoseconds * (double)denom) / (double)numer);
    if (!isfinite(ticks) || ticks < 0 || ticks >= 0x1p64) return VM27InputInvalid;
    *output = (uint64_t)ticks;
    return VM27InputOK;
}

static VM27InputResult validate_pan(const VM27InputPacket *packet, uint32_t *native_phase) {
    if (!packet || !native_phase || packet->version != 1 || !packet->owner_epoch ||
        !packet->event_sequence || !packet->coordinate_generation) return VM27InputInvalid;
    if (packet->source != VM27InputPan) return VM27InputUnsupported;
    const uint64_t supported = VM27InputHasProcessedScroll | VM27InputHasPhase | VM27InputHasPosition;
    if (packet->present != supported) return VM27InputUnsupported;
    if (!isfinite(packet->view_x_points) || !isfinite(packet->view_y_points) ||
        !isfinite(packet->processed_scroll_x_points) || !isfinite(packet->processed_scroll_y_points) ||
        packet->processed_scroll_x_points <= -32768.0 || packet->processed_scroll_x_points >= 32768.0 ||
        packet->processed_scroll_y_points <= -32768.0 || packet->processed_scroll_y_points >= 32768.0 ||
        packet->additive_scale_delta != 0 || packet->rotation_delta_radians != 0 ||
        packet->hid_usage_page || packet->hid_usage || packet->named_modifiers || packet->pressed ||
        packet->contact_count || packet->contacts) return VM27InputInvalid;
    /* Named semantic mapping, not a reinterpretation of UIKit/NSEvent bits. */
    switch (packet->phase) {
    case VM27InputBegan: *native_phase = 1; break;
    case VM27InputChanged: *native_phase = 2; break;
    case VM27InputEnded: *native_phase = 4; break;
    case VM27InputCancelled: *native_phase = 8; break;
    default: return VM27InputUnsupported;
    }
    return VM27InputOK;
}

VM27InputResult vm27_processed_scroll_create_owned(const VM27InputPacket *packet, CFTypeRef *output) {
    if (!output) return VM27InputInvalid;
    uint32_t phase;
    VM27InputResult result = validate_pan(packet, &phase);
    if (result != VM27InputOK) return result;
    mach_timebase_info_data_t timebase = {0};
    if (mach_timebase_info(&timebase) != KERN_SUCCESS) return VM27InputUnavailable;
    uint64_t ticks;
    result = vm27_processed_scroll_mach_ticks(packet->monotonic_timestamp_seconds,
                                             timebase.numer, timebase.denom, &ticks);
    if (result != VM27InputOK) return result;
    if (!vm27_processed_scroll_native_profile_matches()) return VM27InputUnavailable;
    CFTypeRef event = IOHIDEventCreateScrollEvent(NULL, ticks, packet->processed_scroll_x_points,
                                                packet->processed_scroll_y_points, 0.0, 0);
    if (!event) return VM27InputNoMemory;
    IOHIDEventSetPhase(event, phase);
    double x = (double)(int32_t)(packet->processed_scroll_x_points * 65536.0) / 65536.0;
    double y = (double)(int32_t)(packet->processed_scroll_y_points * 65536.0) / 65536.0;
    if (object_getClass((id)event) != objc_getClass("HIDEvent") || IOHIDEventGetType(event) != 6 ||
        IOHIDEventGetTimeStamp(event) != ticks || IOHIDEventGetPhase(event) != phase ||
        IOHIDEventGetFloatValue(event, 0x60000) != x || IOHIDEventGetFloatValue(event, 0x60001) != y ||
        IOHIDEventGetFloatValue(event, 0x60002) != 0.0) {
        objc_release((id)event); return VM27InputUnavailable;
    }
    *output = event;
    return VM27InputOK;
}

void vm27_processed_scroll_release_owned(CFTypeRef *event) {
    if (!event || !*event) return;
    CFTypeRef owned = *event; *event = NULL;
    objc_release((id)owned);
}
