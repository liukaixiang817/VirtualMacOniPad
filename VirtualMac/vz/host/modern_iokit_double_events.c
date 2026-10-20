// Finite native old-host adaptation for the two original27 double packets.
// Allocation and object lifetime stay with genuine system IOKit. No event is
// published to a service; native kernel consumption of these types is unproved.
#include "modern_iokit_double_event_packets.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <stdint.h>
#include <string.h>

extern CFTypeRef _IOHIDEventCreate(CFAllocatorRef, CFIndex, uint32_t, uint64_t, uint32_t);
extern void objc_release(id);

#ifndef VM27_FORCE_EVENT_EXPORT
#define VM27_FORCE_EVENT_EXPORT IOHIDEventCreateForceStageEvent
#endif
#ifndef VM27_TOUCH_EVENT_EXPORT
#define VM27_TOUCH_EVENT_EXPORT IOHIDEventCreateTouchSensitiveButtonEventWithRadius
#endif

#ifdef VM27_IOKIT_MAC_PACKET_FIXTURE
// An explicit ordinary Mac comparison profile. This binary cannot validate or
// exercise the old iPad initializer or its +104 data layout.
static const uint8_t native_uuid[16] = {0x0e,0x4c,0xf3,0xe4,0xb0,0xc2,0x31,0x2a,
    0xb1,0x47,0x0b,0xd4,0x97,0x8e,0xf0,0xb7};
enum { native_instance_size=104, native_data_offset=96 };
#else
static const uint8_t native_uuid[16] = {0x87,0xae,0x25,0xce,0x3b,0xef,0x39,0xd9,
    0xba,0xa9,0x0d,0x8c,0xc1,0x5a,0x34,0xa0};
enum { native_instance_size=112, native_data_offset=104 };
static const char native_ivar_type[] = "{?=\"timeStamp\"Q\"senderID\"Q\"typeMask\"Q\"options\"I"
    "\"attributeData\"*\"context\"^v\"attachments\"^{__CFDictionary}\"sender\"^v"
    "\"children\"^{__CFArray}\"parent\"^{__IOHIDEvent}\"attributeDataLength\"q"
    "\"eventCount\"q\"eventData\"^{IOHIDEventData}}";
#endif

static int genuine_uuid(const void *address) {
    Dl_info origin = {0};
    if (!dladdr(address, &origin) || !origin.dli_fbase) return 0;
    const struct mach_header_64 *header = origin.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > 128 * 1024) return 0;
    const uint8_t *at = (const uint8_t *)(header + 1);
    const uint8_t *end = at + header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t index=0; index<header->ncmds; ++index) {
        if ((size_t)(end-at) < sizeof(struct load_command)) return 0;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize > (size_t)(end-at)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command)) return 0;
            const struct uuid_command *uuid = (const void *)at;
            if (memcmp(uuid->uuid,native_uuid,16)) return 0;
            ++matches;
        }
        at += command->cmdsize;
    }
    return at==end && matches==1;
}

int vm27_iokit_double_events_profile_matches(void) {
    Class cls = objc_getClass("HIDEvent");
    const void *allocation = ptrauth_strip((void *)&_IOHIDEventCreate, ptrauth_key_function_pointer);
    if (!cls || !genuine_uuid(allocation) || !genuine_uuid(cls) ||
        class_getInstanceSize(cls)!=native_instance_size) return 0;
#ifndef VM27_IOKIT_MAC_PACKET_FIXTURE
    Ivar ivar = class_getInstanceVariable(cls,"_event");
    if (!ivar || ivar_getOffset(ivar)!=8) return 0;
    const char *type = ivar_getTypeEncoding(ivar);
    if (!type || strcmp(type,native_ivar_type)) return 0;
#endif
    return 1;
}

static CFTypeRef allocate_packet(CFAllocatorRef allocator, CFIndex bytes,
    uint32_t type, uint64_t timestamp, uint32_t options, uint8_t **packet) {
    if (!vm27_iokit_double_events_profile_matches()) return NULL;
    CFTypeRef event = _IOHIDEventCreate(allocator,bytes,type,timestamp,options);
    if (!event) return NULL;
    Class cls = objc_getClass("HIDEvent");
    if (object_getClass((id)event)!=cls) { objc_release((id)event); return NULL; }
    uint8_t *data = NULL;
    memcpy(&data,(const uint8_t *)event+native_data_offset,sizeof(data));
    uint32_t header[3]; uint64_t actual_timestamp, mask; uint32_t actual_options;
    if (!data) { objc_release((id)event); return NULL; }
    memcpy(header,data,sizeof(header));
    memcpy(&actual_timestamp,(const uint8_t *)event+8,8);
    memcpy(&mask,(const uint8_t *)event+24,8);
    memcpy(&actual_options,(const uint8_t *)event+32,4);
    if (header[0]!=(uint32_t)bytes || header[1]!=type || header[2]!=options ||
        actual_timestamp!=timestamp || mask!=(UINT64_C(1)<<type) || actual_options!=options) {
        objc_release((id)event); return NULL;
    }
    *packet = data;
    return event;
}

__attribute__((visibility("default")))
CFTypeRef VM27_FORCE_EVENT_EXPORT(CFAllocatorRef allocator, uint64_t timestamp,
    uint32_t index, uint32_t stage, double progress, double stage_pressure,
    double pressure, double accumulated_pressure, double overall_progress,
    uint32_t options) {
    uint8_t *packet;
    CFTypeRef event = allocate_packet(allocator,80,41,timestamp,options,&packet);
    if (event) vm27_iokit_write_force_stage_packet(packet,index,stage,progress,
        stage_pressure,pressure,accumulated_pressure,overall_progress);
    return event;
}

__attribute__((visibility("default")))
CFTypeRef VM27_TOUCH_EVENT_EXPORT(CFAllocatorRef allocator, uint64_t timestamp,
    uint32_t usage_page, uint32_t usage, uint32_t mask, uint32_t touching,
    double x, double y, double z, double pressure, double major_radius,
    double minor_radius, uint32_t options) {
    uint8_t *packet;
    CFTypeRef event = allocate_packet(allocator,96,42,timestamp,options,&packet);
    if (event) vm27_iokit_write_touch_radius_packet(packet,usage_page,usage,mask,
        touching,x,y,z,pressure,major_radius,minor_radius);
    return event;
}
