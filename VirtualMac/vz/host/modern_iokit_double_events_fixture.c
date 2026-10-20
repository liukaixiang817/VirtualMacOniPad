// Adapted from modern_iokit_event_packet_fixture.c, retained frozen unchanged.
// Compare a finite generic-allocator packet implementation with both genuine
// original27 native named constructors. Ordinary Mac objects only, no publish.
// Production-profile mode verifies rejection on this different real host.
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int vm27_iokit_double_events_profile_matches(void);
extern CFTypeRef VM27ForceStageFixture(CFAllocatorRef, uint64_t, uint32_t, uint32_t,
    double, double, double, double, double, uint32_t);
extern CFTypeRef VM27TouchRadiusFixture(CFAllocatorRef, uint64_t, uint32_t, uint32_t,
    uint32_t, uint32_t, double, double, double, double, double, double, uint32_t);
extern id objc_retain(id);
extern void objc_release(id);
typedef CFTypeRef (*ForceFn)(CFAllocatorRef, uint64_t, uint32_t, uint32_t,
                           double, double, double, double, double, uint32_t);
typedef CFTypeRef (*TouchFn)(CFAllocatorRef, uint64_t, uint32_t, uint32_t,
                           uint32_t, uint32_t, double, double, double, double,
                           double, double, uint32_t);
typedef CFArrayRef (*ChildrenFn)(CFTypeRef);
typedef void (*AppendFn)(CFTypeRef, CFTypeRef, uint32_t);
static unsigned checks;
static void require(int condition, const char *message) {
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message); exit(2); }
}
#ifndef VM27_PRODUCTION_REJECTION_FIXTURE
static void *symbol(void *handle, const char *name) {
    void *result = dlsym(handle, name);
    require(result != NULL, name);
    Dl_info info = {0};
    require(dladdr(result, &info) != 0 && info.dli_fbase != NULL, "real symbol origin");
    const struct mach_header_64 *header = info.dli_fbase;
    require(header->magic == MH_MAGIC_64, "real 64-bit loaded IOKit header");
    const uint8_t expected[16] = {0x0e,0x4c,0xf3,0xe4,0xb0,0xc2,0x31,0x2a,
                                 0xb1,0x47,0x0b,0xd4,0x97,0x8e,0xf0,0xb7};
    const uint8_t *at = (const uint8_t *)(header + 1);
    const uint8_t *end = at + header->sizeofcmds;
    unsigned found = 0;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        require(at + sizeof(struct load_command) <= end, "bounded loaded command");
        const struct load_command *command = (const void *)at;
        require(command->cmdsize >= 8 && at + command->cmdsize <= end, "loaded command extent");
        if (command->cmd == LC_UUID) {
            require(command->cmdsize == sizeof(struct uuid_command), "loaded UUID extent");
            const struct uuid_command *uuid = (const void *)at;
            require(memcmp(uuid->uuid, expected, 16) == 0, "genuine original27 IOKit UUID");
            ++found;
        }
        at += command->cmdsize;
    }
    require(at == end && found == 1, "complete loaded UUID contract");
    return result;
}
static void store16(uint8_t *packet, size_t offset, uint16_t value) { memcpy(packet + offset, &value, 2); }
static void store32(uint8_t *packet, size_t offset, uint32_t value) { memcpy(packet + offset, &value, 4); }
static void store64(uint8_t *packet, size_t offset, uint64_t value) { memcpy(packet + offset, &value, 8); }
static double floating(uint64_t bits) { double result; memcpy(&result, &bits, 8); return result; }
static const uint8_t *data(CFTypeRef event) {
    const uint8_t *result;
    memcpy(&result, (const uint8_t *)event + 96, sizeof(result));
    require(result != NULL, "real Mac data pointer at original27 +96");
    return result;
}
static void check_event(CFTypeRef event, Class type, uint64_t timestamp,
                        const uint8_t *expected, size_t bytes, uint64_t type_mask) {
    require(event != NULL, "real +1 native event object");
    require(object_getClass((id)event) == type, "real HIDEvent class identity");
    require(memcmp(data(event), expected, bytes) == 0, "all real original27 packet bytes");
    uint64_t actual_timestamp, actual_mask;
    memcpy(&actual_timestamp, (const uint8_t *)event + 8, 8);
    memcpy(&actual_mask, (const uint8_t *)event + 24, 8);
    require(actual_timestamp == timestamp, "real object timestamp");
    require(actual_mask == type_mask, "real object type mask");
    require(objc_retain((id)event) == (id)event, "actual native object retain");
    objc_release((id)event);
    require(memcmp(data(event), expected, bytes) == 0, "owned object alive after balanced retain/release");
}
#endif
int main(void) {
#ifdef VM27_PRODUCTION_REJECTION_FIXTURE
    require(!vm27_iokit_double_events_profile_matches(), "old iPad profile rejects genuine different Mac UUID/layout");
    for (unsigned iteration=0; iteration<32; ++iteration) {
        require(VM27ForceStageFixture(NULL,iteration,iteration,iteration,1,2,3,4,5,iteration)==NULL,
                "production force entry rejects unsupported real host before allocation");
        require(VM27TouchRadiusFixture(NULL,iteration,iteration,iteration,iteration,iteration,
                1,2,3,4,5,6,iteration)==NULL,
                "production touch entry rejects unsupported real host before allocation");
    }
    printf("{\"checks\":%u,\"productionProfileRejectedOnRealDifferentHost\":true,"
           "\"nativeEventsAllocated\":0,\"deviceOperations\":0}\n",checks);
    return 0;
#else
    require(vm27_iokit_double_events_profile_matches(), "explicit genuine original27 Mac packet comparison profile");
    void *handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_NOLOAD);
    require(handle != NULL, "ordinary linked native IOKit present");
    ForceFn force = (ForceFn)symbol(handle, "IOHIDEventCreateForceStageEvent");
    TouchFn touch = (TouchFn)symbol(handle, "IOHIDEventCreateTouchSensitiveButtonEventWithRadius");
    ChildrenFn children = (ChildrenFn)symbol(handle, "IOHIDEventGetChildren");
    AppendFn append = (AppendFn)symbol(handle, "IOHIDEventAppendEvent");
    Class type = (Class)symbol(handle, "OBJC_CLASS_$_HIDEvent");
    require(strcmp(class_getName(type), "HIDEvent") == 0 && class_getInstanceSize(type) == 104,
            "real original27 Mac class size, separate from current iPad 112");
    const uint64_t patterns[] = {0, UINT64_C(0x8000000000000000), UINT64_C(0x3ff0000000000000),
        UINT64_C(0xbff0000000000000), UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
        UINT64_C(0x7ff8000000000042), UINT64_C(0xfff8000000001337), 1, UINT64_C(0x000fffffffffffff),
        UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff), UINT64_C(0x400921fb54442d18)};
    unsigned events = 0, retained_children = 0;
    for (unsigned iteration = 0; iteration < 512; ++iteration) {
        uint64_t bits[6]; double values[6];
        for (unsigned slot = 0; slot < 6; ++slot) {
            bits[slot] = patterns[(iteration + slot * 3) % (sizeof(patterns) / sizeof(patterns[0]))];
            values[slot] = floating(bits[slot]);
        }
        uint64_t timestamp = UINT64_C(0xfedcba9800000000) | iteration;
        uint32_t index = UINT32_C(0xabcdef00) | iteration;
        uint32_t stage = UINT32_C(0x12345600) | iteration;
        uint32_t options = iteration & 3;
        uint8_t expected_force[80] = {0};
        store32(expected_force, 0, 80); store32(expected_force, 4, 41); store32(expected_force, 8, options);
        store32(expected_force, 16, index); expected_force[20] = (uint8_t)stage;
        for (unsigned slot = 0; slot < 5; ++slot) store64(expected_force, 24 + slot * 8, bits[slot]);
        CFTypeRef parent = force(NULL, timestamp, index, stage, values[0], values[1], values[2], values[3], values[4], options);
        check_event(parent, type, timestamp, expected_force, sizeof(expected_force), UINT64_C(1) << 41);
        CFTypeRef candidate_parent = VM27ForceStageFixture(NULL,timestamp,index,stage,
            values[0],values[1],values[2],values[3],values[4],options);
        check_event(candidate_parent,type,timestamp,expected_force,sizeof(expected_force),UINT64_C(1)<<41);
        require(memcmp(data(candidate_parent),data(parent),80)==0,"candidate force vs genuine named constructor entire packet");
        uint32_t usage_page = UINT32_C(0x12340000) | iteration;
        uint32_t usage = UINT32_C(0xfedc0000) | (iteration * 13);
        uint32_t mask = UINT32_C(0x76543210) ^ iteration;
        uint32_t touching = iteration % 3 == 0 ? 0 : iteration % 3 == 1 ? 1 : 0x100;
        uint8_t expected_touch[96] = {0};
        store32(expected_touch, 0, 96); store32(expected_touch, 4, 42); store32(expected_touch, 8, options);
        store16(expected_touch, 16, (uint16_t)usage_page); store16(expected_touch, 18, (uint16_t)usage);
        store64(expected_touch, 24, bits[2]); store64(expected_touch, 32, bits[3]);
        expected_touch[40] = touching != 0; store32(expected_touch, 44, mask);
        store64(expected_touch, 48, bits[0]); store64(expected_touch, 56, bits[1]);
        store64(expected_touch, 64, bits[4]); store64(expected_touch, 72, bits[5]);
        CFTypeRef child = touch(NULL, timestamp, usage_page, usage, mask, touching,
            values[0], values[1], values[2], values[3], values[4], values[5], options);
        check_event(child, type, timestamp, expected_touch, sizeof(expected_touch), UINT64_C(1) << 42);
        CFTypeRef candidate_child = VM27TouchRadiusFixture(NULL,timestamp,usage_page,usage,mask,touching,
            values[0],values[1],values[2],values[3],values[4],values[5],options);
        check_event(candidate_child,type,timestamp,expected_touch,sizeof(expected_touch),UINT64_C(1)<<42);
        require(memcmp(data(candidate_child),data(child),96)==0,"candidate touch vs genuine named constructor entire packet");
        append(candidate_parent,candidate_child,0);
        CFArrayRef candidate_array=children(candidate_parent);
        require(candidate_array && CFArrayGetCount(candidate_array)==1 && CFArrayGetValueAtIndex(candidate_array,0)==candidate_child,
                "candidate native parent owns exact native child");
        objc_release((id)candidate_child);
        require(CFArrayGetValueAtIndex(candidate_array,0)==candidate_child && object_getClass((id)candidate_child)==type,
                "candidate child alive after its create ownership release");
        objc_release((id)candidate_parent);
        ++retained_children;
        append(parent, child, 0);
        CFArrayRef array = children(parent);
        require(array != NULL && CFGetTypeID(array) == CFArrayGetTypeID(), "actual append creates child array");
        require(CFArrayGetCount(array) == 1 && CFArrayGetValueAtIndex(array, 0) == child, "actual append preserves exact child identity");
        objc_release((id)child);
        require(CFArrayGetValueAtIndex(array, 0) == child && object_getClass((id)child) == type,
                "real child retained by real parent after create ownership release");
        ++retained_children;
        objc_release((id)parent);
        events += 4;
    }
    require(dlclose(handle) == 0, "ordinary NOLOAD handle balance");
    printf("{\"checks\":%u,\"realEventsCreatedAndReleased\":%u,\"realParentOwnedChildren\":%u,"
           "\"originalIOKitUUID\":\"0e4cf3e4b0c2312ab1470bd4978ef0b7\","
           "\"allOriginalPacketBytesCompared\":true,\"finiteCandidateComparedToBothGenuineConstructors\":true,\"macDataOffset\":96,"
           "\"ipadLayoutOrInitializerExecuted\":false,\"deviceOperations\":0}\n",
           checks, events, retained_children);
    return 0;
#endif
}
