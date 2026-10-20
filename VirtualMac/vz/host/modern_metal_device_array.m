// A finite old-iOS backport of the documented iOS18 Metal owned-array API.
// This source does not implement macOS multi-GPU catalogs or modify MTLDevice.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <string.h>

#ifndef VM27_METAL_DEVICE_ARRAY_EXPORT
#define VM27_METAL_DEVICE_ARRAY_EXPORT VM27MTLCopyAllDevices
// Keep the SDK's nonnull declaration on the genuine system function. This
// separate private C identifier exposes its exact linker symbol while its
// unsupported-UUID failure boundary remains explicitly nullable.
NSArray<id<MTLDevice>> * _Nullable VM27MTLCopyAllDevices(void)
    __asm__("_MTLCopyAllDevices") __attribute__((ns_returns_retained));
#endif

#ifdef VM27_METAL_MAC_ARRAY_FIXTURE
static const uint8_t expected_metal_uuid[16] = {
    0xb0,0xbc,0x74,0xfe,0x70,0x80,0x34,0x7d,0x92,0xee,0x38,0x19,0x50,0x58,0xcc,0xce};
#else
static const uint8_t expected_metal_uuid[16] = {
    0x8f,0x06,0x21,0x25,0x74,0x88,0x39,0xef,0xaf,0xda,0x57,0xdb,0x8c,0xd8,0x00,0x33};
#endif

int vm27_metal_device_array_profile_matches(void) {
    Dl_info origin = {0};
    const void *entry = ptrauth_strip((void *)&MTLCreateSystemDefaultDevice, ptrauth_key_function_pointer);
    if (!dladdr(entry, &origin) || !origin.dli_fbase) return 0;
    const struct mach_header_64 *header = origin.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->sizeofcmds > 128*1024 ||
        header->ncmds > header->sizeofcmds/8) return 0;
    const uint8_t *at = (const uint8_t *)(header+1), *end = at+header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t index=0; index<header->ncmds; ++index) {
        if ((size_t)(end-at) < sizeof(struct load_command)) return 0;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize%8 || command->cmdsize > (size_t)(end-at)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command)) return 0;
            const struct uuid_command *uuid = (const void *)at;
            if (memcmp(uuid->uuid, expected_metal_uuid, 16)) return 0;
            ++matches;
        }
        at += command->cmdsize;
    }
    return at == end && matches == 1;
}

// The input is borrowed; Foundation retains it in the owned array. This helper
// also makes the empty-array branch testable without faking a system API result.
NSArray *vm27_metal_owned_device_array(id device) __attribute__((ns_returns_retained));
NSArray *vm27_metal_owned_device_array(id device) {
    return [[NSArray alloc] initWithObjects:&device count:device ? 1 : 0];
}

__attribute__((visibility("default"), ns_returns_retained))
NSArray<id<MTLDevice>> * _Nullable VM27_METAL_DEVICE_ARRAY_EXPORT(void) {
    if (!vm27_metal_device_array_profile_matches()) return nil;
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    NSArray *result = nil;
    @try {
        result = vm27_metal_owned_device_array(device);
    } @finally {
        // MTLCreateSystemDefaultDevice has the +1 SDK contract. The array owns
        // its independent retain; this releases only the temporary device.
        [device release];
    }
    return result;
}
