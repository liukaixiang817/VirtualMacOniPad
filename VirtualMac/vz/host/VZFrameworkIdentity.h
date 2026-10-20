#ifndef VZ_FRAMEWORK_IDENTITY_H
#define VZ_FRAMEWORK_IDENTITY_H
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Only this extracted 22D68 image has the audited GOT and private RPC layout.
// A new backend needs its own binding profile; version labels are insufficient.
static inline bool VZIsAuditedVenturaImage(const void *bytes, size_t length) {
    static const uint8_t uuid[16] = {
        0xdc, 0xfc, 0x0a, 0x79, 0x77, 0x28, 0x30, 0x89,
        0x94, 0xd7, 0x15, 0x08, 0xe7, 0x1f, 0x38, 0xe5
    };
    if (!bytes || length < sizeof(struct mach_header_64)) return false;
    struct mach_header_64 header;
    memcpy(&header, bytes, sizeof(header));
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        header.filetype != MH_DYLIB || header.ncmds > 512 ||
        header.sizeofcmds > length - sizeof(header)) return false;
    size_t at = sizeof(header), end = at + header.sizeofcmds;
    bool matchingUUID = false, matchingSlots = false;
    unsigned uuidCount = 0;
    for (uint32_t index = 0; index < header.ncmds; ++index) {
        struct load_command command;
        if (end - at < sizeof(command)) return false;
        memcpy(&command, (const uint8_t *)bytes + at, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize % 8 ||
            command.cmdsize > end - at) return false;
        if (command.cmd == LC_UUID) {
            if (command.cmdsize != sizeof(struct uuid_command)) return false;
            ++uuidCount;
            matchingUUID = !memcmp((const uint8_t *)bytes + at + 8, uuid, 16);
        } else if (command.cmd == LC_SEGMENT_64) {
            struct segment_command_64 segment;
            if (command.cmdsize < sizeof(segment)) return false;
            memcpy(&segment, (const uint8_t *)bytes + at, sizeof(segment));
            if (!memcmp(segment.segname, "__AUTH_CONST\0\0\0\0", 16)) {
                matchingSlots = segment.vmaddr == UINT64_C(0x100140000) &&
                    segment.vmsize == UINT64_C(0x8000);
            }
        }
        at += command.cmdsize;
    }
    return at == end && uuidCount == 1 && matchingUUID && matchingSlots;
}
#endif
