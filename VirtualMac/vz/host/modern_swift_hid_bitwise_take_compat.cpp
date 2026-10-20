// Adapt the actual default Swift CVW initWithTake bitwise path, audited against
// Swift-BytecodeLayouts.cpp and the original 0x194e4b2cc machine body.
// The production entry accepts only completed original HID EventReportSenderID.
#include "modern_swift_hid_bitwise_take_compat.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstring>

namespace VM27HIDBitwiseTake {
static_assert(sizeof(Layout) == 24 && sizeof(void *) == 8, "Audited LP64 ABI");
constexpr uint32_t NonBitwiseTakable = 0x00100000;
constexpr uint32_t Incomplete = 0x00400000;
constexpr uint32_t AddressableForDependencies = 0x02000000;
constexpr unsigned char UHUUID[] = {0x72,0x82,0x4f,0xab,0x0b,0xb7,0x3b,0x56,
    0xa4,0x0d,0x00,0x08,0x84,0x10,0xf0,0x53};

bool Read(const void *source, void *destination, size_t bytes) {
    vm_size_t actual = 0;
    return source && destination && bytes && bytes <= 65536 &&
        vm_read_overwrite(mach_task_self(), (vm_address_t)source, bytes,
            (vm_address_t)destination, &actual) == KERN_SUCCESS && actual == bytes;
}

const void *DataPointer(const void *metadata, intptr_t offset, uint16_t discriminator) {
    const void *pointer = nullptr;
    auto slot = (const unsigned char *)metadata + offset;
    if (!metadata || !Read(slot, &pointer, sizeof(pointer)) || !pointer) return nullptr;
#if __has_feature(ptrauth_calls)
    pointer = ptrauth_auth_data(pointer, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator(slot, discriminator));
#endif
    return pointer == ptrauth_strip(pointer, ptrauth_key_process_independent_data) ? pointer : nullptr;
}

bool TypeLayout(const void *metadata, Layout &layout) {
    auto table = (const unsigned char *)DataPointer(metadata, -8, 0x2e3f);
    return table && Read(table + 64, &layout, sizeof(layout));
}

bool ProductionMetadata(const void *metadata, Layout &layout) {
    Dl_info owner{};
    if (!metadata || !dladdr(metadata, &owner) || !owner.dli_fbase ||
        (const unsigned char *)metadata != (const unsigned char *)owner.dli_fbase + 0xccb08) return false;
    mach_header_64 header{};
    if (!Read(owner.dli_fbase, &header, sizeof(header)) || header.magic != MH_MAGIC_64 ||
        !header.ncmds || header.ncmds > 512 || header.sizeofcmds > 65536) return false;
    auto at = (const unsigned char *)owner.dli_fbase + sizeof(header);
    auto end = at + header.sizeofcmds;
    unsigned matched = 0;
    for (uint32_t i = 0; i < header.ncmds; ++i) {
        load_command command{};
        if (end - at < 8 || !Read(at, &command, 8) || command.cmdsize < 8 ||
            command.cmdsize % 8 || command.cmdsize > size_t(end - at)) return false;
        if (command.cmd == LC_UUID) {
            uuid_command uuid{};
            if (command.cmdsize != sizeof(uuid) || !Read(at, &uuid, sizeof(uuid)) ||
                std::memcmp(uuid.uuid, UHUUID, sizeof(UHUUID))) return false;
            ++matched;
        }
        at += command.cmdsize;
    }
    if (at != end || matched != 1) return false;
    uintptr_t kind = 0;
    uint32_t offsets[2]{};
    auto descriptor = (const unsigned char *)DataPointer(metadata, 8, 0xae86);
    if (!Read(metadata, &kind, sizeof(kind)) || kind != 0x200 ||
        descriptor != (const unsigned char *)owner.dli_fbase + 0x9f9e0 ||
        DataPointer(metadata, -8, 0x2e3f) != (const unsigned char *)owner.dli_fbase + 0xccaa0 ||
        !TypeLayout(metadata, layout) || layout.size != 24 || layout.stride != 24 ||
        (layout.flags & ~AddressableForDependencies) != 7 || layout.extra != 0 ||
        !Read((const unsigned char *)metadata + 16, offsets, sizeof(offsets)) || offsets[0] != 0 || offsets[1] != 16) return false;
    uint32_t context[7]{};
    if (!Read(descriptor, context, sizeof(context)) || context[0] != 0x00110051 || context[5] != 2 || context[6] != 2) return false;
    char name[20]{};
    if (!Read(descriptor + 8 + int32_t(context[2]), name, sizeof(name)) ||
        std::memcmp(name, "EventReportSenderID", sizeof(name))) return false;
    // The finite initializer installs the true resolved POD program, with
    // the actual low-bit tag and DA2/address/8b65 signature. No general
    // layout-string interpreter or foreign metadata identity is accepted.
    const void *program = DataPointer(metadata, -16, 0x8b65);
    if (!(uintptr_t(program) & 1)) return false;
    uint64_t instructions[3]{};
    return Read((const void *)(uintptr_t(program) & ~uintptr_t(1)), instructions, sizeof(instructions)) &&
        instructions[0] == 0 && instructions[1] == 0 && instructions[2] == 24;
}

bool Move(void *destination, const void *source, const Layout &layout) {
    if (!destination || !source || !layout.size || layout.size > 4096 ||
        (layout.flags & (NonBitwiseTakable | Incomplete))) return false;
    // Original fast path uses metadata->vw_size() and transfers ownership
    // with memcpy. It neither retains a copied reference nor destroys source.
    std::memcpy(destination, source, layout.size);
    return true;
}
} // namespace VM27HIDBitwiseTake

#ifndef VM27_HID_BITWISE_TAKE_COMPONENT_FIXTURE
extern "C" void *swift_cvw_initWithTake(void *destination, const void *source, const void *metadata) {
    VM27HIDBitwiseTake::Layout layout{};
    if (!VM27HIDBitwiseTake::ProductionMetadata(metadata, layout) ||
        !VM27HIDBitwiseTake::Move(destination, source, layout)) __builtin_trap();
    return destination;
}
#endif
