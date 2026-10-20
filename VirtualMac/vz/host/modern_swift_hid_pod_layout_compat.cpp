// Finite old-host adaptation of Swift Metadata.cpp at
// 5ea0a2a5d8e126628da27747739e8d017c1d4882. The only accepted production
// metadata is the genuine HID EventReportSenderID with UUID + UInt64 fields.
// Original DIKit/VZ routers and their identity checks are independent.
#include "modern_swift_hid_pod_layout_compat.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstring>

extern "C" void swift_initStructMetadata(void *, uintptr_t, size_t,
    const void *const *, uint32_t *);
extern "C" const unsigned char VM27NativeUUIDMetadata[] __asm__("_$s10Foundation4UUIDVN");
extern "C" const unsigned char VM27NativeUInt64Metadata[] __asm__("_$ss6UInt64VN");

namespace VM27HIDPODLayout {
struct Layout { size_t size, stride; uint32_t flags, extra; };
static_assert(sizeof(Layout) == 24 && sizeof(void *) == 8, "Audited LP64 layout");
alignas(8) constexpr uint64_t Program[] = {0, 0, 24};
// ValueWitnessFlags::IsAddressableForDependencies, MetadataValues.h. New
// Foundation.UUID has this ABI bit; older native UUID metadata can lack it.
// It changes lifetime-dependent argument passing, not the POD byte layout.
constexpr uint32_t AddressableForDependencies = 0x02000000;
constexpr unsigned char UHUUID[16] = {0x72,0x82,0x4f,0xab,0x0b,0xb7,0x3b,0x56,
    0xa4,0x0d,0x00,0x08,0x84,0x10,0xf0,0x53};

bool Read(const void *source, void *dest, size_t bytes) {
    vm_size_t actual = 0;
    return source && dest && bytes && bytes <= 65536 &&
        vm_read_overwrite(mach_task_self(), (vm_address_t)source, bytes,
                          (vm_address_t)dest, &actual) == KERN_SUCCESS && actual == bytes;
}

const void *DataPointer(const void *metadata, intptr_t offset, uint16_t discriminator) {
    const void *pointer = nullptr;
    auto slot = (const unsigned char *)metadata + offset;
    if (!Read(slot, &pointer, sizeof(pointer)) || !pointer) return nullptr;
#if __has_feature(ptrauth_calls)
    pointer = ptrauth_auth_data(pointer, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator(slot, discriminator));
#endif
    if (pointer != ptrauth_strip(pointer, ptrauth_key_process_independent_data)) return nullptr;
    return pointer;
}

bool TypeLayout(const void *metadata, Layout &layout, const void **table = nullptr) {
    auto vwt = (const unsigned char *)DataPointer(metadata, -8, 0x2e3f);
    if (!vwt || !Read(vwt + 64, &layout, sizeof(layout))) return false;
    if (table) *table = vwt;
    return true;
}

bool Fields(uintptr_t flags, size_t count, const void *const *fields,
            const uint8_t *tags, const void **layouts) {
    const void *types[2]{};
    uint8_t codes[2]{};
    if (flags != 0x100 || count != 2 || !Read(fields, types, sizeof(types)) ||
        !Read(tags, codes, sizeof(codes)) || codes[0] || codes[1] ||
        types[0] != VM27NativeUUIDMetadata || types[1] != VM27NativeUInt64Metadata) return false;
    Layout first{}, second{};
    const void *vwt0 = nullptr, *vwt1 = nullptr;
    if (!TypeLayout(types[0], first, &vwt0) || !TypeLayout(types[1], second, &vwt1) ||
        first.size != 16 || first.stride != 16 ||
        (first.flags & ~AddressableForDependencies) != 0 || first.extra != 0 ||
        second.size != 8 || second.stride != 8 || second.flags != 7 || second.extra != 0) return false;
    layouts[0] = (const unsigned char *)vwt0 + 64;
    layouts[1] = (const unsigned char *)vwt1 + 64;
    return true;
}

bool ProductionMetadata(void *metadata, uint32_t *offsets) {
    Dl_info owner{};
    if (!metadata || !dladdr(metadata, &owner) || !owner.dli_fbase ||
        (const unsigned char *)metadata != (const unsigned char *)owner.dli_fbase + 0xccb08 ||
        offsets != (uint32_t *)((unsigned char *)metadata + 16)) return false;
    mach_header_64 header{};
    if (!Read(owner.dli_fbase, &header, sizeof(header)) || header.magic != MH_MAGIC_64 ||
        header.ncmds == 0 || header.ncmds > 512 || header.sizeofcmds > 65536) return false;
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
                std::memcmp(uuid.uuid, UHUUID, 16)) return false;
            ++matched;
        }
        at += command.cmdsize;
    }
    if (at != end || matched != 1) return false;
    uintptr_t kind = 0;
    if (!Read(metadata, &kind, 8) || kind != 0x200) return false;
    auto descriptor = (const unsigned char *)DataPointer(metadata, 8, 0xae86);
    const void *table = nullptr;
    Layout layout{};
    if (descriptor != (const unsigned char *)owner.dli_fbase + 0x9f9e0 ||
        !TypeLayout(metadata, layout, &table) ||
        table != (const unsigned char *)owner.dli_fbase + 0xccaa0 ||
        layout.size || layout.stride || layout.flags != 0x400000 || layout.extra) return false;
    uint32_t context[7]{};
    if (!Read(descriptor, context, sizeof(context)) || context[0] != 0x00110051 ||
        context[5] != 2 || context[6] != 2) return false;
    auto name = descriptor + 8 + int32_t(context[2]);
    char actual[20]{};
    return Read(name, actual, sizeof(actual)) &&
        !std::memcmp(actual, "EventReportSenderID", sizeof(actual));
}

// Shared semantic component. The ordinary fixture calls this with its own
// isolated metadata copies; the production entry first checks exact HID identity.
void Apply(void *metadata, const void *const *layouts, uint32_t *offsets) {
    Layout first{}, second{};
    if (!Read(layouts[0], &first, sizeof(first)) ||
        !Read(layouts[1], &second, sizeof(second))) __builtin_trap();
    // performBasicLayout ORs the documented dependency-addressability bit.
    // Do not clear it or guess additional flags. A native initializer that
    // fails to express the actual imported field ABI is rejected below.
    const uint32_t expectedFlags = 7 |
        ((first.flags | second.flags) & AddressableForDependencies);
    // Original helper 0x194e8141c sets low bit 1 before signing a resolved
    // runtime layout string. Static unresolved strings have an untagged slot.
    const void *program = (const void *)(uintptr_t(Program) | 1);
    auto slot = (unsigned char *)metadata - 16;
#if __has_feature(ptrauth_calls)
    program = ptrauth_sign_unauthenticated(program, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator(slot, 0x8b65));
#endif
    std::memcpy(slot, &program, sizeof(program));
    // Original Metadata.cpp sets the layout pointer before publishing the VWT.
    // The existing native initializer performs real alignment/common-witness
    // selection, preserves generic enum witnesses, and publishes completeness.
    swift_initStructMetadata(metadata, 0x100, 2, layouts, offsets);
    Layout result{};
    if (!TypeLayout(metadata, result) || result.size != 24 || result.stride != 24 ||
        result.flags != expectedFlags || result.extra != 0 || offsets[0] != 0 || offsets[1] != 16 ||
        DataPointer(metadata, -16, 0x8b65) !=
            (const void *)(uintptr_t(Program) | 1)) __builtin_trap();
}
} // namespace VM27HIDPODLayout

#ifndef VM27_HID_POD_LAYOUT_COMPONENT_FIXTURE
extern "C" void swift_cvw_initStructMetadataWithLayoutString(void *metadata,
    uintptr_t flags, size_t count, const void *const *types, const uint8_t *tags, uint32_t *offsets) {
    const void *layouts[2]{};
    if (!VM27HIDPODLayout::Fields(flags, count, types, tags, layouts) ||
        !VM27HIDPODLayout::ProductionMetadata(metadata, offsets)) __builtin_trap();
    VM27HIDPODLayout::Apply(metadata, layouts, offsets);
}
#endif
