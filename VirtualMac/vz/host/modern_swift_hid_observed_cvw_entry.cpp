// Finite production entry for only the audited 65 original static metadata
// objects and the separately completed original EventReportSenderID POD.
// No class identity alias or generic Swift bytecode schema is supplied.
#include "modern_swift_hid_observed_cvw_v2_compat.cpp"
#include "modern_swift_hid_observed_cvw_registry.h"
#include "modern_swift_hid_observed_cvw_prefix_registry.h"

namespace VM27HIDObservedEntry {
using namespace VM27HIDObservedCVW;
using namespace VM27HIDObservedRegistry;
using VM27HIDBitwiseTake::Read;
using VM27HIDBitwiseTake::DataPointer;

bool Header(const void *base, unsigned &owner, mach_header_64 &header, uint64_t &preferred) {
    if (!Read(base, &header, sizeof(header)) || header.magic != MH_MAGIC_64 ||
        header.filetype != MH_DYLIB || !header.ncmds || header.ncmds > 512 || header.sizeofcmds > 65536) return false;
    auto at = (const unsigned char *)base + sizeof(header);
    auto end = at + header.sizeofcmds;
    unsigned uuids = 0, texts = 0;
    for (unsigned i = 0; i < header.ncmds; ++i) {
        load_command command{};
        if (end - at < 8 || !Read(at, &command, 8) || command.cmdsize < 8 ||
            command.cmdsize % 8 || command.cmdsize > size_t(end - at)) return false;
        if (command.cmd == LC_UUID) {
            uuid_command uuid{};
            if (command.cmdsize != sizeof(uuid) || !Read(at, &uuid, sizeof(uuid))) return false;
            if (!std::memcmp(uuid.uuid, UUIDs[0], 16)) owner = 0;
            else if (!std::memcmp(uuid.uuid, UUIDs[1], 16)) owner = 1;
            else return false;
            ++uuids;
        } else if (command.cmd == LC_SEGMENT_64) {
            segment_command_64 segment{};
            if (command.cmdsize < sizeof(segment) || !Read(at, &segment, sizeof(segment))) return false;
            if (!std::memcmp(segment.segname, "__TEXT\0\0\0\0\0\0\0\0\0\0", 16)) {
                if (segment.fileoff || !segment.filesize || segment.filesize > segment.vmsize) return false;
                preferred = segment.vmaddr; ++texts;
            }
        }
        at += command.cmdsize;
    }
    return at == end && uuids == 1 && texts == 1;
}

bool ReadOnlyRange(const void *base, const mach_header_64 &header, uint64_t preferred,
                   size_t rva, size_t bytes, bool executable) {
    auto at = (const unsigned char *)base + sizeof(header);
    if (!bytes || rva > UINT64_MAX - preferred) return false;
    const uint64_t address = preferred + rva;
    for (unsigned i = 0; i < header.ncmds; ++i) {
        load_command command{};
        if (!Read(at, &command, sizeof(command))) return false;
        if (command.cmd == LC_SEGMENT_64) {
            segment_command_64 segment{};
            if (!Read(at, &segment, sizeof(segment))) return false;
            if (address >= segment.vmaddr && address - segment.vmaddr <= segment.filesize &&
                bytes <= segment.filesize - (address - segment.vmaddr) &&
                segment.initprot & VM_PROT_READ && !(segment.initprot & VM_PROT_WRITE) &&
                (!executable || segment.initprot & VM_PROT_EXECUTE)) return true;
        }
        at += command.cmdsize;
    }
    return false;
}

bool AllowGetter(const void *target, const void *base) {
    return target == (const unsigned char *)base + GetterRVA;
}

// Also exposed to an ordinary synthetic-owner fixture. Only Checked performs
// real dladdr ownership; a synthetic owner is never claimed as loaded HID.
bool Identity(const void *base, const void *metadata, Program &program, Layout &layout) {
    unsigned owner = 2;
    mach_header_64 header{};
    uint64_t preferred = 0;
    if (!Header(base, owner, header, preferred) || uintptr_t(metadata) < uintptr_t(base)) return false;
    size_t rva = uintptr_t(metadata) - uintptr_t(base);
    for (size_t index = 0; index < sizeof(Metadata) / sizeof(Metadata[0]); ++index) {
        const auto &entry = Metadata[index];
        if (entry.owner != owner || entry.metadataRVA != rva) continue;
        uintptr_t kind = 0;
        if (!Read(metadata, &kind, 8) || kind != MetadataKinds[index] ||
            DataPointer(metadata, 8, 0xae86) != (const unsigned char *)base + DescriptorRVAs[index]) return false;
        auto table = (const unsigned char *)DataPointer(metadata, -8, 0x2e3f);
        if (table != (const unsigned char *)base + entry.vwtRVA ||
            !Read(table + 64, &layout, sizeof(layout)) || std::memcmp(&layout, &entry.layout, sizeof(layout))) return false;
        const auto &expected = Programs[entry.programIndex];
        const void *pointer = DataPointer(metadata, -16, 0x8b65);
        // Static original programs remain untagged. Relative FN handlers in
        // genuine Core reject the resolved-reader high bit made by low tag 1.
        if (pointer != (const unsigned char *)base + expected.rva || uintptr_t(pointer) & 1 ||
            !ReadOnlyRange(base, header, preferred, expected.rva, expected.size, false)) return false;
        // Largest exact program in the immutable 37-program registry is 584B.
        // The build verifies this bound; no generic large-stack interpreter.
        unsigned char bytes[584]{};
        if (expected.size > sizeof(bytes) || !Read(pointer, bytes, expected.size) ||
            std::memcmp(bytes, expected.bytes, expected.size)) return false;
        uint64_t flags = 0; std::memcpy(&flags, bytes, 8);
        if (flags >> 63) {
            unsigned char getter[sizeof(GetterBytes)]{};
            if (owner != 0 || !ReadOnlyRange(base, header, preferred, GetterRVA, sizeof(getter), true) ||
                !Read((const unsigned char *)base + GetterRVA, getter, sizeof(getter)) ||
                std::memcmp(getter, GetterBytes, sizeof(getter))) return false;
        }
        program = {(const unsigned char *)pointer, expected.size, AllowGetter, base};
        return Validate(program, layout);
    }
    return false;
}

bool Checked(const void *metadata, Program &program, Layout &layout) {
    // The initializer publishes this original POD only after real old-native
    // UUID/UInt64 layout. Its exact independent guard includes descriptor,
    // completed VWT, field offsets and the DA2-signed resolved POD bytes.
    VM27HIDBitwiseTake::Layout pod{};
    if (VM27HIDBitwiseTake::ProductionMetadata(metadata, pod)) {
        const void *pointer = DataPointer(metadata, -16, 0x8b65);
        layout = {pod.size, pod.stride, pod.flags, pod.extra};
        program = {(const unsigned char *)(uintptr_t(pointer) & ~uintptr_t(1)), 24, nullptr, nullptr};
        return Validate(program, layout);
    }
    Dl_info owner{};
    return metadata && dladdr(metadata, &owner) && owner.dli_fbase &&
        Identity(owner.dli_fbase, metadata, program, layout);
}

void *Perform(Operation operation, void *destination, const void *source, const void *metadata) {
    Program program{}; Layout layout{}; void *address = nullptr;
    if (!Checked(metadata, program, layout) || !Apply(operation, program, layout, destination, source, &address)) __builtin_trap();
    return address;
}
} // namespace VM27HIDObservedEntry

#ifndef VM27_HID_OBSERVED_ENTRY_COMPONENT_FIXTURE
extern "C" __attribute__((visibility("default"))) void swift_cvw_destroy(void *value, const void *metadata) {
    VM27HIDObservedEntry::Perform(VM27HIDObservedCVW::Operation::Destroy, value, nullptr, metadata);
}
extern "C" __attribute__((visibility("default"))) void *swift_cvw_initWithCopy(void *destination, const void *source, const void *metadata) {
    return VM27HIDObservedEntry::Perform(VM27HIDObservedCVW::Operation::InitializeCopy, destination, source, metadata);
}
extern "C" __attribute__((visibility("default"))) void *swift_cvw_assignWithCopy(void *destination, const void *source, const void *metadata) {
    return VM27HIDObservedEntry::Perform(VM27HIDObservedCVW::Operation::AssignCopy, destination, source, metadata);
}
extern "C" __attribute__((visibility("default"))) void *swift_cvw_assignWithTake(void *destination, const void *source, const void *metadata) {
    return VM27HIDObservedEntry::Perform(VM27HIDObservedCVW::Operation::AssignTake, destination, source, metadata);
}
extern "C" __attribute__((visibility("default"))) void *swift_cvw_initializeBufferWithCopyOfBuffer(void *destination, const void *source, const void *metadata) {
    return VM27HIDObservedEntry::Perform(VM27HIDObservedCVW::Operation::CopyBuffer, destination, source, metadata);
}
#endif
