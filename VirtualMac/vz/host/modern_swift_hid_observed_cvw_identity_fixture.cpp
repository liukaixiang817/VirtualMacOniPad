// Synthetic owners derived from actual inert Mach-O files. This exercises
// the exact production Identity implementation; Checked must still reject
// these buffers because dyld has not loaded either original framework.
#define VM27_HID_OBSERVED_ENTRY_COMPONENT_FIXTURE 1
#include "modern_swift_hid_observed_cvw_entry.cpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <iterator>

using namespace VM27HIDObservedEntry;
unsigned Checks = 0, Cases = 0, Rejects = 0, ProductionRejections = 0;
void CheckImpl(bool value, unsigned line) {
    if (!value) { std::fprintf(stderr, "CVW identity fixture failed at line %u\n", line); std::abort(); }
    ++Checks;
}
#define Check(value) CheckImpl((value), __LINE__)
void Store(void *slot, const void *pointer, uint16_t discriminator) {
#if __has_feature(ptrauth_calls)
    pointer = ptrauth_sign_unauthenticated(pointer, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator(slot, discriminator));
#endif
    std::memcpy(slot, &pointer, 8);
}
std::vector<unsigned char> Load(const char *path) {
    auto file = std::fopen(path, "rb"); Check(file);
    Check(!std::fseek(file, 0, SEEK_END)); long size = std::ftell(file);
    Check(size > 0 && size < 2097152 && !std::fseek(file, 0, SEEK_SET));
    std::vector<unsigned char> bytes(size);
    Check(std::fread(bytes.data(), 1, size, file) == size && !std::fclose(file));
    return bytes;
}
std::vector<unsigned char> Model(const std::vector<unsigned char> &raw) {
    auto header = (const mach_header_64 *)raw.data();
    Check(raw.size() >= sizeof(*header) && header->magic == MH_MAGIC_64 && header->sizeofcmds < raw.size() - sizeof(*header));
    size_t at = sizeof(*header), extent = 0;
    const uint64_t preferred = 0x100000000;
    for (unsigned i = 0; i < header->ncmds; ++i) {
        auto command = (const load_command *)(raw.data() + at);
        Check(command->cmdsize >= 8 && command->cmdsize <= raw.size() - at);
        if (command->cmd == LC_SEGMENT_64) {
            auto segment = (const segment_command_64 *)command;
            Check(segment->vmaddr >= preferred && segment->vmsize <= 2097152 &&
                segment->vmaddr - preferred <= 2097152 - segment->vmsize);
            size_t end = segment->vmaddr - preferred + segment->vmsize;
            if (end > extent) extent = end;
        }
        at += command->cmdsize;
    }
    Check(at == sizeof(*header) + header->sizeofcmds);
    std::vector<unsigned char> memory(extent);
    at = sizeof(*header);
    for (unsigned i = 0; i < header->ncmds; ++i) {
        auto command = (const load_command *)(raw.data() + at);
        if (command->cmd == LC_SEGMENT_64) {
            auto segment = (const segment_command_64 *)command;
            Check(segment->fileoff <= raw.size() && segment->filesize <= raw.size() - segment->fileoff);
            std::memcpy(memory.data() + segment->vmaddr - preferred, raw.data() + segment->fileoff, segment->filesize);
        }
        at += command->cmdsize;
    }
    return memory;
}
int main(int argc, const char **argv) {
    Check(argc == 3);
    auto uh = Model(Load(argv[1])), uhk = Model(Load(argv[2]));
    unsigned char *bases[2]{uh.data(), uhk.data()};
    for (size_t index = 0; index < sizeof(Metadata)/sizeof(Metadata[0]); ++index) {
        const auto &entry = Metadata[index]; const auto &expected = Programs[entry.programIndex];
        auto base = bases[entry.owner], metadata = base + entry.metadataRVA;
        Store(metadata - 16, base + expected.rva, 0x8b65);
        Store(metadata - 8, base + entry.vwtRVA, 0x2e3f);
        Store(metadata + 8, base + DescriptorRVAs[index], 0xae86);
        Program program{}; Layout layout{};
        Check(Identity(base, metadata, program, layout)); ++Cases;
        Check(program.bytes == base + expected.rva && program.byteCount == expected.size);
        Check(!std::memcmp(&layout, &entry.layout, sizeof(layout)));
        Check(!Checked(metadata, program, layout)); ++ProductionRejections;
        auto reject = [&] { Check(!Identity(base, metadata, program, layout)); ++Rejects; };
        Store(metadata - 16, (const void *)(uintptr_t(base + expected.rva) | 1), 0x8b65); reject();
        Store(metadata - 16, base + expected.rva, 0x8b65);
        Store(metadata - 8, base + entry.vwtRVA + 8, 0x2e3f); reject();
        Store(metadata - 8, base + entry.vwtRVA, 0x2e3f);
        Store(metadata + 8, base + DescriptorRVAs[index] + 4, 0xae86); reject();
        Store(metadata + 8, base + DescriptorRVAs[index], 0xae86);
        uint64_t kind = 0; std::memcpy(&kind, metadata, 8);
        uint64_t wrongKind = 0; std::memcpy(metadata, &wrongKind, 8); reject(); std::memcpy(metadata, &kind, 8);
        auto actualLayout = (Layout *)(base + entry.vwtRVA + 64);
        Layout saved = *actualLayout; ++actualLayout->extra; reject(); *actualLayout = saved;
        auto byte = base + expected.rva + 16; auto savedByte = *byte; *byte ^= 1; reject(); *byte = savedByte;
        uint64_t flags = 0; std::memcpy(&flags, expected.bytes, 8);
        if (flags >> 63) {
            auto code = base + GetterRVA; auto old = *code; *code ^= 1; reject(); *code = old;
        }
        Check(Identity(base, metadata, program, layout));
    }
    for (auto base : bases) {
        auto header = (mach_header_64 *)base;
        auto commands = base + sizeof(*header);
        for (unsigned i = 0; i < header->ncmds; ++i) {
            auto command = (load_command *)commands;
            if (command->cmd == LC_UUID) {
                auto uuid = (uuid_command *)command; uuid->uuid[0] ^= 1;
                unsigned owner = 2; mach_header_64 copy{}; uint64_t preferred = 0;
                Check(!Header(base, owner, copy, preferred)); ++Rejects;
                uuid->uuid[0] ^= 1;
            }
            if (command->cmd == LC_SEGMENT_64) {
                auto segment = (segment_command_64 *)command;
                if (!std::memcmp(segment->segname, "__TEXT\0\0\0\0\0\0\0\0\0\0", 16)) {
                    auto old = segment->initprot; segment->initprot |= VM_PROT_WRITE;
                    unsigned owner = 2; mach_header_64 copy{}; uint64_t preferred = 0;
                    Check(Header(base, owner, copy, preferred));
                    const auto &entry = *std::find_if(std::begin(Metadata), std::end(Metadata),
                        [&](const MetadataRecord &x) { return x.owner == owner; });
                    Program program{}; Layout layout{};
                    Check(!Identity(base, base + entry.metadataRVA, program, layout)); ++Rejects;
                    segment->initprot = old;
                }
            }
            commands += command->cmdsize;
        }
    }
    Check(Cases == 65 && ProductionRejections == 65);
    std::printf("{\"checks\":%u,\"syntheticExactOriginalMetadataCases\":%u,\"counterexamplesRejected\":%u,\"realProductionOwnerRejections\":%u,\"originalHIDLoaded\":false,\"originalGetterExecuted\":false}\n",Checks,Cases,Rejects,ProductionRejections);
}
