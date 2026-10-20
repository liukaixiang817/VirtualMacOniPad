// Parse every original program without executing a foreign relative function.
#include "modern_swift_hid_observed_cvw_v2_compat.cpp"
#include "modern_swift_hid_observed_cvw_registry.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
using namespace VM27HIDObservedCVW;
using namespace VM27HIDObservedRegistry;
unsigned Checks = 0, Rejects = 0, MetadataCases = 0;
bool Allow(const void *target, const void *context) {
    return target == (const unsigned char *)context + GetterRVA;
}
void Check(bool value) { if (!value) std::abort(); ++Checks; }
int main() {
    for (const auto &entry : Metadata) {
        const auto &row = Programs[entry.programIndex];
        Program original{row.bytes, row.size, Allow, (const void *)(uintptr_t(row.bytes) - row.rva)};
        Check(Validate(original, entry.layout)); ++MetadataCases;
        alignas(8) unsigned char changed[65536]{};
        std::memcpy(changed, row.bytes, row.size);
        Program program{changed, row.size, Allow, (const void *)(uintptr_t(changed) - row.rva)};
        Check(Validate(program, entry.layout));
        for (size_t field : {size_t(0),size_t(8),size_t(16)}) {
            uint64_t prior = 0;
            std::memcpy(&prior, changed + field, 8);
            uint64_t bad = field == 0 ? 7 : field == 8 ? row.size : uint64_t(23) << 56;
            std::memcpy(changed + field, &bad, 8);
            Check(!Validate(program, entry.layout)); ++Rejects;
            std::memcpy(changed + field, &prior, 8);
        }
        for (uint32_t flag : {0x100000u, 0x400000u}) {
            Layout wrong = entry.layout; wrong.flags |= flag;
            Check(!Validate(program, wrong)); ++Rejects;
        }
        Program shortProgram = program; --shortProgram.byteCount;
        Check(!Validate(shortProgram, entry.layout)); ++Rejects;
        Layout wrongSize = entry.layout; ++wrongSize.size; wrongSize.stride = wrongSize.size;
        Check(!Validate(program, wrongSize)); ++Rejects;
        uint64_t header = 0; std::memcpy(&header, changed, 8);
        if (header >> 63) {
            Program forbidden = program; forbidden.allowFunction = nullptr;
            Check(!Validate(forbidden, entry.layout)); ++Rejects;
        }
    }
    Check(MetadataCases == 65);
    std::printf("{\"checks\":%u,\"completedOriginalMetadataSchemasValidated\":%u,\"counterexamplesRejected\":%u,\"originalGetterExecuted\":false,\"originalHIDLoaded\":false}\n", Checks, MetadataCases, Rejects);
}
