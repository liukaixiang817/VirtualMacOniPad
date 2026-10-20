// Ordinary process component test, no original HID or VZ loading.
// Two isolated metadata/VWT copies use a real SDK struct descriptor and real
// UUID/UInt64 field metadata. Original HID production identity never passes.
#define VM27_HID_POD_LAYOUT_COMPONENT_FIXTURE 1
#include "modern_swift_hid_pod_layout_compat.cpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>
#include <unistd.h>

using Init = void *(*)(void *, const void *, const void *);
using Destroy = void (*)(void *, const void *);
using GetTag = unsigned (*)(const void *, unsigned, const void *);
using SetTag = void (*)(void *, unsigned, unsigned, const void *);
struct Table {
    Init __ptrauth(0,1,0xda4a) buffer;
    Destroy __ptrauth(0,1,0x04f8) destroy;
    Init __ptrauth(0,1,0xe3ba) copy;
    Init __ptrauth(0,1,0x8751) assignCopy;
    Init __ptrauth(0,1,0x48d8) take;
    Init __ptrauth(0,1,0xefda) assignTake;
    GetTag __ptrauth(0,1,0x60f0) getTag;
    SetTag __ptrauth(0,1,0xa0d1) setTag;
    VM27HIDPODLayout::Layout layout;
};
struct Full {
    const void *__ptrauth(2,1,0x8b65) program;
    Table *__ptrauth(2,1,0x2e3f) table;
    uintptr_t kind;
    const void *__ptrauth(2,1,0xae86) descriptor;
    uint32_t offsets[2];
};
static_assert(sizeof(Table) == 88 && offsetof(Full, kind) == 16, "actual LP64 VWT/full metadata ABI");
std::atomic<unsigned> Checks{0}, Cases{0}, Rejects{0}, WrongOwners{0};
using Original = void (*)(void *, uintptr_t, size_t, const void *const *, const uint8_t *, uint32_t *);
Original Native = nullptr;

void CheckImpl(bool value, unsigned line) {
    if (!value) { std::fprintf(stderr, "POD fixture check failed at line %u\n", line); std::abort(); }
    ++Checks;
}
#define Check(value) CheckImpl((value), __LINE__)

extern "C" void vm27_hid_pod_fixture_run(const void *metadata, const void *uuid,
                                         const void *integer, const void *value) {
    static bool initialized = [] {
        alarm(45);
        auto core = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
        Check(core != nullptr);
        Native = (Original)dlsym(core, "swift_cvw_initStructMetadataWithLayoutString");
        Check(Native != nullptr);
        return true;
    }();
    (void)initialized;
    Check(uuid == VM27NativeUUIDMetadata && integer == VM27NativeUInt64Metadata);
    const void *types[2] = {uuid, integer};
    uint8_t tags[2]{};
    const void *layouts[2]{};
    if (!VM27HIDPODLayout::Fields(0x100, 2, types, tags, layouts)) {
        VM27HIDPODLayout::Layout a{}, b{};
        bool first = VM27HIDPODLayout::TypeLayout(uuid, a), second = VM27HIDPODLayout::TypeLayout(integer, b);
        std::fprintf(stderr, "native UUID layout %d %zu %zu %x %u; UInt64 layout %d %zu %zu %x %u\n",
            first, a.size, a.stride, a.flags, a.extra, second, b.size, b.stride, b.flags, b.extra);
    }
    Check(VM27HIDPODLayout::Fields(0x100, 2, types, tags, layouts));
    VM27HIDPODLayout::Layout actualUUID{};
    Check(VM27HIDPODLayout::TypeLayout(uuid, actualUUID));
    const uint32_t expectedFlags = 7 |
        (actualUUID.flags & VM27HIDPODLayout::AddressableForDependencies);
    auto originalTable = (const Table *)VM27HIDPODLayout::DataPointer(metadata, -8, 0x2e3f);
    auto descriptor = VM27HIDPODLayout::DataPointer(metadata, 8, 0xae86);
    Check(originalTable && descriptor && originalTable->layout.size == 24 &&
          originalTable->layout.stride == 24 && originalTable->layout.flags == expectedFlags);
    for (unsigned test = 0; test < 128; ++test) {
        Table one = *originalTable, two = *originalTable;
        one.layout = two.layout = {0, 0, 0x400000, 0};
        Full candidate{nullptr, &one, 0x200, descriptor, {0xdeadbeef, 0xdeadbeef}};
        Full stock{nullptr, &two, 0x200, descriptor, {0xdeadbeef, 0xdeadbeef}};
        Check(!VM27HIDPODLayout::ProductionMetadata(&candidate.kind, candidate.offsets));
        ++WrongOwners;
        VM27HIDPODLayout::Apply(&candidate.kind, layouts, candidate.offsets);
        Native(&stock.kind, 0x100, 2, types, tags, stock.offsets);
        Check(!std::memcmp(&one.layout, &two.layout, sizeof(one.layout)));
        Check(!std::memcmp(candidate.offsets, stock.offsets, sizeof(candidate.offsets)));
        uint64_t expected[3]{};
        const void *stockProgram = VM27HIDPODLayout::DataPointer(&stock.kind, -16, 0x8b65);
        Check((uintptr_t(stockProgram) & 1) == 1);
        stockProgram = (const void *)(uintptr_t(stockProgram) & ~uintptr_t(1));
        Check(VM27HIDPODLayout::Read(stockProgram, expected, sizeof(expected)));
        if (std::memcmp(expected, VM27HIDPODLayout::Program, sizeof(expected)))
            std::fprintf(stderr, "native POD program %016llx %016llx %016llx\n",
                (unsigned long long)expected[0], (unsigned long long)expected[1],
                (unsigned long long)expected[2]);
        Check(!std::memcmp(expected, VM27HIDPODLayout::Program, sizeof(expected)));
        // All native initializer-written callbacks must point to the same
        // genuine functions, including the six common POD witnesses.
        Check(ptrauth_strip((void *)one.buffer, ptrauth_key_function_pointer) == ptrauth_strip((void *)two.buffer, ptrauth_key_function_pointer));
        Check(ptrauth_strip((void *)one.destroy, ptrauth_key_function_pointer) == ptrauth_strip((void *)two.destroy, ptrauth_key_function_pointer));
        Check(ptrauth_strip((void *)one.copy, ptrauth_key_function_pointer) == ptrauth_strip((void *)two.copy, ptrauth_key_function_pointer));
        Check(ptrauth_strip((void *)one.assignCopy, ptrauth_key_function_pointer) == ptrauth_strip((void *)two.assignCopy, ptrauth_key_function_pointer));
        Check(ptrauth_strip((void *)one.take, ptrauth_key_function_pointer) == ptrauth_strip((void *)two.take, ptrauth_key_function_pointer));
        Check(ptrauth_strip((void *)one.assignTake, ptrauth_key_function_pointer) == ptrauth_strip((void *)two.assignTake, ptrauth_key_function_pointer));
        alignas(8) unsigned char a[24]{}, b[24]{};
        Check(one.copy(a, value, &candidate.kind) == a);
        Check(two.copy(b, value, &stock.kind) == b);
        Check(!std::memcmp(a, b, sizeof(a)) && !std::memcmp(a, value, sizeof(a)));
        Check(one.buffer(a, value, &candidate.kind) == a);
        Check(!std::memcmp(a, value, sizeof(a)));
        Check(one.assignCopy(a, b, &candidate.kind) == a);
        Check(one.take(a, b, &candidate.kind) == a);
        Check(one.assignTake(a, b, &candidate.kind) == a);
        one.destroy(a, &candidate.kind);
        two.destroy(b, &stock.kind);
        Check(one.getTag(value, 0, &candidate.kind) == two.getTag(value, 0, &stock.kind));
        ++Cases;
    }
    const void *reversed[2] = {integer, uuid};
    uint8_t wrongTags[2] = {1, 0};
    for (bool accepted : {VM27HIDPODLayout::Fields(0, 2, types, tags, layouts),
                         VM27HIDPODLayout::Fields(0x100, 1, types, tags, layouts),
                         VM27HIDPODLayout::Fields(0x100, 2, reversed, tags, layouts),
                         VM27HIDPODLayout::Fields(0x100, 2, types, wrongTags, layouts),
                         VM27HIDPODLayout::Fields(0x100, 2, nullptr, tags, layouts),
                         VM27HIDPODLayout::Fields(0x100, 2, types, nullptr, layouts)}) {
        Check(!accepted);
        ++Rejects;
    }
}

extern "C" void vm27_hid_pod_fixture_finish() {
    std::printf("{\"nativeComparedCases\":%u,\"checks\":%u,\"fieldCounterexamplesRejected\":%u,\"productionWrongOwnerRejections\":%u,\"productionHIDEntryExecuted\":false,\"nativeCallbacksExecuted\":true}\n",
                Cases.load(), Checks.load(), Rejects.load(), WrongOwners.load());
}
