// Ordinary component comparisons against already-loaded genuine Swift Core.
// Isolated metadata carries an exact fixture program; no original HID/VZ load.
#include "modern_swift_hid_observed_cvw_compat.cpp"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <initializer_list>

using namespace VM27HIDObservedCVW;
using GetTag = unsigned (*)(const void *, unsigned, const void *);
using SetTag = void (*)(void *, unsigned, unsigned, const void *);
struct Full {
    const void *__ptrauth(2,1,0x8b65) program;
    Table *__ptrauth(2,1,0x2e3f) table;
    uintptr_t kind;
};
struct BoxPair { void *object; void *payload; };
using AllocBox = __attribute__((swiftcall)) BoxPair (*)(const void *);
using RetainCount = size_t (*)(const void *);
Init NativeCopy = nullptr, NativeAssign = nullptr, NativeTake = nullptr, NativeBuffer = nullptr;
Destroy NativeDestroy = nullptr;
RetainCount Count = nullptr;
AllocBox Box = nullptr;
unsigned Checks = 0, Cases = 0, OwnershipChecks = 0, Rejected = 0;
unsigned OperationCases[5]{}, TagPairs = 0, BoxCases = 0;
alignas(16) uint64_t Storage[64]{};
size_t StorageBytes = 0;
unsigned EnumTag(const void *value) {
    uint32_t low = 0; uint64_t upper = 0;
    std::memcpy(&low, value, 4); std::memcpy(&upper, (const char *)value + 8, 8);
    unsigned tag = upper >> 62;
    return tag == 3 ? low + 3 : tag;
}
bool Allow(const void *target, const void *) {
    return target == ptrauth_strip((void *)&EnumTag, ptrauth_key_function_pointer);
}
void CheckImpl(bool ok, unsigned line) {
    if (!ok) { std::fprintf(stderr, "observed CVW fixture failed at line %u\n", line); std::abort(); }
    ++Checks;
}
#define Check(value) CheckImpl((value), __LINE__)

Program Build(unsigned schema, const Layout &layout) {
    std::memset(Storage, 0, sizeof(Storage));
    size_t words = 2;
    auto word = [&](uint64_t tag, uint64_t skip = 0) { Storage[words++] = tag << 56 | skip; };
    switch (schema) {
    case 0: Check(layout.size == 8); word(0, 8); break;
    case 1: Check(layout.size == 8); word(2); word(0); break;
    case 2: Check(layout.size == 16); word(8, 8); word(0); break;
    case 3: Check(layout.size == 8); word(10); word(0); break;
    case 4: Check(layout.size == 32); word(2); word(8, 8); word(8); word(0); break;
    case 5: Check(layout.size == 32); word(14); word(0, 8); break;
    case 6: {
        Check(layout.size == 16);
        Storage[0] = uint64_t(1) << 63;
        word(20);
        uintptr_t target = uintptr_t(ptrauth_strip((void *)&EnumTag, ptrauth_key_function_pointer));
        intptr_t relative = target - uintptr_t(&Storage[words]);
        Check(relative == int32_t(relative));
        Storage[words++] = uint32_t(relative); Storage[words++] = 3;
        Storage[words++] = 48; Storage[words++] = 16;
        Storage[words++] = 0; Storage[words++] = 16; Storage[words++] = 32;
        for (unsigned i = 0; i < 3; ++i) { word(2, 8); word(0); }
        word(0); break;
    }
    default: Check(false);
    }
    Storage[1] = words * 8 - 24;
    StorageBytes = words * 8;
    return {(const unsigned char *)Storage, StorageBytes, Allow, nullptr};
}
void Ownership(const void *first, const void *second, size_t a, size_t b) {
    if (first) { Check(Count(first) == a); ++OwnershipChecks; }
    if (second && first != second) { Check(Count(second) == b); ++OwnershipChecks; }
}
void CompareBytes(const unsigned char *a, const unsigned char *b, size_t size) {
    if (std::memcmp(a, b, size)) {
        std::fprintf(stderr, "bytes mismatch: ");
        for (size_t i = 0; i < size; ++i) std::fprintf(stderr, "%02x/%02x ", a[i], b[i]);
        std::fprintf(stderr, "\n");
    }
    Check(!std::memcmp(a, b, size));
}

extern "C" void vm27_hid_cvw_fixture_run(const void *metadata, const void *left,
    const void *right, unsigned schema, const void *first, const void *second,
    unsigned leftTag, unsigned rightTag) {
    static bool initialized = [] {
        alarm(55);
        auto core = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
        Check(core);
        NativeCopy = (Init)dlsym(core, "swift_cvw_initWithCopy");
        NativeAssign = (Init)dlsym(core, "swift_cvw_assignWithCopy");
        NativeTake = (Init)dlsym(core, "swift_cvw_assignWithTake");
        NativeBuffer = (Init)dlsym(core, "swift_cvw_initializeBufferWithCopyOfBuffer");
        NativeDestroy = (Destroy)dlsym(core, "swift_cvw_destroy");
        Count = (RetainCount)dlsym(core, "swift_retainCount");
        Box = (AllocBox)dlsym(core, "swift_allocBox");
        Check(NativeCopy && NativeAssign && NativeTake && NativeBuffer && NativeDestroy && Count && Box);
        return true;
    }();
    (void)initialized;
    auto sdk = Witnesses(metadata);
    Check(sdk && sdk->layout.size <= 4096 && !(sdk->layout.flags & 0x100000));
    Program program = Build(schema, sdk->layout);
    Check(Validate(program, sdk->layout));
    if (schema == 6) { Check(EnumTag(left) == leftTag && EnumTag(right) == rightTag); ++TagPairs; }
    Table isolated = *sdk;
    // Genuine getLayoutString makes reader.bit63 from metadata's low tag.
    // Relative FN schemas keep the actual untagged program; resolved POD
    // programs may set low tag 1. A tagged relative FN traps in genuine Core.
    Full full{(const void *)(uintptr_t(program.bytes) | (schema == 6 ? 0 : 1)), &isolated, 0x200};
    Check(VM27HIDBitwiseTake::DataPointer(&full.kind, -16, 0x8b65) == full.program);
    const size_t a = first ? Count(first) : 0, b = second ? Count(second) : 0;
    for (unsigned iteration = 0; iteration < 16; ++iteration) {
        for (Operation operation : {Operation::InitializeCopy, Operation::Destroy,
                                   Operation::AssignCopy, Operation::AssignTake}) {
            alignas(16) unsigned char candidate[4096]{}, stock[4096]{}, src1[4096]{}, src2[4096]{};
            if (operation != Operation::InitializeCopy) {
                sdk->copy(candidate, left, metadata); sdk->copy(stock, left, metadata);
            }
            const void *source = right;
            if (operation == Operation::AssignTake) {
                sdk->copy(src1, right, metadata); sdk->copy(src2, right, metadata);
                source = src1;
            }
            Check(Apply(operation, program, sdk->layout, candidate, source));
            if (operation == Operation::InitializeCopy) Check(NativeCopy(stock, right, &full.kind) == stock);
            if (operation == Operation::Destroy) NativeDestroy(stock, &full.kind);
            if (operation == Operation::AssignCopy) Check(NativeAssign(stock, right, &full.kind) == stock);
            if (operation == Operation::AssignTake) Check(NativeTake(stock, src2, &full.kind) == stock);
            if (operation != Operation::Destroy) {
                CompareBytes(candidate, stock, sdk->layout.size);
                sdk->destroy(candidate, metadata); sdk->destroy(stock, metadata);
            }
            Ownership(first, second, a, b);
            ++Cases; ++OperationCases[unsigned(operation)];
        }
        if (!(sdk->layout.flags & 0x20000)) {
            alignas(16) unsigned char candidate[24]{}, stock[24]{}, source[24]{};
            sdk->copy(source, right, metadata);
            void *address = nullptr;
            Check(Apply(Operation::CopyBuffer, program, sdk->layout, candidate, source, &address));
            Check(address == candidate && NativeBuffer(stock, source, &full.kind) == stock);
            CompareBytes(candidate, stock, sdk->layout.size);
            sdk->destroy(candidate, metadata); sdk->destroy(stock, metadata); sdk->destroy(source, metadata);
        } else {
            auto box = Box(metadata);
            Check(box.object && box.payload == (unsigned char *)box.object + 16);
            sdk->copy(box.payload, right, metadata);
            unsigned char *source[3]{(unsigned char *)box.object, nullptr, nullptr};
            unsigned char *candidate[3]{}, *stock[3]{};
            const size_t boxCount = Count(box.object);
            void *address = nullptr;
            Check(Apply(Operation::CopyBuffer, program, sdk->layout, candidate, source, &address));
            Check(address == box.payload && NativeBuffer(stock, source, &full.kind) == box.payload);
            Check(candidate[0] == source[0] && stock[0] == source[0] && Count(box.object) == boxCount + 2);
            swift_release(candidate[0]); swift_release(stock[0]); swift_release(source[0]);
            ++BoxCases;
        }
        Ownership(first, second, a, b);
        ++Cases; ++OperationCases[unsigned(Operation::CopyBuffer)];
    }
    for (uint64_t bad : {uint64_t(23) << 56, uint64_t(1) << 56, uint64_t(0x00ffffffffffffff)}) {
        uint64_t saved = Storage[2]; Storage[2] = bad;
        Check(!Validate(program, sdk->layout)); ++Rejected; Storage[2] = saved;
    }
    for (auto flag : {0x100000u, 0x400000u}) {
        Layout wrong = sdk->layout; wrong.flags |= flag;
        Check(!Validate(program, wrong)); ++Rejected;
    }
    if (schema == 6) {
        Program wrong = program; wrong.allowFunction = nullptr;
        Check(!Validate(wrong, sdk->layout)); ++Rejected;
    }
}
extern "C" void vm27_hid_cvw_fixture_finish(unsigned created, unsigned destroyed) {
    Check(created == destroyed && created == 16);
    std::printf("{\"checks\":%u,\"nativeComparedCases\":%u,\"genuineRetainCountChecks\":%u,\"counterexamplesRejected\":%u,\"enumTagPairs\":%u,\"nativeBoxCases\":%u,\"operations\":[%u,%u,%u,%u,%u],\"realObjectsCreated\":%u,\"realObjectsDestroyed\":%u,\"productionOriginalHIDEntryExecuted\":false}\n", Checks, Cases, OwnershipChecks, Rejected, TagPairs, BoxCases,
        OperationCases[0],OperationCases[1],OperationCases[2],OperationCases[3],OperationCases[4],created,destroyed);
}
