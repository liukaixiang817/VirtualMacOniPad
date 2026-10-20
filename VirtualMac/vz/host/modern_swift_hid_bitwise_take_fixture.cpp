// Ordinary Mac comparisons of the genuine bitwise ownership-transfer branch.
// These SDK metadata objects cannot pass the original HID production guard.
#define VM27_HID_BITWISE_TAKE_COMPONENT_FIXTURE 1
#include "modern_swift_hid_bitwise_take_compat.cpp"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
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
    VM27HIDBitwiseTake::Layout layout;
};
using RetainCount = size_t (*)(const void *);
Init Native = nullptr;
RetainCount Count = nullptr;
unsigned Checks = 0, Cases = 0, OwnershipChecks = 0, Rejects = 0, WrongOwners = 0, NonBitwise = 0;
void CheckImpl(bool value, unsigned line) {
    if (!value) { std::fprintf(stderr, "take fixture failed at line %u\n", line); std::abort(); }
    ++Checks;
}
#define Check(value) CheckImpl((value), __LINE__)

extern "C" void vm27_hid_take_fixture_run(const void *metadata, const void *value, const void *object) {
    static bool initialized = [] {
        alarm(45);
        auto core = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
        Check(core != nullptr);
        Native = (Init)dlsym(core, "swift_cvw_initWithTake");
        Count = (RetainCount)dlsym(core, "swift_retainCount");
        Check(Native && Count);
        return true;
    }();
    (void)initialized;
    auto table = (const Table *)VM27HIDBitwiseTake::DataPointer(metadata, -8, 0x2e3f);
    Check(table && table->layout.size && table->layout.size <= 4096);
    VM27HIDBitwiseTake::Layout layout{};
    Check(VM27HIDBitwiseTake::TypeLayout(metadata, layout));
    Check(!VM27HIDBitwiseTake::ProductionMetadata(metadata, layout));
    ++WrongOwners;
    if (layout.flags & 0x100000) {
        alignas(16) unsigned char untouched[4096]{};
        Check(!VM27HIDBitwiseTake::Move(untouched, value, layout));
        ++NonBitwise;
        return;
    }
    for (unsigned iteration = 0; iteration < 128; ++iteration) {
        alignas(16) unsigned char a[4096]{}, b[4096]{}, candidate[4096]{}, stock[4096]{};
        size_t baseline = object ? Count(object) : 0;
        Check(table->copy(a, value, metadata) == a);
        Check(table->copy(b, value, metadata) == b);
        size_t copied = object ? Count(object) : 0;
        if (object) { Check(copied == baseline + 2); ++OwnershipChecks; }
        Check(VM27HIDBitwiseTake::Move(candidate, a, layout));
        if (object) { Check(Count(object) == copied); ++OwnershipChecks; }
        Check(Native(stock, b, metadata) == stock);
        if (object) { Check(Count(object) == copied); ++OwnershipChecks; }
        Check(!std::memcmp(candidate, stock, layout.size));
        Check(!std::memcmp(candidate, value, layout.size));
        // a/b have transferred their ownership. Only initialized destinations
        // are destroyed, using the genuine SDK VWT's authenticated callback.
        table->destroy(candidate, metadata);
        table->destroy(stock, metadata);
        if (object) { Check(Count(object) == baseline); ++OwnershipChecks; }
        ++Cases;
    }
    unsigned char a[4096]{}, b[4096]{};
    for (auto bad : {VM27HIDBitwiseTake::Layout{24,24,0x100007,0},
                    VM27HIDBitwiseTake::Layout{24,24,0x400007,0},
                    VM27HIDBitwiseTake::Layout{0,0,7,0},
                    VM27HIDBitwiseTake::Layout{4097,4097,7,0}}) {
        Check(!VM27HIDBitwiseTake::Move(a, b, bad));
        ++Rejects;
    }
    Check(!VM27HIDBitwiseTake::Move(nullptr, b, layout));
    Check(!VM27HIDBitwiseTake::Move(a, nullptr, layout));
    Rejects += 2;
}

extern "C" void vm27_hid_take_fixture_finish(unsigned created, unsigned destroyed) {
    Check(created == destroyed && created == 8);
    Check(NonBitwise == 8);
    std::printf("{\"nativeComparedCases\":%u,\"checks\":%u,\"genuineRetainCountChecks\":%u,\"counterexamplesRejected\":%u,\"productionWrongOwnerRejections\":%u,\"nativeNonBitwiseMetadataRejected\":%u,\"realObjectsCreated\":%u,\"realObjectsDestroyed\":%u,\"productionHIDEntryExecuted\":false}\n",
        Cases, Checks, OwnershipChecks, Rejects, WrongOwners, NonBitwise, created, destroyed);
}
