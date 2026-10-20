// This fixture writes callback slots only in its own ordinary Mac process.
// The provider itself never writes the existing native Core callback slot.
#include "modern_swift_typed_throw_compat.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <initializer_list>
#include <pthread.h>
#include <unistd.h>

extern "C" const void *swift_conformsToProtocol(const void *, const void *);
extern "C" void *swift_errorRetain(void *);
extern "C" void swift_errorRelease(void *);
struct OpenedError { const void *value; const void *metadata; const void *witness; };
extern "C" void swift_getErrorValue(void *, void **, OpenedError *);
extern "C" int32_t vm27_typed_fixture_values_equal(const void *, const void *);
using Entry = void (__attribute__((swiftcall)) *)(void *, const void *, const void *);

static Entry originalEntry;
static std::atomic<VM27TypedThrowHandler> *nativeTyped;
static std::atomic<VM27LegacyThrowHandler> *nativeLegacy;
static VM27TypedThrowHandler savedTyped;
static VM27LegacyThrowHandler savedLegacy;
static void *errorProtocol;
static std::atomic<size_t> typedCalls{0}, legacyCalls{0}, noHookCalls{0}, checkedCopies{0};
static thread_local const void *expectedValue, *expectedMetadata, *expectedWitness;
static thread_local bool retainNextBox;
static thread_local void *retainedBox;

static void typedHandler(void *value, const void *metadata, const void *witness) {
    assert(value == expectedValue && metadata == expectedMetadata && witness == expectedWitness);
    typedCalls.fetch_add(1, std::memory_order_relaxed);
}
static void legacyHandler(void *box) {
    assert(box != nullptr);
    void *scratch = nullptr;
    OpenedError opened{};
    swift_getErrorValue(box, &scratch, &opened);
    assert(opened.value != expectedValue && opened.metadata == expectedMetadata && opened.witness == expectedWitness);
    assert(vm27_typed_fixture_values_equal(expectedValue, opened.value) == 1);
    checkedCopies.fetch_add(1, std::memory_order_relaxed);
    legacyCalls.fetch_add(1, std::memory_order_relaxed);
    if (retainNextBox) {
        assert(retainedBox == nullptr);
        retainedBox = swift_errorRetain(box);
        assert(retainedBox == box);
        retainNextBox = false;
    }
}
static void invokeBoth(void *value, const void *metadata, const void *witness) {
    swift_willThrowTypedImpl(value, metadata, witness);
    originalEntry(value, metadata, witness);
}
static void setHooks(bool typed, bool legacy) {
    _swift_willThrowTypedImpl.store(typed ? typedHandler : nullptr, std::memory_order_release);
    nativeTyped->store(typed ? typedHandler : nullptr, std::memory_order_release);
    nativeLegacy->store(legacy ? legacyHandler : nullptr, std::memory_order_release);
}
extern "C" void vm27_typed_fixture_initialize() {
    alarm(45);
    void *core = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_NOLOAD);
    assert(core);
    originalEntry = reinterpret_cast<Entry>(dlsym(core, "swift_willThrowTypedImpl"));
    nativeTyped = reinterpret_cast<std::atomic<VM27TypedThrowHandler> *>(dlsym(core, "_swift_willThrowTypedImpl"));
    nativeLegacy = reinterpret_cast<std::atomic<VM27LegacyThrowHandler> *>(dlsym(core, "_swift_willThrow"));
    errorProtocol = dlsym(core, "$ss5ErrorMp");
    assert(originalEntry && nativeTyped && nativeLegacy && errorProtocol);
    assert(nativeTyped != &_swift_willThrowTypedImpl);
    Dl_info info{};
    assert(dladdr(reinterpret_cast<void *>(originalEntry), &info));
    assert(strcmp(info.dli_fname, "/usr/lib/swift/libswiftCore.dylib") == 0);
    savedTyped = nativeTyped->load(std::memory_order_acquire);
    savedLegacy = nativeLegacy->load(std::memory_order_acquire);
}
struct Worker { void *value; const void *metadata; const void *witness; };
static void *worker(void *opaque) {
    auto *input = static_cast<Worker *>(opaque);
    expectedValue = input->value;
    expectedMetadata = input->metadata;
    expectedWitness = input->witness;
    for (size_t i = 0; i < 128; ++i) invokeBoth(input->value, input->metadata, input->witness);
    return nullptr;
}
extern "C" void vm27_typed_fixture_run(void *value, const void *metadata, size_t size, int32_t concurrent) {
    assert(size > sizeof(void *) && retainedBox == nullptr);
    const void *witness = swift_conformsToProtocol(metadata, errorProtocol);
    assert(witness != nullptr);
    expectedValue = value;
    expectedMetadata = metadata;
    expectedWitness = witness;
    if (concurrent) {
        Worker input{value, metadata, witness};
        for (bool typed : {true, false}) {
            setHooks(typed, true);
            pthread_t threads[4];
            for (auto &thread : threads) assert(pthread_create(&thread, nullptr, worker, &input) == 0);
            for (auto &thread : threads) assert(pthread_join(thread, nullptr) == 0);
        }
    } else {
        setHooks(false, false);
        invokeBoth(value, metadata, witness);
        noHookCalls.fetch_add(2, std::memory_order_relaxed);
        const size_t before = legacyCalls.load();
        setHooks(true, true); // Real typed hook must take priority over legacy.
        invokeBoth(value, metadata, witness);
        assert(legacyCalls.load() == before);
        setHooks(false, true);
        retainNextBox = true; // Retain the candidate's real copied box.
        invokeBoth(value, metadata, witness);
        assert(retainedBox && !retainNextBox && legacyCalls.load() == before + 2);
    }
    setHooks(false, false);
}
extern "C" void vm27_typed_fixture_release_saved() {
    assert(retainedBox);
    swift_errorRelease(retainedBox);
    retainedBox = nullptr;
}
extern "C" void vm27_typed_fixture_finish() {
    assert(retainedBox == nullptr);
    assert(noHookCalls == 512 && typedCalls == 1536 && legacyCalls == 1536 && checkedCopies == 1536);
    _swift_willThrowTypedImpl.store(nullptr, std::memory_order_release);
    nativeTyped->store(savedTyped, std::memory_order_release);
    nativeLegacy->store(savedLegacy, std::memory_order_release);
    assert(nativeTyped->load(std::memory_order_acquire) == savedTyped && nativeLegacy->load(std::memory_order_acquire) == savedLegacy);
    alarm(0);
    printf("{\"noHookCalls\":512,\"typedCalls\":1536,\"legacyCalls\":1536,\"realCopiedBoxes\":1536,\"retainedARCValueCases\":256,\"workers\":4,\"nativeMacCompared\":true,\"nativeCallbacksRestored\":true}\n");
}
