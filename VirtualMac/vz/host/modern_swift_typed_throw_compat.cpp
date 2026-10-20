// Adapted three-branch behavior from Swift ErrorObjectCommon.cpp, Apache-2.0
// with Runtime Library Exception. Upstream implementation and genuine machine
// ABI are pinned by swift-typedthrow-original-abi-readonly-v1/audit.json.
// https://github.com/swiftlang/swift/blob/main/stdlib/public/runtime/ErrorObjectCommon.cpp
#include "modern_swift_typed_throw_compat.h"

struct VM27ErrorBoxPair { void *object; void *payload; };
extern "C" {
extern std::atomic<VM27LegacyThrowHandler> _swift_willThrow;
__attribute__((swiftcall)) VM27ErrorBoxPair swift_allocError(
    const void *metadata, const void *errorWitness, const void *value, bool take);
void swift_errorRelease(void *box);
__attribute__((visibility("default")))
std::atomic<VM27TypedThrowHandler> _swift_willThrowTypedImpl{nullptr};
}
static_assert(std::atomic<VM27TypedThrowHandler>::is_always_lock_free);
static_assert(sizeof(_swift_willThrowTypedImpl) == sizeof(void *));

extern "C" __attribute__((swiftcall, visibility("default")))
void swift_willThrowTypedImpl(void *value, const void *metadata,
                             const void *errorWitness) {
    VM27TypedThrowHandler typed = _swift_willThrowTypedImpl.load(std::memory_order_acquire);
    if (typed) {
        typed(value, metadata, errorWitness);
        return;
    }
    VM27LegacyThrowHandler legacy = _swift_willThrow.load(std::memory_order_acquire);
    if (legacy) {
        // Native allocError copies the actual value using its actual witnesses.
        // The caller's value remains owned by its caller, including ARC fields.
        VM27ErrorBoxPair box = swift_allocError(metadata, errorWitness, value, false);
        legacy(box.object);
        swift_errorRelease(box.object);
    }
}
