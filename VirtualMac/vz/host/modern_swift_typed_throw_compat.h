// Finite old-host typed-throw entry; callback pointers use the normal C ABI.
#pragma once
#include <atomic>

using VM27TypedThrowHandler = void (*)(void *, const void *, const void *);
using VM27LegacyThrowHandler = void (*)(void *);

extern "C" {
// This slot belongs to this private provider. It is not the original new-host
// Core slot, and does not claim process-wide new-runtime debugger identity.
extern std::atomic<VM27TypedThrowHandler> _swift_willThrowTypedImpl;
__attribute__((swiftcall)) void swift_willThrowTypedImpl(
    void *value, const void *metadata, const void *errorWitness);
}
