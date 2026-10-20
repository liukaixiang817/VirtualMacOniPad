// App-private, finite old-host coroutine allocation entry.
// ABI: Swift-RuntimeFunctions.def CoroFrameAlloc and SlowAlloc are both C_CC.
// The genuine Core 27 caller requests ordinary malloc alignment, converts zero
// to one, and ends in the same fatal failure entry used by swift_slowAlloc.
// https://github.com/swiftlang/swift/blob/main/stdlib/public/runtime/Heap.cpp
// Type-ID telemetry is unavailable on the old host; this is an explicit
// allocator adaptation, not a replacement Swift 27 runtime or tagged allocator.
#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(size_t) == 8 && sizeof(uint64_t) == 8, "Audited Darwin LP64 ABI");
extern void *VM27NativeSlowAlloc(size_t size, size_t align_mask) __asm("_swift_slowAlloc");
__attribute__((visibility("default")))
void *VM27CoroFrameAlloc(size_t size, uint64_t type_id) __asm("_swift_coroFrameAlloc");

void *VM27CoroFrameAlloc(size_t size, uint64_t type_id) {
    (void)type_id;
    // A single real native allocation. The native runtime normalizes size zero,
    // returns actual owned 16-byte-aligned storage, and reports fatal failure.
    return VM27NativeSlowAlloc(size, 0);
}
