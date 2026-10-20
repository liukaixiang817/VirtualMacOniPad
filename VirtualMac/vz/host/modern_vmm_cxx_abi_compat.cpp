// Narrow CPU-only typed new/delete definitions for the original macOS27 VMM.
// The advisory 64-bit type descriptor has the exact SDK LP64 mangled ABI.
// Ordinary native new/delete retain their real throwing and ownership behavior.
// Build with -fno-typed-cxx-new-delete to prevent recursive typed lowering.
#include <cstddef>
#include <new>

namespace std { enum class __type_descriptor_t : unsigned long long; }
static_assert(sizeof(std::__type_descriptor_t) == 8 && sizeof(std::size_t) == 8,
    "Audited Darwin LP64 typed-new ABI");

void *operator new(std::size_t size, std::__type_descriptor_t) {
    return ::operator new(size);
}
void *operator new[](std::size_t size, std::__type_descriptor_t) {
    return ::operator new[](size);
}
void operator delete(void *pointer, std::__type_descriptor_t) noexcept {
    ::operator delete(pointer);
}
void operator delete[](void *pointer, std::__type_descriptor_t) noexcept {
    ::operator delete[](pointer);
}
