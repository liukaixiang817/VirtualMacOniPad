#pragma once
#include <cstddef>
#include <cstdint>

// This is a semantic component, not an original framework entry or router.
// A production entry needs the exact original metadata/program identity gate.
namespace VM27HIDObservedCVW {
struct Layout { size_t size, stride; uint32_t flags, extra; };
using AllowFunction = bool (*)(const void *, const void *);
struct Program {
    const unsigned char *bytes;
    size_t byteCount;
    AllowFunction allowFunction;
    const void *functionContext;
};
enum class Operation { Destroy, InitializeCopy, AssignCopy, AssignTake, CopyBuffer };
bool Validate(const Program &program, const Layout &layout);
// dest is initialized for Destroy/AssignCopy/AssignTake, uninitialized for
// InitializeCopy/CopyBuffer. AssignTake transfers source ownership to dest.
bool Apply(Operation operation, const Program &program, const Layout &layout,
           void *destination, const void *source, void **valueAddress = nullptr);
}
