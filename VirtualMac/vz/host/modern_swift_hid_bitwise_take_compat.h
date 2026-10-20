#pragma once
#include <cstddef>
#include <cstdint>
extern "C" __attribute__((visibility("default"))) void *swift_cvw_initWithTake(
    void *destination, const void *source, const void *metadata);

namespace VM27HIDBitwiseTake {
struct Layout { size_t size, stride; uint32_t flags, extra; };
bool Read(const void *source, void *destination, size_t bytes);
const void *DataPointer(const void *metadata, intptr_t offset, uint16_t discriminator);
bool TypeLayout(const void *metadata, Layout &layout);
bool ProductionMetadata(const void *metadata, Layout &layout);
// The genuine default CVW's bitwise-takable branch. Source ownership transfers
// to destination; the moved source must not subsequently be destroyed.
bool Move(void *destination, const void *source, const Layout &layout);
}
