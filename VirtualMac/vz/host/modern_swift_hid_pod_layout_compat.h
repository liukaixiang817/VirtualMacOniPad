#pragma once
#include <cstddef>
#include <cstdint>
// Exact six-argument C ABI used by the one genuine HID struct completion.
extern "C" __attribute__((visibility("default"))) void swift_cvw_initStructMetadataWithLayoutString(
    void *metadata, uintptr_t flags, size_t fields, const void *const *types,
    const uint8_t *tags, uint32_t *offsets);
