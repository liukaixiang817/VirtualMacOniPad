#pragma once
#include "vm27_owned_pvg_buffer_capability_v1.h"
#ifdef __cplusplus
extern "C" {
#endif
/* The original address-range heap feature is unsupported when no actual
 * native BOOL method exists; no heap or Apple-class method is fabricated. */
__attribute__((visibility("default")))
BOOL VM27OwnedPVGSupportsHeapAddressRangesV1(id _Nullable device, SEL _Nonnull selector);
#ifdef __cplusplus
}
#endif
