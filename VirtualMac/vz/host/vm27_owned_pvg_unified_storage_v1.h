#pragma once
#import <Metal/Metal.h>
#include "vm27_owned_pvg_address_range_capability_v3.h"
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"),ns_returns_retained))
id _Nullable VM27OwnedPVGNewBufferWithLengthOptionsV1(id _Nullable device,SEL _Nonnull selector,NSUInteger length,MTLResourceOptions options);
__attribute__((visibility("default")))
void VM27OwnedPVGDidModifyManagedRangeV1(id _Nullable buffer,SEL _Nonnull selector,NSRange range);
#ifdef __cplusplus
}
#endif
