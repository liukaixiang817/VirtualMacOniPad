#pragma once
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif
/* The original ObjC call registers and the native new-method +1 contract
 * are unchanged. This is diagnostic forwarding, never a pipeline substitute. */
__attribute__((visibility("default"), ns_returns_retained))
id _Nullable VM27OwnedPVGNewComputePipelineStateWithFunctionV1(
    id _Nullable device, SEL _Nonnull selector, id _Nullable function,
    NSError * __autoreleasing _Nullable * _Nullable error);
#ifdef __cplusplus
}
#endif
