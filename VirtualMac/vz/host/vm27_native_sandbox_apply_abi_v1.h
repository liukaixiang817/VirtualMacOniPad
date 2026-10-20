#ifndef VM27_NATIVE_SANDBOX_APPLY_ABI_V1_H
#define VM27_NATIVE_SANDBOX_APPLY_ABI_V1_H

#include <stddef.h>
#include <stdint.h>

/* A consumed prefix, not a declaration of a producer's allocation size.
 * Source: current iPad UUID41a96a45... apply_container RVA24fc.
 * Pass the genuine compiler-owned object; do not allocate this prefix as a
 * replacement or release foreign compiler storage with the native library. */
typedef struct {
    const char *namedProfile;
    const uint8_t *serializedBytes;
    uint64_t serializedLength;
} VM27NativeSandboxApplyProfilePrefixV1;

/* sandbox_apply RVA2590 has one pointer argument and int native result. */
typedef int (*VM27NativeSandboxApplyFunctionV1)(const void *actualCompilerOwnedObject);

#ifdef __cplusplus
static_assert(sizeof(VM27NativeSandboxApplyProfilePrefixV1) == 24, "LP64 consumed span");
static_assert(offsetof(VM27NativeSandboxApplyProfilePrefixV1, serializedBytes) == 8, "actual byte pointer");
static_assert(offsetof(VM27NativeSandboxApplyProfilePrefixV1, serializedLength) == 16, "actual uint64 length");
#else
_Static_assert(sizeof(VM27NativeSandboxApplyProfilePrefixV1) == 24, "LP64 consumed span");
_Static_assert(offsetof(VM27NativeSandboxApplyProfilePrefixV1, serializedBytes) == 8, "actual byte pointer");
_Static_assert(offsetof(VM27NativeSandboxApplyProfilePrefixV1, serializedLength) == 16, "actual uint64 length");
#endif
#endif
