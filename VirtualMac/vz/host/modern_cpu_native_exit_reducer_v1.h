// Application-private value reducer. It neither runs a CPU nor publishes an
// Apple USER, VIEW, native context or native public-exit object.
#ifndef VZ_MODERN_CPU_NATIVE_EXIT_REDUCER_V1_H
#define VZ_MODERN_CPU_NATIVE_EXIT_REDUCER_V1_H
#include <stddef.h>
#include <stdint.h>

#define VZ_CPU_EXIT_REDUCER_SCHEMA_V1 UINT32_C(1)
#define VZ_CPU_EXIT_REDUCER_NATIVE_VERSION_V1 UINT64_C(0x206879700000000e)
#define VZ_CPU_EXIT_REASON_KNOWN_V1 UINT32_C(1)
#define VZ_CPU_EXIT_SYNDROME_KNOWN_V1 UINT32_C(2)
#define VZ_CPU_EXIT_VA_KNOWN_V1 UINT32_C(4)
#define VZ_CPU_EXIT_IPA_KNOWN_V1 UINT32_C(8)
#define VZ_CPU_EXIT_ALL_KNOWN_V1 UINT32_C(15)

// Exact old-host widths: reason@4008:4, syndrome@400c:4,
// virtual address@4018:8, physical address@4020:8. The producer must obtain
// these from a successful native return on the same live CPU/owner/generation
// and run token, within its post-return read lease. This pure value API does
// not establish any of that provenance or authorize those memory reads.
typedef struct {
    uint32_t schemaVersion;
    uint32_t nativeReturnBits;
    uint64_t nativeContextVersion;
    uint32_t knownFields;
    uint32_t rawReason;
    uint32_t syndrome32;
    uint32_t reserved;
    uint64_t virtualAddress;
    uint64_t physicalAddress;
} VZCPUNativeExitValuesV1;

// The independently owned exception value has the SDK's 32-byte layout.
// Its address must never substitute for a real kernel/Apple-owned object.
typedef struct {
    uint32_t reason;
    uint32_t reserved;
    uint64_t syndrome;
    uint64_t virtualAddress;
    uint64_t physicalAddress;
} VZCPUDecodedPublicExceptionV1;

typedef enum {
    VZ_CPU_EXIT_INTERNAL_RETRY_V1 = 1,
    VZ_CPU_EXIT_DECODED_EXCEPTION_V1 = 2
} VZCPUExitReductionKindV1;

typedef struct {
    uint32_t schemaVersion;
    uint32_t kind;
    uint32_t hasPublicException;
    uint32_t rawReason;
    // Defined only when hasPublicException == 1. For INTERNAL_RETRY this is
    // all zero and is not a CANCELED record or any other public exit.
    VZCPUDecodedPublicExceptionV1 exception;
} VZCPUExitReductionV1;

typedef enum {
    VZ_CPU_EXIT_REDUCER_OK_V1 = 0,
    VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1,
    VZ_CPU_EXIT_REDUCER_NATIVE_FAILED_V1,
    VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1,
    VZ_CPU_EXIT_REDUCER_INCOMPLETE_V1
} VZCPUExitReducerStatusV1;

// Supports raw 2/11 as an internal classification only. No retry is performed.
// Supports raw 1/6/8 only when the original old-provider exception path returns
// without HVC, SYS or private-emulation handling (EC != 16/18/3f hex).
// All other reasons, modern context versions and incomplete values are refused.
// Every refusal preserves out byte-for-byte. Buffers must be disjoint.
// An EXCEPTION value does not prove that guest instructions executed.
#ifdef __cplusplus
extern "C" {
#endif
VZCPUExitReducerStatusV1 VZCPUReduceNativeExitV1(
    const VZCPUNativeExitValuesV1 *, VZCPUExitReductionV1 *);
#ifdef __cplusplus
}
#define VZ_CPU_EXIT_STATIC_ASSERT_V1 static_assert
#else
#define VZ_CPU_EXIT_STATIC_ASSERT_V1 _Static_assert
#endif

VZ_CPU_EXIT_STATIC_ASSERT_V1(sizeof(VZCPUDecodedPublicExceptionV1) == 32, "public exception value size");
VZ_CPU_EXIT_STATIC_ASSERT_V1(offsetof(VZCPUDecodedPublicExceptionV1, reason) == 0, "reason offset");
VZ_CPU_EXIT_STATIC_ASSERT_V1(offsetof(VZCPUDecodedPublicExceptionV1, syndrome) == 8, "syndrome offset");
VZ_CPU_EXIT_STATIC_ASSERT_V1(offsetof(VZCPUDecodedPublicExceptionV1, virtualAddress) == 16, "VA offset");
VZ_CPU_EXIT_STATIC_ASSERT_V1(offsetof(VZCPUDecodedPublicExceptionV1, physicalAddress) == 24, "IPA offset");
#undef VZ_CPU_EXIT_STATIC_ASSERT_V1
#endif
