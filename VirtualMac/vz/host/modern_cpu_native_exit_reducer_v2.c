#include "modern_cpu_native_exit_reducer_v2.h"
#include <string.h>
#include <stdbool.h>

static int Disjoint(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    if (av > UINTPTR_MAX - an || bv > UINTPTR_MAX - bn) return 0;
    return av + an <= bv || bv + bn <= av;
}

VZCPUExitReducerStatusV1 VZCPUReduceNativeExitV1(
    const VZCPUNativeExitValuesV1 *input, VZCPUExitReductionV1 *out) {
    if (!input || !out || !Disjoint(input, sizeof(*input), out, sizeof(*out)))
        return VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1;
    // Freeze all inputs before validating or preparing any output.
    VZCPUNativeExitValuesV1 value;
    memcpy(&value, input, sizeof(value));
    if (value.schemaVersion != VZ_CPU_EXIT_REDUCER_SCHEMA_V1 || value.reserved ||
        (value.knownFields & ~VZ_CPU_EXIT_ALL_KNOWN_V1))
        return VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1;
    if (value.nativeReturnBits) return VZ_CPU_EXIT_REDUCER_NATIVE_FAILED_V1;
    if (value.nativeContextVersion != VZ_CPU_EXIT_REDUCER_NATIVE_VERSION_V1)
        return VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1;
    if (!(value.knownFields & VZ_CPU_EXIT_REASON_KNOWN_V1))
        return VZ_CPU_EXIT_REDUCER_INCOMPLETE_V1;
    VZCPUExitReductionV1 result = {0};
    result.schemaVersion = VZ_CPU_EXIT_REDUCER_SCHEMA_V1;
    result.rawReason = value.rawReason;
    if (value.rawReason == 2 || value.rawReason == 11) {
        result.kind = VZ_CPU_EXIT_INTERNAL_RETRY_V1;
    } else {
        if (value.rawReason != 1 && value.rawReason != 6 && value.rawReason != 8)
            return VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1;
        if (value.knownFields != VZ_CPU_EXIT_ALL_KNOWN_V1)
            return VZ_CPU_EXIT_REDUCER_INCOMPLETE_V1;
        uint32_t ec = value.syndrome32 >> 26;
        // Real GIC/timer handlers run before this pure reducer. An unhandled
        // 64-bit MRS/MSR remains a genuine public exception for the original
        // VMM, including its c038 guest-feature instruction. Preserve every
        // native exception bit/address and leave guest PC/registers untouched.
        // HVC/private families and non-register SYS encodings still require
        // their own stateful handling and are not admitted by this route.
        bool ordinarySystem = ec == 0x18 && (value.syndrome32 & (1u << 25)) &&
            ((value.syndrome32 >> 20) & 3) >= 2;
        if (ec == 0x16 || ec == 0x3f || (ec == 0x18 && !ordinarySystem))
            return VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1;
        result.kind = VZ_CPU_EXIT_DECODED_EXCEPTION_V1;
        result.hasPublicException = 1;
        result.exception.reason = 1;
        // The original13 LDR w8 then STR x8 zero-extends this native u32.
        result.exception.syndrome = value.syndrome32;
        result.exception.virtualAddress = value.virtualAddress;
        result.exception.physicalAddress = value.physicalAddress;
    }
    memcpy(out, &result, sizeof(result));
    return VZ_CPU_EXIT_REDUCER_OK_V1;
}
