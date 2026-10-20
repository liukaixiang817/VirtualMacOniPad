#include "modern_cpu_native_exit_reducer_v1.h"
#include <Hypervisor/hv_vcpu_types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(VZCPUDecodedPublicExceptionV1) == sizeof(hv_vcpu_exit_t), "SDK exit size");
_Static_assert(offsetof(hv_vcpu_exit_t, reason) == 0, "SDK reason offset");
_Static_assert(offsetof(hv_vcpu_exit_t, exception.syndrome) == 8, "SDK syndrome offset");
_Static_assert(offsetof(hv_vcpu_exit_t, exception.virtual_address) == 16, "SDK VA offset");
_Static_assert(offsetof(hv_vcpu_exit_t, exception.physical_address) == 24, "SDK IPA offset");
_Static_assert(HV_EXIT_REASON_CANCELED == 0 && HV_EXIT_REASON_EXCEPTION == 1 &&
    HV_EXIT_REASON_VTIMER_ACTIVATED == 2 && HV_EXIT_REASON_UNKNOWN == 3, "SDK reason enum");

static unsigned checks;
#define CHECK(v) do { assert(v); ++checks; } while (0)

static VZCPUNativeExitValuesV1 Valid(uint32_t raw) {
    VZCPUNativeExitValuesV1 input = {0};
    input.schemaVersion = 1;
    input.nativeContextVersion = VZ_CPU_EXIT_REDUCER_NATIVE_VERSION_V1;
    input.knownFields = VZ_CPU_EXIT_ALL_KNOWN_V1;
    input.rawReason = raw;
    input.syndrome32 = UINT32_C(0xf200abcd); // EC=3c, independently owned fixture.
    input.virtualAddress = UINT64_C(0xffff000012345678);
    input.physicalAddress = UINT64_C(0x0000000fedcba987);
    return input;
}

static void Refuses(const VZCPUNativeExitValuesV1 *input, VZCPUExitReducerStatusV1 status) {
    VZCPUExitReductionV1 out, before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(before));
    CHECK(VZCPUReduceNativeExitV1(input, &out) == status);
    CHECK(memcmp(&out, &before, sizeof(out)) == 0);
}

int main(void) {
    // Every old jump-table exception entry, with all 64 architectural ECs.
    // Only the three helper lanes are refused: their original handlers may
    // emulate/re-enter and cannot be replaced with a value-only return.
    const uint32_t exceptionReasons[] = {1, 6, 8};
    for (unsigned i = 0; i < 3; ++i) {
        for (uint32_t ec = 0; ec < 64; ++ec) {
            VZCPUNativeExitValuesV1 input = Valid(exceptionReasons[i]);
            input.syndrome32 = (ec << 26) | UINT32_C(0x02123456);
            VZCPUNativeExitValuesV1 before = input;
            if (ec == 0x16 || ec == 0x18 || ec == 0x3f) {
                Refuses(&input, VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1);
            } else {
                VZCPUExitReductionV1 out;
                memset(&out, 0xa5, sizeof(out));
                CHECK(VZCPUReduceNativeExitV1(&input, &out) == VZ_CPU_EXIT_REDUCER_OK_V1);
                CHECK(out.schemaVersion == 1 && out.kind == VZ_CPU_EXIT_DECODED_EXCEPTION_V1);
                CHECK(out.hasPublicException == 1 && out.rawReason == exceptionReasons[i]);
                CHECK(out.exception.reason == 1 && out.exception.reserved == 0);
                CHECK(out.exception.syndrome == input.syndrome32);
                CHECK((out.exception.syndrome >> 32) == 0);
                CHECK(out.exception.virtualAddress == input.virtualAddress);
                CHECK(out.exception.physicalAddress == input.physicalAddress);
                hv_vcpu_exit_t sdk;
                memcpy(&sdk, &out.exception, sizeof(sdk));
                CHECK(sdk.reason == HV_EXIT_REASON_EXCEPTION);
                CHECK(sdk.exception.syndrome == input.syndrome32);
                CHECK(sdk.exception.virtual_address == input.virtualAddress);
                CHECK(sdk.exception.physical_address == input.physicalAddress);
            }
            CHECK(memcmp(&input, &before, sizeof(input)) == 0);
        }
        for (uint32_t mask = 0; mask < 15; ++mask) {
            VZCPUNativeExitValuesV1 input = Valid(exceptionReasons[i]);
            input.knownFields = mask;
            Refuses(&input, VZ_CPU_EXIT_REDUCER_INCOMPLETE_V1);
        }
    }
    // Raw 11 is not public UNKNOWN=3, EXCEPTION=1, errno or an instruction
    // result. Its unneeded metadata may be unavailable; no stale output leaks.
    const uint32_t retryReasons[] = {2, 11};
    for (unsigned i = 0; i < 2; ++i) {
        for (uint32_t mask = 1; mask <= 15; mask += 2) {
            VZCPUNativeExitValuesV1 input = Valid(retryReasons[i]);
            input.knownFields = mask;
            VZCPUExitReductionV1 out;
            memset(&out, 0xa5, sizeof(out));
            CHECK(VZCPUReduceNativeExitV1(&input, &out) == VZ_CPU_EXIT_REDUCER_OK_V1);
            CHECK(out.kind == VZ_CPU_EXIT_INTERNAL_RETRY_V1 && !out.hasPublicException);
            CHECK(out.rawReason == retryReasons[i]);
            VZCPUDecodedPublicExceptionV1 zero = {0};
            CHECK(memcmp(&out.exception, &zero, sizeof(zero)) == 0);
        }
    }
    const uint32_t unsupported[] = {0, 3, 4, 5, 7, 9, 10, 12, 13, 0x7fffffff, 0x80000000, 0xffffffff};
    for (unsigned i = 0; i < sizeof(unsupported) / sizeof(*unsupported); ++i) {
        VZCPUNativeExitValuesV1 input = Valid(unsupported[i]);
        Refuses(&input, VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1);
    }
    const uint32_t returns[] = {1, 11, 0x80000000, 0xfae94003, 0xffffffff};
    for (unsigned i = 0; i < sizeof(returns) / sizeof(*returns); ++i) {
        for (unsigned raw = 0; raw <= 12; ++raw) {
            VZCPUNativeExitValuesV1 input = Valid(raw);
            input.nativeReturnBits = returns[i];
            Refuses(&input, VZ_CPU_EXIT_REDUCER_NATIVE_FAILED_V1);
        }
    }
    VZCPUNativeExitValuesV1 input = Valid(1);
    input.nativeContextVersion = UINT64_C(0x2068797003000004);
    Refuses(&input, VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1);
    input = Valid(1); input.nativeContextVersion = 0;
    Refuses(&input, VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1);
    input = Valid(1); input.schemaVersion = 2;
    Refuses(&input, VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1);
    input = Valid(1); input.reserved = 1;
    Refuses(&input, VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1);
    input = Valid(1); input.knownFields |= 16;
    Refuses(&input, VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1);
    Refuses(NULL, VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1);
    input = Valid(1);
    CHECK(VZCPUReduceNativeExitV1(&input, NULL) == VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1);
    // Exact/partial alias refusal happens before input interpretation or output
    // writes; preserve even the input bytes as an independent boundary check.
    union { uint64_t alignment; unsigned char bytes[160]; } storage, before;
    memset(&storage, 0xa5, sizeof(storage));
    memcpy(storage.bytes + 48, &input, sizeof(input));
    memcpy(&before, &storage, sizeof(storage));
    const unsigned offsets[] = {8, 40, 48, 56, 88};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(*offsets); ++i) {
        CHECK(VZCPUReduceNativeExitV1((const void *)(storage.bytes + 48),
              (void *)(storage.bytes + offsets[i])) == VZ_CPU_EXIT_REDUCER_BAD_ARGUMENT_V1);
        CHECK(memcmp(&storage, &before, sizeof(storage)) == 0);
    }
    printf("native exit reducer v1: %u model checks passed; native calls=0, guest instruction claims=0\n", checks);
    return 0;
}
