// Link from a real C++ caller to the C reducer; no native/Apple call occurs.
#include "modern_cpu_native_exit_reducer_v1.h"
#include <cassert>
#include <cstdio>
#include <type_traits>

static_assert(std::is_same<decltype(&VZCPUReduceNativeExitV1),
    VZCPUExitReducerStatusV1 (*)(const VZCPUNativeExitValuesV1 *,
                                VZCPUExitReductionV1 *)>::value, "typed caller signature");

int main() {
    VZCPUNativeExitValuesV1 input{};
    input.schemaVersion = 1;
    input.nativeContextVersion = VZ_CPU_EXIT_REDUCER_NATIVE_VERSION_V1;
    input.knownFields = VZ_CPU_EXIT_REASON_KNOWN_V1;
    input.rawReason = 11;
    VZCPUExitReductionV1 result{};
    assert(VZCPUReduceNativeExitV1(&input, &result) == VZ_CPU_EXIT_REDUCER_OK_V1);
    assert(result.kind == VZ_CPU_EXIT_INTERNAL_RETRY_V1 && !result.hasPublicException);
    assert(result.rawReason == 11);
    std::puts("C++ caller linked to C reducer; native calls=0, retries=0");
}
