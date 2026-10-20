#include "modern_vz_hypervisor_ipa_transform_v1.h"
#include "modern_vz_hypervisor_framework_limits.h"
#include <limits.h>

_Static_assert(CHAR_BIT == 8 && sizeof(uint32_t) == 4 && sizeof(int32_t) == 4,
               "Exact original output/status width");
_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8 &&
               offsetof(VZFrameworkNativeIPAInputV1, wireBytes) == 24 &&
               offsetof(VZFrameworkNativeIPAInputV1, wireCapacity) == 32 &&
               sizeof(VZFrameworkNativeIPAInputV1) == 40,
               "Explicit LP64 schema1 input layout");
_Static_assert(VZ_IPA_NATIVE_FIELD_A_OFFSET + 8 <= VZ_IPA_ORIGINAL_NATIVE_WIRE_BYTES &&
               VZ_IPA_NATIVE_FIELD_B_OFFSET + 8 <= VZ_IPA_ORIGINAL_NATIVE_WIRE_BYTES,
               "Both genuine packed fields fit original zero-input wire capacity");

static uint64_t ReadPackedLE64(const unsigned char *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

int32_t VZFrameworkComputeMaxIPAFromNativeV1(const VZFrameworkNativeIPAInputV1 *q,
                                           uint32_t *out) {
    if (!q || !out || !q->wireBytes || q->schemaVersion != VZ_IPA_TRANSFORM_SCHEMA_V1 ||
        q->validatedKernelProfile != VZ_IPA_KERNEL_PROFILE_IPADOS_16_1_1 ||
        q->nativeOperation != 0 || q->wireCapacity != VZ_IPA_ORIGINAL_NATIVE_WIRE_BYTES ||
        q->queryCompleted > 1) return VZ_FRAMEWORK_HV_BAD_ARGUMENT;
    // Exactly mirror the original query's acquisition-error ordering: an
    // unsuccessful native return never authorizes reading result fields.
    if (!q->queryCompleted) return (int32_t)UINT32_C(0xfae94001);
    if (q->actualNativeReturn) return q->actualNativeReturn;
    uintptr_t buffer = (uintptr_t)q->wireBytes, output = (uintptr_t)out;
    if (buffer > UINTPTR_MAX - q->wireCapacity || output > UINTPTR_MAX - sizeof(*out) ||
        (output < buffer + q->wireCapacity && buffer < output + sizeof(*out)))
        return VZ_FRAMEWORK_HV_BAD_ARGUMENT;
    uint64_t a = ReadPackedLE64(q->wireBytes + VZ_IPA_NATIVE_FIELD_A_OFFSET);
    uint64_t b = ReadPackedLE64(q->wireBytes + VZ_IPA_NATIVE_FIELD_B_OFFSET);
    // Original27 rejects either nonzero high half before writing uint32.
    if ((a >> 32) || (b >> 32)) return (int32_t)UINT32_C(0xfae94001);
    uint32_t result = (uint32_t)(a < b ? a : b);
    *out = result;
    return VZ_FRAMEWORK_HV_SUCCESS;
}
