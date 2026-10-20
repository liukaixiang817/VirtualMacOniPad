#ifndef MODERN_VZ_HYPERVISOR_IPA_TRANSFORM_V1_H
#define MODERN_VZ_HYPERVISOR_IPA_TRANSFORM_V1_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define VZ_IPA_TRANSFORM_SCHEMA_V1 UINT32_C(1)
#define VZ_IPA_KERNEL_PROFILE_IPADOS_16_1_1 UINT32_C(1)
#define VZ_IPA_ORIGINAL_NATIVE_WIRE_BYTES ((size_t)352)
#define VZ_IPA_NATIVE_FIELD_A_OFFSET ((size_t)0x149)
#define VZ_IPA_NATIVE_FIELD_B_OFFSET ((size_t)0x151)

typedef struct {
    uint32_t schemaVersion;
    uint32_t validatedKernelProfile;
    // This records a returned native operation, not an intention to query.
    // The acquisition caller must independently establish provenance, buffer
    // ownership, zero-input policy, syscall bytes, canaries and lifetime.
    uint32_t queryCompleted;
    uint32_t nativeOperation;
    int32_t actualNativeReturn;
    const unsigned char *wireBytes;
    size_t wireCapacity;
} VZFrameworkNativeIPAInputV1;

// Pure conversion only, deliberately NOT hv_vm_config_get_max_ipa_size.
// Error/unready input leaves *out unchanged. This routine cannot authenticate
// the caller's provenance record or itself perform a capability query.
int32_t VZFrameworkComputeMaxIPAFromNativeV1(const VZFrameworkNativeIPAInputV1 *input,
                                           uint32_t *out);

#ifdef __cplusplus
}
#endif
#endif
