#ifndef MODERN_VZ_HYPERVISOR_FRAMEWORK_LIMITS_H
#define MODERN_VZ_HYPERVISOR_FRAMEWORK_LIMITS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// This is the genuine macOS27 framework's declared upper bound, established
// by its original sixteen-byte function body. It is not a kernel capacity
// observation or permission to admit sixty-four CPUs on this iPad.
#define VZ_FRAMEWORK_MAXIMUM_VCPU_COUNT UINT32_C(64)
#define VZ_FRAMEWORK_HV_SUCCESS INT32_C(0)
#define VZ_FRAMEWORK_HV_BAD_ARGUMENT ((int32_t)UINT32_C(0xfae94003))

// Original ABI: hv_return_t hv_vm_get_max_vcpu_count(uint32_t *out).
// The original nonnull contract writes exactly four bytes on success.
// This app-private provider additionally rejects null without a store.
int32_t hv_vm_get_max_vcpu_count(uint32_t *out);

#ifdef __cplusplus
}
#endif
#endif
