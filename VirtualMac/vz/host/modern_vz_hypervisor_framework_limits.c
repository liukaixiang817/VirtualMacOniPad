#include "modern_vz_hypervisor_framework_limits.h"
#include <limits.h>

_Static_assert(CHAR_BIT == 8 && sizeof(uint32_t) == 4 && sizeof(int32_t) == 4,
               "Exact original uint32 output and signed32 status ABI");

int32_t hv_vm_get_max_vcpu_count(uint32_t *out) {
    // Null rejection is an explicit app defense beyond Apple's nonnull
    // contract. Never write a result or manufacture success for null.
    if (!out) return VZ_FRAMEWORK_HV_BAD_ARGUMENT;
    *out = VZ_FRAMEWORK_MAXIMUM_VCPU_COUNT;
    return VZ_FRAMEWORK_HV_SUCCESS;
}
