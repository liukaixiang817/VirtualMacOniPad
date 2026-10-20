#ifndef VM27_KERNEL_CONTEXT_PROFILE_V2_H
#define VM27_KERNEL_CONTEXT_PROFILE_V2_H

#include "modern_cpu_kernel_lifecycle.h"

// Both selectors have a verified version-0e context on the pinned iPadOS
// 16.1.1 profile. This permits lifecycle and existing typed state slices;
// it does not permit native ISA3, EL2, VHE or guest execution.
static inline bool VZKernelNativeISAHasValidatedContextV2(uint32_t selector) {
    return selector == VZ_KERNEL_NATIVE_HV_ISA_1 ||
        selector == VZ_KERNEL_NATIVE_HV_ISA_2;
}

#endif
