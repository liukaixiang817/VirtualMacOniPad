// Descriptor-only half of the fixed native reader. Native ownership and the
// context pointer remain private to modern_cpu_kernel_lifecycle.c.
#include "modern_cpu_native_fields.h"
#include <stdio.h>
#include <string.h>

VZKernelStatus VZKernelNativeFieldAt(uint32_t index, VZKernelNativeField *out) {
    if (!out) return VZ_KERNEL_BAD_ARGUMENT;
    if (index >= VZ_KERNEL_NATIVE_FIELD_COUNT) return VZ_KERNEL_UNSUPPORTED;
    VZKernelNativeField f = {.index = index, .bytes = 8};
    if (index < 34) {
        f.domain = VZ_NATIVE_SCALAR;
        f.logicalIdentifier = index;
        f.modernValueKind = VZ_NATIVE_MODERN_SCALAR_VALUE;
        if (index < 31) {
            f.nativeOffset = 8 + index * 8;
            snprintf(f.name, sizeof(f.name), "X%u", index);
        } else {
            static const uint32_t offsets[] = {0x108, 0x344, 0x340};
            static const char *const names[] = {"PC", "FPCR", "FPSR"};
            f.nativeOffset = offsets[index - 31];
            if (index > 31) f.bytes = 4;
            snprintf(f.name, sizeof(f.name), "%s", names[index - 31]);
        }
    } else if (index < 66) {
        f.domain = VZ_NATIVE_SIMD;
        f.logicalIdentifier = index - 34;
        f.nativeOffset = 0x140 + (index - 34) * 16;
        f.bytes = 16;
        f.modernValueKind = VZ_NATIVE_MODERN_SIMD_VALUE;
        snprintf(f.name, sizeof(f.name), "Q%u", index - 34);
    } else if (index < 74) {
        static const uint32_t identifiers[] = {0xc208, 0xe208, 0xc080, 34, 0xc684, 0xde82, 0xde83, 0xd000};
        static const uint32_t offsets[] = {0x370, 0x378, 0x400, 0x110, 0x358, 0x360, 0x368, 0x388};
        static const char *const names[] = {"SP_EL0", "SP_EL1", "SCTLR_EL1", "physical_CPSR", "TPIDR_EL1", "TPIDR_EL0", "TPIDRRO_EL0", "CSSELR_EL1"};
        unsigned which = index - 66;
        f.domain = index == 69 ? VZ_NATIVE_PHYSICAL_CPSR : VZ_NATIVE_SYSTEM;
        f.logicalIdentifier = identifiers[which];
        f.nativeOffset = offsets[which];
        f.modernValueKind = index == 67 || index == 68 || index == 69 ?
            VZ_NATIVE_MODERN_REQUIRES_VIEW : VZ_NATIVE_MODERN_DIRECT_SYSTEM_VALUE;
        if (index == 68) f.nativeReadinessMask = 1;
        if (index == 69) f.bytes = 4;
        snprintf(f.name, sizeof(f.name), "%s", names[which]);
    } else {
        static const uint32_t offsets[] = {0x670, 0x678, 0x748, 0x4100};
        static const char *const names[] = {"native_dirty_670", "native_dirty_678", "native_dirty_748", "native_ready_4100"};
        f.domain = VZ_NATIVE_SYNCHRONIZATION;
        f.logicalIdentifier = UINT32_MAX;
        f.nativeOffset = offsets[index - 74];
        f.modernValueKind = VZ_NATIVE_MODERN_METADATA_ONLY;
        snprintf(f.name, sizeof(f.name), "%s", names[index - 74]);
    }
    *out = f;
    return VZ_KERNEL_OK;
}
