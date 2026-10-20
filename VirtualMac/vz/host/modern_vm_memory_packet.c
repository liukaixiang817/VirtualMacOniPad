#include "modern_vm_memory_packet.h"
#include <limits.h>

_Static_assert(sizeof(uintptr_t) == 8, "Audited LP64 ABI only");
_Static_assert(sizeof(VZKernelMemoryPacket) == 40, "Original native packet width");
_Static_assert(offsetof(VZKernelMemoryPacket, guestAddress) == 8, "Original IPA offset");
_Static_assert(offsetof(VZKernelMemoryPacket, bytes) == 16, "Original size offset");
_Static_assert(offsetof(VZKernelMemoryPacket, flags) == 24, "Original flags offset");
_Static_assert(offsetof(VZKernelMemoryPacket, spaceWord) == 32, "Original space offset");

VZKernelStatus VZKernelMemoryPacketEncode(uint32_t profile,
    VZKernelMemoryOperation operation, uintptr_t hostAddress,
    uint64_t guestAddress, uint64_t bytes, uint64_t flags,
    uint64_t spaceWord, VZKernelMemoryPacket *out) {
    if (!out) return VZ_KERNEL_BAD_ARGUMENT;
    if (profile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 || spaceWord)
        return VZ_KERNEL_UNSUPPORTED;
    if (operation != VZKernelMemoryMap && operation != VZKernelMemoryUnmap &&
        operation != VZKernelMemoryProtect) return VZ_KERNEL_UNSUPPORTED;
    const uint64_t mask = VZ_KERNEL_MEMORY_PROFILE_PAGE_BYTES - 1;
    const uint64_t limit = UINT64_C(1) << 36;
    if (!bytes || ((guestAddress | bytes) & mask) || guestAddress >= limit ||
        bytes > limit - guestAddress || flags & ~UINT64_C(7))
        return VZ_KERNEL_BAD_ARGUMENT;
    if (operation == VZKernelMemoryMap) {
        if (!hostAddress || (hostAddress & mask) || bytes > UINTPTR_MAX - hostAddress)
            return VZ_KERNEL_BAD_ARGUMENT;
    } else if (hostAddress || (operation == VZKernelMemoryUnmap && flags)) {
        return VZ_KERNEL_BAD_ARGUMENT;
    }
    VZKernelMemoryPacket encoded = {hostAddress, guestAddress, bytes, flags, 0};
    *out = encoded;
    return VZ_KERNEL_OK;
}
