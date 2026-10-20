// Pure encoding of the original native3/4/5 memory packet, no kernel calls.
#ifndef VZ_MODERN_VM_MEMORY_PACKET_H
#define VZ_MODERN_VM_MEMORY_PACKET_H
#include "modern_cpu_kernel_lifecycle.h"

#define VZ_KERNEL_MEMORY_PACKET_BYTES 40u
#define VZ_KERNEL_MEMORY_PROFILE_PAGE_BYTES 16384u
typedef enum {
    VZKernelMemoryMap = 3,
    VZKernelMemoryUnmap = 4,
    VZKernelMemoryProtect = 5
} VZKernelMemoryOperation;
typedef struct {
    uint64_t hostAddress, guestAddress, bytes, flags, spaceWord;
} VZKernelMemoryPacket;

// This first profile supports only the default space, 16KiB-aligned ranges
// below the validated 36-bit VM limit and public READ/WRITE/EXECUTE bits.
// Encoding does not establish host ownership, VM ownership or map success.
// The native caller must check those separately. Invalid input preserves out.
VZKernelStatus VZKernelMemoryPacketEncode(uint32_t profile,
    VZKernelMemoryOperation operation, uintptr_t hostAddress,
    uint64_t guestAddress, uint64_t bytes, uint64_t flags,
    uint64_t spaceWord, VZKernelMemoryPacket *out);
#endif
